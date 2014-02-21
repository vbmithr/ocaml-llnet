(* GLOBAL CONFIG *)

let ttl = 5

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module StringMap = Map.Make(String)

let get_ai addr service =
  Lwt_unix.getaddrinfo addr service
    Unix.([AI_SOCKTYPE SOCK_DGRAM]) >>= function
  | [] -> Lwt.fail (Failure "getaddrinfo cannot resolve request")
  | ai::tl -> Lwt.return ai

let sock_of_ai ai =
  Unix.(socket ai.ai_family ai.ai_socktype ai.ai_protocol)

type id = string

type t = {
  id: string; (* 20-bytes random identifier *)
  group_saddr: Unix.sockaddr;
  sock: Lwt_unix.file_descr;
  mutable peers: (Unix.sockaddr * int) StringMap.t
}

type typ =
  | HELLO
  | HELLOACK
  | PING
  | PONG
  | USER

let int_of_typ = function
  | HELLO -> 1
  | HELLOACK -> 2
  | PING -> 3
  | PONG -> 4
  | USER -> 100

let typ_of_int = function
  | 1 -> HELLO
  | 2 -> HELLOACK
  | 3 -> PING
  | 4 -> PONG
  | 100 -> USER
  | _ -> raise (Invalid_argument "typ_of_int")

let saddr_of_v6addr_port v6addr port =
  Unix.ADDR_INET (Ipaddr_unix.V6.to_inet_addr v6addr, port)

let connect iface v6addr port user_reactor =
  (* Generate a 20 bytes random identifier *)
  let id = Cryptokit.Random.(device_rng "/dev/urandom" |> fun rng -> string rng 20) in
  get_ai v6addr port >>= fun ai ->
  let sock = sock_of_ai ai in
  let v6addr =
    let open Lwt_unix in
    match ai.ai_addr with
    | ADDR_INET (a, p) -> Ipaddr_unix.V6.of_inet_addr_exn a
    | _ -> raise (Invalid_argument "connect does not support UNIX sockaddrs")
  in
  (* Join multicast group and bind socket to the unspec address. *)
  Unix.handle_unix_error (fun () ->
      Unix.(setsockopt sock SO_REUSEADDR true);
      Sockopt.IPV6.membership ~iface sock v6addr `Join;
      Sockopt.bind6 ~iface sock v6addr (port |> int_of_string);
    ) ();
  let sock = Lwt_unix.of_unix_file_descr sock in
  let h =
    { id;
      group_saddr = ai.Lwt_unix.ai_addr;
      sock;
      peers = StringMap.empty
    }
  in

  let idmsg = String.create 23 in
  EndianString.BigEndian.set_int16 idmsg 1 20;
  String.blit id 0 idmsg 3 20;

  (* ping group every ival seconds *)
  let ping ival =
    (* First time, say HELLO *)
    idmsg.[0] <- int_of_typ HELLO |> Char.chr;
    Lwt_unix.sendto sock idmsg 0 23 [] h.group_saddr >>= fun (_:int) ->
    let rec inner () =
      (* Decrease TTL of all members *)
      h.peers <- StringMap.fold (fun k v a ->
          if snd v > 0 then StringMap.add k (fst v, (pred (snd v))) a
          else a
        ) h.peers StringMap.empty;
      idmsg.[0] <- int_of_typ PING |> Char.chr;
      Lwt_unix.sendto sock idmsg 0 23 [] h.group_saddr >>= fun (_:int) ->
      Lwt_unix.sleep ival >>= fun () -> inner ()
    in inner ()
  in

  (* Base reactor to react to protocol messages *)
  let base_reactor dst_saddr buf =
    (match typ_of_int (Char.code buf.[0]) with
     | HELLO ->
       Lwt_log.ign_info "Received HELLO.";
       h.peers <- StringMap.add buf (dst_saddr, ttl) h.peers;
       idmsg.[0] <- int_of_typ HELLOACK |> Char.chr;
       Lwt_unix.sendto sock idmsg 0 23 [] dst_saddr
     | PING ->
       Lwt_log.ign_info "Received PING.";
       h.peers <- StringMap.add buf (dst_saddr, ttl) h.peers;
       idmsg.[0] <- int_of_typ PONG |> Char.chr;
       Lwt_unix.sendto h.sock idmsg 0 23 [] dst_saddr
     | _ -> Lwt.return 0) (* We don't react to other messages. *)
    >>= fun (_:int) ->
    Lwt.return_unit
  in

  (* react to incoming messages*)
  let react () =
    let hdrbuf = String.create 3 in
    let rec inner () =
      (* Read header only *)
      Lwt_unix.(recvfrom sock hdrbuf 0 3 [MSG_PEEK]) >>= fun (nbread, saddr) ->
      Lwt_log.ign_debug "Incoming message: read header.";
      if nbread <> 3 then
        (
          Lwt_log.ign_debug_f "Corrupted header: len %d, expected 3" nbread;
          inner ()
        )
      else
        let msgtyp = Char.code hdrbuf.[0] in
        let msglen = EndianString.BigEndian.get_uint16 hdrbuf 1 in
        let buf = String.create (msglen+3) in
        Lwt_unix.recvfrom sock buf 0 (msglen+3) [] >>= fun (nbread, saddr) ->
        if nbread <> (msglen+3)
        then
          (
            Lwt_log.ign_debug_f "Corrupted message: len %d, expected %d" nbread msglen;
            inner ()
          )
        else
          ((if msgtyp < 100
           then (* control msg *)
             (
               Lwt_log.ign_debug "Receiving a control msg.";
               Lwt.async (fun () -> base_reactor saddr buf)
             )
           else (* user msg *)
             (
               Lwt_log.ign_debug "Receiving a user msg.";
               Lwt.async (fun () -> user_reactor h saddr buf)
             )
          );
          inner ())
    in inner ()
  in

  (* Launch threads and return handler *)
  Lwt.async (fun () -> react ());
  Lwt_unix.sleep 0.1 >>= fun () ->
  Lwt.async (fun () -> ping 1.);
  Lwt.return h

let master h = fst (StringMap.min_binding h.peers)

let sendto h buf off len flags saddr =
  buf.[off-3] <- '\100';
  EndianString.BigEndian.set_int16 buf (off-2) len;
  Lwt_unix.sendto h.sock buf (off-3) (len+3) flags saddr

let sendto_group h buf off len flags = sendto h buf off len flags h.group_saddr

let sendto_master h buf off len flags =
  let master_saddr = snd (StringMap.min_binding h.peers) |> fst in
  sendto h buf off len flags master_saddr

let sendto_peer h buf off len flags id =
  let id_saddr = (StringMap.find id h.peers) |> fst in
  sendto h buf off len flags id_saddr
