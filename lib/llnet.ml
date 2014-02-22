(* GLOBAL CONFIG *)

let init_ttl = 5
let hdr_size = 3

(*****************)

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module SaddrMap = Map.Make(struct
    type t = Ipaddr.V6.t * int
    let compare = Pervasives.compare
  end)

type id = string

type t = {
  group_sock: Lwt_unix.file_descr;
  group_saddr: Unix.sockaddr;
  my_sock: Lwt_unix.file_descr;
  my_port: int;
  mutable peers: int SaddrMap.t
}

type typ =
  | HELLO
  | HELLOACK
  | PING
  | PONG
  | USER of int

let int_of_typ = function
  | HELLO -> 1
  | HELLOACK -> 2
  | PING -> 3
  | PONG -> 4
  | USER n -> n

let typ_of_int = function
  | 1 -> HELLO
  | 2 -> HELLOACK
  | 3 -> PING
  | 4 -> PONG
  | n when n > 99 -> USER n
  | _ -> raise (Invalid_argument "typ_of_int")

let saddr_of_v6addr_port v6addr port =
  Unix.ADDR_INET (Ipaddr_unix.V6.to_inet_addr v6addr, port)

let v6addr_of_saddr = function
  | Unix.ADDR_INET (a, _) -> Ipaddr_unix.V6.of_inet_addr_exn a
  | _ -> raise (Invalid_argument "v6addr_of_saddr")

let connect iface v6addr port user_reactor =
  (* Join multicast group and bind socket to the group address. *)
  let group_sock = Unix.(socket PF_INET6 SOCK_DGRAM 0) in
  let my_sock = Unix.(socket PF_INET6 SOCK_DGRAM 0) in
  Unix.handle_unix_error (fun () ->
      Unix.(setsockopt group_sock SO_REUSEADDR true);
      Unix.(setsockopt my_sock SO_REUSEADDR true);
      Sockopt.IPV6.membership ~iface group_sock v6addr `Join;
      Sockopt.bind6 ~iface group_sock v6addr port;
      Sockopt.bind6 my_sock Ipaddr.V6.unspecified 0;
    ) ();
  let my_port = Unix.(match getsockname my_sock with
    | ADDR_INET (a, p) -> p
    | _ -> raise (Invalid_argument "my_port")) in
  let group_sock = Lwt_unix.of_unix_file_descr group_sock in
  let my_sock = Lwt_unix.of_unix_file_descr my_sock in
  let h =
    { group_sock;
      group_saddr = saddr_of_v6addr_port v6addr port;
      my_sock;
      my_port;
      peers = SaddrMap.empty
    }
  in

  let idmsg = String.create 5 in
  EndianString.BigEndian.set_int16 idmsg 1 (String.length idmsg - hdr_size);
  EndianString.BigEndian.set_int16 idmsg 3 my_port;

  (* ping group every ival seconds *)
  let ping ival =
    let rec inner () =
      (* Decrease TTL of all members *)
      h.peers <- SaddrMap.fold (fun k v a ->
          if v > 0 then SaddrMap.add k (pred v) a
          else a
        ) h.peers SaddrMap.empty;
      idmsg.[0] <- int_of_typ PING |> Char.chr;
      Lwt_unix.sendto group_sock idmsg 0 (String.length idmsg) [] h.group_saddr >>= fun (_:int) ->
      Lwt_unix.sleep ival >>= fun () -> inner ()
    in inner ()
  in

  (* Base reactor to react to protocol messages *)
  let base_reactor dst_saddr buf =
    (match typ_of_int (Char.code buf.[0]) with
     | PING ->
       Lwt_log.ign_info "Received PING.";
       h.peers <- SaddrMap.add (dst_saddr |> v6addr_of_saddr,
                                EndianString.BigEndian.get_uint16 buf 3) init_ttl h.peers;
       idmsg.[0] <- int_of_typ PONG |> Char.chr;
       Lwt_unix.sendto h.group_sock idmsg 0 (String.length idmsg) [] dst_saddr
     | _ -> Lwt.return 0) (* We don't react to other messages. *)
    >>= fun (_:int) ->
    Lwt.return_unit
  in

  (* react to incoming messages*)
  let react () =
    let hdrbuf = String.create 3 in
    let rec inner () =
      (* Read header only *)
      Lwt_unix.(recvfrom group_sock hdrbuf 0 3 [MSG_PEEK]) >>= fun (nbread, saddr) ->
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
        Lwt_unix.recvfrom group_sock buf 0 (msglen+3) [] >>= fun (nbread, saddr) ->
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
  Lwt.async (fun () -> ping 1.);
  h

let master h = fst (SaddrMap.min_binding h.peers)

let sendto_group h buf off len flags =
  Lwt_unix.sendto h.group_sock buf off len flags h.group_saddr

let sendto_master h buf off len flags =
  let master_saddr = SaddrMap.min_binding h.peers |> fst
                     |> fun (a,p) -> saddr_of_v6addr_port a p in
  Lwt_unix.sendto h.my_sock buf off len flags master_saddr
