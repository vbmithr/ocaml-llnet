(* GLOBAL CONFIG *)

let ttl = 5

let (>>=) = Lwt.(>>=)

module V6Map = Map.Make(Ipaddr.V6)

type t = {
  group_saddr: Unix.sockaddr;
  sock: Lwt_unix.file_descr;
  mutable peers: int V6Map.t
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

let base_reactor h dst_saddr typ buf =
  let dst_v6addr = match dst_saddr with
    | Unix.ADDR_INET(addr, _) -> Ipaddr_unix.V6.of_inet_addr_exn addr
    | _ -> raise (Invalid_argument "ADDR_UNIX not supported here") in
  (match typ with
  | HELLO ->
    h.peers <- V6Map.add dst_v6addr ttl h.peers;
    Lwt_unix.sendto h.sock "\002\000\000" 0 3 [] dst_saddr
  | PING ->
    h.peers <- V6Map.add dst_v6addr ttl h.peers;
    Lwt_unix.sendto h.sock "\004\000\000" 0 3 [] dst_saddr
  | _ -> Lwt.return 0) (* We don't react to other messages. *)
  >>= fun (_:int) ->
  Lwt.return_unit

let connect v6addr port user_reactor =
  let sock = Unix.(socket PF_INET6 SOCK_DGRAM 0) in
  Sockopt.IPV6.membership sock v6addr `Join;
  let sock = Lwt_unix.of_unix_file_descr sock in
  let h =
    { group_saddr = Unix.ADDR_INET (Ipaddr_unix.V6.to_inet_addr v6addr, port);
      sock;
      peers = V6Map.empty
    }
  in

  (* ping group every ival seconds *)
  let ping ival =
    let rec inner () =
      (* Decrease TTL of all members *)
      h.peers <- V6Map.fold (fun k v a ->
          if v > 0 then V6Map.add k (pred v) a
          else a
        ) h.peers V6Map.empty;
      Lwt_unix.sendto sock "\003\000\000" 0 3 [] h.group_saddr >>= fun (_:int) ->
      Lwt_unix.sleep ival >>= fun () -> inner ()
    in inner ()
  in

  (* react to incoming messages*)
  let react () =
    let hdrbuf = String.create 3 in
    let rec inner () =
      (* Read header only *)
      Lwt_unix.recvfrom sock hdrbuf 0 3 [] >>= fun (nbread, saddr) ->
      if nbread <> 3 then inner () (* Corrupted header *)
      else
        let msgtyp = Char.code hdrbuf.[0] in
        let msglen = EndianString.BigEndian.get_uint16 hdrbuf 1 in
        let buf = String.create msglen in
        Lwt_unix.recvfrom sock buf 0 msglen [] >>= fun (nbread, saddr) ->
        if nbread <> msglen
        then inner () (* Corrupted message *)
        else
          ((if msgtyp < 100
           then (* control msg *)
             Lwt.async (fun () -> base_reactor h saddr (Char.code buf.[0] |> typ_of_int) buf)
           else (* user msg *)
             Lwt.async (fun () -> user_reactor h saddr buf)
          );
          inner ())
    in inner ()
  in

  (* Launch threads and return handler *)
  Lwt.async (fun () -> react ());
  Lwt.async (fun () -> ping 1.);
  h

let master h = fst (V6Map.min_binding h.peers)

let sendto fd buf off len flags saddr =
  buf.[off-3] <- '\100';
  EndianString.BigEndian.set_int16 buf (off-2) len;
  Lwt_unix.sendto fd buf (off-3) (len+3) flags saddr
