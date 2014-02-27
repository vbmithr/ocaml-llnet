(* GLOBAL CONFIG *)

let init_ttl = 5
let hdr_size = 5

(*****************)

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

let section = Lwt_log.Section.make "Llnet"

module Helpers = struct
  let string_of_saddr saddr =
    let open Unix in
    match saddr with
    | ADDR_INET (a, p) -> Printf.sprintf "[%s]:%d" (string_of_inet_addr a) p
    | ADDR_UNIX p -> Printf.sprintf "unix://%s" p
end

module SaddrMap = Map.Make(struct
    type t = Unix.sockaddr
    let compare = Pervasives.compare
  end)

type id = string

type t = {
  group_sock: Lwt_unix.file_descr;
  group_saddr: Unix.sockaddr;
  tcp_in_sock: Lwt_unix.file_descr;
  tcp_in_port: int;
  mutable peers: (int * bool) SaddrMap.t;
}

type typ =
  | PING

let int_of_typ = function
  | PING -> 3

let typ_of_int = function
  | 3 -> PING
  | _ -> raise (Invalid_argument "typ_of_int")

let saddr_of_v6addr_port v6addr port =
  Unix.ADDR_INET (Ipaddr_unix.V6.to_inet_addr v6addr, port)

let v6addr_of_saddr = function
  | Unix.ADDR_INET (a, _) -> Ipaddr_unix.V6.of_inet_addr_exn a
  | _ -> raise (Invalid_argument "v6addr_of_saddr")

let saddr_with_port saddr port =
  match saddr with
  | Unix.ADDR_INET (a, _) -> Unix.ADDR_INET (a, port)
  | _ -> raise (Invalid_argument "saddr_with_port")

let peer_ignored h p =
  try SaddrMap.find p h.peers |> snd
  with Not_found -> false

let connect iface v6addr port mcast_reactor tcp_reactor =
  (* Join multicast group and bind socket to the group address. *)
  let group_sock = Unix.(socket PF_INET6 SOCK_DGRAM 0) in
  let tcp_in_sock = Unix.(socket PF_INET6 SOCK_STREAM 0) in
  Unix.handle_unix_error (fun () ->
      Unix.(setsockopt group_sock SO_REUSEADDR true);
      Unix.(setsockopt tcp_in_sock SO_REUSEADDR true);
      Sockopt.IPV6.membership ~iface group_sock v6addr `Join;
      Sockopt.bind6 ~iface group_sock v6addr port;
      Sockopt.bind6 tcp_in_sock Ipaddr.V6.unspecified 0;
      Unix.listen tcp_in_sock 5;
    ) ();
  let tcp_in_port = Unix.(match getsockname tcp_in_sock with
      | ADDR_INET (a, p) -> p
      | _ -> raise (Invalid_argument "my_port")) in
  let group_sock = Lwt_unix.of_unix_file_descr group_sock in
  let tcp_in_sock = Lwt_unix.of_unix_file_descr tcp_in_sock in
  let h =
    { group_sock;
      group_saddr = saddr_of_v6addr_port v6addr port;
      tcp_in_sock;
      tcp_in_port;
      peers = SaddrMap.empty
    }
  in

  Lwt_log.ign_debug_f ~section "Bound TCP port %d" tcp_in_port;

  let idmsg = String.create 5 in
  EndianString.BigEndian.set_int16 idmsg 1 tcp_in_port;
  EndianString.BigEndian.set_int16 idmsg 3 (String.length idmsg - hdr_size);

  (* ping group every ival seconds *)
  let ping ival =
    let rec inner () =
      (* Decrease TTL of all members *)
      h.peers <- SaddrMap.fold (fun k (ttl, ign) a ->
          if ttl > 0 then SaddrMap.add k (pred ttl, ign) a
          else a
        ) h.peers SaddrMap.empty;
      idmsg.[0] <- int_of_typ PING |> Char.chr;
      Lwt_unix.sendto group_sock idmsg 0 (String.length idmsg) [] h.group_saddr >>= fun (_:int) ->
      Lwt_unix.sleep ival >>= fun () -> inner ()
    in inner ()
  in

  (* Base reactor to react to protocol messages *)
  let base_reactor saddr buf =
    match typ_of_int (Char.code buf.[0]) with
    | PING ->
      Lwt_log.ign_info ~section "Received PING.";
      (try
        let ttl, ign = SaddrMap.find saddr h.peers in
        h.peers <- SaddrMap.add saddr (init_ttl, ign) h.peers
      with Not_found ->
        h.peers <- SaddrMap.add saddr (init_ttl, false) h.peers
      );
      Lwt.return_unit
  in

  let process h saddr buf =
    let remote_port = EndianString.BigEndian.get_uint16 buf 1 in
    let saddr = saddr_with_port saddr remote_port in
    match buf.[0], peer_ignored h saddr with
    | c,  _ when c < '\100' -> (* control msg *)
      (
        Lwt_log.ign_debug ~section "Receiving a control msg.";
        Lwt.async (fun () -> base_reactor saddr buf)
      )
    | _, false ->
      (
        Lwt_log.ign_debug ~section "Receiving a user msg, forwarding";
        Lwt.async (fun () -> mcast_reactor h saddr buf)
      )
    | _ -> ()
  in

  (* react to incoming messages *)
  let react sock process =
    let hdrbuf = String.create hdr_size in
    let rec inner () =
      (* Read header only *)
      Lwt_unix.(recvfrom sock hdrbuf 0 hdr_size [MSG_PEEK]) >>= fun (nbread, saddr) ->
      Lwt_log.ign_debug ~section "Incoming message: read header.";
      if nbread <> hdr_size then
        (
          Lwt_log.ign_debug_f ~section
            "Corrupted header: len %d, expected %d" nbread hdr_size;
          inner ()
        )
      else
        let msglen = EndianString.BigEndian.get_uint16 hdrbuf 3 in
        let buf = String.create (hdr_size + msglen) in
        Lwt_unix.recvfrom group_sock buf 0 (hdr_size + msglen) [] >>= fun (nbread, saddr) ->
        if nbread <> (hdr_size + msglen)
        then
          (
            Lwt_log.ign_debug_f ~section
              "Corrupted message: len %d, expected %d" nbread (hdr_size + msglen);
            inner ();
          )
        else
          (
            process h saddr buf;
            inner ()
          )
    in inner ()
  in

  let accept_forever fd =
    let rec inner () =
      Lwt_unix.accept fd >>= fun (fd, dst_saddr) ->
      Lwt.async (fun () -> tcp_reactor fd dst_saddr);
      inner ()
    in inner ()

  in
  (* Launch threads and return handler *)
  Lwt.async (fun () -> react group_sock process);
  Lwt.async (fun () -> accept_forever tcp_in_sock);
  Lwt.async (fun () -> ping 1.);
  h

let master h = fst (SaddrMap.min_binding h.peers)

let sendto_master h buf off len flags =
  let master_saddr = SaddrMap.min_binding h.peers |> fst in
  Lwt_unix.sendto h.group_sock buf off len flags master_saddr

let sendto_group h buf off len flags =
  Lwt_unix.sendto h.group_sock buf off len flags h.group_saddr

let ignore_peer h p =
  try
    let ttl, _ = SaddrMap.find p h.peers in
    h.peers <- SaddrMap.add p (ttl, true) h.peers
  with Not_found ->
    h.peers <- SaddrMap.add p (0, true) h.peers
