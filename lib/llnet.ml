(* GLOBAL CONFIG *)

let init_ttl = 5
let hdr_size = 5

(* Message format used by the protocol:

0   1   2   3   4   5
---------------------
| T | port  | size  |
---------------------

T: 1 byte, message type
port: 2 bytes, tcp port of the host
size: 2 bytes, message size not including the header

*)


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

  let saddr_of_v6addr_port v6addr port =
    Unix.ADDR_INET (Ipaddr_unix.V6.to_inet_addr v6addr, port)

  let v6addr_of_saddr = function
    | Unix.ADDR_INET (a, _) -> Ipaddr_unix.V6.of_inet_addr_exn a
    | _ -> raise (Invalid_argument "v6addr_of_saddr")

  let v6addr_port_of_saddr saddr =
    let open Unix in
    match saddr with
    | ADDR_INET (a, p) -> Ipaddr_unix.V6.of_inet_addr_exn a, p
    | _ -> raise (Invalid_argument "v6addr_of_saddr")

  let saddr_with_port saddr port =
    match saddr with
    | Unix.ADDR_INET (a, _) -> Unix.ADDR_INET (a, port)
    | _ -> raise (Invalid_argument "saddr_with_port")

  let port_of_saddr = function
    | Unix.ADDR_INET (_, p) -> p
    | _ -> raise (Invalid_argument "port_of_saddr")
end

open Helpers

module OrderedSockaddr = struct
  type t = Unix.sockaddr
  let compare = Pervasives.compare
end

module SaddrMap = Map.Make(OrderedSockaddr)
module SaddrSet = Set.Make(OrderedSockaddr)

type id = string

type t = {
  group_sock: Lwt_unix.file_descr;
  group_saddr: Unix.sockaddr;
  tcp_in_sock: Lwt_unix.file_descr;
  tcp_in_saddr: Unix.sockaddr;
  mutable peers: (int * bool) SaddrMap.t;
  not_alone: bool Lwt_condition.t
}

type typ =
  | PING

let int_of_typ = function
  | PING -> 3

let typ_of_int = function
  | 3 -> PING
  | _ -> raise (Invalid_argument "typ_of_int")

let peer_ignored h p =
  try SaddrMap.find p h.peers |> snd
  with Not_found -> false

let valid_cardinal peers =
  SaddrMap.fold (fun saddr (ttl, ign) a -> if ign || ttl <= 0 then a else succ a) peers 0

let connect
    ?(ival=1.)
    ?(udp_wait=Lwt.return_unit)
    ?(tcp_wait=Lwt.return_unit)
    ?(group_reactor=(fun _ _ _ -> Lwt.return_unit))
    ?(tcp_reactor=(fun _ fd _ -> Lwt_unix.close fd >>= fun () -> Lwt.return_unit))
    ~iface group_addr port =
  (* Join multicast group and bind socket to the group address. *)
  let group_sock = Unix.(socket PF_INET6 SOCK_DGRAM 0) in
  let tcp_in_sock = Unix.(socket PF_INET6 SOCK_STREAM 0) in
  Unix.handle_unix_error (fun () ->
      Unix.(setsockopt group_sock SO_REUSEADDR true);
      Unix.(setsockopt tcp_in_sock SO_REUSEADDR true);
      Sockopt.IPV6.membership ~iface group_sock group_addr `Join;
      Sockopt.bind6 ~iface group_sock group_addr port;
      Sockopt.bind6 tcp_in_sock Ipaddr.V6.unspecified 0;
      Unix.listen tcp_in_sock 5;
    ) ();
  let my_ipaddr =
    let open Tuntap in
    List.fold_left
      (fun a { name; ipaddr } -> match name, ipaddr with
         | name, AF_INET6 (addr, _) when Ipaddr.(V6.is_private addr) && name = iface ->
           Some (Ipaddr_unix.V6.to_inet_addr addr)
         | _ -> a
      ) None (Tuntap.getifaddrs ()) in
  let tcp_in_saddr = Unix.(match my_ipaddr, (getsockname tcp_in_sock) with
      | Some ip, ADDR_INET (a, p) -> ADDR_INET (ip, p)
      | None, _ -> failwith (Printf.sprintf "Interface %s either do not exist or does not have an associated IPv6 address" iface)
      | _ -> raise (Invalid_argument "tcp_in_saddr")) in
  let group_sock = Lwt_unix.of_unix_file_descr group_sock in
  let tcp_in_sock = Lwt_unix.of_unix_file_descr tcp_in_sock in
  let h =
    { group_sock;
      group_saddr = saddr_of_v6addr_port group_addr port;
      tcp_in_sock;
      tcp_in_saddr;
      peers = SaddrMap.singleton tcp_in_saddr (init_ttl, false);
      not_alone = Lwt_condition.create ()
    }
  in

  Lwt_log.ign_debug_f ~section "Bound TCP port %d" (port_of_saddr tcp_in_saddr);

  let idmsg = String.create 5 in
  EndianString.BigEndian.set_int16 idmsg 1 (port_of_saddr tcp_in_saddr);
  EndianString.BigEndian.set_int16 idmsg 3 (String.length idmsg - hdr_size);

  (* ping group every ival seconds *)
  let ping ival =
    let rec inner n =
      (* Decrease TTL of all members and remove the expired ones *)
      h.peers <- SaddrMap.fold (fun k (ttl, ign) a ->
          if ttl > 0 then SaddrMap.add k (pred ttl, ign) a
          else a
        ) h.peers SaddrMap.empty;
      idmsg.[0] <- int_of_typ PING |> Char.chr;
      Lwt_unix.sendto group_sock idmsg 0 (String.length idmsg) [] h.group_saddr >>= fun (_:int) ->
      Lwt_unix.sleep ival >>= fun () -> inner (succ n)
    in inner 0
  in

  (* Base reactor to react to protocol messages *)
  let base_reactor saddr buf =
    match typ_of_int (Char.code buf.[0]) with
    | PING ->
      Lwt_log.ign_info ~section "Received PING";
      (try
        let ttl, ign = SaddrMap.find saddr h.peers in
        h.peers <- SaddrMap.add saddr (init_ttl, ign) h.peers
      with Not_found ->
        h.peers <- SaddrMap.add saddr (init_ttl, false) h.peers
      );
      if valid_cardinal h.peers = 2 (* We just detected a first peer *)
      then Lwt_condition.broadcast h.not_alone true;
      Lwt.return_unit
  in

  let process h saddr buf =
    let remote_port = EndianString.BigEndian.get_uint16 buf 1 in
    let saddr = saddr_with_port saddr remote_port in
    match buf.[0], peer_ignored h saddr with
    | c,  _ when c < '\100' -> (* control msg *)
      (
        Lwt_log.ign_debug ~section "Receiving a control msg";
        Lwt.async (fun () -> base_reactor saddr buf)
      )
    | _, false ->
      (
        Lwt_log.ign_debug ~section "Receiving a user msg, forwarding";
        Lwt.async (fun () -> udp_wait >>= fun () -> group_reactor h saddr buf)
      )
    | _ -> ()
  in

  (* react to incoming messages *)
  let react sock process =
    let hdrbuf = String.create hdr_size in
    let rec inner () =
      (* Read header only *)
      Lwt_unix.(recvfrom sock hdrbuf 0 hdr_size [MSG_PEEK]) >>= fun (nbread, saddr) ->
      if nbread <> hdr_size then
        (
          Lwt_log.ign_debug_f ~section
            "Corrupted header: len %d, expected %d" nbread hdr_size;
          inner ()
        )
      else
        let msglen = hdr_size + EndianString.BigEndian.get_uint16 hdrbuf 3 in
        let buf = String.create msglen in
        Lwt_unix.recvfrom group_sock buf 0 msglen [] >>= fun (nbread, saddr) ->
        if nbread <> msglen
        then
          (
            Lwt_log.ign_debug_f ~section
              "Corrupted message: len %d, expected %d" nbread msglen;
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
      Lwt.async (fun () -> tcp_reactor h fd dst_saddr);
      inner ()
    in inner ()

  in
  (* Launch threads and return handler *)
  Lwt.async (fun () -> react group_sock process);
  Lwt.async (fun () -> tcp_wait >>= fun () -> accept_forever tcp_in_sock);
  Lwt.async (fun () -> ping ival);
  Lwt.return h

let ignore_peer h p =
  try
    let ttl, _ = SaddrMap.find p h.peers in
    h.peers <- SaddrMap.add p (ttl, true) h.peers
  with Not_found ->
    h.peers <- SaddrMap.add p (0, true) h.peers

let order h =
  let indexed_list =
    List.mapi
      (fun i (k,_) -> k, i)
      (SaddrMap.bindings h.peers)
  in
  List.find (fun (k, _) -> h.tcp_in_saddr = k) indexed_list |> snd

let neighbours h =
  (if valid_cardinal h.peers < 2
  then Lwt_condition.wait h.not_alone
  else Lwt.return true)
  >>= fun _ ->
  let peers_rev_list =
    SaddrMap.fold
      (fun saddr (ttl, ignored) a ->
         if ttl > 0 && not ignored && saddr <> h.tcp_in_saddr
         then saddr::a
         else a
      )
      h.peers [] in
  Lwt.return (List.rev peers_rev_list)
