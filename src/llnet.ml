(*---------------------------------------------------------------------------
   Copyright (c) 2016 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
   %%NAME%% %%VERSION%%
  ---------------------------------------------------------------------------*)

(* GLOBAL CONFIG *)

let init_ttl = 5
let hdr_size = 24

(* Message format used by the protocol:

T: 2 byte, message type, big endian
IP addr: 8 bytes, unicast address of the host
port: 2 bytes, tcp port of the host, big endian
size: 4 bytes, message size not including the header, big endian

*)


(*****************)

open Lwt.Infix

let section = Lwt_log.Section.make "Llnet"

module Helpers = struct
  let string_of_saddr saddr =
    let open Unix in
    match saddr with
    | ADDR_INET (a, p) -> Printf.sprintf "[%s]:%d" (string_of_inet_addr a) p
    | ADDR_UNIX p -> Printf.sprintf "unix://%s" p

  let saddr_of_v6addr_port v6addr port =
    Unix.ADDR_INET (Ipaddr_unix.V6.to_inet_addr v6addr, port)

  let saddr_of_addr_port addr port =
    Unix.ADDR_INET (Ipaddr_unix.to_inet_addr addr, port)

  let v6addr_of_saddr = function
    | Unix.ADDR_INET (a, _) -> Ipaddr_unix.V6.of_inet_addr_exn a
    | _ -> raise (Invalid_argument "v6addr_of_saddr")

  let v6addr_port_of_saddr saddr =
    let open Unix in
    match saddr with
    | ADDR_INET (a, p) -> Ipaddr_unix.V6.of_inet_addr_exn a, p
    | _ -> raise (Invalid_argument "v6addr_port_of_saddr")

  let addr_port_of_saddr saddr =
    let open Unix in
    match saddr with
    | ADDR_INET (a, p) -> Ipaddr_unix.of_inet_addr a, p
    | _ -> raise (Invalid_argument "addr_port_of_saddr")

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

type 'a t = {
  ival: float;
  group_sock: Lwt_unix.file_descr;
  group_saddr: Unix.sockaddr;
  tcp_in_sock: Lwt_unix.file_descr;
  tcp_in_saddr: Unix.sockaddr;
  mutable peers: (int * bool) SaddrMap.t;
  not_alone: bool Lwt_condition.t;
  clock: unit Lwt_condition.t;
  mutable user_data: 'a option;
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
    ?(tcp_port=0)
    ?(ival=1.)
    ?(udp_wait=Lwt.return_unit)
    ?(tcp_wait=Lwt.return_unit)
    ?(group_reactor=(fun _ _ _ -> Lwt.return_unit))
    ?(tcp_reactor=(fun _ fd _ -> Lwt_unix.close fd >>= fun () -> Lwt.return_unit))
    ?user_data
    ~iface group_saddr =

  let group_addr, group_port = match group_saddr with
    | Unix.ADDR_UNIX _ -> raise (Invalid_argument "UNIX sockets not supported")
    | Unix.ADDR_INET (a, p) -> a, p in

  (* Find a valid IP address to bind the TCP sock to. Prefer IPv6 over
     IPv4. *)

  let my_ipaddr =
    let ifaddrs =
      List.filter (fun (name, ipaddr) -> name = iface) (Tuntap.getifaddrs ())
    in
    let ifaddrs =
      ListLabels.fast_sort ifaddrs ~cmp:(fun a b -> match a, b with
          | (_, `V4 _), (_, `V6 _) -> -1
          | (_, `V6 _), (_, `V4 _) -> 1
          | _ -> 0)
    in
    match ifaddrs with
    | [] ->
        failwith
          (Printf.sprintf "Interface %s has no usable IP address associated" iface)
    | (name, ipaddr) :: _ ->
        (match ipaddr with
         | `V4 (ip, _) -> Ipaddr_unix.V4.to_inet_addr ip
         | `V6 (ip, _) -> Ipaddr_unix.V6.to_inet_addr ip
        )
  in

  (* Join multicast group and bind socket to the group address. *)

  let group_sock = Unix.(socket (domain_of_sockaddr group_saddr) SOCK_DGRAM 0) in
  let tcp_in_sock = Unix.(socket PF_INET6 SOCK_STREAM 0) in

  Unix.(setsockopt group_sock SO_REUSEADDR true);
  Unix.(setsockopt tcp_in_sock SO_REUSEADDR true);

  Sockopt.Unix.bind ~iface group_sock group_saddr;
  Sockopt.Unix.membership ~iface group_sock group_addr `Join;

  Unix.(bind tcp_in_sock (ADDR_INET(inet6_addr_any, tcp_port)));

  Unix.listen tcp_in_sock 5;

  (* substitute inet6_addr_any with the real IP and maybe 0 with the
     real port *)
  let tcp_in_saddr, tcp_port = match Unix.getsockname tcp_in_sock with
    | Unix.ADDR_INET (a, p) -> Unix.ADDR_INET (my_ipaddr, p), p
    | _ -> assert false in

  (* Obtain Lwt_unix.file_descr from Unix.file_descr *)
  let group_sock = Lwt_unix.of_unix_file_descr group_sock in
  let tcp_in_sock = Lwt_unix.of_unix_file_descr tcp_in_sock in

  let h =
    { ival;
      group_sock;
      group_saddr;
      tcp_in_sock;
      tcp_in_saddr;
      peers = SaddrMap.singleton tcp_in_saddr (max_int, false);
      not_alone = Lwt_condition.create ();
      clock = Lwt_condition.create ();
      user_data
    }
  in

  Lwt_log.ign_debug_f ~section "Bound TCP port %d" tcp_port;

  let idmsg = Bytes.make hdr_size '\000'in
  (match Ipaddr_unix.of_inet_addr my_ipaddr with
  | Ipaddr.V4 addr -> Ipaddr.V4.to_bytes_raw addr idmsg 14
  | Ipaddr.V6 addr -> Ipaddr.V6.to_bytes_raw addr idmsg 2);
  EndianString.BigEndian.set_int16 idmsg 18 tcp_port;
  EndianString.BigEndian.set_int32 idmsg 20 0l;

  (* ping group every ival seconds *)
  let ping ival =
    let rec inner n =
      (* Decrease TTL of all members (except oneself) and remove the
         expired ones *)
      h.peers <- SaddrMap.fold (fun k (ttl, ign) a ->
          match k, ttl with
          | k, _ when k = tcp_in_saddr -> SaddrMap.add k (max_int, false) a
          | k, ttl when ttl > 0 -> SaddrMap.add k (pred ttl, ign) a
          | _ -> a
        ) h.peers SaddrMap.empty;
      EndianString.BigEndian.set_int16 idmsg 0 (int_of_typ PING);
      Lwt_unix.sendto group_sock idmsg 0 (Bytes.length idmsg) [] h.group_saddr >>= fun (_:int) ->
      Lwt_unix.sleep ival >>= fun () -> inner (succ n)
    in inner 0
  in

  (* Base reactor to react to protocol messages *)
  let base_reactor saddr buf =
    match typ_of_int (EndianString.BigEndian.get_int16 buf 0) with
    | PING ->
      Lwt_log.ign_info_f ~section "Received PING from %s" (string_of_saddr saddr);
      Lwt_condition.broadcast h.clock ();
      if saddr <> tcp_in_saddr then
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

  let saddr_of_msg buf =
    let port = EndianString.BigEndian.get_int16 buf 18 in
    (* Correct endianness: weird issue I have just got with
       ocplib-endian. *)
    let port = if port < 0 then port + 65536 else port in
    let ipver = if buf.[3] = '\000' then `V4 else `V6 in
    if ipver = `V4
    then
      let ipv4 = Ipaddr.V4.of_bytes_raw buf 14 in
      Unix.ADDR_INET (Ipaddr_unix.V4.to_inet_addr ipv4, port)
    else
      let ipv6 = Ipaddr.V6.of_bytes_raw buf 2 in
      Unix.ADDR_INET (Ipaddr_unix.V6.to_inet_addr ipv6, port)

  in

  let process h buf =
    let saddr = saddr_of_msg buf in
    match buf.[0], peer_ignored h saddr with
    | c,  _ when c = '\000' -> (* control msg: [0; 255] *)
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

  (* react to incoming messages on the multicast network *)
  let react sock process =
    let hdrbuf = Bytes.create hdr_size in
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
        let msglen = hdr_size + (EndianBytes.BigEndian.get_int32 hdrbuf 20
                                 |> Int32.to_int) in
        let buf = Bytes.create msglen in
        Lwt_unix.recvfrom group_sock buf 0 msglen [] >>= fun (nbread, _) ->
        if nbread <> msglen
        then
          (
            Lwt_log.ign_debug_f ~section
              "Corrupted message: len %d, expected %d" nbread msglen;
            inner ();
          )
        else
          (
            process h @@ Bytes.unsafe_to_string buf;
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

let neighbours_nonblock h =
  let peers_rev_list =
    SaddrMap.fold
      (fun saddr (ttl, ignored) a ->
         if ttl > 0 && not ignored && saddr <> h.tcp_in_saddr
         then saddr::a
         else a
      )
      h.peers [] in
  List.rev peers_rev_list

let neighbours h =
  (if valid_cardinal h.peers < 2
  then Lwt_condition.wait h.not_alone
  else Lwt.return true)
  >>= fun _ -> neighbours_nonblock h |> Lwt.return

(*---------------------------------------------------------------------------
   Copyright (c) 2016 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
