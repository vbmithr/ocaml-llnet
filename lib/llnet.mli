(** Library to use unreliable IPv6 multicast networks. It mostly
    handles keeping track of peers that use the same protocol. *)

module Helpers : sig
  val string_of_saddr: Unix.sockaddr -> string
end

module SaddrMap : Map.S with type key = Unix.sockaddr

type id = string
(** Type of peer identifiers. *)

type t = {
  group_sock: Lwt_unix.file_descr; (* UDP socket bound to a multicast sockaddr. *)
  group_saddr: Unix.sockaddr; (* multicast group sockaddr. *)
  tcp_in_sock: Lwt_unix.file_descr; (* TCP socket for incoming connection. *)
  tcp_in_port: int; (* Port of the incoming TCP socket. *)
  mutable peers: (int * bool) SaddrMap.t (* Map of saddr -> TTL *)
}
(** Handler to a connection to a multicast network. *)

val hdr_size : int
(** Size of the header of protocol messages. *)

val connect : string -> Ipaddr.V6.t -> int ->
  (t -> Unix.sockaddr -> string -> unit Lwt.t) ->
  (Lwt_unix.file_descr -> Lwt_unix.sockaddr -> unit Lwt.t) ->
  t
(** [connect iface v6addr port group_reactor my_reactor] returns an
    handler to the multicast network [v6addr:port], where [v6addr] is
    a IPv6 multicast address, port is the port number to use and
    [group_reactor] and [my_reactor] are callbacks that will be
    triggered upon receiving a message on the UDP multicast socket,
    resp. the private unicast TCP socket. *)

val master : t -> SaddrMap.key
(** IP address of the master on the network (defined by the smallest
    IPv6 on this current implementation. *)

val sendto_master : t -> string -> int -> int -> Lwt_unix.msg_flag list -> int Lwt.t
(** Send a message to the master. *)

val sendto_group : t -> string -> int -> int -> Lwt_unix.msg_flag list -> int Lwt.t
(** Send a message to the group. *)

val ignore_peer : t -> Unix.sockaddr -> unit
(** [ignore_peer peer] do not forward user messages from peer [peer]
    to the application anymore. *)

val peer_ignored : t -> Unix.sockaddr -> bool
(** [peer_ignored p] is [true] if [p] is ignored. *)
