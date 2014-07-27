(** Library to use unreliable IPv6 multicast networks. It mostly
    handles keeping track of peers that use the same protocol. *)

module Helpers : sig
  val string_of_saddr : Unix.sockaddr -> string
  val port_of_saddr : Unix.sockaddr -> int
  val v6addr_of_saddr : Unix.sockaddr -> Ipaddr.V6.t
  val v6addr_port_of_saddr : Unix.sockaddr -> Ipaddr.V6.t * int
  val addr_port_of_saddr : Unix.sockaddr -> Ipaddr.t * int
  val saddr_with_port : Unix.sockaddr -> int -> Unix.sockaddr
end

module SaddrMap : Map.S with type key = Unix.sockaddr

type id = string
(** Type of peer identifiers. *)

type t = {
  group_sock: Lwt_unix.file_descr; (* UDP socket bound to a multicast sockaddr. *)
  group_saddr: Unix.sockaddr; (* multicast group sockaddr. *)
  tcp_in_sock: Lwt_unix.file_descr; (* TCP socket for incoming connection. *)
  tcp_in_saddr: Unix.sockaddr; (* sockaddr of the incoming TCP socket. *)
  mutable peers: (int * bool) SaddrMap.t; (* Map of saddr -> TTL * ignored *)
  not_alone: bool Lwt_condition.t (* Notification when a first peer is detected *)
}
(** Handler to a connection to a multicast network. *)

val hdr_size : int
(** Size of the header of protocol messages. *)

val connect :
  ?ival:float ->
  ?udp_wait:unit Lwt.t ->
  ?tcp_wait:unit Lwt.t ->
  ?group_reactor:(t -> Unix.sockaddr -> string -> unit Lwt.t) ->
  ?tcp_reactor:(t -> Lwt_unix.file_descr -> Lwt_unix.sockaddr -> unit Lwt.t) ->
  iface:string ->
  Ipaddr.t -> int -> t Lwt.t
(** [connect ?ival ?udp_wait ?tcp_wait ?group_reactor ?tcp_reactor
    ~iface addr port] returns an handler to the multicast network
    [addr:port], where [addr:port] is a multicast sockaddr,
    [group_reactor] and [my_reactor] are callbacks that will be
    triggered upon receiving a message on the UDP multicast socket,
    resp. the private unicast TCP socket. Neighbours are discovered
    every [ival] seconds (default 1s). *)

val order : t -> int
(** [order c] is the order of oneself in the list of peers *)

val neighbours : t -> Unix.sockaddr list Lwt.t
(** [neighbours c] is the list of neighbours (not oneself)
    that are not ignored, in sockaddr order. *)

val ignore_peer : t -> Unix.sockaddr -> unit
(** [ignore_peer c peer] do not forward user messages from peer [peer]
    to the application anymore. *)

val peer_ignored : t -> Unix.sockaddr -> bool
(** [peer_ignored c p] is [true] if [p] is ignored. *)
