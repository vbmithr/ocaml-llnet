(** Library to use unreliable IPv6 multicast networks. It mostly
    handles keeping track of peers that use the same protocol. *)

module Helpers : sig
  val string_of_saddr : Unix.sockaddr -> string
  val port_of_saddr : Unix.sockaddr -> int
end

module SaddrMap : Map.S with type key = Unix.sockaddr

type id = string
(** Type of peer identifiers. *)

type t = {
  group_sock: Lwt_unix.file_descr; (* UDP socket bound to a multicast sockaddr. *)
  group_saddr: Unix.sockaddr; (* multicast group sockaddr. *)
  tcp_in_sock: Lwt_unix.file_descr; (* TCP socket for incoming connection. *)
  tcp_in_saddr: Unix.sockaddr; (* sockaddr of the incoming TCP socket. *)
  mutable peers: (int * bool) SaddrMap.t (* Map of saddr -> TTL * ignored *)
}
(** Handler to a connection to a multicast network. *)

val hdr_size : int
(** Size of the header of protocol messages. *)

val connect :
  ?ival:float ->
  ?udp_wait:unit Lwt.t ->
  ?tcp_wait:unit Lwt.t ->
  string -> Ipaddr.V6.t -> int ->
  (t -> Unix.sockaddr -> string -> unit Lwt.t) ->
  (t -> Lwt_unix.file_descr -> Lwt_unix.sockaddr -> unit Lwt.t) ->
  t Lwt.t
(** [connect ?ival iface v6addr port group_reactor my_reactor] returns
    an handler to the multicast network [v6addr:port], where [v6addr]
    is a IPv6 multicast address, port is the port number to use and
    [group_reactor] and [my_reactor] are callbacks that will be
    triggered upon receiving a message on the UDP multicast socket,
    resp. the private unicast TCP socket. Neighbours are discovered
    every [ival] seconds. *)

val order : t -> int
(** [order c] is the order of oneself in the list of peers *)

val first_neighbour : t -> Unix.sockaddr option
(** [first_neighbour c] is the sockaddr of the neighbour (not oneself)
    of smallest order that is not ignored. *)

val ignore_peer : t -> Unix.sockaddr -> unit
(** [ignore_peer c peer] do not forward user messages from peer [peer]
    to the application anymore. *)

val peer_ignored : t -> Unix.sockaddr -> bool
(** [peer_ignored c p] is [true] if [p] is ignored. *)
