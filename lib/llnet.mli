(** Library to use unreliable IPv6 multicast networks. It mostly
    handles keeping track of peers that use the same protocol. *)

module SaddrMap : Map.S with type key = Ipaddr.V6.t * int

type id = string
(** Type of peer identifiers. *)

type t = {
  group_sock: Lwt_unix.file_descr;
  group_saddr: Unix.sockaddr;
  my_sock: Lwt_unix.file_descr;
  my_port: int;
  mutable peers: int SaddrMap.t
}
(** Handler to a connection to a multicast network. *)

val hdr_size : int
(** Size of the header of protocol messages. *)

val connect : string -> Ipaddr.V6.t -> int -> (t -> Unix.sockaddr -> string -> unit Lwt.t) -> t
(** [connect iface v6addr port listener] returns an handler to the multicast
    network [v6addr:port], where [v6addr] is a IPv6 multicast address,
    port is the port number to use and [listener] is a callback that
    will be triggered on receiving a message. *)

val master : t -> SaddrMap.key
(** IP address of the master on the network (defined by the smallest
    IPv6 on this current implementation. *)

val sendto_group : t -> string -> int -> int -> Lwt_unix.msg_flag list -> int Lwt.t
(** Broadcast a message to the group. *)

val sendto_master : t -> string -> int -> int -> Lwt_unix.msg_flag list -> int Lwt.t
(** Send a message to the master. *)
