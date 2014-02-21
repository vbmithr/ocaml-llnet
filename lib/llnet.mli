(** Library to use unreliable IPv6 multicast networks. It mostly
    handles keeping track of peers that use the same protocol. *)

module StringMap : Map.S with type key = string

type id = string
(** Type of peer identifiers. *)

type t = {
  id: id; (* 20-bytes random identifier *)
  group_saddr: Unix.sockaddr;
  sock: Lwt_unix.file_descr;
  mutable peers: (Unix.sockaddr * int) StringMap.t
}
(** Handler to a connection to a multicast network. *)

val connect : string -> string -> string -> (t -> Unix.sockaddr -> string -> unit Lwt.t) -> t Lwt.t
(** [connect iface v6addr port listener] returns an handler to the multicast
    network [v6addr:port], where [v6addr] is a IPv6 multicast address,
    port is the port number to use and [listener] is a callback that
    will be triggered on receiving a message. *)

val master : t -> id
(** IP address of the master on the network (defined by the smallest
    IPv6 on this current implementation. *)

val sendto : t -> string -> int -> int -> Lwt_unix.msg_flag list -> Lwt_unix.sockaddr -> int Lwt.t
(** Wrapper to Lwt_unix.sendto that prepend the protocol's 3-bytes
    header to user messages. There MUST be 3 available bytes before
    the message in the buffer. *)

val sendto_group : t -> string -> int -> int -> Lwt_unix.msg_flag list -> int Lwt.t
(** Broadcast a message to the group. *)

val sendto_master : t -> string -> int -> int -> Lwt_unix.msg_flag list -> int Lwt.t
(** Send a message to the master. *)

val sendto_peer : t -> string -> int -> int -> Lwt_unix.msg_flag list -> id -> int Lwt.t
(** Send a message to a peer by id. Raise [Not_found] when the peer is
    not in the group. *)
