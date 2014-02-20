(** Library to use unreliable IPv6 multicast networks. It mostly
    handles keeping track of peers that use the same protocol. *)

module V6Map : Map.S with type key = Ipaddr.V6.t

type t = {
  group_saddr: Unix.sockaddr;
  sock: Lwt_unix.file_descr;
  mutable peers: int V6Map.t
}
(** Handler to a connection to a multicast network. *)

val connect : Ipaddr.V6.t -> int -> (t -> Unix.sockaddr -> string -> unit Lwt.t) -> t
(** [connect v6addr port listener] returns an handler to the multicast
    network [v6addr:port], where [v6addr] is a IPv6 multicast address,
    port is the port number to use and [listener] is a callback that
    will be triggered on receiving a message. *)

val master : t -> Ipaddr.V6.t
(** IP address of the master on the network (defined by the smallest
    IPv6 on this current implementation *)

val sendto : Lwt_unix.file_descr -> string -> int -> int ->
  Lwt_unix.msg_flag list -> Lwt_unix.sockaddr -> int Lwt.t
(** Wrapper to Lwt_unix.sendto that prepend the protocol's 3-bytes
    header to user messages. There MUST be 3 available bytes before
    the message in the buffer. *)
