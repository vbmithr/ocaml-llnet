(*---------------------------------------------------------------------------
   Copyright (c) 2016 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
   %%NAME%% %%VERSION%%
  ---------------------------------------------------------------------------*)

(** Local gossip network using IPv6 multicast

    {e %%VERSION%% — {{:%%PKG_HOMEPAGE%% }homepage}} *)

(** {1 Llnet} *)

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

type 'a t = {
  ival: float;                            (* Period between PINGs                       *)
  group_sock: Lwt_unix.file_descr;        (* UDP socket bound to a multicast sockaddr.  *)
  group_saddr: Unix.sockaddr;             (* multicast group sockaddr.                  *)
  tcp_in_sock: Lwt_unix.file_descr;       (* TCP socket for incoming connection.        *)
  tcp_in_saddr: Unix.sockaddr;            (* sockaddr of the incoming TCP socket.       *)
  mutable peers: (int * bool) SaddrMap.t; (* Map of saddr -> TTL * ignored              *)
  not_alone: bool Lwt_condition.t;        (* Notification when a first peer is detected *)
  clock: unit Lwt_condition.t;            (* Signalled when receiving a PING            *)
  mutable user_data: 'a option;           (* Can contain custom data needed             *)
}
(** Handler to a connection to a multicast network. *)

val hdr_size : int
(** Size of the header of protocol messages. *)

val connect :
  ?tcp_port:int ->
  ?ival:float ->
  ?udp_wait:unit Lwt.t ->
  ?tcp_wait:unit Lwt.t ->
  ?group_reactor:('a t -> Unix.sockaddr -> string -> unit Lwt.t) ->
  ?tcp_reactor:('a t -> Lwt_unix.file_descr -> Lwt_unix.sockaddr -> unit Lwt.t) ->
  ?user_data:'a ->
  iface:string ->
  Unix.sockaddr -> 'a t Lwt.t
(** [connect ?ival ?udp_wait ?tcp_wait ?group_reactor ?tcp_reactor
    ~iface mcast_saddr] returns an handler to the multicast network
    [mcast_saddr], where [mcast_saddr] is a multicast sockaddr,
    [group_reactor] and [my_reactor] are callbacks that will be
    triggered upon receiving a message on the UDP multicast socket,
    resp. the private unicast TCP socket. Neighbours are discovered
    every [ival] seconds (default 1s). *)

val order : 'a t -> int
(** [order c] is the order of oneself in the list of peers *)

val neighbours_nonblock : 'a t -> Unix.sockaddr list
(** [neighbours_nonblock c] is the list of neighbours (not oneself)
    that are not ignored, in sockaddr order. *)

val neighbours : 'a t -> Unix.sockaddr list Lwt.t
(** [neighbours c] is a thread that returns the list of neighbours
    (not oneself) that are not ignored, in sockaddr order, whenever
    there is at least one other peer in the network.

    Invariant: never returns [] *)

val ignore_peer : 'a t -> Unix.sockaddr -> unit
(** [ignore_peer c peer] do not forward user messages from peer [peer]
    to the application anymore. *)

val peer_ignored : 'a t -> Unix.sockaddr -> bool
(** [peer_ignored c p] is [true] if [p] is ignored. *)

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
