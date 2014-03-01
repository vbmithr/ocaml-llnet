open Llnet
open Core_kernel.Std

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

let section = Lwt_log.Section.make "IrminDistributed"

let sha1_to_hex ?nb_digit s =
  let transform = Cryptokit.Hexa.encode () in
  let hex = Cryptokit.transform_string transform s in
  match nb_digit with
  | None -> hex
  | Some n -> String.sub hex 0 n

let string_of_hex s =
  let transform = Cryptokit.Hexa.decode () in
  Cryptokit.transform_string transform s

module Lwt_unix = struct
  include Lwt_unix

  let recv_into_exactly fd buf pos len flags =
    let rec inner pos len =
      if len > 0 then
        recv fd buf pos len flags >>= function
        | 0 -> Lwt.fail End_of_file
        | nb_recv -> inner (pos+nb_recv) (len-nb_recv)
      else Lwt.return_unit
    in inner pos len

  let send_from_exactly fd buf pos len flags =
    let rec inner pos len =
      if len > 0 then
        send fd buf pos len flags >>= fun nb_sent ->
        inner (pos+nb_sent) (len-nb_sent)
      else Lwt.return_unit
    in inner pos len

  let really_sendto fd buf pos len flags saddr =
    let rec inner () =
      sendto fd buf pos len flags saddr >>= fun nb_sent ->
      if nb_sent = len then Lwt.return_unit
      else inner ()
    in inner ()

  let recv_into_bigstring_exactly ?(buf=String.create 4096) fd bs pos len flags =
    let bufsize = String.length buf in
    let rec inner pos len =
      if len > 0 then
        recv fd buf 0 (min bufsize len) flags >>= function
        | 0 -> Lwt.fail End_of_file
        | nb_recv ->
          Bigstring.From_string.blit ~src:buf ~src_pos:0 ~dst:bs ~dst_pos:pos ~len:nb_recv;
          inner (pos+nb_recv) (len-nb_recv)
      else Lwt.return_unit
    in inner pos len

  let send_from_bigstring_exactly ?(buf=String.create 4096) fd bs pos len flags =
    let bufsize = String.length buf in
    let rec inner pos len =
      if len > 0 then
        (
          Bigstring.To_string.blit ~src:bs ~src_pos:pos ~dst:buf ~dst_pos:0 ~len:(min bufsize len);
          send fd buf 0 (min bufsize len) flags >>= fun nb_sent ->
          inner (pos+nb_sent) (len-nb_sent)
        )
      else Lwt.return_unit
    in inner pos len
end

type protocol =
  | KEYREQ
  | NEWKEY
  | HELLO
  | HELLOACK

let int_of_protocol = function
  | KEYREQ -> 100
  | NEWKEY -> 104
  | HELLO -> 105
  | HELLOACK -> 106

let protocol_of_int = function
  | 100 -> KEYREQ
  | 104 -> NEWKEY
  | 105 -> HELLO
  | 106 -> HELLOACK
  | _ -> raise (Invalid_argument "protocol_of_int")

let string_of_protocol = function
  | KEYREQ -> "KEYREQ"
  | NEWKEY -> "NEWKEY"
  | HELLO -> "HELLO"
  | HELLOACK -> "HELLOACK"

let saddr_with_port saddr port =
  let open Unix in
  match saddr with
  | ADDR_INET (a, _) -> ADDR_INET (a, port)
  | _ -> raise (Invalid_argument "saddr_with_port")

let v6addr_of_saddr saddr =
  let open Unix in
  match saddr with
  | ADDR_INET (a, p) -> Ipaddr_unix.V6.of_inet_addr_exn a, p
  | _ -> raise (Invalid_argument "v6addr_of_saddr")


module type CONFIG = sig
  val iface : string
  val mcast_addr : Ipaddr.V6.t
  val mcast_port : int
  val key_size : int
end

module AO (AO : IrminStore.AO_BINARY) (C : CONFIG) = struct
  open C

  type key = AO.key
  type value = AO.value
  type t = AO.t * Llnet.t

  (* Broadcast a key on the multicast sockaddr *)
  let new_key ?(msgbuf=String.create 512) c k v =
    let vlen = Bigstring.length v in
    let klen = String.length k in
    let msglen = hdr_size + klen + vlen in
    msgbuf.[0] <- int_of_protocol NEWKEY |> Char.of_int_exn;
    EndianString.BigEndian.set_int16 msgbuf 1 c.tcp_in_port;
    EndianString.BigEndian.set_int16 msgbuf 3 klen;
    String.blit k 0 msgbuf hdr_size klen;
    (if msglen <= 512 then (* send value as well *)
      (
        EndianString.BigEndian.set_int16 msgbuf 3 (klen + vlen);
        Bigstring.To_string.blit ~src:v ~src_pos:0 ~dst:msgbuf
          ~dst_pos:(hdr_size + klen) ~len:vlen;
        Lwt_unix.really_sendto c.group_sock msgbuf 0 msglen [] c.group_saddr
      )
    else
      Lwt_unix.really_sendto c.group_sock msgbuf 0 (hdr_size + klen) [] c.group_saddr)
    >>= fun () ->
    Lwt_log.debug_f ~section "-> NEWKEY %s %s"
      (sha1_to_hex ~nb_digit:7 k)
      (Helpers.string_of_saddr c.group_saddr)


  let create () =
    (* Create the underlying store *)
    AO.create () >>= fun store ->

    (* [msg] is only used in this function, hence can be trashed. *)
    let group_reactor c saddr msg =
      let payload_len = EndianString.BigEndian.get_uint16 msg 3 in
      match msg.[0] |> Char.to_int |> protocol_of_int with

      | NEWKEY -> (* maybe KEYREQ it *)
        let remote_k = String.sub msg hdr_size key_size in
        Lwt_log.debug_f ~section "<- NEWKEY %s %s"
          (sha1_to_hex ~nb_digit:7 remote_k)
          (Helpers.string_of_saddr saddr) >>= fun () ->
        AO.mem store remote_k >>= (function
            | true -> Lwt.return_unit
            | false ->
              if payload_len > C.key_size
              then (* value is embedded *)
                (
                  Bigstring.From_string.sub msg
                    ~pos:(hdr_size + key_size)
                    ~len:(payload_len - key_size)
                  |>
                  AO.add store >>= fun k ->
                  assert_lwt (k = remote_k)
                )
              else (* KEYREQ it *)
                (
                  let s = Unix.(socket PF_INET6 SOCK_STREAM 0) in
                  try_lwt
                    let addr, port = v6addr_of_saddr saddr in
                    Sockopt.connect6 ~iface:C.iface s addr port;
                    let s = Lwt_unix.of_unix_file_descr s in
                    msg.[0] <- int_of_protocol KEYREQ |> Char.of_int_exn;
                    EndianString.BigEndian.set_int16 msg 1 c.tcp_in_port;
                    Lwt_unix.send_from_exactly s msg 0 (hdr_size + key_size) [] >>= fun () ->
                    Lwt_unix.recv_into_exactly s msg 0 4 [] >>= fun () ->
                    let vlen = EndianString.BigEndian.get_int32 msg 0 |> Int32.to_int_exn in
                    if vlen < 0
                    then Lwt.fail Not_found
                    else
                      let v = Bigstring.create vlen in
                      Lwt_unix.recv_into_bigstring_exactly ~buf:msg s v 0 vlen [] >>= fun () ->
                      AO.add store v >>= fun k ->
                      Lwt_log.debug_f ~section "<- KEYACK %s from %s"
                        (sha1_to_hex ~nb_digit:7 k) (Helpers.string_of_saddr saddr)
                  with exn ->
                    Lwt_log.warning_f ~section ~exn "<- KEYACK %s from %s"
                      (sha1_to_hex ~nb_digit:7 remote_k) (Helpers.string_of_saddr saddr)
                  finally
                    Unix.close s; Lwt.return_unit
                ))

      | HELLO -> (* Send our keys to peer *)
        let remote_key_size = EndianString.BigEndian.get_uint16 msg hdr_size in
        if key_size <> remote_key_size then
          Lwt_log.warning_f ~section
            "<- HELLO %s (FAIL: incompatible key size %d, ignoring peer)"
            (Helpers.string_of_saddr saddr) remote_key_size >|= fun () ->
          ignore_peer c saddr
        else
          (
            Lwt_log.debug_f ~section "<- HELLO %s (OK: key size matches)"
              (Helpers.string_of_saddr saddr) >>= fun () ->
            let s = Unix.(socket PF_INET6 SOCK_STREAM 0) in
            let k_sent = ref 0 in
            let v_sent = ref 0 in
            try_lwt
              let addr, port = v6addr_of_saddr saddr in
              Sockopt.connect6 ~iface:C.iface s addr port;
              let s = Lwt_unix.of_unix_file_descr s in
              AO.contents store >>= fun kvs ->
              msg.[0] <- int_of_protocol HELLOACK |> Char.of_int_exn;
              Lwt_unix.send_from_exactly s msg 0 hdr_size [] >>= fun () ->
              Lwt_list.iter_s (fun (k,v) ->
                  Lwt_unix.send_from_exactly s k 0 key_size [] >>= fun () ->
                  incr k_sent;
                  Lwt_unix.recv_into_exactly s msg 0 1 [] >>= fun () ->
                  match msg.[0] with
                  | '\000' -> Lwt.return_unit (* Remote is not interested by this key *)
                  | '\001' -> (* Remote is interested *)
                    let vlen = Bigstring.length v in
                    EndianString.BigEndian.set_int32 msg 0 (Int32.of_int_exn vlen);
                    Lwt_unix.send_from_exactly s msg 0 4 [] >>= fun () ->
                    Lwt_unix.send_from_bigstring_exactly ~buf:msg s v 0 vlen [] >|= fun () ->
                    incr v_sent
                  | _ -> Lwt.fail (Failure "HELLOACK implementation error.")
                ) kvs
            with exn ->
              Lwt_log.warning_f ~section ~exn "-> HELLOACK: Error sending values to %s"
                (Helpers.string_of_saddr saddr)
            finally
              Lwt_log.debug_f ~section "-> HELLOACK: Sent (%d, %d) kvs to %s" !k_sent !v_sent
                (Helpers.string_of_saddr saddr) >|= fun () ->
              Unix.close s
          )

      | _ -> Lwt.return_unit (* Ignore all other message types sent to the group socket *)
    in

    let tcp_reactor fd saddr =
      let tcpbuf = String.create 4096 in
      Lwt_unix.recv fd tcpbuf 0 hdr_size [] >>= fun nb_read ->
      if nb_read <> hdr_size then
        Lwt_log.debug_f ~section "TCP reactor: Corrupted message from %s"
          (Helpers.string_of_saddr saddr) >>= fun () ->
        Lwt_unix.close fd (* Corrupted message *)
      else
        let remote_port = EndianString.BigEndian.get_uint16 tcpbuf 1 in
        let saddr = saddr_with_port saddr remote_port in
        match tcpbuf.[0] |> Char.to_int |> protocol_of_int with

        | KEYREQ ->
          let rec inner k_sent v_sent =
            try_lwt
              Lwt_unix.recv_into_exactly fd tcpbuf 0 key_size [] >>= fun () ->
              let k = String.sub tcpbuf 0 key_size in
              AO.mem store k >>= function
              | false -> (* Asked key not in our store, send -1 *)
                EndianString.BigEndian.set_int32 tcpbuf 0 (-1l);
                Lwt_unix.send_from_exactly fd tcpbuf 0 4 [] >>= fun () ->
                inner (succ k_sent) v_sent
              | true -> (* Asked key in our store, send it *)
                AO.read_exn store k >>= fun v ->
                let vlen = Bigstring.length v in
                EndianString.BigEndian.set_int32 tcpbuf 0 (Int32.of_int_exn vlen);
                Lwt_unix.send_from_exactly fd tcpbuf 0 4 [] >>= fun () ->
                Lwt_unix.send_from_bigstring_exactly ~buf:tcpbuf fd v 0 vlen [] >>= fun () ->
                inner (succ k_sent) (succ v_sent)

            with exn ->
              Lwt_log.debug_f ~section ~exn "-> KEYREQ: Sent (%d, %d) kvs to %s"
                k_sent v_sent (Helpers.string_of_saddr saddr) >>= fun () ->
              Lwt_unix.close fd
          in inner 0 0

        | HELLOACK ->
          let rec inner kr vr =
            try_lwt
              Lwt_unix.recv_into_exactly fd tcpbuf 0 key_size [] >>= fun () ->
              let k = String.sub tcpbuf 0 key_size in
              AO.mem store k >>= function
              | false -> (* We don't have it, asking for it *)
                tcpbuf.[0] <- '\001';
                Lwt_log.debug_f ~section "<- HELLOACK: + %s"
                  (sha1_to_hex ~nb_digit:7 k) >>= fun () ->
                Lwt_unix.send_from_exactly fd tcpbuf 0 1 [] >>= fun () ->
                Lwt_unix.recv_into_exactly fd tcpbuf 0 4 [] >>= fun () ->
                let vlen = EndianString.BigEndian.get_int32 tcpbuf 0 |> Int32.to_int_exn in
                let v = Bigstring.create vlen in
                Lwt_unix.recv_into_bigstring_exactly ~buf:tcpbuf fd v 0 vlen [] >>= fun () ->
                AO.add store v >>= fun (_:AO.key) -> inner (succ kr) (succ vr)
              | true -> (* We already have the value *)
                tcpbuf.[0] <- '\000';
                Lwt_log.debug_f ~section "<- HELLOACK: = %s"
                  (sha1_to_hex ~nb_digit:7 k) >>= fun () ->
                Lwt_unix.send_from_exactly fd tcpbuf 0 1 [] >>= fun () ->
                inner (succ kr) vr
            with exn ->
              Lwt_log.debug_f ~section ~exn "<- HELLOACK summary: + (%d, %d) %s"
                kr vr (Helpers.string_of_saddr saddr) >>= fun () ->
              Lwt_unix.close fd
          in inner 0 0

        | _ -> Lwt.return_unit (* Ignore all other messages *)

    in
    let c = connect iface mcast_addr mcast_port group_reactor tcp_reactor in

    (* Say hello and give our keys *)
    let say_hello c =
      let msgbuf = String.create 512 in
      msgbuf.[0] <- int_of_protocol HELLO |> Char.of_int_exn;
      EndianString.BigEndian.set_int16 msgbuf 1 c.tcp_in_port;
      EndianString.BigEndian.set_int16 msgbuf 3 2;
      EndianString.BigEndian.set_int16 msgbuf 5 key_size;
      Lwt_unix.really_sendto c.group_sock msgbuf 0 (hdr_size + 2) [] c.group_saddr >>= fun () ->
      Lwt_log.debug_f ~section "-> HELLO %s" (Helpers.string_of_saddr c.group_saddr) >>= fun () ->
      AO.contents store >>= fun kvs ->
      Lwt_list.iter_s (fun (k, v) -> new_key ~msgbuf c k v) kvs
    in
    say_hello c >|= fun () ->
    (store, c)


  (* [add] is overloaded by a function that broadcast new keys on the
     network. Interested nodes will KEYREQ it. *)
  let add (store, c) v =
    AO.add store v >>= fun k ->
    Lwt_log.info_f ~section "New blob: %s" (sha1_to_hex ~nb_digit:7 k)
    >>= fun () ->
    new_key c k v >>= fun () ->
    Lwt.return k

  let read (store, c) k = AO.read store k
  let read_exn (store, c) k = AO.read_exn store k
  let mem (store, c) k = AO.mem store k
  let list (store, c) k = AO.list store k
  let contents (store, c) = AO.contents store
end
