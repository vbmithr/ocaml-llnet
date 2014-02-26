open Core_kernel.Std

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module Lwt_unix = struct
  include Lwt_unix

  let recv_into_exactly fd buf pos len flags =
    let rec inner pos len =
      if len > 0 then
        recv fd buf pos len flags >>= fun nb_recv ->
        inner (pos+nb_recv) (len-nb_recv)
      else Lwt.return_unit
    in inner pos len

  let send_from_exactly fd buf pos len flags =
    let rec inner pos len =
      if len > 0 then
        send fd buf pos len flags >>= fun nb_sent ->
        inner (pos+nb_sent) (len-nb_sent)
      else Lwt.return_unit
    in inner pos len
end

type protocol =
  | KEYREQ
  | KEYACK
  | DUMPREQ
  | DUMPACK
  | NEWKEY

let int_of_protocol = function
  | KEYREQ -> 100
  | KEYACK -> 101
  | DUMPREQ -> 102
  | DUMPACK -> 103
  | NEWKEY -> 104

let protocol_of_int = function
  | 100 -> KEYREQ
  | 101 -> KEYACK
  | 102 -> DUMPREQ
  | 103 -> DUMPACK
  | 104 -> NEWKEY
  | _ -> raise (Invalid_argument "protocol_of_int")

let saddr_with_port saddr port =
  let open Unix in
  match saddr with
  | ADDR_INET (a, _) -> ADDR_INET (a, port)
  | _ -> raise (Invalid_argument "saddr_with_port")

let v6addr_of_saddr saddr =
  let open Unix in
  match saddr with
  | ADDR_INET (a, _) -> Ipaddr_unix.V6.of_inet_addr_exn a
  | _ -> raise (Invalid_argument "v6addr_of_saddr")

module type CONFIG = sig
  val iface : string
  val mcast_addr : Ipaddr.V6.t
  val mcast_port : int
end

module AO (AO : IrminStore.AO_BINARY) (C : CONFIG) = struct

  type key = AO.key
  type value = AO.value
  type t = AO.t * Llnet.t

  let create () =
    (* Create the underlying store *)
    AO.create () >>= fun store ->

    let group_reactor c saddr msg =
      match msg.[0] |> Char.to_int |> protocol_of_int with

      | NEWKEY -> (* KEYREQ it *)
        let remote_port = EndianString.BigEndian.get_uint16 msg 3 in
        let s = Unix.(socket PF_INET6 SOCK_STREAM 0) in
        Lwt.try_bind
          (fun () -> Lwt.wrap (fun () ->
               Sockopt.connect6 ~iface:C.iface s (v6addr_of_saddr saddr) remote_port))
          (fun () ->
             let s = Lwt_unix.of_unix_file_descr s in
             msg.[0] <- int_of_protocol KEYREQ |> Char.of_int_exn;
             EndianString.BigEndian.set_int16 msg 3 c.Llnet.tcp_in_port;
             Lwt_unix.send_from_exactly s msg 0 (String.length msg) [])
          (fun exn -> Lwt_log.warning_f ~exn "Cannot connect to [%s]:%d"
              Unix.(match saddr with
                  | ADDR_INET(a, _) -> string_of_inet_addr a
                  | _ -> assert false) remote_port)

      | KEYREQ -> (* Send our keys to peer *)
        let remote_port = EndianString.BigEndian.get_uint16 msg 3 in
        let s = Unix.(socket PF_INET6 SOCK_STREAM 0) in
        Lwt.try_bind
          (fun () -> Lwt.wrap (fun () ->
               Sockopt.connect6 ~iface:C.iface s (v6addr_of_saddr saddr) remote_port))
          (fun () ->
             let s = Lwt_unix.of_unix_file_descr s in
             AO.contents store >>= fun cts ->
             let all_keys = List.map cts fst in
             let msg_size = List.fold_left all_keys ~f:(fun a k -> a + 2 + String.length k) ~init:0 in
             msg.[0] <- int_of_protocol KEYACK |> Char.of_int_exn;
             EndianString.BigEndian.set_int16 msg 1 msg_size;
             Lwt_unix.send_from_exactly s msg 0 3 [] >>= fun () ->
             Lwt_list.iter_s (fun k ->
                 let klen = String.length k in
                 EndianString.BigEndian.set_int16 msg 1 klen;
                 Lwt_unix.send_from_exactly s msg 1 2 [] >>= fun () ->
                 Lwt_unix.send_from_exactly s k 0 klen []
               ) all_keys)
          (fun exn -> Lwt_log.warning_f ~exn "Cannot connect to [%s]:%d"
              Unix.(match saddr with
                  | ADDR_INET(a, _) -> string_of_inet_addr a
                  | _ -> assert false) remote_port)

      | _ -> Lwt.return_unit (* Ignore all other message types sent to the group socket *)
    in
    let tcp_reactor fd saddr =
      (* We create our own buffers here, they will not be used by
         anybody else *)
      let tcpbuf = String.create 4096 in
      let tcpmsg = Buffer.create 4096 in
      Lwt_unix.recv fd tcpbuf 0 3 [] >>= fun nbread ->
      if nbread <> 3 then Lwt.return_unit (* Corrupted message *)
      else
        let msgtyp = tcpbuf.[0] |> Char.to_int |> protocol_of_int in
        let payload_len = EndianString.BigEndian.get_uint16 tcpbuf 1 in
        let rec read_all len =
          if len < 1
          then Lwt.return_unit
          else
            (
              Lwt_unix.recv fd tcpbuf 0 4096 [] >>= fun nb_read ->
              Buffer.add_substring tcpmsg tcpbuf 0 nb_read;
              read_all (len-nb_read)
            )
        in
        read_all payload_len >>= fun () ->

        (* The message is now in tcpmsg. Variants have to extract it. *)

        match msgtyp with
        | KEYACK -> (* DUMPREQ keys we don't have *)

          (* Extract the keys into a list *)
          let msg = Buffer.contents tcpmsg in

          let list_of_keys buf off len =
            let rec inner acc off len =
            if len > 0 then
              let klen = EndianString.BigEndian.get_uint16 msg off in
              inner ((String.sub msg (off+2) klen)::acc) (off+2+klen) (len-2-klen)
            else acc
            in inner [] off len
          in
          let recv_keys = list_of_keys msg 0 payload_len in

          (* Iterate on keys and ask the ones we don't have *)
          Lwt_list.iter_s (fun k ->
              AO.mem store k >>= function
              | true -> Lwt.return_unit
              | false ->
                let klen = String.length k in
                tcpbuf.[0] <- int_of_protocol DUMPREQ |> Char.of_int_exn;
                EndianString.BigEndian.set_int16 tcpbuf 1 klen;
                String.blit k 0 tcpbuf 3 klen;
                Lwt_unix.send_from_exactly fd tcpbuf 0 (klen+3) [] >>= fun () ->
                Lwt_unix.recv_into_exactly fd tcpbuf 0 3 [] >>= fun () ->
                let vlen = EndianString.BigEndian.get_uint16 tcpbuf 1 in
                Lwt_unix.recv_into_exactly fd tcpbuf 0 vlen [] >>= fun () ->
                let value = Bigstring.create vlen in
                Bigstring.From_string.blit ~src:tcpbuf ~src_pos:0 ~dst:value ~dst_pos:0 ~len:vlen;
                AO.add store value >>= fun (_:string) -> Lwt.return_unit)
            recv_keys;

        | _ -> Lwt.return_unit (* Ignore all other messages *)

    in
    let c = Llnet.connect C.iface C.mcast_addr C.mcast_port group_reactor tcp_reactor in
    let send_keyreq c =
      let buf = String.create 5 in
      buf.[0] <- int_of_protocol KEYREQ |> Char.of_int_exn;
      EndianString.BigEndian.set_int16 buf 1 2;
      EndianString.BigEndian.set_int16 buf 3 c.Llnet.tcp_in_port;
      Lwt_unix.sendto c.Llnet.group_sock buf 0 5 [] c.Llnet.group_saddr
    in
    send_keyreq c >|= fun (_:int) ->
    (store, c)

  (* [add] is overloaded by a function that broadcast new keys on the
     network. Interested nodes will KEYREQ it. *)
  let msgbuf = String.create 512
  let add (store, c) v =
    AO.add store v >>= fun k ->
    let klen = String.length k in
    let msg_size = Llnet.hdr_size + 2 + klen in
    msgbuf.[0] <- int_of_protocol NEWKEY |> Char.of_int_exn;
    EndianString.BigEndian.set_int16 msgbuf 1 (2 + klen);
    EndianString.BigEndian.set_int16 msgbuf 3 c.Llnet.tcp_in_port;
    String.blit k 0 msgbuf 5 klen;
    Lwt_unix.sendto c.Llnet.group_sock msgbuf 0 msg_size [] c.Llnet.group_saddr >>= fun (_:int) ->
    Lwt.return k

  let read (store, c) k = AO.read store k
  let read_exn (store, c) k = AO.read_exn store k
  let mem (store, c) k = AO.mem store k
  let list (store, c) k = AO.list store k
  let contents (store, c) = AO.contents store
end
