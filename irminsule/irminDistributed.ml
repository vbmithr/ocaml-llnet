open Llnet
open Core_kernel.Std

let (>>=) = Lwt.(>>=)

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

module AO (AO: IrminStore.AO_BINARY) = struct
  include AO

  let conn = ref None

  let create () =
    create () >>= fun store ->
    let reactor h saddr msg = Lwt.return_unit in
    conn := Some (connect "eth0" (Ipaddr.V6.of_string_exn "ff02::dead:beaf") 5555 reactor);
    Lwt.return store

  (* add is overloaded by a function that broadcast new values on the
     network. *)
  let msgbuf = String.create 4096
  let add store v =
    add store v >>= fun k ->
    let klen = String.length k in
    let vlen = Bigstring.length v in
    let msg_size = hdr_size + klen + vlen in
    match !conn with
    | None -> Lwt.return k
    | Some c ->
      let msgbuf =
        if (msg_size <= String.length msgbuf)
        then msgbuf
        else String.create msg_size in
      (
        msgbuf.[0] <- int_of_protocol NEWKEY |> Char.of_int_exn;
        EndianString.BigEndian.set_int16 msgbuf 1 (klen + vlen);
        String.blit k 0 msgbuf 3 klen;
        Bigstring.To_string.blit ~src:v ~src_pos:0 ~dst:msgbuf ~dst_pos:(hdr_size + klen) ~len:vlen;
        sendto_group c msgbuf 0 msg_size []
      ) >>= fun (_:int) ->
      Lwt.return k
end
