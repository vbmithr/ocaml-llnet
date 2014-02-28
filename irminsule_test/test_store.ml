open Core_kernel.Std

let (>>=) = Lwt.(>>=)

let main dao =
  let module DAO = (val dao : IrminStore.AO_BINARY) in
  let open DAO in
  let open Cryptokit in
  let rng = Random.device_rng "/dev/urandom" in
  create () >>= fun store ->
  let add_forever period =
    let rec inner () =
      let v = Random.string rng 10 |> Bigstring.of_string in
      add store v >>= fun (_:string) ->
      Lwt_unix.sleep period >>= fun () ->
      inner ()
    in inner ()
  in add_forever 1.

let () =
  let iface = ref "eth0" in
  let group_addr = ref "ff02::dead:beaf" in
  let group_port = ref 5555 in
  let speclist = Arg.(align [
      "--iface", Set_string iface, "<string> Interface to use (default: eth0)";
      "--addr", Set_string group_addr, "<string> IPv6 multicast group address to use (default: ff02::dead:beef)";
      "--port", Set_int group_port, "<int> Group port to use (default: 5555)";
      "-v", String (fun s -> Lwt_log.(add_rule s Info)), "<string> Log section to put in Info mode";
      "-vv", String (fun s -> Lwt_log.(add_rule s Debug)), "<string> Log section to put in Debug mode";
    ]) in
  let anon_fun s = () in
  let usage_msg = "Usage: " ^ Sys.argv.(0) ^ " <options>\nOptions are:" in
  Arg.parse speclist anon_fun usage_msg;
  let module Conf = struct
    let iface = !iface
    let mcast_addr = Ipaddr.V6.of_string_exn !group_addr
    let mcast_port = !group_port
    let key_size = 20
  end in
  let module DAO = IrminDistributed.AO(IrminMemory.AO(IrminKey.SHA1))(Conf) in
  Lwt_main.run (main (module DAO: IrminStore.AO_BINARY))
