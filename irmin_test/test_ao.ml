open Core_kernel.Std

let (>>=) = Lwt.(>>=)

let () = Sys.catch_break true

let sha1_to_hex ?nb_digit s =
  let transform = Cryptokit.Hexa.encode () in
  let hex = Cryptokit.transform_string transform s in
  match nb_digit with
  | None -> hex
  | Some n -> String.sub hex 0 n

let main dao vsize =
  let module DAO = (val dao : IrminStore.AO with type key = IrminKey.SHA1.t and type value = IrminIdent.String.t) in
  let open DAO in
  create () >>= fun store ->
  Lwt_main.at_exit (fun () ->
      dump store >>= fun kvs ->
      Lwt_io.printf "\nExiting with %d keys in store\n" (List.length kvs) >>= fun () ->
      Lwt_list.iter_s (fun (k, _) -> Lwt_io.printf "%s " (sha1_to_hex ~nb_digit:7 (IrminKey.SHA1.to_raw k))) kvs
      >>= fun () ->
      Lwt_io.printf "\n"
    );
  let add_forever period =
    let rec inner () =
      let v = String.create (max 4 vsize) in
      let seed = Random.bits () |> Int64.of_int in
      EndianString.BigEndian.set_int64 v 0 seed;
      add store (IrminIdent.String.of_string v) >>= fun _ ->
      Lwt_unix.sleep period >>= fun () ->
      inner ()
    in inner ()
  in add_forever 1.

let () =
  let iface = ref "eth0" in
  let group_addr = ref "ff02::dead:beaf" in
  let group_port = ref 5555 in
  let vsize = ref 10 in
  let speclist = Arg.(align [
      "--iface", Set_string iface, "<string> Interface to use (default: eth0)";
      "--addr", Set_string group_addr, "<string> IPv6 multicast group address to use (default: ff02::dead:beef)";
      "--port", Set_int group_port, "<int> Group port to use (default: 5555)";
      "--vsize", Set_int vsize, "<int> Size of the random values to add in the DB (default: 10)";
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
  let module DAO = IrminDistributed.AO(Conf)(IrminMemory.AO)(IrminKey.SHA1)(IrminIdent.String) in
  Lwt_main.run (main
                  (module DAO: IrminStore.AO
                    with type key = IrminKey.SHA1.t
                     and type value = IrminIdent.String.t) !vsize)
