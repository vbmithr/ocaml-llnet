open Core_kernel.Std

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

let () = Sys.catch_break true

let sha1_to_hex ?nb_digit s =
  let transform = Cryptokit.Hexa.encode () in
  let hex = Cryptokit.transform_string transform s in
  match nb_digit with
  | None -> hex
  | Some n -> String.sub hex 0 n

let main drw vsize =
  let module DRW = (val drw : IrminStore.RW_BINARY) in
  let open DRW in
  create () >>= fun store ->
  Lwt_main.at_exit (fun () ->
      contents store >>= fun kvs ->
      let kvs = List.sort compare kvs in
      Lwt_io.printf "\nExiting with %d kvs in store\n" (List.length kvs) >>= fun () ->
      Lwt_list.iter_s (fun (k, v) -> Lwt_io.printf "%Ld -> %s\n"
                          (EndianString.BigEndian.get_int64 k 0)
                          (sha1_to_hex ~nb_digit:7 k)) kvs
    );
  let forever period =
    let rec inner () =
      (match Random.int 4 with
      | 0 | 3 -> (* ADD (frequency two times more) *)
        let rint = Random.bits () |> Int64.of_int in
        let r = String.create 8 in
        EndianString.BigEndian.set_int64 r 0 rint;
        update store r (Bigstring.create 20)
      | 1 -> (* UPDATE *)
        contents store >>= fun cts ->
        (try_lwt
          let rid = Random.int (List.length cts) in
          update store (List.nth_exn cts rid |> fst) (Bigstring.create 20)
        with _ -> Lwt.return_unit)
      | 2 -> (* REMOVE *)
        contents store >>= fun cts ->
        (try_lwt
          let rid = Random.int (List.length cts) in
          remove store (List.nth_exn cts rid |> fst)
        with _ -> Lwt.return_unit)
      | _ -> assert_lwt false
      ) >>= fun () -> Lwt_unix.sleep period >>= fun () ->
      inner ()
    in inner ()
  in forever 1.

let () =
  let () = Random.self_init () in
  let iface = ref "eth0" in
  let group_addr = ref "ff02::dead:beaf" in
  let group_port = ref 5555 in
  let vsize = ref 20 in
  let speclist = Arg.(align [
      "--iface", Set_string iface, "<string> Interface to use (default: eth0)";
      "--addr", Set_string group_addr, "<string> IPv6 multicast group address to use (default: ff02::dead:beef)";
      "--port", Set_int group_port, "<int> Group port to use (default: 5555)";
      "--vsize", Set_int vsize, "<int> Size of the random values to add in the DB (default: 20).";
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
    let key_size = !vsize
  end in
  let module DRW = IrminDistributed.RW(IrminMemory.RW(IrminReference.String))(Conf) in
  Lwt_main.run (main (module DRW: IrminStore.RW_BINARY) !vsize)
