open Core_kernel.Std

let (>>=) = Lwt.(>>=)

let () = Sys.catch_break true

let to_hex ?nb_digit s =
  let transform = Cryptokit.Hexa.encode () in
  let hex = Cryptokit.transform_string transform s in
  match nb_digit with
  | None -> hex
  | Some n -> String.sub hex 0 n

let main irmin iface mcast_addr mcast_port ksize =
  let module I = (val irmin : Irmin.S) in
  I.create () >>= fun store ->
  Llnet.connect iface mcast_addr mcast_port
      (fun f saddr msg ->
        I.Sync.fetch store (IrminSync.uri "aueabiue") >>= function
        | Some new_store -> (* Merge the fetched contents with our store *)
          I.Sync.merge_exn store new_store (* TODO: do sth with the exn *)
        | None -> Lwt.return_unit) (* Keep our store *)
      (fun _ _ _ -> Lwt.return_unit) >>= fun c ->

  Lwt_main.at_exit (fun () ->
      I.dump store >>= fun kvs ->
      Lwt_io.printf "\nExiting with %d keys in store\n" (List.length kvs) >>= fun () ->
      Lwt_list.iter_s (fun (path, v) ->
          let v_str = I.Value.to_string v in
          Lwt_io.printf "/%s -> %s\n" (match path with |[] -> "" |h::t -> to_hex h) (to_hex v_str)) kvs
      >>= fun () ->
      Lwt_io.printf "\n"
    );
  let add_forever period =
    let rec inner () =
      let key = String.create (max 8 ksize) in
      let seed = Random.bits () |> Int64.of_int in
      EndianString.BigEndian.set_int64 key 0 seed;
      I.update store [key] (I.Value.of_string key) >>= fun () ->
      (* Signal other peers that we commited our repo *)
      let open Llnet in
      Lwt_unix.sendto c.group_sock "\200\000\000\000\000" 0 5 [] c.group_saddr >>= fun (_:int) ->
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
      "--size", Set_int vsize, "<int> Size of the random values to add in the DB (default: 10)";
      "-v", String (fun s -> Lwt_log.(add_rule s Info)), "<string> Log section to put in Info mode";
      "-vv", String (fun s -> Lwt_log.(add_rule s Debug)), "<string> Log section to put in Debug mode";
    ]) in
  let anon_fun s = () in
  let usage_msg = "Usage: " ^ Sys.argv.(0) ^ " <options>\nOptions are:" in
  Arg.parse speclist anon_fun usage_msg;
  let iface = !iface in
  let mcast_addr = Ipaddr.V6.of_string_exn !group_addr in
  let mcast_port = !group_port in

  let module IM = IrminMemory.Make(IrminKey.SHA1)(IrminContents.String)(IrminTag.String) in
  Lwt_main.run (main
                  (module IM: Irmin.S) iface mcast_addr mcast_port !vsize)
                    (* with type key = IrminKey.SHA1.t *)
                    (*  and type value = IrminIdent.String.t) !vsize) *)
