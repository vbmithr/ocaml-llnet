open Core_kernel.Std
open Irmin_unix

let (>>=) = Lwt.(>>=)

let () = Sys.catch_break true

let section = Lwt_log.Section.make "test_irmin"

let to_hex ?nb_digit s =
  let transform = Cryptokit.Hexa.encode () in
  let hex = Cryptokit.transform_string transform s in
  match nb_digit with
  | None -> hex
  | Some n -> String.sub hex 0 n

let saddr_with_port saddr port =
  let open Unix in
  match saddr with
  | ADDR_INET (a, _) -> ADDR_INET (a, port)
  | _ -> raise (Invalid_argument "saddr_with_port")

let main iface mcast_addr mcast_port ksize =
  let module I = IrminGit.Memory.Make(IrminKey.SHA1)(IrminContents.String)(IrminTag.String) in
  let module IS = IrminHTTP.Make(I) in
  I.create () >>= fun store ->

  Llnet.connect iface mcast_addr mcast_port
      (fun f saddr msg ->
        let remote_port = EndianString.BigEndian.get_uint16 msg 1 in
        let saddr = saddr_with_port saddr remote_port in
        let saddr_str = match saddr with
          | Unix.ADDR_INET (sa, port) -> Printf.sprintf "[%s%%25%s]:%d"
                                            (Unix.string_of_inet_addr sa)
                                            iface port
          | _ -> failwith "saddr_str"
        in
        let git_remote_str = "http://" ^ saddr_str ^ "/scanlight" in
        Lwt_log.info_f ~section "Connecting to %s" git_remote_str >>= fun () ->
        Lwt.return_unit
        (* I.Sync.fetch store (IrminSync.uri git_remote_str) >>= function *)
        (* | Some new_store -> (\* Merge the fetched contents with our store *\) *)
        (*   I.Sync.merge_exn store new_store (\* TODO: do sth with the exn *\) *)
        (* | None -> Lwt.return_unit (\* Keep our store *\) *)
      )
      (fun _ _ _ -> Lwt.return_unit) >>= fun c ->

  let my_tcp_port = Llnet.(Helpers.port_of_saddr c.tcp_in_saddr) in
  (* Close Llnet TCP insock that we do not use, and use the port for
     the irminsule server *)
  (* We close the UNIX sock because Lwt is buggy and do not want to
     close the wrapped socket *)
  let unix_sock = Lwt_unix.unix_file_descr c.Llnet.tcp_in_sock in
  Unix.close unix_sock;
  (* Print summary on Ctrl-C *)
  Lwt_main.at_exit (fun () ->
      I.dump store >>= fun kvs ->
      Lwt_io.printf "\nExiting with %d keys in store\n" (List.length kvs) >>= fun () ->
      Lwt_list.iter_s (fun (path, v) ->
          let v_str = I.Value.to_string v in
          Lwt_io.printf "/%s -> %s\n" (match path with |[] -> "" |h::t -> to_hex h) (to_hex v_str)) kvs
      >>= fun () ->
      Lwt_io.printf "\n"
    );

  (* Serve content over HTTP *)
  IS.listen store ("http://[::]:" ^ string_of_int my_tcp_port |> Uri.of_string) |> Lwt.ignore_result;

  let add_forever period =
    let msgbuf = "\200\000\000\000\000" in
    EndianString.BigEndian.set_int16 msgbuf 1 my_tcp_port;
    let rec inner () =
      Lwt_unix.sleep period >>= fun () ->
      let key = String.create (max 8 ksize) in
      let seed = Random.bits () |> Int64.of_int in
      EndianString.BigEndian.set_int64 key 0 seed;
      I.update store [key] (I.Value.of_string key) >>= fun () ->
      (* Signal other peers that we commited our repo *)
      let open Llnet in
      Lwt_unix.sendto c.group_sock msgbuf 0 5 [] c.group_saddr >>= fun (_:int) ->
      inner ()
    in inner ()
  in add_forever 1.

let () =
  let iface = ref "wlan0" in
  let group_addr = ref "ff02::dead:beaf" in
  let group_port = ref 5555 in
  let vsize = ref 10 in
  let speclist = Arg.(align [
      "--iface", Set_string iface, "<string> Interface to use (default: wlan0)";
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
  Lwt_main.run (main iface mcast_addr mcast_port !vsize)
