open Llnet
open Ipaddr

let (>>=) = Lwt.(>>=)

let main iface addr port =
  let group_reactor _ _ _ = Lwt.return_unit in
  let tcp_reactor _ _ = Lwt.return_unit in
  let h = connect iface addr port group_reactor tcp_reactor in
  let rec inner () =
    Lwt_unix.sleep 1. >>= fun () ->
    if h.peers <> SaddrMap.empty then
      SaddrMap.iter (fun k v -> Printf.printf "[%s]:%d\n%!"
                        (Ipaddr.V6.to_string (fst k)) (snd k)) h.peers;
    inner ()
  in inner ()

let () =
  let iface = ref "eth0" in
  let group_addr = ref "ff02::dead:beaf" in
  let group_port = ref 5555 in
  let speclist = Arg.(align [
      "--iface", Set_string iface, "<string> Interface to use (default: eth0)";
      "--addr", Set_string group_addr, "<string> IPv6 multicast group address to use (default: ff02::dead:beef)";
      "--port", Set_int group_port, "<int> Group port to use (default: 5555)";
      "-v", Unit (fun () -> Lwt_log.(add_rule "*" Info)), " Be verbose";
      "-vv", Unit (fun () -> Lwt_log.(add_rule "*" Debug)), " Be more verbose"
    ]) in
  let anon_fun s = () in
  let usage_msg = "Usage: " ^ Sys.argv.(0) ^ " <options>\nOptions are:" in
  Arg.parse speclist anon_fun usage_msg;

  Lwt_main.run (main !iface V6.(of_string_exn !group_addr) !group_port)
