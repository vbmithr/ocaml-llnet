open Llnet
open Llnet.Helpers

let (>>=) = Lwt.(>>=)

module Lwt_unix = struct
  include Lwt_unix

  let safe_close s = match state s with
    | Closed -> Lwt.return_unit
    | _ -> close s
end

let main iface (addr:Ipaddr.t) port =
  let group_reactor _ _ _ = Lwt.return_unit in
  let tcp_reactor h fd remote_saddr =
    (* Returns a serialized list of our IP addresses at the selected
       interface *)
    let open Tuntap in
    Lwt_list.iter_s
      (fun {name; ipaddr} ->
         if name <> iface then Lwt.return_unit
         else
           match ipaddr with
           | AF_INET6 (a, prefix) -> Lwt.return_unit
           | AF_INET (a, prefix) ->
             Lwt_unix.write fd (Ipaddr.V4.to_bytes a) 0 4 >>= fun nb_written ->
             assert (nb_written = 4);
             Lwt.return_unit
      )
      (getifaddrs ()) >>= fun () ->
    Lwt_unix.close fd
  in
  let peers_ipv4addr = Hashtbl.create 13 in
  let ipv4buf = String.create 4 in
  let obtain_ipv4addr_from_peers saddr =
      let ss = Unix.(socket (domain_of_sockaddr saddr) SOCK_STREAM 0) in
      let s = Lwt_unix.of_unix_file_descr ss in
      try_lwt
        Sockopt.connect ~iface ss saddr;
        let rec read_one_addr () =
          Lwt_unix.read s ipv4buf 0 4 >>= function
          | 4 ->
            Hashtbl.replace peers_ipv4addr saddr (Ipaddr.V4.of_bytes_exn ipv4buf);
            Lwt_log.debug_f "Read one IPv4 from %s" (Ipaddr.to_string addr) >>= fun () ->
            read_one_addr ()
          | n -> (* done, or error *)
            Lwt_log.debug_f "Lwt_unix.read returned %d" n
        in
        read_one_addr ()
      with
      | Unix.Unix_error (Unix.ECONNREFUSED,_,_) -> Lwt_unix.safe_close s
      finally
        Lwt_unix.safe_close s

  in
  Llnet.connect ~group_reactor ~tcp_reactor ~iface (addr:Ipaddr.t) port  >>= fun h ->
  let rec inner () =
    Lwt_unix.sleep 1. >>= fun () ->
    Printf.printf "I am peer number %d and my group is:\n%!" (order h);
    Lwt_list.iter_s
      (fun (k, (ttl, ign)) ->
         Printf.printf "  %s -> TTL=%d, ignored=%b" (Helpers.string_of_saddr k) ttl ign;
         obtain_ipv4addr_from_peers k >>= fun () ->
         (try
            let ipv4 = Hashtbl.find peers_ipv4addr k in
          Printf.printf ", ipv4=%s\n%!" (Ipaddr.V4.to_string ipv4)
          with Not_found -> Printf.printf "\n%!");
         Lwt.return_unit
      ) (h.peers |> SaddrMap.bindings) >>= fun () ->
    inner ()
  in inner ()

let () =
  let iface = ref "eth0" in
  let group_addr = ref "ff02::dead:beaf" in
  let group_port = ref 5555 in
  let speclist = Arg.(align [
      "--iface", Set_string iface, "<string> Interface to use (default: eth0)";
      "--addr", Set_string group_addr, "<string> Multicast group address to use (default: ff02::dead:beef)";
      "--port", Set_int group_port, "<int> Group port to use (default: 5555)";
      "-v", Unit (fun () -> Lwt_log.(add_rule "*" Info)), " Be verbose";
      "-vv", Unit (fun () -> Lwt_log.(add_rule "*" Debug)), " Be more verbose"
    ]) in
  let anon_fun s = () in
  let usage_msg = "Usage: " ^ Sys.argv.(0) ^ " <options>\nOptions are:" in
  Arg.parse speclist anon_fun usage_msg;

  Lwt_main.run (main !iface (Ipaddr.of_string_exn !group_addr) !group_port)
