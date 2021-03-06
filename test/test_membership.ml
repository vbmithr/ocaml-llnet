open Lwt.Infix
open Llnet
open Llnet.Helpers

let section =  Lwt_log.Section.make "test_membership"

module Lwt_unix = struct
  include Lwt_unix

  let safe_close s = match state s with
    | Closed -> Lwt.return_unit
    | _ -> close s
end

let main iface tcp_port group_saddr =

  (* Handle TLS *)
  let group_reactor _ _ _ = Lwt.return_unit in

  let myipv4addrs =
    ListLabels.fold_left (Tuntap.getifaddrs ()) ~init:[] ~f:begin fun acc (name, ipaddr) ->
      if name <> iface then acc
      else
        match ipaddr with
        | `V4 (a, prefix) -> a::acc
        | `V6 (a, prefix) -> acc
    end
  in

  let tcp_reactor h fd remote_saddr =
    (* When requested, returns a the number (uint16_be) of IPv4 addrs
       we possess and the serialized list thereof *)
    let buf = Lwt_bytes.create 256 in
    let rec inner () =
      (* request-reply model here *)
      Lwt_bytes.read fd buf 0 (Lwt_bytes.length buf) >>= fun (_:int) ->
      Lwt_log.debug_f ~section "Got a IPv4 request from %s"
        (string_of_saddr remote_saddr) >>= fun () ->
      EndianBigstring.BigEndian.set_int16 buf 0 (List.length myipv4addrs);
      Lwt_bytes.write fd buf 0 2 >>= fun (_:int) ->
      Lwt_list.iter_s
        (fun addr ->
           let addr_bytes = Ipaddr.V4.to_bytes addr |> Lwt_bytes.of_string in
           let%lwt _ =  Lwt_bytes.write fd addr_bytes 0 4 in Lwt.return_unit)
        myipv4addrs >>
      inner ()
    in
    (inner ()) [%finally Lwt_unix.close fd]
  in
  let peers_ipv4addr = Hashtbl.create 13 in
  let make_getipv4addr () =
    let ipv4buf = Lwt_bytes.create 4 in
    let conns = Hashtbl.create 13 in

    let read_addrs fd saddr =
      (* Requesting IPv4 listing to the server *)
      Lwt_bytes.write fd ipv4buf 0 4 >>= fun (_:int) ->
      (* Getting number of IPv4 of remote peer *)
      Lwt_bytes.read fd ipv4buf 0 2 >>= fun (_:int) ->
      let nb_ipv4 = EndianBigstring.BigEndian.get_int16 ipv4buf 0 in
      let nb_ipv4 = if nb_ipv4 < 0 then nb_ipv4 + 65535 else nb_ipv4 in

      let rec inner n =
        if n < 1 then Lwt.return_unit
        else
          try%lwt
            Lwt_bytes.read fd ipv4buf 0 4 >>= function
            | 4 ->
              Hashtbl.replace peers_ipv4addr saddr
                (ipv4buf |> Lwt_bytes.to_string |> Ipaddr.V4.of_bytes_exn);
              inner (n-1)
            | n -> (* done, or error *)
              Lwt_log.debug_f ~section "Lwt_unix.read returned %d" n
          with exn ->
            Lwt_log.debug_f ~section "Removing conn from %s" (string_of_saddr saddr)
      in
      Lwt_log.debug_f ~section "Reading %n IPv4 from %s"
        nb_ipv4 (string_of_saddr saddr) >>
      inner nb_ipv4
    in

    fun saddr ->
      let%lwt fd =
        try Hashtbl.find conns saddr |> Lwt.return
        with Not_found ->
          let fd = Lwt_unix.(socket (Unix.domain_of_sockaddr saddr) SOCK_STREAM 0) in
          try%lwt
            Lwt_unix.connect fd saddr >>= fun () ->
            Hashtbl.replace conns saddr fd;
            Lwt_log.debug_f ~section "Adding conn to %s" (string_of_saddr saddr) >>
            Lwt.return fd
          with
          | Unix.Unix_error (Unix.ECONNREFUSED,_,_) as exn ->
              Lwt_unix.safe_close fd >>
              Lwt.fail exn
      in
      read_addrs fd saddr
  in
  let getipv4addr = make_getipv4addr () in

  Llnet.connect ~tcp_port ~group_reactor ~tcp_reactor ~iface group_saddr  >>= fun h ->
  let rec inner () =
    Lwt_condition.wait h.clock >>= fun () ->
    Printf.printf "I am peer number %d and my group is:\n%!" (order h);
    Lwt_list.iter_s
      (fun (k, (ttl, ign)) ->
         Printf.printf "  %s -> TTL=%d, ignored=%b" (Helpers.string_of_saddr k) ttl ign;
         getipv4addr k >>= fun () ->
         (try
            let ipv4 = Hashtbl.find peers_ipv4addr k in
            Printf.printf ", ipv4=%s\n%!" (Ipaddr.V4.to_string ipv4)
          with Not_found -> Printf.printf "\n%!");
         Lwt.return_unit
      ) (h.peers |> SaddrMap.bindings) >>= fun () ->
    inner ()
  in inner ()

let () =
  let iface = ref "enp0s25" in
  let group_addr = ref "ff02::dead:beaf" in
  let group_port = ref 5555 in
  let tcp_port = ref 0 in
  let speclist = Arg.(align [
      "-iface", Set_string iface,
      "<string> Interface to use (default: enp0s25)";
      "-addr", Set_string group_addr,
      "<string> Multicast group address to use (default: ff02::dead:beef)";
      "-port", Set_int group_port,
      "<int> Group port to use (default: 5555)";
      "-tcp-port", Set_int tcp_port,
      "<int> Port to bind the TCP server to (default: automatic)";
      "-v", Unit (fun s -> Lwt_log.(add_rule "*" Info)),
      "<section> Put <section> to the verbose level";
      "-vv", Unit (fun s -> Lwt_log.(add_rule "*" Debug)),
      "<section> Put <section> to the debug level"
    ]) in
  let anon_fun s = () in
  let usage_msg = "Usage: " ^ Sys.argv.(0) ^ " <options>\nOptions are:" in
  Arg.parse speclist anon_fun usage_msg;

  let group_saddr = Unix.(ADDR_INET (inet_addr_of_string !group_addr, !group_port)) in
  Lwt_main.run (main !iface !tcp_port group_saddr)
