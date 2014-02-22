open Llnet
open Ipaddr

let (>>=) = Lwt.(>>=)

(* Set log level to Debug *)
let () = Lwt_log.(add_rule "*" Info)

let main () =
  let reactor _ _ _ = Lwt.return_unit in
  let h = connect "eth0" (Ipaddr.V6.of_string_exn "ff02::dead:beef") 5555 reactor in
  let rec inner () =
    Lwt_unix.sleep 1. >>= fun () ->
    if h.peers <> SaddrMap.empty then
      SaddrMap.iter (fun k v -> Printf.printf "[%s]:%d\n%!"
                        (Ipaddr.V6.to_string (fst k)) (snd k)) h.peers;
    inner ()
  in inner ()

let () = Lwt_main.run (main ())
