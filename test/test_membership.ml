open Llnet
open Ipaddr

let (>>=) = Lwt.(>>=)

(* Set log level to Debug *)
let () = Lwt_log.(add_rule "*" Info)

let main () =
  let hex_encode = Cryptokit.Hexa.encode () in
  let reactor _ _ _ = Lwt.return_unit in
  connect "eth0" "ff02::dead:beef" "5555" reactor >>= fun h ->
  let rec inner () =
    Lwt_unix.sleep 1. >>= fun () ->
    if h.peers <> StringMap.empty then
      StringMap.iter (fun k v -> Printf.printf "%s\n%!"
                         (k |> Cryptokit.transform_string hex_encode)) h.peers;
    inner ()
  in inner ()

let () = Lwt_main.run (main ())
