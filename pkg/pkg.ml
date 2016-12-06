#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "llnet" @@ fun c ->
  Ok [ Pkg.mllib "src/llnet.mllib" ]
