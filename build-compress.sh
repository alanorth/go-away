#!/bin/bash

set -e
set -o pipefail

cd "$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

do_compress () {
  find "$1" \( -type f -name "*.wasm" -o -name "*.css" -o -name "*.js" -o -name "*.mjs" \) -exec zopfli {} \;
  find "$1" \( -type f -name "*.wasm" -o -name "*.css" -o -name "*.js" -o -name "*.mjs" \) -exec brotli -v -f -9 -o {}.br {} \;
  #find "$1" \( -type f -name "*.wasm" -o -name "*.css" -o -name "*.js" -o -name "*.mjs" \) -exec zstd -v -f -19 -o {}.zst {} \;
}

do_compress challenge/
do_compress assets/