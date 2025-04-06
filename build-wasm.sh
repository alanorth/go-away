#!/bin/bash

set -e
set -o pipefail

cd "$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

mkdir -p .bin/ 2>/dev/null

# Setup tinygo first
if [[ ! -d .bin/tinygo ]]; then
  git clone --depth=1 --branch v0.37.0 https://github.com/tinygo-org/tinygo.git .bin/tinygo
  pushd .bin/tinygo
  git submodule update --init --recursive

  go mod download -x && go mod verify

  make binaryen STATIC=1
  make wasi-libc

  make llvm-source
  make llvm-build

  make build/release
else
  pushd .bin/tinygo
fi

export TINYGOROOT="$(realpath ./build/release/tinygo/)"
export PATH="$PATH:$(realpath ./build/release/tinygo/bin/)"

popd

go generate ./...