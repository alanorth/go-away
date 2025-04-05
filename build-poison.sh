#!/bin/bash

set -e
set -o pipefail

cd "$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"


go run ./generate-poison -path ./poison/