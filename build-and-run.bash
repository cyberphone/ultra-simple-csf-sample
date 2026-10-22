#!/bin/bash

# Rudimentary Linux bash script for building and running CSF sample.
#
# Run from any directory: $ bash path-to-this-script
#
pushd $(dirname "${BASH_SOURCE[0]}")/out
gcc -o demo -Os -Wno-gnu-folding-constant -I ../lib ../src/demo.c ../lib/*.c
./demo
popd
