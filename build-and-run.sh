#!/bin/bash

# Rudimentary Linux bash script for building and running the CSF sample.
#
# Run from any directory: $ bash path-to-this-script
#
pushd $(dirname "${BASH_SOURCE[0]}")/out >/dev/null
gcc -o demo -Os ../src/demo.c ../lib/*.c
./demo
popd >/dev/null
