#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Prints then runs the command based on: https://stackoverflow.com/questions/31656645/how-do-i-echo-directly-on-standard-output-inside-a-shell-function
runthis(){
    echo "$@"
    ## Run the command and redirect its error output
    "$@" >&2
}

# This script is used to set the default toolchain for the current directory and run cargo clippy and cargo fmt. 
rustup update stable
rustup override unset

echo "======= cargo fmt & clippy"
runthis rustup component add rustfmt clippy
runthis cargo fmt --all
runthis cargo clippy -- -D warnings
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo clippy with exit-code: $error_code"
    exit $error_code
fi