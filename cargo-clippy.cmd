REM Copyright (c) Microsoft Corporation
REM SPDX-License-Identifier: MIT

@echo off

REM This script is used to set the default toolchain for the current directory and run cargo clippy and cargo fmt.

echo ======= rustup default stable
echo rustup update stable
rustup update stable
echo rustup override unset
rustup override unset

echo ======= cargo fmt and clippy
echo call rustup component add rustfmt clippy
call rustup component add rustfmt clippy
echo call cargo fmt --all
cargo fmt --all
echo call cargo clippy -- -D warnings
cargo clippy -- -D warnings
if  %ERRORLEVEL% NEQ 0 (
    echo cargo clippy failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)
