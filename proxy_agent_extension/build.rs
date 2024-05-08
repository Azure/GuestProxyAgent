// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
fn main() {
    #[cfg(windows)]
    {
        static_vcruntime::metabuild();
        let res = winres::WindowsResource::new();
        res.compile().unwrap();
    }
}