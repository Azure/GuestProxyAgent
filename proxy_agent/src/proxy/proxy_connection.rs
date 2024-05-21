// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::proxy::Claims;
use std::net::TcpStream;
use std::time::Instant;

pub struct Connection {
    pub stream: TcpStream,
    pub id: u128,

    pub now: Instant,
    pub cliams: Option<Claims>,
    pub ip: String,
    pub port: u16,
}
