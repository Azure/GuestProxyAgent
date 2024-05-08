// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(windows)]

use core::ffi::c_void;
use std::mem::{self, MaybeUninit};
use std::net::TcpStream;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::windows::io::AsRawSocket;
use std::os::windows::prelude::{FromRawSocket, RawSocket};
use std::ptr;
use windows_sys::Win32::Networking::WinSock;
use crate::common;

fn to_in_addr(addr: &Ipv4Addr) -> WinSock::IN_ADDR {
    WinSock::IN_ADDR {
        S_un: WinSock::IN_ADDR_0 {
            // `S_un` is stored as BE on all machines, and the array is in BE
            // order. So the native endian conversion method is used so that
            // it's never swapped.
            S_addr: u32::from_ne_bytes(addr.octets()),
        },
    }
}

const fn as_ptr(addr: &WinSock::SOCKADDR_IN) -> *const WinSock::SOCKADDR {
    addr as *const _ as *const WinSock::SOCKADDR
}

fn as_sockaddr_storage(addr: SocketAddrV4) -> WinSock::SOCKADDR_IN {
    WinSock::SOCKADDR_IN {
        sin_family: WinSock::AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: to_in_addr(addr.ip()),
        ..unsafe { mem::zeroed() }
    }
}

pub fn connect_with_redirect_record(
    ip: String,
    port: u16,
    client_stream: &TcpStream,
) -> std::io::Result<TcpStream> {
    unsafe {
        let socket = WinSock::WSASocketW(
            WinSock::AF_INET as i32,
            WinSock::SOCK_STREAM as i32,
            WinSock::IPPROTO_TCP as i32,
            ptr::null_mut(),
            0,
            0,
        );
        // WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS
        let mut redirect_record: [MaybeUninit<*mut c_void>; 256] =
            MaybeUninit::uninit().assume_init();
        let redirect_record_size = mem::size_of::<[MaybeUninit<*mut c_void>; 256]>() as u32;
        let mut redirect_record_returned: u32 = 0;
        let record_buff = redirect_record.as_mut_ptr().cast::<c_void>();
        WinSock::WSAIoctl(
            client_stream.as_raw_socket() as usize,
            WinSock::SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            ptr::null(),
            0,
            record_buff,
            redirect_record_size,
            &mut redirect_record_returned,
            ptr::null_mut(),
            Option::None,
        );
        common::windows::check_winsock_last_error(
            "WinSock::WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS",
        )?;

        WinSock::WSAIoctl(
            socket,
            WinSock::SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
            record_buff,
            redirect_record_size,
            ptr::null_mut(),
            0,
            &mut redirect_record_returned,
            ptr::null_mut(),
            Option::None,
        );
        common::windows::check_winsock_last_error(
            "WinSock::WSAIoctl - SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS",
        )?;

        let address: SocketAddrV4 = format!("{ip}:{port}").parse().unwrap();
        let address = as_sockaddr_storage(address);
        let len = mem::size_of::<WinSock::SOCKADDR_IN>() as i32;
        WinSock::connect(socket, as_ptr(&address), len);
        common::windows::check_winsock_last_error("WinSock::connect")?;

        Ok(TcpStream::from_raw_socket(socket as RawSocket))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_mock::server_mock;
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn connect_with_redirect_record_test() {
        // start wire_server listener
        let ip = "127.0.0.1";
        let port = 1080u16;
        thread::spawn(move || {
            server_mock::start(ip.to_string(), port);
        });
        thread::sleep(Duration::from_millis(100));

        let client = TcpStream::connect(format!("{}:{}", ip, port)).unwrap();
        match super::connect_with_redirect_record(ip.to_string(), port, &client) {
            Ok(_) => {
                // test failed if no error thrown
                assert!(false);
            }
            Err(e) => {
                // expected to throw error
                let error = format!("expected connect_with_redirect_record_test error: {}", e);
                assert!(
                    error.contains("WinSock::WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS")
                );
            }
        }

        server_mock::stop(ip.to_string(), port);
    }
}
