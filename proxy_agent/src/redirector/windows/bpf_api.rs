// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(windows)]
#![allow(non_snake_case)]

use super::bpf_obj::*;
use libloading::{Library, Symbol};
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use std::ffi::{c_char, c_int, c_uint, c_void, CString};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

static mut EBPF_API: Lazy<Option<Library>> = Lazy::new(|| None);

pub fn load_ebpf_api(bpf_api_file_path: PathBuf) -> std::io::Result<()> {
    unsafe {
        match Library::new(bpf_api_file_path.as_path()) {
            Ok(api) => {
                *EBPF_API = Some(api);
            }
            Err(e) => {
                let message = format!(
                    "Loading ebpf api from file {} failed with error: {}",
                    misc_helpers::path_to_string(bpf_api_file_path.to_path_buf()),
                    e
                );
                return Err(Error::new(ErrorKind::Other, message));
            }
        }
    }

    Ok(())
}

fn get_ebpf_api() -> std::io::Result<&'static Library> {
    unsafe {
        match EBPF_API.as_ref() {
            Some(api) => Ok(api),
            None => {
                let message = "Ebpf api is not loaded".to_string();
                return Err(Error::new(ErrorKind::Other, message));
            }
        }
    }
}

// function name must null terminated with '\0'.
fn get_ebpf_api_fun<'a, T>(ebpf_api: &'a Library, name: &str) -> std::io::Result<Symbol<'a, T>> {
    unsafe {
        match ebpf_api.get(name.as_bytes()) {
            Ok(f) => Ok(f),
            Err(e) => {
                let message: String = format!("Loading {} failed with error: {}", name, e);
                return Err(Error::new(ErrorKind::Other, message));
            }
        }
    }
}

// Object
type BpfObjectOpen = unsafe extern "C" fn(path: *const c_char) -> *mut bpf_object;
type BpfObjectLoad = unsafe extern "C" fn(obj: *mut bpf_object) -> c_int;
type BpfObjectClose = unsafe extern "C" fn(obj: *mut bpf_object) -> c_void;
// Program
type BpfObjectFindProgramByName =
    unsafe extern "C" fn(obj: *const bpf_object, name: *const c_char) -> *mut ebpf_program_t;
type BpfProgramFd = unsafe extern "C" fn(prog: *const ebpf_program_t) -> c_int;
type BpfProgAttach = unsafe extern "C" fn(
    prog_fd: c_int,
    attachable_fd: c_int,
    attach_type: bpf_attach_type,
    flags: c_uint,
) -> c_int;
// Map
type BpfObjectFindMapByName =
    unsafe extern "C" fn(obj: *const bpf_object, name: *const c_char) -> *mut bpf_map;
type BpfMapFd = unsafe extern "C" fn(map: *const bpf_map) -> c_int;
type BpfMapUpdateElem = unsafe extern "C" fn(
    map_fd: c_int,
    key: *const c_void,
    value: *const c_void,
    flags: c_uint,
) -> c_int;
type BpfMapLookupElem =
    unsafe extern "C" fn(map_fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;

fn get_cstring(s: &str) -> std::io::Result<CString> {
    CString::new(s).map_err(|e| Error::new(ErrorKind::InvalidInput, e))
}

pub fn bpf_object__open(path: &str) -> std::io::Result<*mut bpf_object> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let open_ebpf_object: Symbol<BpfObjectOpen> =
            get_ebpf_api_fun(&ebpf_api, "bpf_object__open\0")?;
        // lifetime of the value must be longer than the lifetime of the pointer returned by as_ptr
        let c_string = get_cstring(path)?;
        Ok(open_ebpf_object(c_string.as_ptr()))
    }
}

pub fn bpf_object__load(obj: *mut bpf_object) -> std::io::Result<c_int> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let load_ebpf_object: Symbol<BpfObjectLoad> =
            get_ebpf_api_fun(&ebpf_api, "bpf_object__load\0")?;
        Ok(load_ebpf_object(obj))
    }
}

pub fn bpf_object__close(object: *mut bpf_object) -> std::io::Result<c_void> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let object__close: Symbol<BpfObjectClose> =
            get_ebpf_api_fun(&ebpf_api, "bpf_object__close\0")?;
        Ok(object__close(object))
    }
}

pub fn bpf_object__find_program_by_name(
    obj: *mut bpf_object,
    name: &str,
) -> std::io::Result<*mut ebpf_program_t> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let find_program_by_name: Symbol<BpfObjectFindProgramByName> =
            get_ebpf_api_fun(&ebpf_api, "bpf_object__find_program_by_name\0")?;
        // lifetime of the value must be longer than the lifetime of the pointer returned by as_ptr
        let c_string = get_cstring(name)?;
        Ok(find_program_by_name(obj, c_string.as_ptr()))
    }
}

pub fn bpf_program__fd(prog: *mut ebpf_program_t) -> std::io::Result<c_int> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let program__fd: Symbol<BpfProgramFd> = get_ebpf_api_fun(&ebpf_api, "bpf_program__fd\0")?;
        Ok(program__fd(prog))
    }
}

pub fn bpf_prog_attach(
    prog_fd: c_int,
    attachable_fd: c_int,
    attach_type: bpf_attach_type,
    flags: c_uint,
) -> std::io::Result<c_int> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let prog_attach: Symbol<BpfProgAttach> = get_ebpf_api_fun(&ebpf_api, "bpf_prog_attach\0")?;
        Ok(prog_attach(prog_fd, attachable_fd, attach_type, flags))
    }
}

pub fn bpf_object__find_map_by_name(
    obj: *mut bpf_object,
    name: &str,
) -> std::io::Result<*mut bpf_map> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let find_map_by_name: Symbol<BpfObjectFindMapByName> =
            get_ebpf_api_fun(&ebpf_api, "bpf_object__find_map_by_name\0")?;
        // lifetime of the value must be longer than the lifetime of the pointer returned by as_ptr
        let c_string = get_cstring(name)?;
        Ok(find_map_by_name(obj, c_string.as_ptr()))
    }
}

pub fn bpf_map__fd(map: *mut bpf_map) -> std::io::Result<c_int> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let map__fd: Symbol<BpfMapFd> = get_ebpf_api_fun(&ebpf_api, "bpf_map__fd\0")?;
        Ok(map__fd(map))
    }
}

pub fn bpf_map_update_elem(
    map_fd: c_int,
    key: *const c_void,
    value: *const c_void,
    flags: c_uint,
) -> std::io::Result<c_int> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let map_update_elem: Symbol<BpfMapUpdateElem> =
            get_ebpf_api_fun(&ebpf_api, "bpf_map_update_elem\0")?;
        Ok(map_update_elem(map_fd, key, value, flags))
    }
}

pub fn bpf_map_lookup_elem(
    map_fd: c_int,
    key: *const c_void,
    value: *mut c_void,
) -> std::io::Result<c_int> {
    unsafe {
        let ebpf_api = get_ebpf_api()?;
        let map_lookup_elem: Symbol<BpfMapLookupElem> =
            get_ebpf_api_fun(&ebpf_api, "bpf_map_lookup_elem\0")?;
        Ok(map_lookup_elem(map_fd, key, value))
    }
}
