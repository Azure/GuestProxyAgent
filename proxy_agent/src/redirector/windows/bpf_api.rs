// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(windows)]
#![allow(non_snake_case)]

use super::bpf_obj::*;
use crate::common::{
    error::{BpfErrorType, Error},
    logger,
    result::Result,
};
use libloading::{Library, Symbol};
use once_cell::sync::Lazy;
use proxy_agent_shared::{logger::LoggerLevel, misc_helpers, telemetry::event_logger};
use std::env;
use std::ffi::{c_char, c_int, c_uint, c_void, CString};
use std::path::PathBuf;

static EBPF_API: Lazy<Option<Library>> = Lazy::new(init_ebpf_lib);
const EBPF_API_FILE_NAME: &str = "EbpfApi.dll";

pub fn ebpf_api_is_loaded() -> bool {
    EBPF_API.is_some()
}

fn init_ebpf_lib() -> Option<Library> {
    let program_files_dir = env::var("ProgramFiles").unwrap_or("C:\\Program Files".to_string());
    let program_files_dir = PathBuf::from(program_files_dir);
    let ebpf_for_windows_dir = program_files_dir.join("ebpf-for-windows");
    let bpf_api_file_path = ebpf_for_windows_dir.join(EBPF_API_FILE_NAME);
    logger::write_information(format!(
        "Try to load ebpf api file from: {}",
        misc_helpers::path_to_string(&bpf_api_file_path)
    ));
    match load_ebpf_api(bpf_api_file_path) {
        Ok(ebpf_lib) => {
            return Some(ebpf_lib);
        }
        Err(e) => {
            event_logger::write_event(
                LoggerLevel::Error,
                format!("{}", e),
                "load_ebpf_api",
                "redirector",
                logger::AGENT_LOGGER_KEY,
            );
        }
    }

    logger::write_warning("Try to load ebpf api file from default system path".to_string());
    match load_ebpf_api(PathBuf::from(EBPF_API_FILE_NAME)) {
        Ok(ebpf_lib) => {
            return Some(ebpf_lib);
        }
        Err(e) => {
            event_logger::write_event(
                LoggerLevel::Warn,
                format!("{}", e),
                "load_ebpf_api",
                "redirector",
                logger::AGENT_LOGGER_KEY,
            );
        }
    }

    None
}

fn load_ebpf_api(bpf_api_file_path: PathBuf) -> Result<Library> {
    // Safety: Loading a library on  Windows has the following safety requirements:
    // 1. The safety requirements of the library initialization and/or termination routines must be met.
    // The eBPF for Windows library does not have any safety requirements for its initialization and de-initialization function[0].
    // [0] https://github.com/microsoft/ebpf-for-windows/blob/Release-v0.17.1/ebpfapi/dllmain.cpp
    //
    // 2. Calling this function is not safe in multi-thread scenarios where a library file name is provided and the library
    //     search path is modified.
    // We satisfy the this requirement by providing the absolute path to the library.
    unsafe { Library::new(bpf_api_file_path.as_path()) }.map_err(|e| {
        Error::Bpf(BpfErrorType::LoadBpfApi(
            misc_helpers::path_to_string(&bpf_api_file_path),
            e.to_string(),
        ))
    })
}

fn get_ebpf_api() -> Result<&'static Library> {
    match EBPF_API.as_ref() {
        Some(api) => Ok(api),
        None => Err(Error::Bpf(BpfErrorType::GetBpfApi)),
    }
}

// function name must null terminated with '\0'.
fn get_ebpf_api_fun<'a, T>(ebpf_api: &'a Library, name: &str) -> Result<Symbol<'a, T>> {
    unsafe { ebpf_api.get(name.as_bytes()) }.map_err(|e| {
        Error::Bpf(BpfErrorType::LoadBpfApiFunction(
            name.to_string(),
            e.to_string(),
        ))
    })
}

// Object
type BpfObjectOpen = unsafe extern "C" fn(path: *const c_char) -> *mut bpf_object;
type BpfObjectLoad = unsafe extern "C" fn(obj: *mut bpf_object) -> c_int;
type BpfObjectClose = unsafe extern "C" fn(obj: *mut bpf_object) -> c_void;
// Program
type BpfObjectFindProgramByName =
    unsafe extern "C" fn(obj: *const bpf_object, name: *const c_char) -> *mut ebpf_program_t;
// type BpfProgramFd = unsafe extern "C" fn(prog: *const ebpf_program_t) -> c_int;
// type BpfProgAttach = unsafe extern "C" fn(
//     prog_fd: c_int,
//     attachable_fd: c_int,
//     attach_type: bpf_attach_type,
//     flags: c_uint,
// ) -> c_int;
type EBpfProgAttach = unsafe extern "C" fn(
    prog: *const ebpf_program_t,
    attach_type: *const ebpf_attach_type_t,
    attach_parameters: *const c_void,
    attach_params_size: usize,
    link: *mut *mut ebpf_link_t,
) -> c_int;
type BpfLinkDisconnect = unsafe extern "C" fn(link: *mut ebpf_link_t) -> c_void;
type BpfLinkDestroy = unsafe extern "C" fn(link: *mut ebpf_link_t) -> c_int;

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

type BpfMapDeleteElem = unsafe extern "C" fn(map_fd: c_int, key: *const c_void) -> c_int;

fn get_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::Bpf(BpfErrorType::CString(e)))
}

pub fn bpf_object__open(path: &str) -> Result<*mut bpf_object> {
    let ebpf_api = get_ebpf_api()?;
    let open_ebpf_object: Symbol<BpfObjectOpen> = get_ebpf_api_fun(ebpf_api, "bpf_object__open\0")?;
    // lifetime of the value must be longer than the lifetime of the pointer returned by as_ptr
    let c_string = get_cstring(path)?;
    Ok(unsafe { open_ebpf_object(c_string.as_ptr()) })
}

pub fn bpf_object__load(obj: *mut bpf_object) -> Result<c_int> {
    let ebpf_api = get_ebpf_api()?;
    let load_ebpf_object: Symbol<BpfObjectLoad> = get_ebpf_api_fun(ebpf_api, "bpf_object__load\0")?;
    Ok(unsafe { load_ebpf_object(obj) })
}

pub fn bpf_object__close(object: *mut bpf_object) -> Result<c_void> {
    let ebpf_api = get_ebpf_api()?;
    let object__close: Symbol<BpfObjectClose> = get_ebpf_api_fun(ebpf_api, "bpf_object__close\0")?;
    Ok(unsafe { object__close(object) })
}

pub fn bpf_object__find_program_by_name(
    obj: *mut bpf_object,
    name: &str,
) -> Result<*mut ebpf_program_t> {
    let ebpf_api = get_ebpf_api()?;
    let find_program_by_name: Symbol<BpfObjectFindProgramByName> =
        get_ebpf_api_fun(ebpf_api, "bpf_object__find_program_by_name\0")?;
    // lifetime of the value must be longer than the lifetime of the pointer returned by as_ptr
    let c_string = get_cstring(name)?;
    Ok(unsafe { find_program_by_name(obj, c_string.as_ptr()) })
}

pub fn ebpf_prog_attach(
    prog: *mut ebpf_program_t,
    attach_type: *const ebpf_attach_type_t,
    attach_parameters: *const c_void,
    attach_params_size: usize,
    link: *mut *mut ebpf_link_t,
) -> Result<c_int> {
    let ebpf_api = get_ebpf_api()?;
    let program_attach: Symbol<EBpfProgAttach> =
        get_ebpf_api_fun(ebpf_api, "ebpf_program_attach\0")?;
    Ok(unsafe {
        program_attach(
            prog,
            attach_type,
            attach_parameters,
            attach_params_size,
            link,
        )
    })
}

pub fn bpf_link_disconnect(link: *mut ebpf_link_t) -> Result<c_void> {
    let ebpf_api = get_ebpf_api()?;
    let link_disconnect: Symbol<BpfLinkDisconnect> =
        get_ebpf_api_fun(ebpf_api, "bpf_link__disconnect\0")?;
    Ok(unsafe { link_disconnect(link) })
}

pub fn bpf_link_destroy(link: *mut ebpf_link_t) -> Result<c_int> {
    let ebpf_api = get_ebpf_api()?;
    let link_destroy: Symbol<BpfLinkDestroy> = get_ebpf_api_fun(ebpf_api, "bpf_link__destroy\0")?;
    Ok(unsafe { link_destroy(link) })
}

pub fn bpf_object__find_map_by_name(obj: *mut bpf_object, name: &str) -> Result<*mut bpf_map> {
    let ebpf_api = get_ebpf_api()?;
    let find_map_by_name: Symbol<BpfObjectFindMapByName> =
        get_ebpf_api_fun(ebpf_api, "bpf_object__find_map_by_name\0")?;
    // lifetime of the value must be longer than the lifetime of the pointer returned by as_ptr
    let c_string = get_cstring(name)?;
    Ok(unsafe { find_map_by_name(obj, c_string.as_ptr()) })
}

pub fn bpf_map__fd(map: *mut bpf_map) -> Result<c_int> {
    let ebpf_api = get_ebpf_api()?;
    let map__fd: Symbol<BpfMapFd> = get_ebpf_api_fun(ebpf_api, "bpf_map__fd\0")?;
    Ok(unsafe { map__fd(map) })
}

pub fn bpf_map_update_elem(
    map_fd: c_int,
    key: *const c_void,
    value: *const c_void,
    flags: c_uint,
) -> Result<c_int> {
    let ebpf_api = get_ebpf_api()?;
    let map_update_elem: Symbol<BpfMapUpdateElem> =
        get_ebpf_api_fun(ebpf_api, "bpf_map_update_elem\0")?;
    Ok(unsafe { map_update_elem(map_fd, key, value, flags) })
}

pub fn bpf_map_lookup_elem(map_fd: c_int, key: *const c_void, value: *mut c_void) -> Result<c_int> {
    let ebpf_api = get_ebpf_api()?;
    let map_lookup_elem: Symbol<BpfMapLookupElem> =
        get_ebpf_api_fun(ebpf_api, "bpf_map_lookup_elem\0")?;
    Ok(unsafe { map_lookup_elem(map_fd, key, value) })
}

pub fn bpf_map_delete_elem(map_fd: c_int, key: *const c_void) -> Result<c_int> {
    let ebpf_api = get_ebpf_api()?;
    let map_delete_elem: Symbol<BpfMapDeleteElem> =
        get_ebpf_api_fun(ebpf_api, "bpf_map_delete_elem\0")?;
    Ok(unsafe { map_delete_elem(map_fd, key) })
}
