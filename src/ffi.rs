use crate::session;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn borrow(text: *const c_char) -> Option<&'static str> {
    if text.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(text) }.to_str().ok()
}

fn hand_over(text: String) -> *mut c_char {
    CString::new(text)
        .map(|owned| owned.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `config_json` must be a NUL-terminated UTF-8 string. The returned string is
/// owned by the caller and is released with `nexguard_string_free`.
#[no_mangle]
pub unsafe extern "C" fn nexguard_mesh_prepare(config_json: *const c_char) -> *mut c_char {
    let Some(config) = borrow(config_json) else {
        return hand_over(r#"{"ok":false,"error":"no configuration"}"#.to_owned());
    };
    hand_over(session::prepare(config))
}

/// # Safety
/// `config_json` must be a NUL-terminated UTF-8 string, and `tun_fd` a
/// descriptor this process may own until `nexguard_mesh_stop`.
#[no_mangle]
pub unsafe extern "C" fn nexguard_mesh_start(tun_fd: i32, config_json: *const c_char) -> i32 {
    match borrow(config_json) {
        Some(config) => session::start(tun_fd, config),
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn nexguard_mesh_status() -> *mut c_char {
    hand_over(session::status())
}

#[no_mangle]
pub extern "C" fn nexguard_mesh_stop() {
    session::stop()
}

/// # Safety
/// `text` must be a pointer this library returned and has not freed yet.
#[no_mangle]
pub unsafe extern "C" fn nexguard_string_free(text: *mut c_char) {
    if !text.is_null() {
        drop(CString::from_raw(text));
    }
}
