use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::tun::TunDevice;
use crate::wg::{connect_relay, run_data_plane_tls, WgState};

const BACKOFF_START_MS: u64 = 1000;
const BACKOFF_MAX_MS: u64 = 30_000;

pub struct Session {
    shutdown: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
    handle: Option<JoinHandle<()>>,
}

pub(crate) struct Params {
    pub tun_fd: i32,
    pub relay: String,
    pub server_name: String,
    pub token: String,
    pub server_pub: [u8; 32],
    pub private_key: [u8; 32],
}

pub(crate) fn start_session(p: Params) -> Box<Session> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let connected = Arc::new(AtomicBool::new(false));
    let tx = Arc::new(AtomicU64::new(0));
    let rx = Arc::new(AtomicU64::new(0));

    let (s_sd, s_co, s_tx, s_rx) = (shutdown.clone(), connected.clone(), tx.clone(), rx.clone());

    let handle = std::thread::spawn(move || {
        let server_pub_key = boringtun::x25519::PublicKey::from(p.server_pub);
        let tun = TunDevice::from_raw_fd(p.tun_fd);
        let mut backoff = BACKOFF_START_MS;

        while !s_sd.load(Ordering::Relaxed) {
            let secret = boringtun::x25519::StaticSecret::from(p.private_key);
            let tunn = boringtun::noise::Tunn::new(
                secret,
                server_pub_key,
                None,
                Some(crate::jittered_keepalive()),
                0,
                None,
            );
            let state = Mutex::new(WgState { tunn, server_pub_key });

            match connect_relay(&p.relay, &p.server_name, &p.token) {
                Ok(mut tls) => {
                    backoff = BACKOFF_START_MS;
                    s_co.store(true, Ordering::Relaxed);
                    run_data_plane_tls(&tun, &mut tls, &state, &s_tx, &s_rx, &s_sd, None, None, None);
                    s_co.store(false, Ordering::Relaxed);
                }
                Err(_) => {}
            }

            if s_sd.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(backoff));
            backoff = (backoff * 2).min(BACKOFF_MAX_MS);
        }
    });

    Box::new(Session {
        shutdown,
        connected,
        tx,
        rx,
        handle: Some(handle),
    })
}

fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

#[no_mangle]
pub extern "C" fn nexguard_set_storage_dir(path: *const c_char) {
    if let Some(p) = cstr(path) {
        crate::set_storage_dir(std::path::PathBuf::from(p));
    }
}

#[no_mangle]
pub extern "C" fn nexguard_keypair(priv_out: *mut u8, pub_out: *mut u8) {
    if priv_out.is_null() || pub_out.is_null() {
        return;
    }
    let key = crate::generate_private_key();
    let secret = boringtun::x25519::StaticSecret::from(key);
    let public = boringtun::x25519::PublicKey::from(&secret);
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), priv_out, 32);
        std::ptr::copy_nonoverlapping(public.as_bytes().as_ptr(), pub_out, 32);
    }
}

#[no_mangle]
pub extern "C" fn nexguard_connect(
    tun_fd: i32,
    relay: *const c_char,
    server_name: *const c_char,
    token: *const c_char,
    server_pub_key_b64: *const c_char,
    private_key_b64: *const c_char,
) -> *mut Session {
    let params = match (
        cstr(relay),
        cstr(server_name),
        cstr(token),
        cstr(server_pub_key_b64).and_then(crate::b64_decode_32),
        cstr(private_key_b64).and_then(crate::b64_decode_32),
    ) {
        (Some(relay), Some(server_name), Some(token), Some(server_pub), Some(private_key)) => Params {
            tun_fd,
            relay: relay.to_string(),
            server_name: server_name.to_string(),
            token: token.to_string(),
            server_pub,
            private_key,
        },
        _ => return std::ptr::null_mut(),
    };
    Box::into_raw(start_session(params))
}

#[no_mangle]
pub extern "C" fn nexguard_stats(ptr: *const Session, tx: *mut u64, rx: *mut u64) -> bool {
    if ptr.is_null() {
        return false;
    }
    let s = unsafe { &*ptr };
    unsafe {
        if !tx.is_null() {
            *tx = s.tx.load(Ordering::Relaxed);
        }
        if !rx.is_null() {
            *rx = s.rx.load(Ordering::Relaxed);
        }
    }
    s.connected.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn nexguard_disconnect(ptr: *mut Session) {
    if ptr.is_null() {
        return;
    }
    let mut s = unsafe { Box::from_raw(ptr) };
    s.shutdown.store(true, Ordering::Relaxed);
    if let Some(h) = s.handle.take() {
        let _ = h.join();
    }
}
