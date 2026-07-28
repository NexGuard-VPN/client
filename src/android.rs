use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jint, jlong};
use jni::JNIEnv;

use crate::ffi::{start_session, Params, Session};

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|v| v.into()).unwrap_or_default()
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_NexGuardNative_nativeSetStorageDir(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) {
    let p = jstr(&mut env, &path);
    if !p.is_empty() {
        crate::set_storage_dir(std::path::PathBuf::from(p));
    }
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_NexGuardNative_nativeKeypair<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
) -> JByteArray<'a> {
    let key = crate::generate_private_key();
    let secret = boringtun::x25519::StaticSecret::from(key);
    let public = boringtun::x25519::PublicKey::from(&secret);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&key);
    out[32..].copy_from_slice(public.as_bytes());
    let arr = env.byte_array_from_slice(&out).unwrap();
    arr
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_NexGuardNative_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    relay: JString,
    server_name: JString,
    token: JString,
    server_pub_b64: JString,
    private_key_b64: JString,
) -> jlong {
    let relay = jstr(&mut env, &relay);
    let server_name = jstr(&mut env, &server_name);
    let token = jstr(&mut env, &token);
    let server_pub = match crate::b64_decode_32(&jstr(&mut env, &server_pub_b64)) {
        Some(k) => k,
        None => return 0,
    };
    let private_key = match crate::b64_decode_32(&jstr(&mut env, &private_key_b64)) {
        Some(k) => k,
        None => return 0,
    };

    let session = start_session(Params {
        tun_fd,
        relay,
        server_name,
        token,
        server_pub,
        private_key,
    });
    Box::into_raw(session) as jlong
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_NexGuardNative_nativeStats(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jlong {
    if ptr == 0 {
        return 0;
    }
    let s = ptr as *const Session;
    let mut tx = 0u64;
    let mut rx = 0u64;
    let connected = crate::ffi::nexguard_stats(s, &mut tx, &mut rx);
    let tx_kb = (tx / 1024).min(0x7FFF_FFFF) as i64;
    let rx_kb = (rx / 1024).min(0x7FFF_FFFF) as i64;
    let flag = if connected { 1i64 } else { 0i64 };
    (flag << 62) | (tx_kb << 31) | rx_kb
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_NexGuardNative_nativeDisconnect(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr == 0 {
        return;
    }
    crate::ffi::nexguard_disconnect(ptr as *mut Session);
}
