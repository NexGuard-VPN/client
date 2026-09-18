use crate::protect::{self, Descriptor};
use crate::session;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};

const PROTECT_METHOD: &str = "protect";
const PROTECT_SIGNATURE: &str = "(I)Z";

fn read(env: &mut JNIEnv, value: &JString) -> Option<String> {
    env.get_string(value).ok().map(|text| text.into())
}

fn hand_over(env: &JNIEnv, text: String) -> jstring {
    env.new_string(text)
        .map(|owned| owned.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_core_NexGuardNative_prepare(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jstring {
    let answer = match read(&mut env, &config_json) {
        Some(config) => session::prepare(&config),
        None => r#"{"ok":false,"error":"no configuration"}"#.to_owned(),
    };
    hand_over(&env, answer)
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_core_NexGuardNative_start(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    config_json: JString,
) -> jint {
    match read(&mut env, &config_json) {
        Some(config) => session::start(tun_fd, &config),
        None => -1,
    }
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_core_NexGuardNative_status(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    hand_over(&env, session::status())
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_core_NexGuardNative_stop(_env: JNIEnv, _class: JClass) {
    session::stop()
}

/// A JNI global reference stays valid on every thread, so the session threads
/// can reach the service from wherever they bound a socket — they only have to
/// attach themselves to the JVM first.
struct Host {
    vm: JavaVM,
    service: GlobalRef,
}

unsafe impl Send for Host {}
unsafe impl Sync for Host {}

impl Host {
    fn protect(&self, socket: Descriptor) -> bool {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return false;
        };
        let answer = env
            .call_method(
                &self.service,
                PROTECT_METHOD,
                PROTECT_SIGNATURE,
                &[JValue::Int(socket)],
            )
            .and_then(|value| value.z());
        match answer {
            Ok(kept_off_the_tunnel) => kept_off_the_tunnel,
            Err(_) => {
                let _ = env.exception_clear();
                false
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_core_NexGuardNative_installProtector(
    env: JNIEnv,
    _class: JClass,
    service: JObject,
) -> jboolean {
    let Ok(vm) = env.get_java_vm() else {
        return JNI_FALSE;
    };
    let Ok(service) = env.new_global_ref(service) else {
        return JNI_FALSE;
    };
    let host = Host { vm, service };
    protect::install(Box::new(move |socket| host.protect(socket)));
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_sh_nexguard_vpn_core_NexGuardNative_removeProtector(
    _env: JNIEnv,
    _class: JClass,
) {
    protect::remove()
}
