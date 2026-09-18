#![allow(dead_code)]
//! The mesh data plane as a library: the desktop binary and the mobile apps run
//! the same code, the apps through the C ABI in `ffi` or the JNI bindings in
//! `android`.
mod api;
pub mod allowed;
mod derp;
mod derpframe;
mod dial;
mod disco;
mod dns;
mod dnspath;
pub mod exitnode;
pub mod ffi;
pub mod keys;
mod meshapi;
pub mod meshnet;
mod meshtypes;
pub mod path;
mod profiles;
pub mod protect;
mod route;
pub mod rng;
pub mod session;
mod stun;
pub mod tun;

#[cfg(target_os = "android")]
pub mod android;

pub use keys::*;
