//! Support for MoYu's `WCU_MY3*` smart cubes (WeiLong V10 AI, V11 AI).
//!
//! Layout mirrors `bluetooth/gan/`: `protocol.rs` holds the entire
//! transport-agnostic state machine and is unit tested plus replayed
//! against captured BLE traffic, `cipher.rs` holds key derivation and MAC
//! discovery, and `native.rs` / `web.rs` are thin btleplug and web-sys
//! shims that decrypt, feed the protocol, and write back whatever it
//! asks for.
//!
//! Nothing in `protocol.rs` or `cipher.rs` touches `btleplug` or
//! `web-sys`, so the interesting half of this driver is testable on any
//! platform with no hardware.

pub(crate) mod cipher;
pub(crate) mod protocol;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod web;

#[cfg(test)]
mod replay;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::moyu32_connect;
#[cfg(target_arch = "wasm32")]
pub(crate) use web::{moyu32_capture_mac, moyu32_web_connect};
