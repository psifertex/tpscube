//! QiYi smart cube support.
//!
//! Covers the QiYi Smart Cube (`QY-QYSC-*`) and the XMD Tornado V4
//! (`XMD-TornadoV4-i-*`), which ship the same firmware protocol — the
//! Tornado just adds gyroscope packets, which this driver drops.
//!
//! Layout mirrors `gan/`: [`protocol`] is a transport-agnostic, offline
//! tested state machine that imports neither `btleplug` nor `web-sys`,
//! and the `native` / `web` modules are thin transports that pump bytes
//! through it. The replay tests in `protocol.rs` run the real captures
//! in `testdata/` through the machine, so the parsing, framing, CRC and
//! acknowledgement behavior are all verified without hardware.

pub(crate) mod protocol;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod web;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::qiyi_cube_connect;
#[cfg(target_arch = "wasm32")]
pub(crate) use web::{capture_qiyi_mac, qiyi_web_connect};

#[allow(unused_imports)]
pub(crate) use protocol::is_qiyi_device_name;
