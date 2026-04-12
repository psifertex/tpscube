//! Shared protocol code for GAN smart cubes.
//!
//! This module contains the pure (transport-agnostic) protocol state machine
//! used by both the native (btleplug) and web (web-sys) bluetooth layers. No
//! code in `cipher.rs` or `gen34_protocol.rs` imports `btleplug` or
//! `web-sys` directly; the seam is "raw bytes in, parsed events + outgoing
//! command bytes out".
//!
//! Only the Gen3 / Gen4 protocols are shared here. Gen1, Gen2 and the GAN
//! Smart Timer are still implemented directly in `native.rs` / `web.rs`.
//!
//! The Gen3/Gen4 protocols are intentionally unified into a single
//! `Gen34Protocol<W: Gen34Wire>` type. Gen3 and Gen4 differ only in byte
//! offsets, magic bytes, opcodes and a few command-packet details; all of
//! that lives behind the `Gen34Wire` trait.

pub(crate) mod cipher;
pub(crate) mod gen34_protocol;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod web;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::gan_cube_connect;
#[cfg(target_arch = "wasm32")]
pub(crate) use web::gan_web_connect;

#[allow(unused_imports)]
pub(crate) use cipher::{GanV2Cipher, GanV3Cipher};
#[allow(unused_imports)]
pub(crate) use gen34_protocol::{
    Gen34Event, Gen34OutMessage, Gen34Protocol, Gen34Wire, Gen3Wire, Gen4Wire,
};
