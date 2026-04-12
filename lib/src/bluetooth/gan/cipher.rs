//! AES ciphers shared by the Gen2/Gen3/Gen4 GAN protocols.
//!
//! `GanV2Cipher` is used by Gen2 (20-byte messages) and Gen4 (20-byte
//! messages). It performs a two-block AES-128 encryption of the first and
//! last 16 bytes of the packet, XORed with a device-specific IV. The two
//! blocks overlap when the packet is shorter than 32 bytes.
//!
//! `GanV3Cipher` is used by Gen3 (exactly 16-byte messages). It is a
//! straightforward single-block AES-128 encrypt/decrypt XORed with the IV.
//!
//! No `btleplug` or `web-sys` types are touched here — both native and wasm
//! can use these ciphers directly.

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Block,
};
use anyhow::{anyhow, Result};
use std::convert::TryFrom;

/// The base key used by Gen2/Gen3/Gen4 before per-device mixing.
pub(crate) const GAN_V2_BASE_KEY: [u8; 16] = [
    0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11, 0x12, 0x53,
];

/// The base IV used by Gen2/Gen3/Gen4 before per-device mixing.
pub(crate) const GAN_V2_BASE_IV: [u8; 16] = [
    0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12, 0x02, 0x43,
];

/// Mix the 6-byte device key into the base key and IV. This is the same
/// derivation used by all of Gen2, Gen3 and Gen4 — the differences between
/// those protocols are all above the cipher layer.
pub(crate) fn derive_key_iv(device_key: &[u8; 6]) -> ([u8; 16], [u8; 16]) {
    let mut key = GAN_V2_BASE_KEY;
    let mut iv = GAN_V2_BASE_IV;
    for (idx, byte) in device_key.iter().enumerate() {
        key[idx] = ((key[idx] as u16 + *byte as u16) % 255) as u8;
        iv[idx] = ((iv[idx] as u16 + *byte as u16) % 255) as u8;
    }
    (key, iv)
}

/// Two-block overlapping AES cipher used by Gen2 and Gen4 (20-byte packets).
#[derive(Clone)]
pub(crate) struct GanV2Cipher {
    pub(crate) device_key: [u8; 16],
    pub(crate) device_iv: [u8; 16],
}

impl GanV2Cipher {
    #[allow(dead_code)]
    pub(crate) fn new(device_key: [u8; 16], device_iv: [u8; 16]) -> Self {
        Self {
            device_key,
            device_iv,
        }
    }

    pub(crate) fn from_device_key(device_key: &[u8; 6]) -> Self {
        let (key, iv) = derive_key_iv(device_key);
        Self {
            device_key: key,
            device_iv: iv,
        }
    }

    pub(crate) fn decrypt(&self, value: &[u8]) -> Result<Vec<u8>> {
        if value.len() <= 16 {
            return Err(anyhow!("Packet size less than expected length"));
        }

        let mut value = value.to_vec();
        let aes = Aes128::new_from_slice(&self.device_key).unwrap();
        let offset = value.len() - 16;
        let end_cipher = &value[offset..];
        let mut end_plain = Block::from(<[u8; 16]>::try_from(end_cipher).unwrap());
        aes.decrypt_block(&mut end_plain);
        for i in 0..16 {
            end_plain[i] ^= self.device_iv[i];
            value[offset + i] = end_plain[i];
        }

        let start_cipher = &value[0..16];
        let mut start_plain = Block::from(<[u8; 16]>::try_from(start_cipher).unwrap());
        aes.decrypt_block(&mut start_plain);
        for i in 0..16 {
            start_plain[i] ^= self.device_iv[i];
            value[i] = start_plain[i];
        }

        Ok(value)
    }

    pub(crate) fn encrypt(&self, value: &[u8]) -> Result<Vec<u8>> {
        if value.len() <= 16 {
            return Err(anyhow!("Packet size less than expected length"));
        }

        let mut value = value.to_vec();
        for i in 0..16 {
            value[i] ^= self.device_iv[i];
        }
        let mut cipher = Block::from(<[u8; 16]>::try_from(&value[0..16]).unwrap());
        let aes = Aes128::new_from_slice(&self.device_key).unwrap();
        aes.encrypt_block(&mut cipher);
        for i in 0..16 {
            value[i] = cipher[i];
        }

        let offset = value.len() - 16;
        for i in 0..16 {
            value[offset + i] ^= self.device_iv[i];
        }
        let mut cipher = Block::from(<[u8; 16]>::try_from(&value[offset..]).unwrap());
        aes.encrypt_block(&mut cipher);
        for i in 0..16 {
            value[offset + i] = cipher[i];
        }

        Ok(value)
    }
}

/// Single-block AES cipher used by Gen3 (16-byte packets).
#[derive(Clone)]
pub(crate) struct GanV3Cipher {
    pub(crate) device_key: [u8; 16],
    pub(crate) device_iv: [u8; 16],
}

impl GanV3Cipher {
    #[allow(dead_code)]
    pub(crate) fn new(device_key: [u8; 16], device_iv: [u8; 16]) -> Self {
        Self {
            device_key,
            device_iv,
        }
    }

    pub(crate) fn from_device_key(device_key: &[u8; 6]) -> Self {
        let (key, iv) = derive_key_iv(device_key);
        Self {
            device_key: key,
            device_iv: iv,
        }
    }

    pub(crate) fn decrypt(&self, value: &[u8]) -> Result<[u8; 16]> {
        if value.len() != 16 {
            return Err(anyhow!("Gen3 packet must be exactly 16 bytes"));
        }
        let aes = Aes128::new_from_slice(&self.device_key).unwrap();
        let mut block = Block::from(<[u8; 16]>::try_from(value).unwrap());
        aes.decrypt_block(&mut block);
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = block[i] ^ self.device_iv[i];
        }
        Ok(result)
    }

    pub(crate) fn encrypt(&self, value: &[u8; 16]) -> [u8; 16] {
        let aes = Aes128::new_from_slice(&self.device_key).unwrap();
        let mut block = Block::default();
        for i in 0..16 {
            block[i] = value[i] ^ self.device_iv[i];
        }
        aes.encrypt_block(&mut block);
        let mut result = [0u8; 16];
        result.copy_from_slice(&block);
        result
    }
}
