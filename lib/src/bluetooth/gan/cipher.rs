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

/// The base key used by MoYu's `AiCube` line (MoYu AI V2 / WeiLong WRM V10 AI).
/// These cubes speak the GAN Gen2 protocol byte-for-byte — same GATT service
/// (`6e400001-b5a3-f393-e0a9-e50e24dc4179`), same characteristics, same packet
/// layout, and the same 6-byte device key in manufacturer data company id
/// 0x0001 — but seed the AES cipher from a different base pair.
pub(crate) const MOYU_AI_BASE_KEY: [u8; 16] = [
    0x05, 0x12, 0x02, 0x45, 0x02, 0x01, 0x29, 0x56, 0x12, 0x78, 0x12, 0x76, 0x81, 0x01, 0x08, 0x03,
];

/// The base IV used by MoYu's `AiCube` line. See [`MOYU_AI_BASE_KEY`].
pub(crate) const MOYU_AI_BASE_IV: [u8; 16] = [
    0x01, 0x44, 0x28, 0x06, 0x86, 0x21, 0x22, 0x28, 0x51, 0x05, 0x08, 0x31, 0x82, 0x02, 0x21, 0x06,
];

/// The base key used by MoYu's `WCU_MY3*` line (WeiLong V10 AI / V11 AI).
/// These cubes do **not** speak a GAN wire protocol at all — see
/// `bluetooth/moyu32/` — but they do use the same two-block AES construction
/// with the same `% 255` mixing, so they seed [`GanV2Cipher`] with their own
/// base pair. The six mixing bytes are the cube's BLE address reversed.
pub(crate) const MOYU32_BASE_KEY: [u8; 16] = [
    0x15, 0x77, 0x3A, 0x5C, 0x67, 0x0E, 0x2D, 0x1F, 0x17, 0x67, 0x2A, 0x13, 0x9B, 0x67, 0x52, 0x57,
];

/// The base IV used by MoYu's `WCU_MY3*` line. See [`MOYU32_BASE_KEY`].
pub(crate) const MOYU32_BASE_IV: [u8; 16] = [
    0x11, 0x23, 0x26, 0x25, 0x86, 0x2A, 0x2C, 0x3B, 0x55, 0x06, 0x7F, 0x31, 0x7E, 0x67, 0x21, 0x57,
];

/// Which base key/IV pair seeds the cipher. The GAN Gen2 wire protocol is used
/// by two vendors with different secrets, so the key set has to be chosen from
/// the advertised device name before any packet can be decrypted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum GanKeySet {
    /// GAN's own cubes: Gen2, Gen3 and Gen4.
    Gan,
    /// MoYu `AiCube` cubes running the Gen2 protocol.
    MoYuAi,
    /// MoYu `WCU_MY3*` cubes. Not a GAN protocol, just the same cipher;
    /// selected explicitly by `moyu32::cipher`, never by device name.
    Moyu32,
}

impl GanKeySet {
    /// Choose the key set from the advertised BLE name. MoYu's Gen2-compatible
    /// cubes advertise as `AiCube…` (e.g. `AiCube2MT`); everything else routed
    /// here is a GAN cube (`GAN…` / `MG…`).
    pub(crate) fn from_device_name(name: &str) -> Self {
        if name.starts_with("AiCube") {
            Self::MoYuAi
        } else {
            Self::Gan
        }
    }

    fn base_key_iv(self) -> ([u8; 16], [u8; 16]) {
        match self {
            Self::Gan => (GAN_V2_BASE_KEY, GAN_V2_BASE_IV),
            Self::MoYuAi => (MOYU_AI_BASE_KEY, MOYU_AI_BASE_IV),
            Self::Moyu32 => (MOYU32_BASE_KEY, MOYU32_BASE_IV),
        }
    }
}

/// Mix the 6-byte device key into the base key and IV for `key_set`. This is
/// the same derivation used by all of Gen2, Gen3 and Gen4 — the differences
/// between those protocols are all above the cipher layer.
pub(crate) fn derive_key_iv(device_key: &[u8; 6], key_set: GanKeySet) -> ([u8; 16], [u8; 16]) {
    let (mut key, mut iv) = key_set.base_key_iv();
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

    pub(crate) fn from_device_key(device_key: &[u8; 6], key_set: GanKeySet) -> Self {
        let (key, iv) = derive_key_iv(device_key, key_set);
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

    pub(crate) fn from_device_key(device_key: &[u8; 6], key_set: GanKeySet) -> Self {
        let (key, iv) = derive_key_iv(device_key, key_set);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_set_selected_from_device_name() {
        // MoYu's Gen2-compatible line.
        assert_eq!(GanKeySet::from_device_name("AiCube2MT"), GanKeySet::MoYuAi);
        assert_eq!(GanKeySet::from_device_name("AiCubeXXX"), GanKeySet::MoYuAi);
        // Everything else routed to the GAN implementation.
        assert_eq!(GanKeySet::from_device_name("GAN-a1b2c3"), GanKeySet::Gan);
        assert_eq!(GanKeySet::from_device_name("GANicXXX"), GanKeySet::Gan);
        assert_eq!(GanKeySet::from_device_name("MG12ui"), GanKeySet::Gan);
        assert_eq!(GanKeySet::from_device_name(""), GanKeySet::Gan);
    }

    #[test]
    fn derivation_differs_by_key_set() {
        // The device key comes from manufacturer data company id 0x0001,
        // bytes 3..9. This is the real key advertised by an AiCube2MT.
        let device_key = [0x79, 0x23, 0x00, 0x75, 0x70, 0x83];

        let (gan_key, gan_iv) = derive_key_iv(&device_key, GanKeySet::Gan);
        let (moyu_key, moyu_iv) = derive_key_iv(&device_key, GanKeySet::MoYuAi);
        assert_ne!(gan_key, moyu_key);
        assert_ne!(gan_iv, moyu_iv);

        // Only the first 6 bytes are mixed; the tail is the untouched base.
        assert_eq!(gan_key[6..], GAN_V2_BASE_KEY[6..]);
        assert_eq!(moyu_key[6..], MOYU_AI_BASE_KEY[6..]);
        assert_eq!(gan_iv[6..], GAN_V2_BASE_IV[6..]);
        assert_eq!(moyu_iv[6..], MOYU_AI_BASE_IV[6..]);

        // Mixing is (base + device_key) % 255, per byte.
        for idx in 0..6 {
            assert_eq!(
                moyu_key[idx],
                ((MOYU_AI_BASE_KEY[idx] as u16 + device_key[idx] as u16) % 255) as u8
            );
            assert_eq!(
                moyu_iv[idx],
                ((MOYU_AI_BASE_IV[idx] as u16 + device_key[idx] as u16) % 255) as u8
            );
        }
    }

    #[test]
    fn v2_cipher_round_trips_with_moyu_key_set() {
        let device_key = [0x79, 0x23, 0x00, 0x75, 0x70, 0x83];
        let cipher = GanV2Cipher::from_device_key(&device_key, GanKeySet::MoYuAi);

        // Gen2 packets are 20 bytes.
        let plaintext: Vec<u8> = (0..20u8).collect();
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(cipher.decrypt(&encrypted).unwrap(), plaintext);

        // A packet encrypted for MoYu must not decrypt to the same plaintext
        // under GAN's key set — this is exactly why the cube was unusable.
        let gan_cipher = GanV2Cipher::from_device_key(&device_key, GanKeySet::Gan);
        assert_ne!(gan_cipher.decrypt(&encrypted).unwrap(), plaintext);
    }
}
