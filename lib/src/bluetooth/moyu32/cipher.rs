//! Key derivation and MAC-address discovery for MoYu32 cubes.
//!
//! MoYu32 uses exactly the same AES construction as the GAN Gen2/Gen4
//! protocols — two overlapping AES-128-ECB blocks over the first and last
//! 16 bytes of the packet, each XORed with a device-specific IV — so the
//! cipher itself is [`GanV2Cipher`], reused verbatim. Only the seed
//! differs: the base key/IV pair is MoYu's own (see
//! [`GanKeySet::Moyu32`](crate::bluetooth::gan::cipher::GanKeySet)) and
//! the six mixing bytes are the cube's BLE MAC address in reverse.
//!
//! There is no handshake, challenge or session nonce: the key is a pure
//! function of the MAC. That makes getting the MAC the entire problem, so
//! most of this file is about the three ways of obtaining it, in
//! decreasing order of reliability:
//!
//! 1. [`mac_from_manufacturer_data`] — the advertisement carries it.
//! 2. [`mac_candidates_from_name`] — the advertised name embeds the last
//!    two octets, and the first four are near-constant per hardware line.
//! 3. Probing — connect with each candidate key and see whose
//!    notifications decrypt to structurally valid packets. That part
//!    needs a transport, so it lives in `native.rs` / `web.rs`; the
//!    per-packet test is `protocol::packet_looks_valid`.

use crate::bluetooth::gan::cipher::{GanKeySet, GanV2Cipher};

/// A MoYu32 cube's BLE address, in display order: `mac[0]` is the octet
/// printed first (`CF` in `CF:30:16:02:AF:9E`).
pub(crate) type Moyu32Mac = [u8; 6];

/// Build the cipher for a cube with the given MAC.
///
/// The derivation is `key[i] = (key[i] + mac[5 - i]) % 255` for the first
/// six bytes of both the key and the IV — note `% 255`, not `% 256`,
/// which is a genuine quirk of the vendor implementations rather than a
/// typo here. `GanV2Cipher::from_device_key` already applies exactly that
/// mixing to `device_key[i]`, so all we have to do is hand it the MAC
/// reversed.
pub(crate) fn cipher_for_mac(mac: &Moyu32Mac) -> GanV2Cipher {
    let mut device_key = [0u8; 6];
    for i in 0..6 {
        device_key[i] = mac[5 - i];
    }
    GanV2Cipher::from_device_key(&device_key, GanKeySet::Moyu32)
}

/// Extract the MAC from a BLE advertisement's manufacturer data payload.
///
/// The company identifier is not fixed: it is `0x0000` for an unbound
/// cube and the top half of the owner's MoYu account id once bound, so
/// callers must accept any CIC and rely on this parse to reject
/// non-matching payloads. The address occupies the last six bytes of the
/// payload in wire (LSB-first) order, so it comes back reversed.
///
/// `payload` may or may not still have the two-byte CIC prefix attached —
/// Chrome strips it, the Bluefy `DataView` workaround does not — but
/// since we read from the end either form works.
pub(crate) fn mac_from_manufacturer_data(payload: &[u8]) -> Option<Moyu32Mac> {
    if payload.len() < 6 {
        return None;
    }
    let tail = &payload[payload.len() - 6..];
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = tail[5 - i];
    }
    // An all-zero or all-ones address is padding, not an address.
    if mac.iter().all(|b| *b == 0x00) || mac.iter().all(|b| *b == 0xFF) {
        return None;
    }
    Some(mac)
}

/// Derive candidate MAC addresses from the advertised name.
///
/// `WCU_MY32_A388` and `WCU_MY33_AF9E` embed the last two octets of the
/// address, and MoYu assigns these cubes out of `CF:30:16:xx`. Only the
/// fourth octet is unknown and only three values have been observed, so
/// the candidate set is tiny enough to probe. The ordering differs per
/// line because that is the order the two hardware generations were most
/// often seen in.
pub(crate) fn mac_candidates_from_name(name: &str) -> Vec<Moyu32Mac> {
    fn parse_suffix(suffix: &str) -> Option<(u8, u8)> {
        if suffix.len() != 4 || !suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let high = u8::from_str_radix(&suffix[0..2], 16).ok()?;
        let low = u8::from_str_radix(&suffix[2..4], 16).ok()?;
        Some((high, low))
    }

    let name = name.trim();
    let (prefix, middles) = if let Some(rest) = name.strip_prefix("WCU_MY32_") {
        (rest, [0x00u8, 0x01, 0x02])
    } else if let Some(rest) = name.strip_prefix("WCU_MY33_") {
        (rest, [0x02u8, 0x01, 0x00])
    } else {
        return Vec::new();
    };

    let (high, low) = match parse_suffix(prefix) {
        Some(pair) => pair,
        None => return Vec::new(),
    };

    middles
        .iter()
        .map(|middle| [0xCF, 0x30, 0x16, *middle, high, low])
        .collect()
}

/// Parse a `CF:30:16:02:AF:9E` style address.
#[allow(dead_code)]
pub(crate) fn parse_mac(text: &str) -> Option<Moyu32Mac> {
    let parts: Vec<&str> = text.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Render an address for logging.
pub(crate) fn format_mac(mac: &Moyu32Mac) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluetooth::gan::cipher::{MOYU32_BASE_IV, MOYU32_BASE_KEY};

    #[test]
    fn key_derivation_mixes_the_reversed_mac() {
        // The MAC of the captured WCU_MY33_AF9E cube.
        let mac = [0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E];
        let cipher = cipher_for_mac(&mac);

        for i in 0..6 {
            assert_eq!(
                cipher.device_key[i],
                ((MOYU32_BASE_KEY[i] as u16 + mac[5 - i] as u16) % 255) as u8
            );
            assert_eq!(
                cipher.device_iv[i],
                ((MOYU32_BASE_IV[i] as u16 + mac[5 - i] as u16) % 255) as u8
            );
        }
        // Only the first six bytes are mixed.
        assert_eq!(cipher.device_key[6..], MOYU32_BASE_KEY[6..]);
        assert_eq!(cipher.device_iv[6..], MOYU32_BASE_IV[6..]);
    }

    #[test]
    fn cipher_round_trips_a_20_byte_packet() {
        let cipher = cipher_for_mac(&[0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E]);
        let plaintext: Vec<u8> = (0..20u8).collect();
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(cipher.decrypt(&encrypted).unwrap(), plaintext);
    }

    #[test]
    fn a_different_mac_produces_a_different_key() {
        let a = cipher_for_mac(&[0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E]);
        let b = cipher_for_mac(&[0xCF, 0x30, 0x16, 0x00, 0xA3, 0x88]);
        assert_ne!(a.device_key, b.device_key);
        assert_ne!(a.device_iv, b.device_iv);
    }

    #[test]
    fn manufacturer_data_is_read_from_the_end_and_reversed() {
        // A six byte payload, as Chrome hands it over with the company id
        // already stripped.
        assert_eq!(
            mac_from_manufacturer_data(&[0x9E, 0xAF, 0x02, 0x16, 0x30, 0xCF]),
            Some([0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E])
        );
        // The same payload with a company id still attached, which is
        // what the Bluefy DataView path sees.
        assert_eq!(
            mac_from_manufacturer_data(&[0x00, 0x00, 0x9E, 0xAF, 0x02, 0x16, 0x30, 0xCF]),
            Some([0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E])
        );
        // Padding is not an address.
        assert_eq!(mac_from_manufacturer_data(&[0x00; 8]), None);
        assert_eq!(mac_from_manufacturer_data(&[0xFF; 8]), None);
        // Too short.
        assert_eq!(mac_from_manufacturer_data(&[0x01, 0x02, 0x03]), None);
    }

    #[test]
    fn name_derived_candidates_match_the_captured_cubes() {
        assert_eq!(
            mac_candidates_from_name("WCU_MY32_A388"),
            vec![
                [0xCF, 0x30, 0x16, 0x00, 0xA3, 0x88],
                [0xCF, 0x30, 0x16, 0x01, 0xA3, 0x88],
                [0xCF, 0x30, 0x16, 0x02, 0xA3, 0x88],
            ]
        );
        assert_eq!(
            mac_candidates_from_name("WCU_MY33_AF9E"),
            vec![
                [0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E],
                [0xCF, 0x30, 0x16, 0x01, 0xAF, 0x9E],
                [0xCF, 0x30, 0x16, 0x00, 0xAF, 0x9E],
            ]
        );
        // Both captured cubes' real addresses are in their candidate set.
        assert!(mac_candidates_from_name("WCU_MY32_A388")
            .contains(&[0xCF, 0x30, 0x16, 0x00, 0xA3, 0x88]));
        assert!(mac_candidates_from_name("WCU_MY33_AF9E")
            .contains(&[0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E]));
    }

    #[test]
    fn unrecognized_names_produce_no_candidates() {
        assert!(mac_candidates_from_name("WCU_MY32_ZZZZ").is_empty());
        assert!(mac_candidates_from_name("WCU_MY32_A38").is_empty());
        assert!(mac_candidates_from_name("WCU_MY34_A388").is_empty());
        assert!(mac_candidates_from_name("GAN-a1b2c3").is_empty());
        assert!(mac_candidates_from_name("").is_empty());
    }

    #[test]
    fn addresses_round_trip_through_text() {
        let mac = [0xCF, 0x30, 0x16, 0x02, 0xAF, 0x9E];
        assert_eq!(format_mac(&mac), "CF:30:16:02:AF:9E");
        assert_eq!(parse_mac("CF:30:16:02:AF:9E"), Some(mac));
        assert_eq!(parse_mac("cf-30-16-02-af-9e"), Some(mac));
        assert_eq!(parse_mac("CF:30:16:02:AF"), None);
        assert_eq!(parse_mac("nonsense"), None);
    }
}
