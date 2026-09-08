//! Pure QiYi smart cube protocol state machine.
//!
//! This module contains no transport code — no `btleplug`, no `web-sys`.
//! The caller feeds raw (still encrypted) notification bytes in via
//! [`QiyiProtocol::handle_notification`], drains semantic events with
//! [`QiyiProtocol::take_events`] and drains ready-to-write (already
//! encrypted) command packets with [`QiyiProtocol::take_outgoing`].
//!
//! Unlike the GAN Gen3/Gen4 machine, the cipher lives *inside* the
//! protocol rather than in the transport. QiYi uses a single fixed
//! AES-128-ECB key with no per-device derivation and no IV, so there is
//! nothing device-specific for a transport to supply and keeping the
//! crypto here makes the transports trivially thin (and makes the whole
//! wire format, framing and CRC included, unit testable offline).
//!
//! Wire format
//! -----------
//! Every packet in both directions is AES-128-ECB over 16-byte blocks
//! with the key in [`QIYI_KEY`]. The plaintext framing is:
//!
//! ```text
//! FE | len | payload… | crc16/modbus lo | crc16/modbus hi | zero pad to 16
//! ```
//!
//! where `len` counts the header, payload and CRC (i.e. `4 +
//! payload.len()` on the way out). On the way in, the CRC is verified by
//! running CRC16/MODBUS over `msg[..msg[1]]` and checking for zero.
//!
//! Notifications carry an opcode at `msg[2]` and a big-endian device
//! timestamp at `msg[3..7]` in units of 1/1.6 ms:
//!
//! * `0x02` — hello response: full facelet state and battery level.
//!   **Must** be acknowledged or the cube retransmits and stalls.
//! * `0x03` — state change: the current move plus an 11-slot move
//!   history ring, used to recover moves that were dropped in transit.
//! * `0x04` — sync confirmation; the cube is solved.
//! * `CC 10 …` — Tornado V4 gyroscope quaternion. Not framed like the
//!   above (no `FE` header) and not used here, so it is dropped early.
//!
//! The Tornado V4 (`XMD-TornadoV4-i-*`) speaks the identical protocol —
//! it only adds the gyro packets — so both cubes share this one machine.

use crate::common::{Color, Cube, CubeFace, InitialCubeState, Move};
use crate::cube3x3x3::{Cube3x3x3, Cube3x3x3Faces};
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Block,
};
use std::convert::TryFrom;

/// GATT service exposed by both the QiYi Smart Cube and the Tornado V4.
pub(crate) const QIYI_SERVICE_UUID: &str = "0000fff0-0000-1000-8000-00805f9b34fb";

/// The single characteristic used for both notifications and writes.
pub(crate) const QIYI_CHARACTERISTIC_UUID: &str = "0000fff6-0000-1000-8000-00805f9b34fb";

/// Bluetooth company identifier that carries the cube's MAC address in
/// its advertisement manufacturer data.
pub(crate) const QIYI_MANUFACTURER_CIC: u16 = 0x0504;

/// The fixed AES-128 key. Unlike GAN, there is no per-device key
/// derivation and no MAC-dependent salt — every QiYi cube ships with
/// this key, so notifications can be decrypted before the MAC is known.
pub(crate) const QIYI_KEY: [u8; 16] = [
    0x57, 0xB1, 0xF9, 0xAB, 0xCD, 0x5A, 0xE8, 0xA7, 0x9C, 0xB9, 0x8C, 0xE7, 0x57, 0x8C, 0x51, 0x08,
];

/// Advertised name prefixes handled by this driver. Advertised names are
/// space padded (`"QY-QYSC-S-A0E6       "`), so trim before matching.
pub(crate) const QIYI_NAME_PREFIXES: [&str; 2] = ["QY-QYSC", "XMD-TornadoV4-i"];

/// Face order of a Kociemba facelet string: U, R, F, D, L, B.
const FACELET_FACES: [CubeFace; 6] = [
    CubeFace::Top,
    CubeFace::Right,
    CubeFace::Front,
    CubeFace::Bottom,
    CubeFace::Left,
    CubeFace::Back,
];

/// Sticker colors matching [`FACELET_FACES`] on a solved cube.
const FACELET_COLORS: [Color; 6] = [
    Color::White,
    Color::Red,
    Color::Green,
    Color::Yellow,
    Color::Orange,
    Color::Blue,
];

/// Letters matching [`FACELET_FACES`], as used in facelet strings.
const FACELET_CHARS: [u8; 6] = *b"URFDLB";

/// The nibble alphabet the cube packs its facelet state in. Note this is
/// *not* URFDLB order — the nibble value indexes into this string.
const FACELET_NIBBLE_CHARS: [u8; 6] = *b"LRDUFB";

/// A solved cube as a Kociemba facelet string. Used by the replay tests.
#[allow(dead_code)]
pub(crate) const QIYI_SOLVED_FACELETS: &str =
    "UUUUUUUUURRRRRRRRRFFFFFFFFFDDDDDDDDDLLLLLLLLLBBBBBBBBB";

/// Whether [`QiyiProtocol`] should handle a cube with this advertised
/// name. The name is trimmed first because the cubes pad theirs with
/// spaces to a fixed advertisement length.
pub(crate) fn is_qiyi_device_name(name: &str) -> bool {
    let name = name.trim();
    QIYI_NAME_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// CRC16/MODBUS (polynomial 0xA001 reflected, initial value 0xFFFF).
pub(crate) fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in data {
        crc ^= *byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// AES-128-ECB over whole 16-byte blocks. Trailing bytes that do not
/// fill a block are dropped, matching the reference implementations.
#[derive(Clone)]
pub(crate) struct QiyiCipher {
    aes: Aes128,
}

impl QiyiCipher {
    pub(crate) fn new() -> Self {
        Self {
            aes: Aes128::new_from_slice(&QIYI_KEY).unwrap(),
        }
    }

    pub(crate) fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() / 16 * 16);
        for chunk in data.chunks_exact(16) {
            let mut block = Block::from(<[u8; 16]>::try_from(chunk).unwrap());
            self.aes.decrypt_block(&mut block);
            out.extend_from_slice(&block);
        }
        out
    }

    pub(crate) fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() / 16 * 16);
        for chunk in data.chunks_exact(16) {
            let mut block = Block::from(<[u8; 16]>::try_from(chunk).unwrap());
            self.aes.encrypt_block(&mut block);
            out.extend_from_slice(&block);
        }
        out
    }
}

/// Frame `payload` (`FE | len | payload | crc | pad`) and encrypt it,
/// producing bytes ready to write to the cube characteristic.
pub(crate) fn build_message(cipher: &QiyiCipher, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(payload.len() + 20);
    msg.push(0xFE);
    msg.push((4 + payload.len()) as u8);
    msg.extend_from_slice(payload);
    let crc = crc16_modbus(&msg);
    msg.push((crc & 0xFF) as u8);
    msg.push((crc >> 8) as u8);
    while msg.len() % 16 != 0 {
        msg.push(0);
    }
    cipher.encrypt(&msg)
}

/// Read the cube's MAC out of advertisement manufacturer data for
/// company identifier [`QIYI_MANUFACTURER_CIC`]. The address is the
/// first six bytes of the payload, least significant byte first.
pub(crate) fn mac_from_manufacturer_data(data: &[u8]) -> Option<[u8; 6]> {
    if data.len() < 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = data[5 - i];
    }
    Some(mac)
}

/// Derive candidate MAC addresses from an advertised device name, for
/// cubes whose advertisement manufacturer data could not be captured
/// (Web Bluetooth on browsers without `watchAdvertisements`, mostly).
///
/// The QiYi firmware derives the advertised name suffix from the last
/// two bytes of the address, and each hardware line uses a fixed prefix.
/// The `QY-QYSC-S` line ships with two known prefixes, newest first.
pub(crate) fn mac_candidates_from_device_name(name: &str) -> Vec<[u8; 6]> {
    fn suffix(name: &str, prefix: &str) -> Option<[u8; 2]> {
        let rest = name.strip_prefix(prefix)?;
        if rest.len() != 4 || !rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let hi = u8::from_str_radix(&rest[0..2], 16).ok()?;
        let lo = u8::from_str_radix(&rest[2..4], 16).ok()?;
        Some([hi, lo])
    }

    let name = name.trim();
    if let Some(s) = suffix(name, "QY-QYSC-A-") {
        return vec![[0xCC, 0xA2, 0x00, 0x00, s[0], s[1]]];
    }
    if let Some(s) = suffix(name, "QY-QYSC-S-") {
        return vec![
            [0xCC, 0xA3, 0x00, 0x00, s[0], s[1]],
            [0xCC, 0xA3, 0x00, 0x01, s[0], s[1]],
        ];
    }
    if let Some(s) = suffix(name, "XMD-TornadoV4-i-") {
        return vec![[0xCC, 0xA6, 0x00, 0x00, s[0], s[1]]];
    }
    Vec::new()
}

/// Decode the cube's 27-byte nibble-packed facelet block into a
/// Kociemba facelet string in URFDLB order.
pub(crate) fn parse_facelets(packed: &[u8]) -> Option<String> {
    if packed.len() < 27 {
        return None;
    }
    let mut out = String::with_capacity(54);
    for i in 0..54 {
        let nibble = (packed[i >> 1] >> ((i % 2) << 2)) & 0x0F;
        if nibble >= 6 {
            return None;
        }
        out.push(FACELET_NIBBLE_CHARS[nibble as usize] as char);
    }
    Some(out)
}

/// Convert a Kociemba facelet string into the crate's piece-based cube
/// representation. Returns `None` if the string is malformed or does not
/// use each color exactly nine times.
pub(crate) fn facelets_to_cube(facelets: &str) -> Option<Cube3x3x3> {
    let bytes = facelets.as_bytes();
    if bytes.len() != 54 {
        return None;
    }
    let mut counts = [0usize; 6];
    let mut colors = [Color::White; 6 * 9];
    for (i, byte) in bytes.iter().enumerate() {
        let color_idx = FACELET_CHARS.iter().position(|c| c == byte)?;
        counts[color_idx] += 1;
        // The crate's face array is ordered by `CubeFace` (Top, Front,
        // Right, Back, Left, Bottom) while facelet strings are URFDLB.
        // Within a face both use the same row-major ordering.
        let target = FACELET_FACES[i / 9] as u8 as usize * 9 + (i % 9);
        colors[target] = FACELET_COLORS[color_idx];
    }
    if counts.iter().any(|c| *c != 9) {
        return None;
    }
    Some(Cube3x3x3Faces::from_colors(colors).as_pieces())
}

/// Render a cube as a Kociemba facelet string. Inverse of
/// [`facelets_to_cube`]; used by the replay tests to compare decoded
/// states against the reference implementation's event log.
#[allow(dead_code)]
pub(crate) fn cube_to_facelets(cube: &Cube3x3x3) -> String {
    let faces = cube.as_faces();
    let mut out = String::with_capacity(54);
    for i in 0..54 {
        let color = faces.color(FACELET_FACES[i / 9], (i % 9) / 3, i % 3);
        let idx = FACELET_COLORS.iter().position(|c| *c == color).unwrap();
        out.push(FACELET_CHARS[idx] as char);
    }
    out
}

/// Decode a move code from a state change packet. Codes run 1..=12 as
/// (counterclockwise, clockwise) pairs over a permuted face order.
pub(crate) fn decode_move(code: u8) -> Option<Move> {
    if code < 1 || code > 12 {
        return None;
    }
    // The cube's own face order is LRDUFB; this table maps a code pair
    // to an index into URFDLB.
    const AXIS: [usize; 6] = [4, 1, 3, 0, 2, 5];
    let axis = AXIS[((code - 1) >> 1) as usize];
    // Odd codes are counterclockwise, even codes clockwise.
    let rotation = if code & 1 == 1 { -1 } else { 1 };
    Move::from_face_and_rotation(FACELET_FACES[axis], rotation)
}

/// Convert a device timestamp (units of 1/1.6 ms) to milliseconds.
fn device_ticks_to_ms(ticks: u32) -> u32 {
    // 1 / 1.6 == 5 / 8 exactly, so this matches a floating point
    // divide-and-truncate without rounding error.
    (ticks as u64 * 5 / 8) as u32
}

fn read_be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// A single decoded move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QiyiMove {
    pub(crate) mv: Move,
    /// Milliseconds since the previously delivered move. Zero for the
    /// first move of a session, matching the GAN drivers.
    pub(crate) delta_ms: u32,
    /// Absolute cube-clock timestamp in milliseconds. Exposed mainly so
    /// the replay tests can check it against captured traffic.
    pub(crate) cube_timestamp_ms: u32,
}

/// A semantic event parsed out of the QiYi wire protocol.
#[derive(Debug, Clone)]
pub(crate) enum QiyiEvent {
    /// The cube reported its complete state (hello response or sync
    /// confirmation). The local state should be replaced with this.
    Facelets(Cube3x3x3),
    /// A move, along with the cube state after applying it.
    Move { mv: QiyiMove, state: Cube3x3x3 },
    /// Battery charge, 0..=100.
    Battery(u32),
}

/// An outgoing packet. Already framed, CRC'd, padded and encrypted — the
/// transport only has to write the bytes.
#[derive(Debug, Clone)]
pub(crate) struct QiyiOutMessage {
    pub(crate) bytes: Vec<u8>,
}

/// The QiYi protocol state machine.
pub(crate) struct QiyiProtocol {
    cipher: QiyiCipher,
    mac: [u8; 6],
    state: Cube3x3x3,
    state_set: bool,
    /// Device timestamp of the last accepted event, in raw ticks. Used
    /// to reject history slots that have already been delivered.
    last_timestamp: u32,
    /// Cube clock of the last delivered move, in milliseconds.
    last_move_ms: Option<u32>,
    battery_percentage: Option<u32>,
    events: Vec<QiyiEvent>,
    outgoing: Vec<QiyiOutMessage>,
}

impl QiyiProtocol {
    /// Hello payload. The trailing six bytes are the cube's own MAC in
    /// reverse order; the cube refuses to answer without them.
    const HELLO_PREFIX: [u8; 11] = [
        0x00, 0x6B, 0x01, 0x00, 0x00, 0x22, 0x06, 0x00, 0x02, 0x08, 0x00,
    ];

    pub(crate) fn new(mac: [u8; 6]) -> Self {
        Self {
            cipher: QiyiCipher::new(),
            mac,
            state: Cube3x3x3::new(),
            state_set: false,
            last_timestamp: 0,
            last_move_ms: None,
            battery_percentage: None,
            events: Vec::new(),
            outgoing: Vec::new(),
        }
    }

    pub(crate) fn state(&self) -> Cube3x3x3 {
        self.state.clone()
    }

    pub(crate) fn state_set(&self) -> bool {
        self.state_set
    }

    pub(crate) fn battery_percentage(&self) -> Option<u32> {
        self.battery_percentage
    }

    /// Reset the tracked state to solved. The cube itself has no reset
    /// command, so callers should follow this with a hello to resync.
    pub(crate) fn reset_state(&mut self) {
        self.state = Cube3x3x3::new();
    }

    pub(crate) fn take_events(&mut self) -> Vec<QiyiEvent> {
        std::mem::take(&mut self.events)
    }

    pub(crate) fn take_outgoing(&mut self) -> Vec<QiyiOutMessage> {
        std::mem::take(&mut self.outgoing)
    }

    /// Build the hello packet, which asks the cube for its full state
    /// and battery level. This is also the only way to resync.
    pub(crate) fn hello_message(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(17);
        payload.extend_from_slice(&Self::HELLO_PREFIX);
        for i in (0..6).rev() {
            payload.push(self.mac[i]);
        }
        build_message(&self.cipher, &payload)
    }

    /// Handle one raw (encrypted) notification from the cube.
    pub(crate) fn handle_notification(&mut self, raw: &[u8]) {
        if raw.len() < 16 {
            return;
        }
        let msg = self.cipher.decrypt(raw);

        // Tornado V4 gyroscope quaternions. They use a different framing
        // and carry no cube state, so drop them before the CRC check.
        if msg.len() >= 2 && msg[0] == 0xCC && msg[1] == 0x10 {
            return;
        }

        if msg.len() < 2 {
            return;
        }
        let len = msg[1] as usize;
        if len < 7 || len > msg.len() {
            return;
        }
        let msg = &msg[..len];
        if crc16_modbus(msg) != 0 || msg[0] != 0xFE {
            return;
        }

        let opcode = msg[2];
        let timestamp = read_be_u32(msg, 3);
        match opcode {
            0x02 => self.handle_hello_response(msg, timestamp),
            0x03 => self.handle_state_change(msg, timestamp),
            0x04 => self.handle_sync_confirm(msg, timestamp),
            // Anything else is left alone, and in particular does not
            // advance `last_timestamp` — doing so would silently drop
            // moves from a later history slot.
            _ => (),
        }
    }

    /// Acknowledge a packet by echoing its opcode and timestamp back.
    /// The cube retransmits and eventually stops sending updates
    /// entirely if these are skipped, so they are not optional.
    fn acknowledge(&mut self, msg: &[u8]) {
        self.outgoing.push(QiyiOutMessage {
            bytes: build_message(&self.cipher, &msg[2..7]),
        });
    }

    fn handle_hello_response(&mut self, msg: &[u8], timestamp: u32) {
        self.acknowledge(msg);

        // Facelets occupy msg[7..34] and the battery level msg[35].
        if msg.len() < 36 {
            return;
        }
        if let Some(cube) = parse_facelets(&msg[7..34]).and_then(|f| facelets_to_cube(&f)) {
            self.state = cube.clone();
            self.state_set = true;
            self.events.push(QiyiEvent::Facelets(cube));
        }
        self.set_battery(msg[35]);
        self.last_timestamp = timestamp;
    }

    fn handle_state_change(&mut self, msg: &[u8], timestamp: u32) {
        // The cube sets msg[91] when it wants the packet acknowledged.
        if msg.len() > 91 && msg[91] != 0 {
            self.acknowledge(msg);
        }

        // The current move plus an 11-slot history ring. The ring lets
        // us recover moves whose own notification was lost; empty slots
        // are all-0xFF.
        let mut candidates: Vec<(u8, u32)> = Vec::with_capacity(12);
        if msg.len() > 34 {
            candidates.push((msg[34], timestamp));
        }
        for i in 0..11 {
            let offset = 36 + 5 * i;
            if offset + 5 > msg.len() {
                break;
            }
            if msg[offset..offset + 5].iter().all(|b| *b == 0xFF) {
                continue;
            }
            candidates.push((msg[offset + 4], read_be_u32(msg, offset)));
        }

        // Oldest first, then drop repeats — the current move is usually
        // also present in the history ring.
        candidates.sort_by_key(|(_, ts)| *ts);
        let mut seen: Vec<(u8, u32)> = Vec::with_capacity(candidates.len());
        candidates.retain(|entry| {
            if seen.contains(entry) {
                false
            } else {
                seen.push(*entry);
                true
            }
        });

        let mut newest = None;
        for (code, ts) in candidates {
            if ts <= self.last_timestamp {
                continue;
            }
            let mv = match decode_move(code) {
                Some(mv) => mv,
                None => continue,
            };
            newest = Some(ts);

            let cube_timestamp_ms = device_ticks_to_ms(ts);
            let delta_ms = match self.last_move_ms {
                Some(prev) => cube_timestamp_ms.saturating_sub(prev),
                None => 0,
            };
            self.last_move_ms = Some(cube_timestamp_ms);

            self.state.do_move(mv);
            self.events.push(QiyiEvent::Move {
                mv: QiyiMove {
                    mv,
                    delta_ms,
                    cube_timestamp_ms,
                },
                state: self.state.clone(),
            });
        }
        if let Some(ts) = newest {
            self.last_timestamp = ts;
        }

        if msg.len() > 35 {
            self.set_battery(msg[35]);
        }
    }

    fn handle_sync_confirm(&mut self, msg: &[u8], timestamp: u32) {
        // Only a full-length sync confirmation means "solved".
        if msg[1] != 38 {
            return;
        }
        self.state = Cube3x3x3::new();
        self.state_set = true;
        self.last_timestamp = timestamp;
        self.events.push(QiyiEvent::Facelets(self.state.clone()));
    }

    fn set_battery(&mut self, raw: u8) {
        let level = (raw as u32).min(100);
        if self.battery_percentage != Some(level) {
            self.battery_percentage = Some(level);
            self.events.push(QiyiEvent::Battery(level));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const QYSC_FIXTURE: &str = include_str!("testdata/fixture_qiyi_qysc.json");
    const TORNADO_FIXTURE: &str = include_str!("testdata/fixture_tornado_v4.json");

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Captured hex is uppercase for writes and lowercase for
    /// notifications, so normalize before comparing.
    fn normalize_hex(s: &str) -> String {
        s.to_ascii_lowercase()
    }

    fn parse_mac(s: &str) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for (i, part) in s.split(':').enumerate() {
            mac[i] = u8::from_str_radix(part, 16).unwrap();
        }
        mac
    }

    #[test]
    fn device_names_are_recognized_after_trimming() {
        // Advertised names are space padded to a fixed length.
        assert!(is_qiyi_device_name("QY-QYSC-S-A0E6       "));
        assert!(is_qiyi_device_name("QY-QYSC-A-1234"));
        assert!(is_qiyi_device_name("XMD-TornadoV4-i-034C "));
        assert!(!is_qiyi_device_name("XMD-TornadoV3-034C"));
        assert!(!is_qiyi_device_name("GAN-a1b2c3"));
        assert!(!is_qiyi_device_name(""));
    }

    #[test]
    fn crc16_modbus_matches_known_vectors() {
        assert_eq!(crc16_modbus(b""), 0xFFFF);
        assert_eq!(crc16_modbus(b"123456789"), 0x4B37);
        // A frame including its own trailing CRC checks out to zero;
        // this is how received packets are validated.
        let mut framed = vec![0xFE, 0x09, 0x02, 0x00, 0x01, 0xB8, 0x87];
        let crc = crc16_modbus(&framed);
        framed.push((crc & 0xFF) as u8);
        framed.push((crc >> 8) as u8);
        assert_eq!(crc16_modbus(&framed), 0);
    }

    #[test]
    fn cipher_round_trips() {
        let cipher = QiyiCipher::new();
        let plain: Vec<u8> = (0..32u8).collect();
        let encrypted = cipher.encrypt(&plain);
        assert_ne!(encrypted, plain);
        assert_eq!(cipher.decrypt(&encrypted), plain);
        // Partial trailing blocks are dropped, not padded.
        assert_eq!(cipher.encrypt(&plain[..20]).len(), 16);
    }

    #[test]
    fn mac_candidates_follow_the_hardware_line_prefixes() {
        assert_eq!(
            mac_candidates_from_device_name("QY-QYSC-A-1234"),
            vec![[0xCC, 0xA2, 0x00, 0x00, 0x12, 0x34]]
        );
        assert_eq!(
            mac_candidates_from_device_name("QY-QYSC-S-A0E6       "),
            vec![
                [0xCC, 0xA3, 0x00, 0x00, 0xA0, 0xE6],
                [0xCC, 0xA3, 0x00, 0x01, 0xA0, 0xE6],
            ]
        );
        assert_eq!(
            mac_candidates_from_device_name("XMD-TornadoV4-i-034C "),
            vec![[0xCC, 0xA6, 0x00, 0x00, 0x03, 0x4C]]
        );
        assert!(mac_candidates_from_device_name("QY-QYSC-S-ZZZZ").is_empty());
        assert!(mac_candidates_from_device_name("GAN-a1b2c3").is_empty());
    }

    #[test]
    fn manufacturer_data_mac_is_byte_reversed() {
        let data = [0xE6, 0xA0, 0x00, 0x00, 0xA3, 0xCC, 0x11, 0x22];
        assert_eq!(
            mac_from_manufacturer_data(&data),
            Some([0xCC, 0xA3, 0x00, 0x00, 0xA0, 0xE6])
        );
        assert_eq!(mac_from_manufacturer_data(&data[..5]), None);
    }

    #[test]
    fn facelets_round_trip_through_the_piece_representation() {
        let solved = facelets_to_cube(QIYI_SOLVED_FACELETS).unwrap();
        assert!(solved.is_solved());
        assert_eq!(cube_to_facelets(&solved), QIYI_SOLVED_FACELETS);

        // A scrambled state must survive the round trip too, which is
        // what pins down the URFDLB-to-CubeFace mapping.
        let mut cube = Cube3x3x3::new();
        cube.do_moves(&[Move::R, Move::U, Move::Rp, Move::Up, Move::F, Move::B2]);
        let facelets = cube_to_facelets(&cube);
        assert_eq!(facelets_to_cube(&facelets).unwrap(), cube);

        assert_eq!(facelets_to_cube("bogus"), None);
        // Right length, wrong color counts.
        assert_eq!(facelets_to_cube(&"U".repeat(54)), None);
    }

    #[test]
    fn move_codes_decode_to_the_documented_faces() {
        assert_eq!(decode_move(1), Some(Move::Lp));
        assert_eq!(decode_move(2), Some(Move::L));
        assert_eq!(decode_move(3), Some(Move::Rp));
        assert_eq!(decode_move(4), Some(Move::R));
        assert_eq!(decode_move(5), Some(Move::Dp));
        assert_eq!(decode_move(6), Some(Move::D));
        assert_eq!(decode_move(7), Some(Move::Up));
        assert_eq!(decode_move(8), Some(Move::U));
        assert_eq!(decode_move(9), Some(Move::Fp));
        assert_eq!(decode_move(10), Some(Move::F));
        assert_eq!(decode_move(11), Some(Move::Bp));
        assert_eq!(decode_move(12), Some(Move::B));
        assert_eq!(decode_move(0), None);
        assert_eq!(decode_move(13), None);
        assert_eq!(decode_move(0xFF), None);
    }

    #[test]
    fn hello_message_matches_captured_traffic() {
        // The first write in each capture is the hello. Byte-for-byte
        // equality proves framing, CRC, padding, MAC order and the key.
        for fixture in [QYSC_FIXTURE, TORNADO_FIXTURE] {
            let capture: Value = serde_json::from_str(fixture).unwrap();
            let mac = parse_mac(capture["device"]["mac"].as_str().unwrap());
            let protocol = QiyiProtocol::new(mac);
            let first_write = capture["traffic"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["op"] == "write")
                .unwrap()["data"]
                .as_str()
                .unwrap();
            assert_eq!(
                bytes_to_hex(&protocol.hello_message()),
                normalize_hex(first_write)
            );
        }
    }

    /// Replay a capture through the protocol machine and compare the
    /// decoded moves, facelets, battery level and outgoing ACKs against
    /// what the reference implementation produced live.
    fn replay(fixture: &str) -> (usize, usize) {
        let capture: Value = serde_json::from_str(fixture).unwrap();
        let mac = parse_mac(capture["device"]["mac"].as_str().unwrap());
        let mut protocol = QiyiProtocol::new(mac);

        let mut got_moves: Vec<(String, u32)> = Vec::new();
        let mut got_facelets: Vec<String> = Vec::new();
        let mut got_acks: Vec<String> = Vec::new();
        let mut battery = None;
        let mut notifications = 0;

        for entry in capture["traffic"].as_array().unwrap() {
            if entry["op"] != "notify" {
                continue;
            }
            notifications += 1;
            protocol.handle_notification(&hex_to_bytes(entry["data"].as_str().unwrap()));

            for event in protocol.take_events() {
                match event {
                    QiyiEvent::Facelets(state) => got_facelets.push(cube_to_facelets(&state)),
                    QiyiEvent::Move { mv, state } => {
                        got_moves.push((mv.mv.to_string(), mv.cube_timestamp_ms));
                        got_facelets.push(cube_to_facelets(&state));
                    }
                    QiyiEvent::Battery(level) => battery = Some(level),
                }
            }
            for out in protocol.take_outgoing() {
                got_acks.push(bytes_to_hex(&out.bytes));
            }
        }

        // Expected values, from the reference implementation's own event
        // log recorded alongside the traffic.
        let events = capture["events"].as_array().unwrap();
        let want_moves: Vec<(String, u32)> = events
            .iter()
            .filter(|e| e["event"]["type"] == "MOVE")
            .map(|e| {
                (
                    e["event"]["move"].as_str().unwrap().to_string(),
                    e["event"]["cubeTimestamp"].as_u64().unwrap() as u32,
                )
            })
            .collect();
        let want_facelets: Vec<String> = events
            .iter()
            .filter(|e| e["event"]["type"] == "FACELETS")
            .map(|e| e["event"]["facelets"].as_str().unwrap().to_string())
            .collect();
        let want_battery = events
            .iter()
            .find(|e| e["event"]["type"] == "BATTERY")
            .map(|e| e["event"]["batteryLevel"].as_u64().unwrap() as u32);

        assert_eq!(want_moves.len(), 30, "fixture should hold two sledgehammers");
        assert_eq!(got_moves, want_moves);
        assert_eq!(battery, want_battery);

        // The event log in both captures starts a few hundred
        // milliseconds after the traffic log, so it is missing the
        // FACELETS event for the very first hello response. Everything
        // from there on must line up exactly, and the events we emit
        // ahead of the log are the same solved state.
        assert!(got_facelets.len() >= want_facelets.len());
        let skew = got_facelets.len() - want_facelets.len();
        assert_eq!(skew, 1);
        for extra in &got_facelets[..skew] {
            assert_eq!(extra, QIYI_SOLVED_FACELETS);
        }
        assert_eq!(&got_facelets[skew..], &want_facelets[..]);

        // Acknowledgements are mandatory: every hello response plus any
        // state change that sets the ack flag. Compare against the
        // acknowledgement writes in the capture (the other writes are
        // application-driven hello resends, which the protocol machine
        // does not generate on its own).
        let want_acks: Vec<String> = capture["traffic"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["op"] == "write")
            .map(|t| normalize_hex(t["data"].as_str().unwrap()))
            .filter(|data| {
                let cipher = QiyiCipher::new();
                cipher.decrypt(&hex_to_bytes(data))[1] == 9
            })
            .collect();
        assert!(!want_acks.is_empty());
        assert_eq!(got_acks, want_acks);

        (notifications, got_moves.len())
    }

    #[test]
    fn qiyi_smart_cube_capture_replays() {
        let (notifications, moves) = replay(QYSC_FIXTURE);
        assert_eq!(notifications, 34);
        assert_eq!(moves, 30);
    }

    #[test]
    fn tornado_v4_capture_replays_and_skips_gyro_packets() {
        // The Tornado V4 interleaves gyroscope quaternion packets with
        // cube data. They must be dropped without disturbing the state
        // machine: 248 notifications carry the same 30 moves.
        let (notifications, moves) = replay(TORNADO_FIXTURE);
        assert_eq!(notifications, 248);
        assert_eq!(moves, 30);

        // Sanity check that the capture really does contain gyro
        // packets, so the assertion above is not vacuous.
        let capture: Value = serde_json::from_str(TORNADO_FIXTURE).unwrap();
        let cipher = QiyiCipher::new();
        let gyro = capture["traffic"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["op"] == "notify")
            .filter(|t| {
                let plain = cipher.decrypt(&hex_to_bytes(t["data"].as_str().unwrap()));
                plain.len() >= 2 && plain[0] == 0xCC && plain[1] == 0x10
            })
            .count();
        assert_eq!(gyro, 214);
    }

    #[test]
    fn garbage_notifications_are_ignored() {
        let mut protocol = QiyiProtocol::new([0xCC, 0xA3, 0x00, 0x00, 0xA0, 0xE6]);
        // Too short to be a block.
        protocol.handle_notification(&[0u8; 8]);
        // Decrypts to noise, so the CRC check rejects it.
        protocol.handle_notification(&[0x5Au8; 16]);
        assert!(protocol.take_events().is_empty());
        assert!(protocol.take_outgoing().is_empty());
        assert!(!protocol.state_set());
        assert!(protocol.state().is_solved());
    }
}
