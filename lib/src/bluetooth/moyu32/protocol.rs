//! Pure MoYu32 protocol state machine.
//!
//! "MoYu32" is the protocol spoken by the MoYu WeiLong V10 AI and V11 AI
//! cubes, which advertise as `WCU_MY32_xxxx` / `WCU_MY33_xxxx`. It is
//! completely unrelated to the older `MHC-` MoYu AI protocol in
//! `bluetooth/moyu.rs` and to the GAN Gen2 protocol that MoYu's `AiCube`
//! line borrows — the only thing it shares with GAN is the shape of the
//! AES construction (see `moyu32/cipher.rs`).
//!
//! This module contains no transport code. The caller decrypts a raw
//! notification with the cipher, feeds the plaintext to
//! `handle_decrypted`, then drains semantic events with `take_events()`
//! and outgoing (plaintext) command packets with `take_outgoing()`. The
//! seam is "plaintext bytes in, parsed events + command bytes out", so
//! both the btleplug and web-sys transports share this one state machine
//! and it can be exercised offline against captured traffic (see
//! `moyu32/replay.rs`).
//!
//! Wire format — every packet is exactly 20 bytes, opcode in byte 0:
//!
//! * `0xA1` hardware info: bytes 1..9 ASCII product name, bytes 9/10
//!   software major/minor, bytes 11/12 hardware major/minor.
//! * `0xA3` facelets: bits 8..152 are 48 facelets of 3 bits each, laid
//!   out as six 24-bit faces in `F B U D L R` order; byte 19 is the move
//!   counter the state corresponds to.
//! * `0xA4` battery: byte 1 is the percentage.
//! * `0xA5` move: byte 11 is the 8-bit move counter, bytes 1..11 are five
//!   big-endian `u16` inter-move times in ms, and bits 96.. hold five
//!   5-bit move codes. Both arrays are newest-first, so the moves that
//!   are actually new are replayed from index `count - 1` down to 0.
//! * `0xAB` gyro quaternion — ignored, tpscube has no use for it.
//! * `0xAC` gyro-enable acknowledgement — ignored.

use crate::bluetooth::gan::gen34_protocol::extract_bits;
use crate::common::{Color, Cube, CubeFace, InitialCubeState, Move, TimedMove};
use crate::cube3x3x3::{Cube3x3x3, Cube3x3x3Faces};

/// GATT service exposed by `WCU_MY3*` cubes.
pub(crate) const MOYU32_SERVICE_UUID: &str = "0783b03e-7735-b5a0-1760-a305d2795cb0";
/// Notification (cube -> host) characteristic.
pub(crate) const MOYU32_NOTIFY_UUID: &str = "0783b03e-7735-b5a0-1760-a305d2795cb1";
/// Command (host -> cube) characteristic.
pub(crate) const MOYU32_WRITE_UUID: &str = "0783b03e-7735-b5a0-1760-a305d2795cb2";

/// Every packet in both directions is exactly this long.
pub(crate) const MOYU32_PACKET_LEN: usize = 20;

pub(crate) const OP_HARDWARE: u8 = 0xA1;
pub(crate) const OP_FACELETS: u8 = 0xA3;
pub(crate) const OP_BATTERY: u8 = 0xA4;
pub(crate) const OP_MOVE: u8 = 0xA5;
pub(crate) const OP_GYRO: u8 = 0xAB;
pub(crate) const OP_GYRO_ENABLE: u8 = 0xAC;

/// The cube reports at most five moves per `0xA5` packet, so a gap larger
/// than this means notifications were dropped and the tracked cube state
/// can no longer be trusted.
const MAX_MOVES_PER_PACKET: usize = 5;

/// A semantic event parsed out of the MoYu32 wire protocol.
#[derive(Debug, Clone)]
pub(crate) enum Moyu32Event {
    /// A single delivered move plus the cube state after applying it.
    /// Kept as a `Vec` to match `BluetoothCubeEvent::Move`.
    Move {
        moves: Vec<TimedMove>,
        state: Cube3x3x3,
    },
    /// A full cube state snapshot arrived (`0xA3`).
    Facelets(Cube3x3x3),
    /// Battery percentage (0..=100).
    Battery(u32),
    /// Product name and firmware versions (`0xA1`).
    Hardware {
        name: String,
        software_version: String,
        hardware_version: String,
    },
    /// More moves happened than the cube can report in one packet, so the
    /// tracked state has diverged from the physical cube. The protocol
    /// automatically queues a facelets request to recover.
    SyncLost,
}

/// An outgoing command packet. The bytes are **plaintext**; the transport
/// encrypts them before writing, exactly like `Gen34OutMessage`.
#[derive(Debug, Clone)]
pub(crate) struct Moyu32OutMessage {
    pub(crate) bytes: Vec<u8>,
}

/// Build a 20-byte zero-padded command with `opcode` in byte 0. Every
/// MoYu32 request except the gyro enable has this shape.
pub(crate) fn build_simple_request(opcode: u8) -> Vec<u8> {
    let mut cmd = vec![0u8; MOYU32_PACKET_LEN];
    cmd[0] = opcode;
    cmd
}

/// Build the "start sending gyro quaternions" command. We send this
/// because some firmware revisions do not begin steady-state status
/// notifications until they have seen it, not because we want the gyro
/// data (`0xAB` packets are dropped).
pub(crate) fn build_gyro_enable() -> Vec<u8> {
    let mut cmd = vec![0u8; MOYU32_PACKET_LEN];
    cmd[0] = OP_GYRO_ENABLE;
    cmd[2] = 0x01;
    cmd
}

/// The initialization burst, in order. The `0xA1`/`0xA3`/`0xA4` triple is
/// deliberately sent twice: some MoYu32 firmware ignores the first burst
/// and never starts sending move notifications. The trailing `0xA3`
/// re-reads the state after the gyro enable, which can itself perturb the
/// notification stream.
pub(crate) fn build_init_sequence() -> Vec<Vec<u8>> {
    vec![
        build_simple_request(OP_HARDWARE),
        build_simple_request(OP_FACELETS),
        build_simple_request(OP_BATTERY),
        build_simple_request(OP_HARDWARE),
        build_simple_request(OP_FACELETS),
        build_simple_request(OP_BATTERY),
        build_gyro_enable(),
        build_simple_request(OP_FACELETS),
    ]
}

/// Decode a 5-bit move code. The low bit is the direction and the rest
/// indexes the cube's own `F B U D L R` face order. Codes >= 12 mark an
/// empty history slot.
fn decode_move(code: u8) -> Option<Move> {
    const FACES: [(Move, Move); 6] = [
        (Move::F, Move::Fp),
        (Move::B, Move::Bp),
        (Move::U, Move::Up),
        (Move::D, Move::Dp),
        (Move::L, Move::Lp),
        (Move::R, Move::Rp),
    ];
    if code >= 12 {
        return None;
    }
    let (cw, ccw) = FACES[(code >> 1) as usize];
    Some(if code & 1 == 0 { cw } else { ccw })
}

/// Decode the 48 facelets of a `0xA3` packet into a cube state.
///
/// The packet stores six 24-bit faces in `F B U D L R` order, each face
/// being its eight non-center stickers in row-major order, and each
/// sticker a 3-bit color index into that same `F B U D L R` alphabet.
/// Returns `None` if the packet does not describe a well-formed coloring,
/// which is also what makes this usable as a decryption sanity check.
pub(crate) fn decode_facelets(packet: &[u8]) -> Option<Cube3x3x3> {
    if packet.len() < MOYU32_PACKET_LEN {
        return None;
    }

    // Packet face order F B U D L R mapped into tpscube's face enum, and
    // the color each of those indices names.
    const FACES: [CubeFace; 6] = [
        CubeFace::Front,
        CubeFace::Back,
        CubeFace::Top,
        CubeFace::Bottom,
        CubeFace::Left,
        CubeFace::Right,
    ];
    const COLORS: [Color; 6] = [
        Color::Green,
        Color::Blue,
        Color::White,
        Color::Yellow,
        Color::Orange,
        Color::Red,
    ];

    let mut state: [Color; 6 * 9] = [Color::White; 6 * 9];
    let mut counts = [0usize; 6];

    for face in 0..6 {
        let target = FACES[face] as u8 as usize;

        // The center sticker is implied by the face itself.
        state[target * 9 + 4] = COLORS[face];
        counts[face] += 1;

        let mut offset = target * 9;
        for i in 0..8 {
            if i == 4 {
                // Skip the center, which is not present in the packet.
                offset += 1;
            }
            let color = extract_bits(packet, 8 + face * 24 + i * 3, 3) as usize;
            if color >= 6 {
                return None;
            }
            state[offset] = COLORS[color];
            counts[color] += 1;
            offset += 1;
        }
    }

    if counts.iter().any(|count| *count != 9) {
        return None;
    }

    Some(Cube3x3x3Faces::from_colors(state).as_pieces())
}

/// Heuristic check that a decrypted packet really is MoYu32 traffic.
///
/// Used when the cube's MAC address (and therefore the AES key) has to be
/// guessed: connect with a candidate key, prod the cube, and see whether
/// the notifications decrypt to something structurally plausible. Ported
/// from the reference implementation's `isValidMoYu32DecryptedPacket` so
/// the same candidate set converges on the same answer.
pub(crate) fn packet_looks_valid(packet: &[u8]) -> bool {
    if packet.len() < MOYU32_PACKET_LEN {
        return false;
    }
    let head = &packet[..MOYU32_PACKET_LEN];

    // Reject the degenerate outputs of a wrong key: mostly 0x00, mostly
    // 0xFF, or high-entropy noise with almost no repeated bytes.
    let zeros = head.iter().filter(|b| **b == 0x00).count();
    let ones = head.iter().filter(|b| **b == 0xFF).count();
    let mut seen = [false; 256];
    let mut distinct = 0;
    for byte in head {
        if !seen[*byte as usize] {
            seen[*byte as usize] = true;
            distinct += 1;
        }
    }
    if zeros > 14 || ones > 14 || distinct > 18 {
        return false;
    }

    match head[0] {
        OP_HARDWARE => head[1..9]
            .iter()
            .all(|b| *b == 0 || (*b >= 0x20 && *b <= 0x7E)),
        OP_BATTERY => head[1] <= 100,
        OP_FACELETS => {
            // A wrong key gives a body that is nearly all zeros or all
            // ones far more often than a real state does.
            let body_bits: u32 = head[1..19].iter().map(|b| b.count_ones()).sum();
            let total = 18 * 8;
            body_bits * 10 >= total && body_bits * 10 <= total * 9
        }
        OP_MOVE => {
            let mut valid_moves = 0;
            for i in 0..MAX_MOVES_PER_PACKET {
                let code = extract_bits(head, 96 + i * 5, 5) as u8;
                if code <= 11 {
                    valid_moves += 1;
                } else if code < 31 {
                    // Neither a real move nor the 0x1F empty-slot filler.
                    return false;
                }
            }
            if valid_moves == 0 {
                return false;
            }
            // The inter-move times for the populated slots must not be
            // uniformly 0x0000 or 0xFFFF.
            let times: Vec<u16> = (0..valid_moves)
                .map(|i| u16::from_be_bytes([head[1 + i * 2], head[2 + i * 2]]))
                .collect();
            !times.iter().all(|t| *t == 0) && !times.iter().all(|t| *t == 0xFFFF)
        }
        OP_GYRO => true,
        _ => false,
    }
}

/// The pure MoYu32 protocol state machine.
pub(crate) struct Moyu32Protocol {
    state: Cube3x3x3,
    state_set: bool,
    synced: bool,
    /// Move counter of the last state we believe we are in sync with.
    /// `None` until the first `0xA3` arrives — move packets before that
    /// have nothing to be relative to and are dropped.
    move_count: Option<u8>,
    /// Whether any move has been delivered yet, used to zero the very
    /// first inter-move time (it measures back to a move that happened
    /// before we connected).
    delivered_move: bool,
    battery_percentage: Option<u32>,
    events: Vec<Moyu32Event>,
    outgoing: Vec<Moyu32OutMessage>,
}

impl Moyu32Protocol {
    pub(crate) fn new() -> Self {
        Self {
            state: Cube3x3x3::new(),
            state_set: false,
            synced: true,
            move_count: None,
            delivered_move: false,
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

    #[allow(dead_code)]
    pub(crate) fn synced(&self) -> bool {
        self.synced
    }

    #[allow(dead_code)]
    pub(crate) fn battery_percentage(&self) -> Option<u32> {
        self.battery_percentage
    }

    /// Drain semantic events accumulated since the last call.
    pub(crate) fn take_events(&mut self) -> Vec<Moyu32Event> {
        std::mem::take(&mut self.events)
    }

    /// Drain outgoing plaintext command packets. The caller encrypts and
    /// writes them.
    pub(crate) fn take_outgoing(&mut self) -> Vec<Moyu32OutMessage> {
        std::mem::take(&mut self.outgoing)
    }

    /// Queue a facelets request. The cube has no "set state to solved"
    /// command, so this is also how `reset_cube_state` recovers.
    pub(crate) fn request_facelets(&mut self) {
        self.outgoing.push(Moyu32OutMessage {
            bytes: build_simple_request(OP_FACELETS),
        });
    }

    /// Optimistically assume the cube is solved (the user asserted it)
    /// and ask the cube to confirm.
    pub(crate) fn assume_solved(&mut self) {
        self.state = Cube3x3x3::new();
        self.request_facelets();
    }

    /// Handle one decrypted 20-byte notification.
    pub(crate) fn handle_decrypted(&mut self, packet: &[u8]) {
        if packet.len() < MOYU32_PACKET_LEN {
            return;
        }

        match packet[0] {
            OP_HARDWARE => self.handle_hardware(packet),
            OP_FACELETS => self.handle_facelets(packet),
            OP_BATTERY => {
                let level = (packet[1] as u32).min(100);
                self.battery_percentage = Some(level);
                self.events.push(Moyu32Event::Battery(level));
            }
            OP_MOVE => self.handle_move(packet),
            // Gyro quaternions and gyro-enable acks carry nothing we use.
            _ => (),
        }
    }

    fn handle_hardware(&mut self, packet: &[u8]) {
        let name: String = packet[1..9]
            .iter()
            .filter(|b| **b != 0)
            .map(|b| *b as char)
            .collect();
        self.events.push(Moyu32Event::Hardware {
            name: name.trim().to_string(),
            software_version: format!("{}.{}", packet[9], packet[10]),
            hardware_version: format!("{}.{}", packet[11], packet[12]),
        });
    }

    fn handle_facelets(&mut self, packet: &[u8]) {
        let cube = match decode_facelets(packet) {
            Some(cube) => cube,
            // A malformed state means either corruption or a wrong key.
            // Leave the previous state alone.
            None => return,
        };

        self.state = cube.clone();
        self.state_set = true;
        // Byte 19 is the move counter this snapshot corresponds to, so it
        // re-anchors move tracking and clears any earlier desync.
        self.move_count = Some(packet[19]);
        self.synced = true;
        self.events.push(Moyu32Event::Facelets(cube));
    }

    fn handle_move(&mut self, packet: &[u8]) {
        // Without a state snapshot to apply moves to there is nothing
        // useful to do; the init sequence always requests one first.
        let previous = match self.move_count {
            Some(count) => count,
            None => return,
        };

        let count = packet[11];
        if count == previous {
            // The cube repeats the same packet several times; this is
            // also what dedupes the duplicated notifications some BLE
            // stacks deliver.
            return;
        }

        let mut moves = [Move::U; MAX_MOVES_PER_PACKET];
        let mut times = [0u32; MAX_MOVES_PER_PACKET];
        for i in 0..MAX_MOVES_PER_PACKET {
            let code = extract_bits(packet, 96 + i * 5, 5) as u8;
            match decode_move(code) {
                Some(mv) => moves[i] = mv,
                // An empty slot anywhere in the history means the packet
                // cannot be trusted. Drop it *without* advancing the
                // counter: the next packet carries the same moves again
                // in its own history, so this recovers by itself.
                None => return,
            }
            times[i] = u16::from_be_bytes([packet[1 + i * 2], packet[2 + i * 2]]) as u32;
        }

        // The counter is 8 bits and wraps.
        let gap = count.wrapping_sub(previous) as usize;
        let new_moves = gap.min(MAX_MOVES_PER_PACKET);
        if gap > MAX_MOVES_PER_PACKET {
            // More moves happened than the cube can report, so we have
            // permanently lost some. Flag it and ask for a fresh state.
            self.synced = false;
            self.events.push(Moyu32Event::SyncLost);
            self.request_facelets();
        }
        self.move_count = Some(count);

        // Both arrays are newest-first, so walk backwards to replay the
        // new moves in the order they were actually made.
        for i in (0..new_moves).rev() {
            let mv = moves[i];
            self.state.do_move(mv);
            let delta = if self.delivered_move { times[i] } else { 0 };
            self.delivered_move = true;
            self.events.push(Moyu32Event::Move {
                moves: vec![TimedMove::new(mv, delta)],
                state: self.state.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `0xA5` packet with the given counter, five move codes and
    /// five inter-move times.
    fn move_packet(count: u8, codes: [u8; 5], times: [u16; 5]) -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = OP_MOVE;
        for i in 0..5 {
            let bytes = times[i].to_be_bytes();
            packet[1 + i * 2] = bytes[0];
            packet[2 + i * 2] = bytes[1];
        }
        packet[11] = count;
        // Five 5-bit codes packed big-endian starting at bit 96 (byte 12).
        let mut bits: u32 = 0;
        for i in 0..5 {
            bits = (bits << 5) | (codes[i] as u32 & 0x1F);
        }
        // 25 bits, left-aligned in a 32-bit window at byte 12.
        let window = bits << 7;
        packet[12] = (window >> 24) as u8;
        packet[13] = (window >> 16) as u8;
        packet[14] = (window >> 8) as u8;
        packet[15] = window as u8;
        packet
    }

    /// A `0xA3` packet for a solved cube with the given move counter.
    fn solved_facelets_packet(count: u8) -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = OP_FACELETS;
        // Faces are stored F B U D L R; on a solved cube every sticker of
        // face `f` has color index `f`, so each 24-bit face is `f`
        // repeated eight times.
        for face in 0..6usize {
            for i in 0..8usize {
                let bit = 8 + face * 24 + i * 3;
                let value = face as u32;
                for b in 0..3 {
                    if value & (1 << (2 - b)) != 0 {
                        let idx = bit + b;
                        packet[idx / 8] |= 1 << (7 - (idx % 8));
                    }
                }
            }
        }
        packet[19] = count;
        packet
    }

    #[test]
    fn move_codes_decode_to_the_expected_faces() {
        // Codes are `face_index * 2 + prime`, faces in F B U D L R order.
        assert_eq!(decode_move(0), Some(Move::F));
        assert_eq!(decode_move(1), Some(Move::Fp));
        assert_eq!(decode_move(2), Some(Move::B));
        assert_eq!(decode_move(3), Some(Move::Bp));
        assert_eq!(decode_move(4), Some(Move::U));
        assert_eq!(decode_move(5), Some(Move::Up));
        assert_eq!(decode_move(6), Some(Move::D));
        assert_eq!(decode_move(7), Some(Move::Dp));
        assert_eq!(decode_move(8), Some(Move::L));
        assert_eq!(decode_move(9), Some(Move::Lp));
        assert_eq!(decode_move(10), Some(Move::R));
        assert_eq!(decode_move(11), Some(Move::Rp));
        // 12..=31 are empty history slots, not moves.
        assert_eq!(decode_move(12), None);
        assert_eq!(decode_move(31), None);
    }

    #[test]
    fn solved_facelets_packet_decodes_to_a_solved_cube() {
        let cube = decode_facelets(&solved_facelets_packet(0)).unwrap();
        assert!(cube.is_solved());
    }

    #[test]
    fn facelets_packet_with_an_impossible_coloring_is_rejected() {
        let mut packet = solved_facelets_packet(0);
        // Turn one sticker of the F face into a 7, which is not a color.
        packet[1] = 0xFF;
        assert!(decode_facelets(&packet).is_none());
    }

    #[test]
    fn move_packets_before_the_first_facelets_are_ignored() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&move_packet(1, [10, 10, 10, 10, 10], [100; 5]));
        assert!(protocol.take_events().is_empty());
        assert!(!protocol.state_set());
    }

    #[test]
    fn a_single_new_move_is_applied() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&solved_facelets_packet(7));
        protocol.take_events();

        // Counter 8 with R as the newest move.
        protocol.handle_decrypted(&move_packet(8, [10, 4, 4, 4, 4], [250, 100, 100, 100, 100]));
        let events = protocol.take_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Moyu32Event::Move { moves, state } => {
                assert_eq!(moves.len(), 1);
                assert_eq!(moves[0].move_(), Move::R);
                // The first delivered move's timer runs from before we
                // connected, so it is reported as zero.
                assert_eq!(moves[0].time(), 0);
                let mut expected = Cube3x3x3::new();
                expected.do_move(Move::R);
                assert_eq!(*state, expected);
            }
            other => panic!("expected a move event, got {:?}", other),
        }
    }

    #[test]
    fn several_moves_in_one_packet_replay_oldest_first() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&solved_facelets_packet(0));
        protocol.take_events();

        // Newest-first history [R, U, F, x, x] with the counter advanced
        // by three, so F then U then R were the new moves.
        protocol.handle_decrypted(&move_packet(3, [10, 4, 0, 4, 4], [30, 20, 10, 5, 5]));
        let events = protocol.take_events();
        let played: Vec<Move> = events
            .iter()
            .filter_map(|e| match e {
                Moyu32Event::Move { moves, .. } => Some(moves[0].move_()),
                _ => None,
            })
            .collect();
        assert_eq!(played, vec![Move::F, Move::U, Move::R]);

        // Only the first delivered move is zeroed; the rest carry the
        // cube's own inter-move times, newest-first indexed.
        let times: Vec<u32> = events
            .iter()
            .filter_map(|e| match e {
                Moyu32Event::Move { moves, .. } => Some(moves[0].time()),
                _ => None,
            })
            .collect();
        assert_eq!(times, vec![0, 20, 30]);

        let mut expected = Cube3x3x3::new();
        expected.do_moves(&[Move::F, Move::U, Move::R]);
        assert_eq!(protocol.state(), expected);
    }

    #[test]
    fn repeated_packets_with_the_same_counter_are_dropped() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&solved_facelets_packet(0));
        protocol.take_events();

        let packet = move_packet(1, [10, 4, 4, 4, 4], [100; 5]);
        protocol.handle_decrypted(&packet);
        assert_eq!(protocol.take_events().len(), 1);
        protocol.handle_decrypted(&packet);
        assert!(protocol.take_events().is_empty());
    }

    #[test]
    fn the_move_counter_wraps_at_256() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&solved_facelets_packet(0xFF));
        protocol.take_events();

        protocol.handle_decrypted(&move_packet(0x00, [10, 4, 4, 4, 4], [100; 5]));
        let events = protocol.take_events();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn a_packet_with_an_empty_history_slot_is_dropped_without_advancing() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&solved_facelets_packet(0));
        protocol.take_events();

        // Slot 4 is empty (0x1F), which the cube uses right after boot.
        protocol.handle_decrypted(&move_packet(1, [10, 4, 4, 4, 31], [100; 5]));
        assert!(protocol.take_events().is_empty());

        // The counter did not advance, so the next (complete) packet
        // still delivers the move.
        protocol.handle_decrypted(&move_packet(1, [10, 4, 4, 4, 4], [100; 5]));
        assert_eq!(protocol.take_events().len(), 1);
    }

    #[test]
    fn a_gap_larger_than_one_packet_desyncs_and_asks_for_a_new_state() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&solved_facelets_packet(0));
        protocol.take_events();
        protocol.take_outgoing();

        // Counter jumped by 9 but only five moves are reported.
        protocol.handle_decrypted(&move_packet(9, [10, 4, 4, 4, 4], [100; 5]));
        let events = protocol.take_events();
        assert!(events.iter().any(|e| matches!(e, Moyu32Event::SyncLost)));
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Moyu32Event::Move { .. }))
                .count(),
            5
        );
        assert!(!protocol.synced());

        let outgoing = protocol.take_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].bytes[0], OP_FACELETS);

        // A fresh state snapshot re-anchors everything.
        protocol.handle_decrypted(&solved_facelets_packet(20));
        assert!(protocol.synced());
    }

    #[test]
    fn hardware_and_battery_packets_are_parsed() {
        let mut protocol = Moyu32Protocol::new();

        let mut packet = [0u8; 20];
        packet[0] = OP_HARDWARE;
        packet[1..9].copy_from_slice(b"WCU_MY33");
        packet[9] = 3;
        packet[10] = 1;
        packet[11] = 3;
        packet[12] = 7;
        protocol.handle_decrypted(&packet);

        let mut packet = [0u8; 20];
        packet[0] = OP_BATTERY;
        packet[1] = 99;
        protocol.handle_decrypted(&packet);

        let events = protocol.take_events();
        match &events[0] {
            Moyu32Event::Hardware {
                name,
                software_version,
                hardware_version,
            } => {
                assert_eq!(name, "WCU_MY33");
                assert_eq!(software_version, "3.1");
                assert_eq!(hardware_version, "3.7");
            }
            other => panic!("expected hardware, got {:?}", other),
        }
        assert!(matches!(events[1], Moyu32Event::Battery(99)));
        assert_eq!(protocol.battery_percentage(), Some(99));
    }

    #[test]
    fn battery_percentage_is_clamped() {
        let mut protocol = Moyu32Protocol::new();
        let mut packet = [0u8; 20];
        packet[0] = OP_BATTERY;
        packet[1] = 200;
        protocol.handle_decrypted(&packet);
        assert!(matches!(
            protocol.take_events()[0],
            Moyu32Event::Battery(100)
        ));
    }

    #[test]
    fn gyro_packets_produce_nothing() {
        let mut protocol = Moyu32Protocol::new();
        protocol.handle_decrypted(&solved_facelets_packet(0));
        protocol.take_events();

        let mut packet = [0u8; 20];
        packet[0] = OP_GYRO;
        for i in 1..17 {
            packet[i] = i as u8;
        }
        protocol.handle_decrypted(&packet);
        assert!(protocol.take_events().is_empty());
        assert!(protocol.state().is_solved());
    }

    #[test]
    fn init_sequence_matches_the_documented_burst() {
        let init = build_init_sequence();
        let opcodes: Vec<u8> = init.iter().map(|cmd| cmd[0]).collect();
        assert_eq!(
            opcodes,
            vec![
                OP_HARDWARE,
                OP_FACELETS,
                OP_BATTERY,
                OP_HARDWARE,
                OP_FACELETS,
                OP_BATTERY,
                OP_GYRO_ENABLE,
                OP_FACELETS,
            ]
        );
        assert!(init.iter().all(|cmd| cmd.len() == MOYU32_PACKET_LEN));
        // The gyro enable is the one command with a payload.
        assert_eq!(init[6][2], 0x01);
    }

    #[test]
    fn packet_sanity_accepts_real_packets_and_rejects_noise() {
        assert!(packet_looks_valid(&solved_facelets_packet(0x12)));

        let mut hardware = [0u8; 20];
        hardware[0] = OP_HARDWARE;
        hardware[1..9].copy_from_slice(b"WCU_MY33");
        hardware[9] = 3;
        hardware[10] = 1;
        hardware[11] = 3;
        hardware[12] = 7;
        hardware[13] = 0xA1;
        hardware[14] = 0x40;
        assert!(packet_looks_valid(&hardware));

        assert!(packet_looks_valid(&move_packet(
            0xD5,
            [5, 5, 5, 5, 5],
            [0x0419, 0x02C6, 0x016F, 0x013F, 0x0134]
        )));

        // All zeros, all 0xFF and an unknown opcode are all rejected.
        assert!(!packet_looks_valid(&[0u8; 20]));
        assert!(!packet_looks_valid(&[0xFFu8; 20]));
        let mut unknown = [0x11u8; 20];
        unknown[0] = 0x42;
        assert!(!packet_looks_valid(&unknown));

        // Too short to be a MoYu32 packet.
        assert!(!packet_looks_valid(&[0xA4, 0x63]));
    }
}
