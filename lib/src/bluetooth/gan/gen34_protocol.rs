//! Pure Gen3/Gen4 GAN protocol state machine.
//!
//! This module contains no transport code. The caller feeds raw packet
//! bytes via `handle_notification`, drains semantic events with
//! `take_events()` and drains outgoing (encrypted) command bytes with
//! `take_outgoing()`. The shared protocol machine handles:
//!
//! * AES decryption / encryption of packets
//! * Parsing MOVE, FACELETS, MOVE_HISTORY, BATTERY and DISCONNECT events
//! * FIFO buffering and gap-detection for move-serial reordering
//! * Issuing history-request commands to recover missed moves
//! * Converting the cube's absolute since-boot timestamp into per-move
//!   deltas (Bug 4 fix)
//! * Treating the first live MOVE as the serial baseline rather than the
//!   FACELETS event (Bug 3 fix)
//!
//! See the module-level doc comment in `gan/mod.rs` for the motivation:
//! eliminating the native/web copy-paste fork so fixes only have to be
//! made once.

use crate::common::{Corner, CornerPiece, Cube, InitialCubeState, Move, TimedMove};
use crate::cube3x3x3::{Cube3x3x3, Edge3x3x3, EdgePiece3x3x3};
use std::collections::{HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::iter::FromIterator;
use std::marker::PhantomData;

/// A buffered move awaiting delivery from the FIFO. Shared between Gen3
/// and Gen4. Named after its historical `Gen3BufferedMove` origin.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gen34BufferedMove {
    pub(crate) serial: u8,
    pub(crate) mv: Move,
    /// Per-move delta (ms) for live moves; 0 for history-recovered moves.
    pub(crate) timestamp: u32,
}

/// A semantic event parsed out of the Gen3/Gen4 wire protocol.
#[derive(Debug, Clone)]
pub(crate) enum Gen34Event {
    /// One or more delivered (in-order) moves along with the resulting
    /// cube state. Always a single move per event in the current impl —
    /// kept as a Vec for symmetry with `BluetoothCubeEvent::Move`.
    Move {
        moves: Vec<TimedMove>,
        state: Cube3x3x3,
    },
    /// Battery percentage (0..=100).
    Battery(u32),
    /// The cube reported a disconnect — callers should set their synced
    /// flag to false.
    Disconnected,
    /// Sync loss (FIFO overflow or bad data). Callers should drop their
    /// synced flag.
    SyncLost,
}

/// An outgoing command packet for the cube. The bytes are **plaintext** —
/// the transport layer is responsible for encrypting them with the
/// appropriate cipher (Gen3 uses `GanV3Cipher`, Gen4 uses `GanV2Cipher`)
/// before writing them to the cube. Keeping the protocol machine cipher-
/// agnostic lets both Gen3 and Gen4 share the same `Gen34Protocol` type.
#[derive(Debug, Clone)]
pub(crate) struct Gen34OutMessage {
    pub(crate) bytes: Vec<u8>,
}

/// Wire-level configuration for Gen3 vs Gen4. The protocol logic in
/// `Gen34Protocol` is identical; only byte offsets, magic bytes, opcodes
/// and command packet shapes differ.
pub(crate) trait Gen34Wire: 'static {
    /// Whether this protocol uses a 0x55 magic byte at the start of
    /// notification packets (Gen3 does, Gen4 does not).
    const HAS_MAGIC: bool;
    /// Opcode byte in notification header that identifies a MOVE event.
    const EVENT_MOVE: u8;
    /// Opcode byte in notification header that identifies a FACELETS event.
    const EVENT_FACELETS: u8;
    /// Opcode byte in notification header that identifies a MOVE_HISTORY event.
    const EVENT_HISTORY: u8;
    /// Opcode byte in notification header that identifies a BATTERY event.
    const EVENT_BATTERY: u8;
    /// Opcode byte in notification header that identifies a DISCONNECT event.
    const EVENT_DISCONNECT: u8;

    // ---- MOVE event field offsets (bytes) ----
    const MOVE_TIMESTAMP_OFF: usize;
    const MOVE_SERIAL_OFF: usize;
    const MOVE_DIR_FACE_OFF: usize;

    // ---- FACELETS event field offsets ----
    const FACELETS_SERIAL_OFF: usize;
    const FACELETS_CORNERS_BIT: usize;
    const FACELETS_CORNER_TWIST_BIT: usize;
    const FACELETS_EDGES_BIT: usize;
    const FACELETS_EDGE_PARITY_BIT: usize;

    // ---- HISTORY event field offsets ----
    const HISTORY_START_SERIAL_OFF: usize;
    const HISTORY_MOVES_OFF: usize;

    /// Build the "request initial cube state" command bytes (unencrypted).
    fn build_state_request() -> Vec<u8>;

    /// Build the "request battery state" command bytes (unencrypted).
    fn build_battery_request() -> Vec<u8>;

    /// Build the "reset cube state" command bytes (unencrypted).
    fn build_reset_cube_state() -> Vec<u8>;

    /// Build a move-history request command. `serial` and `count` have
    /// already been aligned/clamped per the shared `align_history_request`.
    fn build_history_request(serial: u8, count: u8) -> Vec<u8>;

    /// Decode a live MOVE event. Bit offsets relative to start of the
    /// decrypted packet. Returns (serial, move, raw absolute timestamp).
    ///
    /// Default impl using the MOVE_ offsets suffices for both Gen3 and
    /// Gen4; the two protocols only differ in offsets.
    fn parse_move(packet: &[u8]) -> Option<(u8, Move, u32)> {
        if packet.len() <= Self::MOVE_DIR_FACE_OFF {
            return None;
        }
        let ts_off = Self::MOVE_TIMESTAMP_OFF;
        let timestamp = u32::from_le_bytes([
            packet[ts_off],
            packet[ts_off + 1],
            packet[ts_off + 2],
            packet[ts_off + 3],
        ]);
        let ser_off = Self::MOVE_SERIAL_OFF;
        let serial_16 = u16::from_le_bytes([packet[ser_off], packet[ser_off + 1]]);
        let serial = (serial_16 & 0xFF) as u8;
        let direction_and_face = packet[Self::MOVE_DIR_FACE_OFF];
        let direction = (direction_and_face >> 6) & 0x03;
        let face_bitmask = direction_and_face & 0x3F;
        decode_live_move(face_bitmask, direction).map(|mv| (serial, mv, timestamp))
    }
}

/// Gen3 wire config (used by GAN356 i Carry 2).
pub(crate) struct Gen3Wire;

impl Gen34Wire for Gen3Wire {
    const HAS_MAGIC: bool = true;

    const EVENT_MOVE: u8 = 0x01;
    const EVENT_FACELETS: u8 = 0x02;
    const EVENT_HISTORY: u8 = 0x06;
    const EVENT_BATTERY: u8 = 0x10;
    const EVENT_DISCONNECT: u8 = 0x11;

    const MOVE_TIMESTAMP_OFF: usize = 3;
    const MOVE_SERIAL_OFF: usize = 7;
    const MOVE_DIR_FACE_OFF: usize = 9;

    const FACELETS_SERIAL_OFF: usize = 3;
    const FACELETS_CORNERS_BIT: usize = 40;
    const FACELETS_CORNER_TWIST_BIT: usize = 61;
    const FACELETS_EDGES_BIT: usize = 77;
    const FACELETS_EDGE_PARITY_BIT: usize = 121;

    const HISTORY_START_SERIAL_OFF: usize = 3;
    const HISTORY_MOVES_OFF: usize = 4;

    fn build_state_request() -> Vec<u8> {
        let mut cmd = vec![0u8; 16];
        cmd[0] = 0x68;
        cmd[1] = 0x01;
        cmd
    }

    fn build_battery_request() -> Vec<u8> {
        let mut cmd = vec![0u8; 16];
        cmd[0] = 0x68;
        cmd[1] = 0x07;
        cmd
    }

    fn build_reset_cube_state() -> Vec<u8> {
        vec![
            0x68, 0x05, 0x05, 0x39, 0x77, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x00,
            0x00, 0x00,
        ]
    }

    fn build_history_request(serial: u8, count: u8) -> Vec<u8> {
        let mut cmd = vec![0u8; 16];
        cmd[0] = 0x68;
        cmd[1] = 0x03;
        cmd[2] = serial;
        cmd[4] = count;
        cmd
    }
}

/// Gen4 wire config (used by GAN12 ui / GAN14 ui / GAN iC4).
pub(crate) struct Gen4Wire;

impl Gen34Wire for Gen4Wire {
    const HAS_MAGIC: bool = false;

    const EVENT_MOVE: u8 = 0x01;
    const EVENT_FACELETS: u8 = 0xED;
    const EVENT_HISTORY: u8 = 0xD1;
    const EVENT_BATTERY: u8 = 0xEF;
    const EVENT_DISCONNECT: u8 = 0xEA;

    const MOVE_TIMESTAMP_OFF: usize = 2;
    const MOVE_SERIAL_OFF: usize = 6;
    const MOVE_DIR_FACE_OFF: usize = 8;

    const FACELETS_SERIAL_OFF: usize = 2;
    const FACELETS_CORNERS_BIT: usize = 32;
    const FACELETS_CORNER_TWIST_BIT: usize = 53;
    const FACELETS_EDGES_BIT: usize = 69;
    const FACELETS_EDGE_PARITY_BIT: usize = 113;

    const HISTORY_START_SERIAL_OFF: usize = 2;
    const HISTORY_MOVES_OFF: usize = 3;

    fn build_state_request() -> Vec<u8> {
        let mut cmd = vec![0u8; 20];
        cmd[0] = 0xDD;
        cmd[1] = 0x04;
        cmd[3] = 0xED;
        cmd
    }

    fn build_battery_request() -> Vec<u8> {
        let mut cmd = vec![0u8; 20];
        cmd[0] = 0xDD;
        cmd[1] = 0x04;
        cmd[3] = 0xEF;
        cmd
    }

    fn build_reset_cube_state() -> Vec<u8> {
        vec![
            0xD2, 0x0D, 0x05, 0x39, 0x77, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn build_history_request(serial: u8, count: u8) -> Vec<u8> {
        let mut cmd = vec![0u8; 20];
        cmd[0] = 0xD1;
        cmd[1] = 0x04;
        cmd[2] = serial;
        cmd[4] = count;
        cmd
    }
}

/// Align and clamp a history-request window per the GAN Gen3/Gen4 spec.
///
/// The cube packs the history response in 4-bit nibbles starting from an
/// odd serial. If `serial` is even we slide it back by 1 (the slot we
/// already know will be harmlessly deduped on injection). We do NOT bump
/// `count` here (this was Bug 2 — the wasm code had a spurious `count +=
/// 1` on the even-serial slide, which over-requested). If `count` is odd
/// we bump it to the next even value. Finally we clamp `count` so the
/// window never wraps past serial 0 (firmware bug).
///
/// Returns `(aligned_serial, aligned_count)`.
pub(crate) fn align_history_request(mut serial: u8, count: u8) -> (u8, u8) {
    let mut count = count as u16;
    if serial % 2 == 0 {
        serial = serial.wrapping_sub(1);
    }
    if count % 2 == 1 {
        count += 1;
    }
    count = count.min(serial as u16 + 1);
    (serial, count as u8)
}

/// The pure Gen3/Gen4 protocol state machine.
///
/// This struct is deliberately cipher-free: callers decrypt raw packets
/// with whichever cipher their protocol uses (Gen3 = `GanV3Cipher`, Gen4
/// = `GanV2Cipher`) and hand plaintext to `handle_decrypted`. Outgoing
/// messages returned by `take_outgoing()` are also plaintext; the caller
/// encrypts them before writing. This lets Gen3 and Gen4 share one
/// `Gen34Protocol<W>` without the protocol layer knowing about the
/// concrete cipher types.
pub(crate) struct Gen34Protocol<W: Gen34Wire> {
    state: Cube3x3x3,
    state_set: bool,
    synced: bool,
    last_serial: Option<u8>,
    last_live_timestamp: Option<u32>,
    fifo_buffer: VecDeque<Gen34BufferedMove>,
    pending_history: bool,
    events: Vec<Gen34Event>,
    outgoing: Vec<Gen34OutMessage>,
    _wire: PhantomData<W>,
}

impl<W: Gen34Wire> Gen34Protocol<W> {
    pub(crate) fn new() -> Self {
        Self {
            state: Cube3x3x3::new(),
            state_set: false,
            synced: true,
            last_serial: None,
            last_live_timestamp: None,
            fifo_buffer: VecDeque::new(),
            pending_history: false,
            events: Vec::new(),
            outgoing: Vec::new(),
            _wire: PhantomData,
        }
    }

    pub(crate) fn state(&self) -> Cube3x3x3 {
        self.state.clone()
    }

    pub(crate) fn state_set(&self) -> bool {
        self.state_set
    }

    /// Drain semantic events accumulated since the last call.
    pub(crate) fn take_events(&mut self) -> Vec<Gen34Event> {
        std::mem::take(&mut self.events)
    }

    /// Drain outgoing command packets (plaintext) accumulated since the
    /// last call. The caller encrypts these with the appropriate cipher
    /// before writing them to the cube.
    pub(crate) fn take_outgoing(&mut self) -> Vec<Gen34OutMessage> {
        std::mem::take(&mut self.outgoing)
    }

    /// Build the plaintext "request initial cube state" command.
    pub(crate) fn build_state_request() -> Vec<u8> {
        W::build_state_request()
    }

    /// Build the plaintext "request battery state" command.
    pub(crate) fn build_battery_request() -> Vec<u8> {
        W::build_battery_request()
    }

    /// Build the plaintext "reset cube state" command.
    pub(crate) fn build_reset_request() -> Vec<u8> {
        W::build_reset_cube_state()
    }

    /// Handle a pre-decrypted notification packet. Callers decrypt raw
    /// packets with whichever cipher their protocol uses and pass the
    /// plaintext bytes here.
    pub(crate) fn handle_decrypted(&mut self, decrypted: &[u8]) {
        let (event_type, data_length) = if W::HAS_MAGIC {
            if decrypted.len() < 3 || decrypted[0] != 0x55 {
                return;
            }
            (decrypted[1], decrypted[2])
        } else {
            if decrypted.len() < 2 {
                return;
            }
            (decrypted[0], decrypted[1])
        };

        if event_type == W::EVENT_MOVE {
            if data_length == 0 {
                return;
            }
            if !self.state_set {
                return;
            }
            let (serial, mv, timestamp) = match W::parse_move(decrypted) {
                Some(t) => t,
                None => return,
            };

            // First live move bootstraps last_serial. We don't trust the
            // facelets event for this — some Gen4 cubes report serial=0
            // in periodic facelets, which would cause a bogus
            // history-recovery request and a phantom move. (Bug 3 fix.)
            if self.last_serial.is_none() {
                self.last_serial = Some(serial.wrapping_sub(1));
            }

            // Convert the cube's absolute since-boot timestamp into a
            // per-move delta. (Bug 4 fix.)
            let move_delta = match self.last_live_timestamp {
                Some(prev) => timestamp.wrapping_sub(prev),
                None => 0,
            };
            self.last_live_timestamp = Some(timestamp);

            self.fifo_buffer.push_back(Gen34BufferedMove {
                serial,
                mv,
                timestamp: move_delta,
            });

            self.try_evict();
        } else if event_type == W::EVENT_FACELETS {
            self.handle_facelets(decrypted);
        } else if event_type == W::EVENT_HISTORY {
            if data_length < 2 {
                return;
            }
            self.handle_history(decrypted, data_length);
        } else if event_type == W::EVENT_BATTERY {
            // Gen3: battery byte at offset 3. Gen4: offset (1 +
            // data_length). We special-case at the wire level.
            if W::HAS_MAGIC {
                // Gen3
                if decrypted.len() > 3 {
                    let level = decrypted[3] as u32;
                    self.events.push(Gen34Event::Battery(level.min(100)));
                }
            } else {
                // Gen4
                let idx = 1 + data_length as usize;
                if idx < decrypted.len() {
                    let level = decrypted[idx] as u32;
                    self.events.push(Gen34Event::Battery(level.min(100)));
                }
            }
        } else if event_type == W::EVENT_DISCONNECT {
            self.synced = false;
            self.events.push(Gen34Event::Disconnected);
        }
    }

    fn handle_facelets(&mut self, decrypted: &[u8]) {
        let ser_off = W::FACELETS_SERIAL_OFF;
        if decrypted.len() < ser_off + 2 {
            return;
        }
        let serial_16 = u16::from_le_bytes([decrypted[ser_off], decrypted[ser_off + 1]]);
        let serial = (serial_16 & 0xFF) as u8;

        let mut corners = [0u32; 8];
        let mut corner_twist = [0u32; 8];
        let mut corners_left: HashSet<u32> =
            HashSet::from_iter([0, 1, 2, 3, 4, 5, 6, 7].iter().cloned());
        let mut edges = [0u32; 12];
        let mut edge_parity = [0u32; 12];
        let mut edges_left: HashSet<u32> =
            HashSet::from_iter([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].iter().cloned());
        let mut total_corner_twist = 0u32;
        let mut total_edge_parity = 0u32;

        let mut valid = true;
        for i in 0..7 {
            corners[i] = extract_bits(decrypted, W::FACELETS_CORNERS_BIT + i * 3, 3);
            corner_twist[i] = extract_bits(decrypted, W::FACELETS_CORNER_TWIST_BIT + i * 2, 2);
            total_corner_twist += corner_twist[i];
            if !corners_left.remove(&corners[i]) || corner_twist[i] >= 3 {
                valid = false;
                break;
            }
        }

        if valid {
            for i in 0..11 {
                edges[i] = extract_bits(decrypted, W::FACELETS_EDGES_BIT + i * 4, 4);
                edge_parity[i] = extract_bits(decrypted, W::FACELETS_EDGE_PARITY_BIT + i, 1);
                total_edge_parity += edge_parity[i];
                if !edges_left.remove(&edges[i]) || edge_parity[i] >= 2 {
                    valid = false;
                    break;
                }
            }
        }

        if !valid {
            return;
        }

        corners[7] = *corners_left.iter().next().unwrap();
        edges[11] = *edges_left.iter().next().unwrap();
        corner_twist[7] = (3 - total_corner_twist % 3) % 3;
        edge_parity[11] = total_edge_parity & 1;

        let mut corner_pieces = Vec::with_capacity(8);
        let mut edge_pieces = Vec::with_capacity(12);
        for i in 0..8 {
            corner_pieces.push(CornerPiece {
                piece: Corner::try_from(corners[i] as u8).unwrap(),
                orientation: corner_twist[i] as u8,
            });
        }
        for i in 0..12 {
            edge_pieces.push(EdgePiece3x3x3 {
                piece: Edge3x3x3::try_from(edges[i] as u8).unwrap(),
                orientation: edge_parity[i] as u8,
            });
        }

        let cube = Cube3x3x3::from_corners_and_edges(
            corner_pieces.try_into().unwrap(),
            edge_pieces.try_into().unwrap(),
        );

        self.state = cube;
        self.state_set = true;

        // Do NOT initialize last_serial from the facelets event — see
        // Bug 3 comment in the MOVE handler. Periodic facelets still
        // drive the "missed last move" gap check as long as the first
        // live move already set last_serial.
        if serial != 0 {
            if let Some(last) = self.last_serial {
                let gap = serial.wrapping_sub(last);
                if gap > 1 && !self.pending_history {
                    // Pass the head (newest missing) serial and the
                    // full gap count. The history response packs
                    // newest-first starting at start_serial and going
                    // backward. (Bug 1 fix: wasm used to pass `last+1,
                    // gap-1`.)
                    self.send_history_request(serial, gap);
                }
            }
        }
    }

    fn handle_history(&mut self, decrypted: &[u8], data_length: u8) {
        let start_off = W::HISTORY_START_SERIAL_OFF;
        if decrypted.len() <= start_off {
            return;
        }
        let start_serial = decrypted[start_off];
        let num_moves = ((data_length - 1) * 2) as usize;

        let mut history_moves = Vec::with_capacity(num_moves);
        for i in 0..num_moves {
            let byte_idx = W::HISTORY_MOVES_OFF + i / 2;
            if byte_idx >= decrypted.len() {
                break;
            }
            let nibble = if i % 2 == 0 {
                (decrypted[byte_idx] >> 4) & 0x0F
            } else {
                decrypted[byte_idx] & 0x0F
            };
            let face_idx = (nibble >> 1) & 0x07;
            let direction = nibble & 0x01;
            if let Some(mv) = decode_history_move(face_idx, direction) {
                let serial = start_serial.wrapping_sub(i as u8);
                history_moves.push(Gen34BufferedMove {
                    serial,
                    mv,
                    timestamp: 0,
                });
            }
        }

        let ls = self.last_serial;
        for hm in history_moves {
            let dominated = if let Some(last) = ls {
                let diff = hm.serial.wrapping_sub(last);
                diff == 0 || diff > 128
            } else {
                false
            };
            if dominated {
                continue;
            }
            if self.fifo_buffer.iter().any(|b| b.serial == hm.serial) {
                continue;
            }
            self.fifo_buffer.push_front(hm);
        }

        self.pending_history = false;
        self.try_evict();
    }

    fn try_evict(&mut self) {
        loop {
            if self.fifo_buffer.is_empty() {
                break;
            }
            if self.fifo_buffer.len() > 16 {
                self.synced = false;
                self.fifo_buffer.clear();
                self.events.push(Gen34Event::SyncLost);
                break;
            }
            let ls = match self.last_serial {
                Some(s) => s,
                None => break,
            };
            let head_serial = self.fifo_buffer.front().unwrap().serial;
            let diff = head_serial.wrapping_sub(ls);

            if diff == 1 {
                let entry = self.fifo_buffer.pop_front().unwrap();
                self.state.do_move(entry.mv);
                self.last_serial = Some(entry.serial);
                self.events.push(Gen34Event::Move {
                    moves: vec![TimedMove::new(entry.mv, entry.timestamp)],
                    state: self.state.clone(),
                });
            } else if diff > 1 && diff < 128 {
                if !self.pending_history {
                    // Pass the head (newest) serial and the full diff.
                    // (Bug 1 fix.)
                    self.send_history_request(head_serial, diff);
                }
                break;
            } else {
                // diff == 0 or wrapped backwards - discard
                self.fifo_buffer.pop_front();
            }
        }
    }

    fn send_history_request(&mut self, start_serial: u8, count: u8) {
        let (serial, count) = align_history_request(start_serial, count);
        let cmd = W::build_history_request(serial, count);
        self.pending_history = true;
        self.outgoing.push(Gen34OutMessage { bytes: cmd });
    }
}

/// Extract `count` consecutive bits from `data` starting at bit `start`,
/// big-endian within each byte. Shared with gan.rs's bit reader.
pub(crate) fn extract_bits(data: &[u8], start: usize, count: usize) -> u32 {
    let mut result = 0;
    for i in 0..count {
        let bit = start + i;
        result <<= 1;
        if data[bit / 8] & (1 << (7 - (bit % 8))) != 0 {
            result |= 1;
        }
    }
    result
}

/// Decode a live move from face bitmask and direction.
/// Bitmask: U=2, R=32, F=8, D=1, L=16, B=4. Direction: 0=CW, 1=CCW.
fn decode_live_move(face_bitmask: u8, direction: u8) -> Option<Move> {
    let face_moves: &[(u8, Move, Move)] = &[
        (2, Move::U, Move::Up),
        (32, Move::R, Move::Rp),
        (8, Move::F, Move::Fp),
        (1, Move::D, Move::Dp),
        (16, Move::L, Move::Lp),
        (4, Move::B, Move::Bp),
    ];
    for &(mask, cw, ccw) in face_moves {
        if face_bitmask == mask {
            return Some(if direction == 0 { cw } else { ccw });
        }
    }
    None
}

/// Decode a history move from 3-bit face index and 1-bit direction.
/// Face: 0=D, 1=U, 2=B, 3=F, 4=L, 5=R. Direction: 0=CW, 1=CCW.
fn decode_history_move(face_idx: u8, direction: u8) -> Option<Move> {
    let face_moves: &[(Move, Move)] = &[
        (Move::D, Move::Dp), // 0
        (Move::U, Move::Up), // 1
        (Move::B, Move::Bp), // 2
        (Move::F, Move::Fp), // 3
        (Move::L, Move::Lp), // 4
        (Move::R, Move::Rp), // 5
    ];
    if (face_idx as usize) < face_moves.len() {
        let (cw, ccw) = face_moves[face_idx as usize];
        Some(if direction == 0 { cw } else { ccw })
    } else {
        None
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a solved-state Gen4 FACELETS packet with the given serial.
    /// The solved-state bit layout is deterministic: corners 0..7 (each
    /// 3 bits) then twists 0..0, edges 0..11 (4 bits each) then parities.
    ///
    /// For Gen4 the facelets event has opcode 0xED at byte 0, length at
    /// byte 1, serial at bytes 2..3, corner perm at bit 32, corner
    /// orientation at bit 53, edge perm at bit 69, edge orientation at
    /// bit 113.
    fn gen4_solved_facelets(serial: u8) -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = 0xED;
        packet[1] = 0x0C; // data_length — nonzero so the parser proceeds
        packet[2] = serial;
        packet[3] = 0;

        // Write corner permutation (7 corners x 3 bits starting at bit 32).
        // Solved state = corners in order 0,1,2,3,4,5,6 (the 8th is
        // implied from the remaining set).
        for i in 0..7 {
            write_bits(&mut packet, 32 + i * 3, 3, i as u32);
        }
        // Corner orientation (7 x 2 bits at bit 53). Solved = all zero.

        // Edge permutation (11 x 4 bits at bit 69). Solved = 0..11.
        for i in 0..11 {
            write_bits(&mut packet, 69 + i * 4, 4, i as u32);
        }
        // Edge orientation (11 x 1 bit at bit 113). Solved = all zero.

        packet
    }

    /// Build a Gen4 MOVE packet with the given serial, F move (face
    /// bitmask 8, direction 0 = CW), and the given absolute cube clock
    /// timestamp.
    fn gen4_move_f(serial: u8, timestamp: u32) -> [u8; 20] {
        gen4_move(serial, timestamp, /*face_bitmask=*/ 8, /*direction=*/ 0)
    }

    /// Build a Gen4 MOVE packet with the given serial, R move.
    fn gen4_move_r(serial: u8, timestamp: u32) -> [u8; 20] {
        gen4_move(serial, timestamp, /*face_bitmask=*/ 32, /*direction=*/ 0)
    }

    fn gen4_move(serial: u8, timestamp: u32, face_bitmask: u8, direction: u8) -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = 0x01; // MOVE event
        packet[1] = 0x0C; // data_length nonzero
        let ts = timestamp.to_le_bytes();
        packet[2] = ts[0];
        packet[3] = ts[1];
        packet[4] = ts[2];
        packet[5] = ts[3];
        packet[6] = serial;
        packet[7] = 0;
        packet[8] = ((direction & 0x03) << 6) | (face_bitmask & 0x3F);
        packet
    }

    fn write_bits(data: &mut [u8], start: usize, count: usize, value: u32) {
        for i in 0..count {
            let bit = start + i;
            let src_bit = (value >> (count - 1 - i)) & 1;
            if src_bit == 1 {
                data[bit / 8] |= 1 << (7 - (bit % 8));
            } else {
                data[bit / 8] &= !(1 << (7 - (bit % 8)));
            }
        }
    }

    #[test]
    fn bug4_first_move_time_is_zero() {
        // Bug 4: absolute cube-clock timestamp used to be passed through
        // as `time`, inflating solve durations. The fix converts it to
        // per-move deltas, and the first delta is always 0.
        let mut proto = Gen34Protocol::<Gen4Wire>::new();

        // Feed solved facelets (serial 0) — sets state_set.
        let fac = gen4_solved_facelets(0);
        proto.handle_decrypted(&fac);
        // Drain the facelets-driven events (none expected — facelets
        // don't emit Gen34Events in the current design).
        let _ = proto.take_events();
        let _ = proto.take_outgoing();

        // Feed a live F move with absolute timestamp 88564.
        let mv = gen4_move_f(1, 88564);
        proto.handle_decrypted(&mv);

        let events = proto.take_events();
        let moves: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let Gen34Event::Move { moves, .. } = e {
                    Some(moves.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            moves.len(),
            1,
            "expected exactly one Move event, got {:?}",
            events
        );
        let m = &moves[0];
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].move_(), Move::F);
        assert_eq!(
            m[0].time(),
            0,
            "first live move should have time=0 delta, not absolute 88564"
        );
    }

    #[test]
    fn bug4_second_move_time_is_delta() {
        // Second move after Bug 4 fix: time should be the cube-clock
        // delta from the first move (88656 - 88564 = 92).
        let mut proto = Gen34Protocol::<Gen4Wire>::new();

        proto.handle_decrypted(&gen4_solved_facelets(0));
        let _ = proto.take_events();
        let _ = proto.take_outgoing();

        proto.handle_decrypted(&gen4_move_f(1, 88564));
        let _ = proto.take_events();
        let _ = proto.take_outgoing();

        proto.handle_decrypted(&gen4_move_r(2, 88656));
        let events = proto.take_events();
        let moves: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let Gen34Event::Move { moves, .. } = e {
                    Some(moves.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(moves.len(), 1);
        let m = &moves[0];
        assert_eq!(m[0].move_(), Move::R);
        assert_eq!(
            m[0].time(),
            92,
            "second move time should be 88656-88564=92 delta, not absolute 88656"
        );
    }

    #[test]
    fn bug3_no_phantom_move_from_facelets_baseline() {
        // Bug 3: the wasm code used to initialize last_serial from the
        // facelets event. With facelets serial=0 and a first live move
        // at serial=2 the gap (2-0=2) would trigger a spurious history
        // request and the bogus response would decode as a phantom move.
        //
        // With the Bug 3 fix, the first live MOVE at serial 2 bootstraps
        // last_serial to 1, so try_evict treats it as the next expected
        // move (diff=1) and delivers it directly with no history request.
        let mut proto = Gen34Protocol::<Gen4Wire>::new();

        proto.handle_decrypted(&gen4_solved_facelets(0));
        let _ = proto.take_events();
        let _ = proto.take_outgoing();

        proto.handle_decrypted(&gen4_move_f(2, 88564));

        let events = proto.take_events();
        let move_events: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let Gen34Event::Move { moves, .. } = e {
                    Some(moves.clone())
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(
            move_events.len(),
            1,
            "expected exactly one Move event (F), no phantom. events: {:?}",
            events
        );
        assert_eq!(move_events[0].len(), 1);
        assert_eq!(move_events[0][0].move_(), Move::F);

        // And no history request should have been issued.
        let outgoing = proto.take_outgoing();
        assert!(
            outgoing.is_empty(),
            "expected no outgoing commands (no history request), got {} commands",
            outgoing.len()
        );
    }

    #[test]
    fn bug12_history_request_alignment() {
        // Bugs 1+2 combined: history request window.
        //
        // Setup: facelets, then a live F move at serial 5, then a live
        // move at serial 8. try_evict sees head=8, ls=5, diff=3.
        //
        // Bug 1 fix: pass head_serial=8 and full diff=3 (NOT ls+1=6 and
        // diff-1=2). Alignment rules:
        //   - serial 8 is even → slide back to 7
        //   - count 3 is odd → bump to 4
        //   - clamp: min(4, 7+1=8) = 4
        //
        // Bug 2 fix: the even-slide must NOT bump count. If it did,
        // count would become 4 after the slide, then 5 (odd→bump) after
        // the odd-bump, then even→... wait, the even check only runs
        // once, so Bug 2's effect was count: 3 → 4 (even slide) → 5
        // (odd bump) → 5. The correct sequence is: 3 → 3 (slide, no
        // bump) → 4 (odd bump).
        //
        // So the expected Gen4 history command plaintext is:
        //     0xD1 0x04 0x07 0x00 0x04 0x00 ...

        let mut proto = Gen34Protocol::<Gen4Wire>::new();

        proto.handle_decrypted(&gen4_solved_facelets(0));
        let _ = proto.take_events();
        let _ = proto.take_outgoing();

        // First live move at serial 5 — bootstraps last_serial to 4 and
        // delivers cleanly.
        proto.handle_decrypted(&gen4_move_f(5, 1000));
        let _ = proto.take_events();
        let out = proto.take_outgoing();
        assert!(
            out.is_empty(),
            "no history request expected after first move, got {} commands",
            out.len()
        );

        // Second live move at serial 8 — diff = 8 - 5 = 3, triggers
        // history request.
        proto.handle_decrypted(&gen4_move_r(8, 2000));

        let outgoing = proto.take_outgoing();
        assert_eq!(
            outgoing.len(),
            1,
            "expected exactly one history request, got {}",
            outgoing.len()
        );

        // Outgoing commands are plaintext now — read bytes directly.
        let bytes = &outgoing[0].bytes;
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0xD1, "opcode");
        assert_eq!(bytes[1], 0x04, "length");
        assert_eq!(bytes[2], 0x07, "aligned serial (8 even → 7)");
        assert_eq!(bytes[3], 0x00, "padding");
        assert_eq!(
            bytes[4], 0x04,
            "aligned count (3 odd → 4; Bug 2: no spurious even-slide bump)"
        );
        assert_eq!(bytes[5], 0x00, "padding");
    }

    #[test]
    fn align_history_request_unit() {
        // Direct unit test for the alignment helper.

        // Odd serial, odd count: serial stays, count bumps.
        assert_eq!(align_history_request(7, 3), (7, 4));
        // Even serial, odd count: serial slides back, count bumps from
        // odd (count change is ONLY from the odd-bump — Bug 2).
        assert_eq!(align_history_request(8, 3), (7, 4));
        // Odd serial, even count: no change.
        assert_eq!(align_history_request(9, 2), (9, 2));
        // Even serial, even count: serial slides back, count unchanged.
        assert_eq!(align_history_request(10, 2), (9, 2));
        // Clamp: count must not exceed serial+1.
        assert_eq!(align_history_request(3, 10), (3, 4));
    }
}
