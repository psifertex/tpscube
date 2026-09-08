//! Offline replay of captured MoYu32 BLE sessions.
//!
//! The fixtures in `testdata/` are unmodified captures from the
//! `poliva/smartcube-web-bluetooth` project. Each records every GATT
//! operation of a real session (`traffic`) together with the semantic
//! events that reference implementation produced from it (`events`), plus
//! the cube's MAC — so there is no key guessing here, only decryption and
//! parsing.
//!
//! These tests drive `Moyu32Protocol` end to end: derive the key from
//! `device.mac`, decrypt every notification, feed the plaintext to the
//! state machine, and compare the moves, per-move cube states, battery
//! and hardware info against what the capture says they should be.
//!
//! ## Where the replay starts
//!
//! A capture is a recording of a debugging session, not of one clean
//! connection. `fixture_WCU_MY33_AF9E` contains an abandoned connection
//! attempt before the one the `marker: connected` entry belongs to, and
//! that earlier attempt ends with a `0xA5` move packet (counter `0xD4`).
//! Replaying the file from byte zero therefore yields 32 moves — a
//! spurious leading `U'` from that stale packet — instead of the 31 the
//! capture's own event list records.
//!
//! Starting at the `connected` marker instead is not an option: the
//! initial `0xA3` state snapshot arrives one millisecond *before* it, and
//! without a snapshot every move packet is (correctly) ignored.
//!
//! So the replay starts at the **last `discover-service` entry**, which
//! is where the final connection attempt begins. That is exactly the
//! traffic a fresh `Moyu32Protocol` would see from a real cube, it needs
//! no fixture-specific special casing, and it also captures the init
//! burst so the hardware and battery packets are exercised too.

use super::cipher::cipher_for_mac;
use super::protocol::{Moyu32Event, Moyu32Protocol};
use crate::common::{Color, Cube, CubeFace, Move, MoveSequence};
use crate::cube3x3x3::Cube3x3x3;
use serde_json::Value;

const MY33_FIXTURE: &str = include_str!("testdata/fixture_WCU_MY33_AF9E.json");
const MY32_FIXTURE: &str = include_str!("testdata/fixture_WCU_MY32_A388.json");

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "hex payload has an odd length");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("invalid hex payload"))
        .collect()
}

fn parse_mac(text: &str) -> [u8; 6] {
    let parts: Vec<&str> = text.split(':').collect();
    assert_eq!(parts.len(), 6, "malformed MAC in fixture");
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).expect("invalid MAC octet");
    }
    mac
}

/// Render a cube as the 54 character `URFDLB` facelet string the fixtures
/// use, so states can be compared directly against the capture.
fn facelet_string(cube: &Cube3x3x3) -> String {
    const ORDER: [CubeFace; 6] = [
        CubeFace::Top,
        CubeFace::Right,
        CubeFace::Front,
        CubeFace::Bottom,
        CubeFace::Left,
        CubeFace::Back,
    ];
    fn letter(color: Color) -> char {
        match color.face() {
            CubeFace::Top => 'U',
            CubeFace::Right => 'R',
            CubeFace::Front => 'F',
            CubeFace::Bottom => 'D',
            CubeFace::Left => 'L',
            CubeFace::Back => 'B',
        }
    }

    let faces = cube.as_faces();
    let mut result = String::with_capacity(54);
    for face in ORDER.iter() {
        for row in 0..3 {
            for col in 0..3 {
                result.push(letter(faces.color(*face, row, col)));
            }
        }
    }
    result
}

/// The outcome of replaying one capture through `Moyu32Protocol`.
struct Replay {
    moves: Vec<Move>,
    /// Cube state after each delivered move, as a facelet string.
    move_states: Vec<String>,
    /// Cube state after each `0xA3` snapshot, as a facelet string.
    snapshot_states: Vec<String>,
    battery: Vec<u32>,
    hardware: Vec<(String, String, String)>,
    /// Inter-move times as delivered to the caller, in milliseconds.
    move_times: Vec<u32>,
    sync_lost: usize,
    notifications: usize,
}

fn replay(fixture: &str) -> Replay {
    let root: Value = serde_json::from_str(fixture).expect("fixture is not valid JSON");
    let mac = parse_mac(root["device"]["mac"].as_str().expect("fixture has no MAC"));
    let cipher = cipher_for_mac(&mac);
    let traffic = root["traffic"].as_array().expect("fixture has no traffic");

    // See the module comment: the last GATT discovery is where the
    // session that the capture's event list describes begins.
    let start = traffic
        .iter()
        .rposition(|entry| entry["op"] == "discover-service")
        .unwrap_or(0);

    let mut protocol = Moyu32Protocol::new();
    let mut result = Replay {
        moves: Vec::new(),
        move_states: Vec::new(),
        snapshot_states: Vec::new(),
        battery: Vec::new(),
        hardware: Vec::new(),
        move_times: Vec::new(),
        sync_lost: 0,
        notifications: 0,
    };

    for entry in &traffic[start..] {
        if entry["op"] != "notify" {
            continue;
        }
        let raw = decode_hex(entry["data"].as_str().expect("notify without data"));
        let decrypted = cipher
            .decrypt(&raw)
            .expect("notification failed to decrypt");
        result.notifications += 1;

        protocol.handle_decrypted(&decrypted);
        for event in protocol.take_events() {
            match event {
                Moyu32Event::Move { moves, state } => {
                    assert_eq!(moves.len(), 1);
                    result.moves.push(moves[0].move_());
                    result.move_times.push(moves[0].time());
                    result.move_states.push(facelet_string(&state));
                }
                Moyu32Event::Facelets(state) => {
                    result.snapshot_states.push(facelet_string(&state));
                }
                Moyu32Event::Battery(level) => result.battery.push(level),
                Moyu32Event::Hardware {
                    name,
                    software_version,
                    hardware_version,
                } => result
                    .hardware
                    .push((name, software_version, hardware_version)),
                Moyu32Event::SyncLost => result.sync_lost += 1,
            }
        }
    }

    result
}

/// Pull the expected move list out of a fixture's recorded event list.
fn expected_moves(fixture: &str) -> Vec<String> {
    let root: Value = serde_json::from_str(fixture).unwrap();
    root["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event"]["type"] == "MOVE")
        .map(|e| e["event"]["move"].as_str().unwrap().to_string())
        .collect()
}

/// Pull the expected facelet strings out of a fixture's recorded event list.
fn expected_facelets(fixture: &str) -> Vec<String> {
    let root: Value = serde_json::from_str(fixture).unwrap();
    root["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event"]["type"] == "FACELETS")
        .map(|e| e["event"]["facelets"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn my33_capture_replays_to_the_recorded_moves() {
    let replayed = replay(MY33_FIXTURE);

    // A warm up quarter turn followed by two T-perms.
    assert_eq!(
        replayed.moves.to_string(),
        "U' R U R' U' R' F R R U' R' U' R U R' F' R U R' U' R' F R R U' R' U' R U R' F'"
    );
    assert_eq!(replayed.moves.len(), 31);

    // Every move must agree with the capture's own decode.
    let expected: Vec<String> = expected_moves(MY33_FIXTURE);
    assert_eq!(expected.len(), 31);
    let actual: Vec<String> = replayed
        .moves
        .iter()
        .map(|mv| vec![*mv].to_string())
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn my33_capture_replays_to_the_recorded_cube_states() {
    let replayed = replay(MY33_FIXTURE);
    let expected = expected_facelets(MY33_FIXTURE);

    // The capture emits a facelet snapshot after every move, then one
    // more from the closing state probe.
    assert_eq!(expected.len(), 32);
    assert_eq!(replayed.move_states, expected[..31]);

    // The final `0xA3` snapshot the cube sent must match too, which
    // independently confirms the move replay left the tracked state
    // exactly where the physical cube was.
    assert_eq!(replayed.snapshot_states.last().unwrap(), &expected[31]);
    assert_eq!(replayed.move_states.last().unwrap(), &expected[31]);
}

#[test]
fn my33_capture_reports_hardware_and_battery() {
    let replayed = replay(MY33_FIXTURE);

    assert_eq!(
        replayed.hardware[0],
        ("WCU_MY33".to_string(), "3.1".to_string(), "3.7".to_string())
    );
    assert!(replayed
        .hardware
        .iter()
        .all(|hw| *hw == replayed.hardware[0]));

    // 99% during the init burst, 97% by the time the capture probes it
    // again a quarter of a minute later.
    assert_eq!(replayed.battery[0], 99);
    assert_eq!(*replayed.battery.last().unwrap(), 97);

    assert_eq!(replayed.sync_lost, 0);
}

#[test]
fn my33_capture_delivers_the_cubes_own_move_timing() {
    let replayed = replay(MY33_FIXTURE);

    // The first delivered move's timer runs back to a move made before
    // the connection, so it is reported as zero.
    assert_eq!(replayed.move_times[0], 0);
    // The rest are the cube's own inter-move times in milliseconds. The
    // second move came 4822 ms after the first, and the ones after that
    // are normal execution speed.
    assert_eq!(replayed.move_times[1], 4822);
    assert_eq!(&replayed.move_times[2..6], &[168, 139, 122, 141]);
    assert!(replayed.move_times[2..]
        .iter()
        .all(|t| *t > 0 && *t < 10000));
}

#[test]
fn my32_capture_replays_to_the_recorded_moves_and_states() {
    let replayed = replay(MY32_FIXTURE);

    let expected_moves = expected_moves(MY32_FIXTURE);
    assert_eq!(expected_moves.len(), 30);
    let actual: Vec<String> = replayed
        .moves
        .iter()
        .map(|mv| vec![*mv].to_string())
        .collect();
    assert_eq!(actual, expected_moves);

    let expected_facelets = expected_facelets(MY32_FIXTURE);
    assert_eq!(replayed.move_states, expected_facelets[..30]);
    assert_eq!(
        replayed.snapshot_states.last().unwrap(),
        expected_facelets.last().unwrap()
    );

    assert_eq!(
        replayed.hardware[0],
        ("WCU_MY32".to_string(), "2.1".to_string(), "2.7".to_string())
    );
    assert_eq!(replayed.battery[0], 38);
    assert_eq!(replayed.sync_lost, 0);
}

#[test]
fn my32_capture_ignores_its_gyro_traffic() {
    let replayed = replay(MY32_FIXTURE);

    // This capture is dominated by `0xAB` gyro quaternions — over 300 of
    // the 371 notifications — and none of them may affect cube state or
    // produce an event.
    assert!(replayed.notifications > 300);
    let accounted = replayed.moves.len()
        + replayed.snapshot_states.len()
        + replayed.battery.len()
        + replayed.hardware.len();
    assert!(
        accounted * 3 < replayed.notifications,
        "expected most notifications to be dropped gyro packets, \
         got {} events from {} notifications",
        accounted,
        replayed.notifications
    );
}

#[test]
fn both_captures_end_on_a_solved_cube() {
    // Both sessions are a scramble-free warm up followed by two T-perms,
    // so the cube finishes solved. This is the strongest single check
    // that the facelet decode, the move decode and the replay order are
    // all mutually consistent.
    for fixture in [MY33_FIXTURE, MY32_FIXTURE].iter() {
        let root: Value = serde_json::from_str(fixture).unwrap();
        let mac = parse_mac(root["device"]["mac"].as_str().unwrap());
        let cipher = cipher_for_mac(&mac);
        let traffic = root["traffic"].as_array().unwrap();
        let start = traffic
            .iter()
            .rposition(|entry| entry["op"] == "discover-service")
            .unwrap_or(0);

        let mut protocol = Moyu32Protocol::new();
        for entry in &traffic[start..] {
            if entry["op"] != "notify" {
                continue;
            }
            let raw = decode_hex(entry["data"].as_str().unwrap());
            protocol.handle_decrypted(&cipher.decrypt(&raw).unwrap());
        }
        assert!(protocol.state_set());
        assert!(protocol.synced());
        assert!(protocol.state().is_solved());
    }
}

#[test]
fn replaying_from_the_top_of_the_my33_capture_picks_up_the_stale_move() {
    // Documents the harness detail called out in the module comment: the
    // capture's abandoned first connection attempt ends with a move
    // packet, so replaying the whole file yields one extra leading move.
    let root: Value = serde_json::from_str(MY33_FIXTURE).unwrap();
    let mac = parse_mac(root["device"]["mac"].as_str().unwrap());
    let cipher = cipher_for_mac(&mac);

    let mut protocol = Moyu32Protocol::new();
    let mut moves = Vec::new();
    for entry in root["traffic"].as_array().unwrap() {
        if entry["op"] != "notify" {
            continue;
        }
        let raw = decode_hex(entry["data"].as_str().unwrap());
        protocol.handle_decrypted(&cipher.decrypt(&raw).unwrap());
        for event in protocol.take_events() {
            if let Moyu32Event::Move { moves: mv, .. } = event {
                moves.push(mv[0].move_());
            }
        }
    }

    assert_eq!(moves.len(), 32);
    assert_eq!(moves[0], Move::Up);
    assert_eq!(moves[1], Move::Up);
    // Even so, the cube still ends solved: the stale move is a real move
    // the cube made, just one from before the capture's event list starts.
    assert!(protocol.state().is_solved());
}
