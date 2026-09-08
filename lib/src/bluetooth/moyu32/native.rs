//! btleplug transport for MoYu32 cubes.
//!
//! Everything protocol-shaped lives in `protocol.rs`; this file only
//! knows how to find the cube's MAC, subscribe to notifications, decrypt,
//! hand the plaintext to `Moyu32Protocol`, and write back whatever the
//! protocol asks for.

use crate::bluetooth::gan::cipher::GanV2Cipher;
use crate::bluetooth::moyu32::cipher::{
    cipher_for_mac, format_mac, mac_candidates_from_name, mac_from_manufacturer_data, Moyu32Mac,
};
use crate::bluetooth::moyu32::protocol::{
    build_init_sequence, build_simple_request, packet_looks_valid, Moyu32Event, Moyu32Protocol,
    MOYU32_NOTIFY_UUID, MOYU32_PACKET_LEN, MOYU32_SERVICE_UUID, MOYU32_WRITE_UUID, OP_BATTERY,
    OP_FACELETS, OP_HARDWARE,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent};
use crate::common::InitialCubeState;
use crate::cube3x3x3::Cube3x3x3;
use anyhow::{anyhow, Result};
use btleplug::api::{CharPropFlags, Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures::stream::StreamExt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// How long to wait for the cube's first state snapshot before giving up.
const CUBE_STATE_TIMEOUT_MS: u64 = 4000;

/// How long to listen for plausible traffic when testing a candidate MAC.
const PROBE_TIMEOUT_MS: u64 = 2000;

/// How many structurally valid packets a candidate MAC must produce
/// before we believe it. Matches the reference implementation's threshold.
const PROBE_GOOD_PACKETS: usize = 3;

/// The cube never pushes battery updates on its own, so poll it.
const BATTERY_POLL_INTERVAL: Duration = Duration::from_secs(60);

fn moyu32_debug() -> bool {
    std::env::var("TPSCUBE_BT_DEBUG").is_ok()
}

/// Pick a write type the command characteristic actually supports.
///
/// Firmware revisions differ here: some declare only write-without-response
/// and some only write-with-response, and btleplug fails the operation
/// outright when the flag is missing.
fn write_type_for(characteristic: &Characteristic) -> WriteType {
    if characteristic
        .properties
        .contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
    {
        WriteType::WithoutResponse
    } else {
        WriteType::WithResponse
    }
}

struct Moyu32Cube {
    device: Peripheral,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
    protocol: Arc<Mutex<Moyu32Protocol>>,
    write: Characteristic,
    cipher: GanV2Cipher,
    last_battery_poll: Mutex<Instant>,
}

impl Moyu32Cube {
    /// Encrypt and write a plaintext command, blocking on the current
    /// tokio runtime. Used by the synchronous `BluetoothCubeDevice`
    /// methods.
    fn write_command_blocking(&self, plaintext: &[u8]) {
        let encrypted = match self.cipher.encrypt(plaintext) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| {
            handle.block_on(
                self.device
                    .write(&self.write, &encrypted, write_type_for(&self.write)),
            )
        });
    }
}

impl BluetoothCubeDevice for Moyu32Cube {
    fn cube_state(&self) -> Cube3x3x3 {
        self.state.lock().unwrap().clone()
    }

    fn battery_percentage(&self) -> Option<u32> {
        *self.battery_percentage.lock().unwrap()
    }

    fn battery_charging(&self) -> Option<bool> {
        // The cube reports a percentage but nothing about charging.
        None
    }

    fn reset_cube_state(&self) {
        // MoYu32 has no "the cube is solved now" command, so take the
        // user's word for it and ask the cube to confirm with a fresh
        // snapshot.
        let request = {
            let mut protocol = self.protocol.lock().unwrap();
            protocol.assume_solved();
            protocol.take_outgoing()
        };
        *self.state.lock().unwrap() = Cube3x3x3::new();
        for message in request {
            self.write_command_blocking(&message.bytes);
        }
    }

    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }

    fn update(&self) {
        // Called roughly every 10ms by the connection loop.
        let due = {
            let mut last = self.last_battery_poll.lock().unwrap();
            if last.elapsed() < BATTERY_POLL_INTERVAL {
                false
            } else {
                *last = Instant::now();
                true
            }
        };
        if due {
            self.write_command_blocking(&build_simple_request(OP_BATTERY));
        }
    }

    fn disconnect(&self) {
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| handle.block_on(self.device.disconnect()));
    }
}

/// Read the cube's MAC out of whatever the adapter already knows.
///
/// The advertisement's manufacturer data holds it under a company id that
/// varies per cube (`0x0000` when unbound, otherwise derived from the
/// owner's account id), so every entry is tried. Failing that, some
/// platforms expose the peripheral's real address directly; macOS does
/// not, and hands out a random-looking UUID instead.
async fn mac_from_advertisement(device: &Peripheral) -> Option<Moyu32Mac> {
    let props = device.properties().await.ok()??;

    for (company, data) in props.manufacturer_data.iter() {
        if let Some(mac) = mac_from_manufacturer_data(data) {
            if moyu32_debug() {
                eprintln!(
                    "MoYu32: MAC {} from manufacturer data (company id 0x{:04x})",
                    format_mac(&mac),
                    company
                );
            }
            return Some(mac);
        }
    }

    let address = props.address.into_inner();
    if address.iter().any(|b| *b != 0) {
        if moyu32_debug() {
            eprintln!(
                "MoYu32: MAC {} from peripheral address",
                format_mac(&address)
            );
        }
        return Some(address);
    }

    None
}

/// Try a candidate MAC by prodding the cube with the init burst encrypted
/// under that key and checking whether the replies decrypt to something
/// structurally valid.
///
/// The cube ignores commands it cannot decrypt, so a wrong candidate
/// normally produces silence rather than garbage; either way it fails.
async fn probe_mac(
    device: &Peripheral,
    write: &Characteristic,
    candidate: &Moyu32Mac,
) -> Result<bool> {
    let cipher = cipher_for_mac(candidate);
    let mut notifications = device.notifications().await?;

    // Two bursts: some firmware ignores the first one entirely.
    for _ in 0..2 {
        for opcode in [OP_HARDWARE, OP_FACELETS, OP_BATTERY].iter() {
            let encrypted = cipher.encrypt(&build_simple_request(*opcode))?;
            device
                .write(write, &encrypted, write_type_for(write))
                .await?;
        }
    }

    let deadline = Instant::now() + Duration::from_millis(PROBE_TIMEOUT_MS);
    let mut good = 0;
    let mut seen = 0;
    while Instant::now() < deadline && good < PROBE_GOOD_PACKETS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let next = match tokio::time::timeout(remaining, notifications.next()).await {
            Ok(Some(value)) => value,
            // Stream ended or the window expired.
            _ => break,
        };
        if next.value.len() < MOYU32_PACKET_LEN {
            continue;
        }
        seen += 1;
        if let Ok(decrypted) = cipher.decrypt(&next.value) {
            if packet_looks_valid(&decrypted) {
                good += 1;
            }
        }
        // Bail out early on a candidate that is clearly wrong.
        if seen > 8 && good == 0 {
            break;
        }
    }

    if moyu32_debug() {
        eprintln!(
            "MoYu32: candidate {} produced {}/{} plausible packets",
            format_mac(candidate),
            good,
            seen
        );
    }
    Ok(good >= PROBE_GOOD_PACKETS)
}

/// Work out which MAC this cube has, trying the cheap sources first.
async fn resolve_mac(
    device: &Peripheral,
    name: &str,
    read: &Characteristic,
    write: &Characteristic,
) -> Result<Moyu32Mac> {
    if let Some(mac) = mac_from_advertisement(device).await {
        return Ok(mac);
    }

    let candidates = mac_candidates_from_name(name);
    if candidates.is_empty() {
        return Err(anyhow!(
            "Could not determine the Bluetooth address of {}, which is needed to decrypt its traffic",
            name
        ));
    }

    // Subscribe once so the probe can watch notifications for each
    // candidate in turn.
    device.subscribe(read).await?;
    for candidate in &candidates {
        if probe_mac(device, write, candidate).await? {
            if moyu32_debug() {
                eprintln!("MoYu32: probed MAC {}", format_mac(candidate));
            }
            return Ok(*candidate);
        }
    }

    Err(anyhow!(
        "None of the {} candidate addresses for {} decrypted its traffic",
        candidates.len(),
        name
    ))
}

/// Mirror protocol events into the externally visible state and fire the
/// listener.
fn dispatch_events(
    events: Vec<Moyu32Event>,
    state: &Arc<Mutex<Cube3x3x3>>,
    battery_percentage: &Arc<Mutex<Option<u32>>>,
    synced: &Arc<Mutex<bool>>,
    move_listener: &Arc<Mutex<Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>>>,
) {
    for event in events {
        match event {
            Moyu32Event::Move {
                moves,
                state: new_state,
            } => {
                *state.lock().unwrap() = new_state.clone();
                let listener = move_listener.lock().unwrap();
                listener(BluetoothCubeEvent::Move(moves, new_state));
            }
            Moyu32Event::Facelets(new_state) => {
                // A full snapshot re-anchors the visible state without
                // producing any moves.
                *state.lock().unwrap() = new_state;
            }
            Moyu32Event::Battery(level) => {
                *battery_percentage.lock().unwrap() = Some(level);
            }
            Moyu32Event::Hardware {
                name,
                software_version,
                hardware_version,
            } => {
                if moyu32_debug() {
                    eprintln!(
                        "MoYu32: {} software {} hardware {}",
                        name, software_version, hardware_version
                    );
                }
            }
            Moyu32Event::SyncLost => {
                *synced.lock().unwrap() = false;
            }
        }
    }
}

pub(crate) async fn moyu32_connect(
    device: Peripheral,
    move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let notify_uuid = Uuid::from_str(MOYU32_NOTIFY_UUID).unwrap();
    let write_uuid = Uuid::from_str(MOYU32_WRITE_UUID).unwrap();

    let characteristics = device.characteristics();
    if moyu32_debug() {
        eprintln!("MoYu32: found {} characteristics", characteristics.len());
        for characteristic in &characteristics {
            eprintln!(
                "  characteristic: uuid={} service={}",
                characteristic.uuid, characteristic.service_uuid
            );
        }
    }

    let service_uuid = Uuid::from_str(MOYU32_SERVICE_UUID).unwrap();
    let find = |uuid: Uuid| {
        characteristics
            .iter()
            .find(|characteristic| {
                characteristic.uuid == uuid && characteristic.service_uuid == service_uuid
            })
            .cloned()
    };
    let read =
        find(notify_uuid).ok_or_else(|| anyhow!("MoYu32 notification characteristic not found"))?;
    let write =
        find(write_uuid).ok_or_else(|| anyhow!("MoYu32 command characteristic not found"))?;

    let name = device
        .properties()
        .await?
        .and_then(|props| props.local_name)
        .unwrap_or_default();

    let mac = resolve_mac(&device, &name, &read, &write).await?;
    let cipher = cipher_for_mac(&mac);

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let battery_percentage: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let synced = Arc::new(Mutex::new(true));
    let protocol = Arc::new(Mutex::new(Moyu32Protocol::new()));

    let cipher_copy = cipher.clone();
    let state_copy = state.clone();
    let battery_percentage_copy = battery_percentage.clone();
    let synced_copy = synced.clone();
    let protocol_copy = protocol.clone();
    let write_copy = write.clone();
    let device_copy = device.clone();

    // `resolve_mac` may already have subscribed while probing; btleplug
    // tolerates a repeat.
    device.subscribe(&read).await?;
    let mut notification_stream = device.notifications().await?;

    let move_listener = Arc::new(Mutex::new(move_listener));

    tokio::spawn(async move {
        while let Some(value) = notification_stream.next().await {
            if value.value.len() < MOYU32_PACKET_LEN {
                continue;
            }
            let decrypted = match cipher_copy.decrypt(&value.value) {
                Ok(decrypted) => decrypted,
                Err(_) => continue,
            };

            let (events, outgoing) = {
                let mut protocol = protocol_copy.lock().unwrap();
                protocol.handle_decrypted(&decrypted);
                (protocol.take_events(), protocol.take_outgoing())
            };

            dispatch_events(
                events,
                &state_copy,
                &battery_percentage_copy,
                &synced_copy,
                &move_listener,
            );

            for message in outgoing {
                let encrypted = match cipher_copy.encrypt(&message.bytes) {
                    Ok(encrypted) => encrypted,
                    Err(_) => continue,
                };
                let write_characteristic = write_copy.clone();
                let device_for_write = device_copy.clone();
                tokio::spawn(async move {
                    let write_type = write_type_for(&write_characteristic);
                    let _ = device_for_write
                        .write(&write_characteristic, &encrypted, write_type)
                        .await;
                });
            }
        }
    });

    // Run the init burst and wait for the first state snapshot.
    for command in build_init_sequence() {
        let encrypted = cipher.encrypt(&command)?;
        device
            .write(&write, &encrypted, write_type_for(&write))
            .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let deadline = Instant::now() + Duration::from_millis(CUBE_STATE_TIMEOUT_MS);
    loop {
        if protocol.lock().unwrap().state_set() {
            *state.lock().unwrap() = protocol.lock().unwrap().state();
            break;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("Did not receive initial cube state"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(Box::new(Moyu32Cube {
        device,
        state,
        battery_percentage,
        synced,
        protocol,
        write,
        cipher,
        last_battery_poll: Mutex::new(Instant::now()),
    }))
}
