//! Web Bluetooth transport for MoYu32 cubes.
//!
//! Mirrors `native.rs`: find the MAC, subscribe, decrypt, feed
//! `Moyu32Protocol`, write back what it asks for. All parsing lives in
//! `protocol.rs`.

use crate::bluetooth::moyu32::cipher::{
    cipher_for_mac, format_mac, mac_candidates_from_name, mac_from_manufacturer_data, Moyu32Mac,
};
use crate::bluetooth::moyu32::protocol::{
    build_init_sequence, build_simple_request, packet_looks_valid, Moyu32Event, Moyu32Protocol,
    MOYU32_NOTIFY_UUID, MOYU32_PACKET_LEN, MOYU32_SERVICE_UUID, MOYU32_WRITE_UUID, OP_BATTERY,
    OP_FACELETS, OP_HARDWARE,
};
use crate::bluetooth::web::{
    dispatch_moves, sleep_ms, subscribe_characteristic, write_characteristic,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent, MoveListenerHandle};
use crate::common::InitialCubeState;
use crate::cube3x3x3::Cube3x3x3;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// How long to wait for the first state snapshot, in 200ms steps.
const CUBE_STATE_TIMEOUT_STEPS: usize = 25;

/// The cube never pushes battery updates, so poll it.
const BATTERY_POLL_INTERVAL_MS: u32 = 60_000;

type Listeners = Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>;

#[allow(dead_code)]
struct Moyu32CubeWeb {
    server: web_sys::BluetoothRemoteGattServer,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
    protocol: Arc<Mutex<Moyu32Protocol>>,
    write: web_sys::BluetoothRemoteGattCharacteristic,
    cipher: crate::bluetooth::gan::cipher::GanV2Cipher,
}

impl BluetoothCubeDevice for Moyu32CubeWeb {
    fn cube_state(&self) -> Cube3x3x3 {
        self.state.lock().unwrap().clone()
    }

    fn battery_percentage(&self) -> Option<u32> {
        *self.battery_percentage.lock().unwrap()
    }

    fn battery_charging(&self) -> Option<bool> {
        None
    }

    fn reset_cube_state(&self) {
        // No reset command exists, so take the user's word that the cube
        // is solved and ask it for a confirming snapshot.
        let outgoing = {
            let mut protocol = self.protocol.lock().unwrap();
            protocol.assume_solved();
            protocol.take_outgoing()
        };
        *self.state.lock().unwrap() = Cube3x3x3::new();
        for message in outgoing {
            if let Ok(encrypted) = self.cipher.encrypt(&message.bytes) {
                let write = self.write.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = write_characteristic(&write, &encrypted).await;
                });
            }
        }
    }

    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }

    fn disconnect(&self) {
        self.server.disconnect();
    }
}

/// Capture the cube's MAC from a BLE advertisement.
///
/// Must be called before connecting to GATT — the cube stops advertising
/// once connected. Unlike GAN, the company identifier is not a fixed
/// pattern (`0x0000` while unbound, derived from the owner's account id
/// afterwards), so every entry in the map is considered and the payload
/// itself decides.
pub(crate) async fn moyu32_capture_mac(device: &web_sys::BluetoothDevice) -> Option<Moyu32Mac> {
    let abort_controller = web_sys::AbortController::new().ok()?;
    let signal = abort_controller.signal();

    let result: Arc<Mutex<Option<Moyu32Mac>>> = Arc::new(Mutex::new(None));
    let result_for_closure = result.clone();
    let abort_for_closure = abort_controller.clone();

    let closure = Closure::wrap(Box::new(move |event: web_sys::Event| {
        let event: web_sys::BluetoothAdvertisingEvent = event.unchecked_into();
        let manufacturer_data = event.manufacturer_data();

        // Bluefy on iOS hands back a raw DataView (company id still
        // attached) instead of a BluetoothManufacturerDataMap. Reading
        // the address from the end of the payload handles both shapes.
        let raw: &JsValue = manufacturer_data.as_ref();
        if let Some(view) = raw.dyn_ref::<js_sys::DataView>() {
            let len = view.byte_length() as usize;
            let bytes: Vec<u8> = (0..len).map(|i| view.get_uint8(i)).collect();
            if let Some(mac) = mac_from_manufacturer_data(&bytes) {
                web_sys::console::log_1(
                    &format!("MoYu32: captured MAC {} (DataView path)", format_mac(&mac)).into(),
                );
                *result_for_closure.lock().unwrap() = Some(mac);
                abort_for_closure.abort();
            }
            return;
        }

        // Standard path. The company id varies per cube, so scan them all.
        for company in 0u32..=0xFFFF {
            let company = company as u16;
            if !manufacturer_data.has(company) {
                continue;
            }
            if let Some(view) = manufacturer_data.get(company) {
                let len = view.byte_length() as usize;
                let bytes: Vec<u8> = (0..len).map(|i| view.get_uint8(i)).collect();
                if let Some(mac) = mac_from_manufacturer_data(&bytes) {
                    web_sys::console::log_1(
                        &format!(
                            "MoYu32: captured MAC {} from company id 0x{:04x}",
                            format_mac(&mac),
                            company
                        )
                        .into(),
                    );
                    *result_for_closure.lock().unwrap() = Some(mac);
                    abort_for_closure.abort();
                    return;
                }
            }
        }
    }) as Box<dyn Fn(web_sys::Event)>);

    device
        .add_event_listener_with_callback("advertisementreceived", closure.as_ref().unchecked_ref())
        .ok()?;

    let options = web_sys::WatchAdvertisementsOptions::new();
    options.set_signal(&signal);
    if JsFuture::from(device.watch_advertisements_with_options(&options))
        .await
        .is_err()
    {
        web_sys::console::log_1(&"MoYu32: watchAdvertisements unavailable".into());
        closure.forget();
        return None;
    }

    for _ in 0..10 {
        sleep_ms(200).await;
        if result.lock().unwrap().is_some() {
            break;
        }
    }

    if result.lock().unwrap().is_none() {
        web_sys::console::log_1(&"MoYu32: no advertisement with a usable address".into());
        abort_controller.abort();
    }
    closure.forget();

    let captured = *result.lock().unwrap();
    captured
}

fn dispatch_events(
    events: Vec<Moyu32Event>,
    state: &Arc<Mutex<Cube3x3x3>>,
    battery_percentage: &Arc<Mutex<Option<u32>>>,
    synced: &Arc<Mutex<bool>>,
    listeners: &Listeners,
) {
    for event in events {
        match event {
            Moyu32Event::Move {
                moves,
                state: new_state,
            } => {
                *state.lock().unwrap() = new_state.clone();
                dispatch_moves(listeners, moves, new_state);
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
                web_sys::console::log_1(
                    &format!(
                        "MoYu32: {} software {} hardware {}",
                        name, software_version, hardware_version
                    )
                    .into(),
                );
            }
            Moyu32Event::SyncLost => {
                *synced.lock().unwrap() = false;
            }
        }
    }
}

/// Get all characteristics of a service in one GATT round trip.
async fn all_characteristics(
    service: &web_sys::BluetoothRemoteGattService,
) -> Vec<web_sys::BluetoothRemoteGattCharacteristic> {
    match JsFuture::from(service.get_characteristics()).await {
        Ok(characteristics) => {
            let array: js_sys::Array = characteristics.unchecked_into();
            (0..array.length())
                .map(|i| array.get(i).unchecked_into())
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

/// Find a characteristic by UUID fragment. Case-insensitive because
/// Bluefy reports short uppercase UUIDs while Chrome reports full
/// lowercase ones.
fn find_characteristic(
    characteristics: &[web_sys::BluetoothRemoteGattCharacteristic],
    uuid: &str,
) -> Option<web_sys::BluetoothRemoteGattCharacteristic> {
    let needle = uuid.to_lowercase();
    characteristics
        .iter()
        .find(|characteristic| characteristic.uuid().to_lowercase() == needle)
        .cloned()
}

/// Test each candidate address in turn by prodding the cube with the
/// init burst encrypted under that key and seeing whether the replies
/// decrypt to structurally valid packets.
///
/// This is the fallback for browsers where `watchAdvertisements` never
/// delivers (notably iOS), and it works because the candidate set derived
/// from the advertised name has only three entries.
async fn probe_mac(
    read: &web_sys::BluetoothRemoteGattCharacteristic,
    write: &web_sys::BluetoothRemoteGattCharacteristic,
    candidates: &[Moyu32Mac],
) -> Option<Moyu32Mac> {
    /// How many valid packets a candidate must produce to be believed.
    const GOOD_PACKETS: usize = 3;

    let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let probing = Arc::new(Mutex::new(true));

    {
        let captured = captured.clone();
        let probing = probing.clone();
        subscribe_characteristic(read, move |value| {
            if *probing.lock().unwrap() {
                captured.lock().unwrap().push(value);
            }
        })
        .await
        .ok()?;
    }

    let mut found = None;
    'candidates: for candidate in candidates {
        let cipher = cipher_for_mac(candidate);
        captured.lock().unwrap().clear();

        // Two bursts: some firmware ignores the first one entirely.
        for _ in 0..2 {
            for opcode in [OP_HARDWARE, OP_FACELETS, OP_BATTERY].iter() {
                match cipher.encrypt(&build_simple_request(*opcode)) {
                    Ok(encrypted) => {
                        if write_characteristic(write, &encrypted).await.is_err() {
                            continue 'candidates;
                        }
                    }
                    Err(_) => continue 'candidates,
                }
            }
        }

        for _ in 0..10 {
            sleep_ms(200).await;
            let good = captured
                .lock()
                .unwrap()
                .iter()
                .filter(|packet| {
                    packet.len() >= MOYU32_PACKET_LEN
                        && cipher
                            .decrypt(packet)
                            .map(|decrypted| packet_looks_valid(&decrypted))
                            .unwrap_or(false)
                })
                .count();
            if good >= GOOD_PACKETS {
                web_sys::console::log_1(
                    &format!("MoYu32: probed MAC {}", format_mac(candidate)).into(),
                );
                found = Some(*candidate);
                break 'candidates;
            }
        }
    }

    // Stop feeding the probe buffer; the real handler takes over.
    *probing.lock().unwrap() = false;
    found
}

pub(crate) async fn moyu32_web_connect(
    server: web_sys::BluetoothRemoteGattServer,
    device_name: String,
    mac: Option<Moyu32Mac>,
    listeners: Listeners,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let service: web_sys::BluetoothRemoteGattService =
        JsFuture::from(server.get_primary_service_with_str(MOYU32_SERVICE_UUID))
            .await
            .map_err(|_| anyhow!("MoYu32 service not found"))?
            .unchecked_into();
    let characteristics = all_characteristics(&service).await;
    let read_char = find_characteristic(&characteristics, MOYU32_NOTIFY_UUID)
        .ok_or_else(|| anyhow!("MoYu32 notification characteristic not found"))?;
    let write_char = find_characteristic(&characteristics, MOYU32_WRITE_UUID)
        .ok_or_else(|| anyhow!("MoYu32 command characteristic not found"))?;

    // Without the address there is no key. The advertisement is the
    // reliable source; when the browser never delivered one, fall back to
    // probing the handful of addresses the device name implies.
    let mac = match mac {
        Some(mac) => mac,
        None => {
            let candidates = mac_candidates_from_name(&device_name);
            if candidates.is_empty() {
                return Err(anyhow!(
                    "Could not read the Bluetooth address of {} from its advertisement, \
                     which is required to decrypt its traffic",
                    device_name
                ));
            }
            probe_mac(&read_char, &write_char, &candidates)
                .await
                .ok_or_else(|| {
                    anyhow!(
                        "None of the {} candidate addresses for {} decrypted its traffic",
                        candidates.len(),
                        device_name
                    )
                })?
        }
    };
    web_sys::console::log_1(&format!("MoYu32: using MAC {}", format_mac(&mac)).into());
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
    let write_for_handler = write_char.clone();
    let listeners_copy = listeners.clone();

    subscribe_characteristic(&read_char, move |value| {
        if value.len() < MOYU32_PACKET_LEN {
            return;
        }
        let decrypted = match cipher_copy.decrypt(&value) {
            Ok(decrypted) => decrypted,
            Err(_) => return,
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
            &listeners_copy,
        );

        for message in outgoing {
            if let Ok(encrypted) = cipher_copy.encrypt(&message.bytes) {
                let write = write_for_handler.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = write_characteristic(&write, &encrypted).await;
                });
            }
        }
    })
    .await?;

    for command in build_init_sequence() {
        let encrypted = cipher.encrypt(&command)?;
        write_characteristic(&write_char, &encrypted).await?;
    }

    let mut steps = 0;
    loop {
        sleep_ms(200).await;
        if protocol.lock().unwrap().state_set() {
            *state.lock().unwrap() = protocol.lock().unwrap().state();
            break;
        }
        steps += 1;
        if steps > CUBE_STATE_TIMEOUT_STEPS {
            return Err(anyhow!("Did not receive initial cube state"));
        }
        // Nudge the cube once a second rather than every 200ms; some BLE
        // stacks drop the connection if the command queue backs up.
        if steps % 5 == 0 {
            let encrypted = cipher.encrypt(&build_simple_request(OP_FACELETS))?;
            write_characteristic(&write_char, &encrypted).await?;
        }
    }

    // Poll the battery for as long as the connection lives.
    {
        let cipher_for_poll = cipher.clone();
        let write_for_poll = write_char.clone();
        let server_for_poll = server.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                sleep_ms(BATTERY_POLL_INTERVAL_MS).await;
                if !server_for_poll.connected() {
                    break;
                }
                if let Ok(encrypted) = cipher_for_poll.encrypt(&build_simple_request(OP_BATTERY)) {
                    if write_characteristic(&write_for_poll, &encrypted)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
    }

    Ok(Box::new(Moyu32CubeWeb {
        server,
        state,
        battery_percentage,
        synced,
        protocol,
        write: write_char,
        cipher,
    }))
}
