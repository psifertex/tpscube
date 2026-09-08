//! web-sys transport for QiYi smart cubes.
//!
//! The mirror image of `native.rs`: all protocol behavior lives in
//! [`crate::bluetooth::qiyi::protocol`], and this file only locates the
//! characteristic, captures the cube's MAC from its advertisement, pumps
//! notifications through the protocol machine and writes back whatever
//! it asks to send.

use crate::bluetooth::qiyi::protocol::{
    mac_candidates_from_device_name, mac_from_manufacturer_data, QiyiEvent, QiyiProtocol,
    QIYI_CHARACTERISTIC_UUID, QIYI_MANUFACTURER_CIC, QIYI_SERVICE_UUID,
};
use crate::bluetooth::web::{
    dispatch_moves, get_characteristic, get_service, sleep_ms, subscribe_characteristic,
    write_characteristic,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent, MoveListenerHandle};
use crate::common::{InitialCubeState, TimedMove};
use crate::cube3x3x3::Cube3x3x3;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

#[allow(dead_code)]
struct QiyiCubeWeb {
    server: web_sys::BluetoothRemoteGattServer,
    protocol: Arc<Mutex<QiyiProtocol>>,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    write: web_sys::BluetoothRemoteGattCharacteristic,
}

impl BluetoothCubeDevice for QiyiCubeWeb {
    fn cube_state(&self) -> Cube3x3x3 {
        self.state.lock().unwrap().clone()
    }

    fn battery_percentage(&self) -> Option<u32> {
        *self.battery_percentage.lock().unwrap()
    }

    fn battery_charging(&self) -> Option<bool> {
        // The cube reports a charge level but no charging flag.
        None
    }

    fn reset_cube_state(&self) {
        // There is no reset command in this protocol. Assume the cube is
        // solved locally, then ask it for its real state so that we
        // resynchronize rather than silently drift if it was not.
        self.protocol.lock().unwrap().reset_state();
        *self.state.lock().unwrap() = Cube3x3x3::new();

        let hello = self.protocol.lock().unwrap().hello_message();
        let write = self.write.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = write_characteristic(&write, &hello).await;
        });
    }

    fn synced(&self) -> bool {
        true
    }

    fn disconnect(&self) {
        self.server.disconnect();
    }
}

/// Capture the cube's MAC address from its BLE advertisement, which is
/// where the hello packet's address field comes from.
///
/// Must be called *before* the GATT connection: the cube stops
/// advertising once connected. Returns `None` when
/// `watchAdvertisements()` is unavailable or nothing arrives in time, in
/// which case the name-derived fallback in [`qiyi_web_connect`] takes
/// over.
pub(crate) async fn capture_qiyi_mac(device: &web_sys::BluetoothDevice) -> Option<[u8; 6]> {
    let abort_controller = web_sys::AbortController::new().ok()?;
    let signal = abort_controller.signal();
    let abort_clone = abort_controller.clone();

    let result: Arc<Mutex<Option<[u8; 6]>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    let closure = Closure::wrap(Box::new(move |event: web_sys::Event| {
        let adv_event: web_sys::BluetoothAdvertisingEvent = event.unchecked_into();
        let manufacturer_data = adv_event.manufacturer_data();

        // Bluefy (the iOS Web Bluetooth browser) hands back a raw
        // DataView instead of a BluetoothManufacturerDataMap. Its layout
        // is [CIC lo, CIC hi, payload…], so the address starts at byte
        // 2 rather than byte 0.
        let mf_raw: &JsValue = manufacturer_data.as_ref();
        if let Some(dv) = mf_raw.dyn_ref::<js_sys::DataView>() {
            let len = dv.byte_length() as usize;
            if len >= 8 {
                let payload: Vec<u8> = (2..8).map(|i| dv.get_uint8(i)).collect();
                if let Some(mac) = mac_from_manufacturer_data(&payload) {
                    *result_clone.lock().unwrap() = Some(mac);
                    abort_clone.abort();
                }
            }
            return;
        }

        if manufacturer_data.has(QIYI_MANUFACTURER_CIC) {
            if let Some(data_view) = manufacturer_data.get(QIYI_MANUFACTURER_CIC) {
                let len = data_view.byte_length() as usize;
                if len >= 6 {
                    let payload: Vec<u8> = (0..6).map(|i| data_view.get_uint8(i)).collect();
                    if let Some(mac) = mac_from_manufacturer_data(&payload) {
                        *result_clone.lock().unwrap() = Some(mac);
                        abort_clone.abort();
                    }
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
        web_sys::console::log_1(
            &"QiYi: watchAdvertisements unavailable, falling back to name-derived address".into(),
        );
        closure.forget();
        return None;
    }

    // Same budget as the GAN capture: long enough for desktop Chrome,
    // short enough not to stall the connect flow when it never arrives.
    for _ in 0..10 {
        sleep_ms(200).await;
        if result.lock().unwrap().is_some() {
            break;
        }
    }

    let captured = *result.lock().unwrap();
    if captured.is_none() {
        abort_controller.abort();
    }
    closure.forget();
    captured
}

pub(crate) async fn qiyi_web_connect(
    server: web_sys::BluetoothRemoteGattServer,
    device_name: String,
    advertised_mac: Option<[u8; 6]>,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let service = get_service(&server, QIYI_SERVICE_UUID).await?;
    let cube_characteristic = get_characteristic(&service, QIYI_CHARACTERISTIC_UUID).await?;

    // The advertisement is authoritative. Without it, the name suffix
    // encodes the last two address bytes for every hardware line we
    // know about, so the first candidate is very likely correct.
    let mac = match advertised_mac {
        Some(mac) => mac,
        None => mac_candidates_from_device_name(&device_name)
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Could not determine QiYi cube address"))?,
    };

    let protocol = Arc::new(Mutex::new(QiyiProtocol::new(mac)));
    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let battery_percentage: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));

    let protocol_copy = protocol.clone();
    let state_copy = state.clone();
    let battery_percentage_copy = battery_percentage.clone();
    let listeners_copy = listeners.clone();
    let write_for_handler = cube_characteristic.clone();

    subscribe_characteristic(&cube_characteristic, move |value| {
        let (events, outgoing) = {
            let mut proto = protocol_copy.lock().unwrap();
            proto.handle_notification(&value);
            (proto.take_events(), proto.take_outgoing())
        };

        // Acknowledgements first: the cube retransmits and stalls if it
        // does not hear back promptly.
        for msg in outgoing {
            let write = write_for_handler.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = write_characteristic(&write, &msg.bytes).await;
            });
        }

        let mut moves = Vec::new();
        let mut latest_state = None;
        for event in events {
            match event {
                QiyiEvent::Facelets(cube) => {
                    *state_copy.lock().unwrap() = cube;
                }
                QiyiEvent::Move { mv, state } => {
                    moves.push(TimedMove::new(mv.mv, mv.delta_ms));
                    latest_state = Some(state);
                }
                QiyiEvent::Battery(level) => {
                    *battery_percentage_copy.lock().unwrap() = Some(level);
                }
            }
        }

        if let Some(new_state) = latest_state {
            *state_copy.lock().unwrap() = new_state.clone();
            dispatch_moves(&listeners_copy, moves, new_state);
        }
    })
    .await?;

    // Ask the cube for its state. This doubles as the handshake — until
    // it is answered the cube sends nothing at all.
    let mut attempts = 0;
    loop {
        let hello = protocol.lock().unwrap().hello_message();
        write_characteristic(&cube_characteristic, &hello).await?;

        sleep_ms(300).await;

        if protocol.lock().unwrap().state_set() {
            *state.lock().unwrap() = protocol.lock().unwrap().state();
            *battery_percentage.lock().unwrap() = protocol.lock().unwrap().battery_percentage();
            break;
        }

        attempts += 1;
        if attempts > 10 {
            return Err(anyhow!("Did not receive initial cube state"));
        }
    }

    Ok(Box::new(QiyiCubeWeb {
        server,
        protocol,
        state,
        battery_percentage,
        write: cube_characteristic,
    }))
}
