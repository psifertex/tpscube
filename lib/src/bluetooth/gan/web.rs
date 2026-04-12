use crate::bluetooth::gan::cipher::{GanV2Cipher, GanV3Cipher};
use crate::bluetooth::gan::gen34_protocol::{
    Gen34Event, Gen34Protocol, Gen34Wire, Gen3Wire, Gen4Wire,
};
use crate::bluetooth::web::{
    dispatch_event, dispatch_moves, discover_all_characteristics, find_characteristic,
    get_characteristic, get_service, read_characteristic, sleep_ms, subscribe_characteristic,
    write_characteristic,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent, MoveListenerHandle};
use crate::common::{Corner, CornerPiece, Cube, InitialCubeState, Move, TimedMove};
use crate::cube3x3x3::{Cube3x3x3, Edge3x3x3, EdgePiece3x3x3};
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Block,
};
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::iter::FromIterator;
use std::sync::{Arc, Mutex};

// ---- GAN v2 (notification-based, newer cubes) ----

#[allow(dead_code)]
struct GANCubeVersion2Web {
    server: web_sys::BluetoothRemoteGattServer,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    battery_charging: Arc<Mutex<Option<bool>>>,
    synced: Arc<Mutex<bool>>,
    write: web_sys::BluetoothRemoteGattCharacteristic,
    cipher: GANCubeVersion2Cipher,
}

#[derive(Clone)]
struct GANCubeVersion2Cipher {
    device_key: [u8; 16],
    device_iv: [u8; 16],
}

impl GANCubeVersion2Cipher {
    fn decrypt(&self, value: &[u8]) -> Result<Vec<u8>> {
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

    fn encrypt(&self, value: &[u8]) -> Result<Vec<u8>> {
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

impl GANCubeVersion2Web {
    const CUBE_MOVES_MESSAGE: u8 = 2;
    const CUBE_STATE_MESSAGE: u8 = 4;
    const BATTERY_STATE_MESSAGE: u8 = 9;
    const RESET_CUBE_STATE_MESSAGE: u8 = 10;

    fn extract_bits(data: &[u8], start: usize, count: usize) -> u32 {
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
}

impl BluetoothCubeDevice for GANCubeVersion2Web {
    fn cube_state(&self) -> Cube3x3x3 {
        self.state.lock().unwrap().clone()
    }

    fn battery_percentage(&self) -> Option<u32> {
        *self.battery_percentage.lock().unwrap()
    }

    fn battery_charging(&self) -> Option<bool> {
        *self.battery_charging.lock().unwrap()
    }

    fn reset_cube_state(&self) {
        let message: [u8; 20] = [
            Self::RESET_CUBE_STATE_MESSAGE,
            0x05,
            0x39,
            0x77,
            0x00,
            0x00,
            0x01,
            0x23,
            0x45,
            0x67,
            0x89,
            0xab,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        if let Ok(message) = self.cipher.encrypt(&message) {
            let write = self.write.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = write_characteristic(&write, &message).await;
            });
        }
        *self.state.lock().unwrap() = Cube3x3x3::new();
    }

    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }

    fn disconnect(&self) {
        self.server.disconnect();
    }
}

// ---- GAN v3 / v4 (shared Gen34Protocol) ----
//
// Both Gen3 and Gen4 cubes share the `Gen34Protocol` state machine in
// `crate::bluetooth::gan::gen34_protocol`. The web-side code here only
// handles:
//
//   * Key derivation (reading manufacturer data via
//     `read_gan_v2_device_key` or taking a user-provided key, and
//     mixing via `GanV{2,3}Cipher::from_device_key`)
//   * The web-sys notification callback wiring
//   * The `BluetoothCubeDevice` impl (state/battery/synced, reset,
//     disconnect)
//
// All protocol-layer logic lives in the shared module.

#[allow(dead_code)]
struct GANCubeVersion3Web {
    server: web_sys::BluetoothRemoteGattServer,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
    write: web_sys::BluetoothRemoteGattCharacteristic,
    cipher: GanV3Cipher,
}

impl BluetoothCubeDevice for GANCubeVersion3Web {
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
        let cmd = Gen34Protocol::<Gen3Wire>::build_reset_request();
        let mut plaintext = [0u8; 16];
        plaintext.copy_from_slice(&cmd);
        let encrypted = self.cipher.encrypt(&plaintext);
        let write = self.write.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = write_characteristic(&write, &encrypted).await;
        });
        *self.state.lock().unwrap() = Cube3x3x3::new();
    }
    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }
    fn disconnect(&self) {
        self.server.disconnect();
    }
}

#[allow(dead_code)]
struct GANCubeVersion4Web {
    server: web_sys::BluetoothRemoteGattServer,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
    write: web_sys::BluetoothRemoteGattCharacteristic,
    cipher: GanV2Cipher,
}

impl BluetoothCubeDevice for GANCubeVersion4Web {
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
        let cmd = Gen34Protocol::<Gen4Wire>::build_reset_request();
        if let Ok(encrypted) = self.cipher.encrypt(&cmd) {
            let write = self.write.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = write_characteristic(&write, &encrypted).await;
            });
        }
        *self.state.lock().unwrap() = Cube3x3x3::new();
    }
    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }
    fn disconnect(&self) {
        self.server.disconnect();
    }
}

/// Encrypt a Gen3 plaintext command.
fn encrypt_gen3_cmd_web(cipher: &GanV3Cipher, plaintext: &[u8]) -> [u8; 16] {
    assert_eq!(plaintext.len(), 16, "Gen3 command must be 16 bytes");
    let mut buf = [0u8; 16];
    buf.copy_from_slice(plaintext);
    cipher.encrypt(&buf)
}

/// Shared event-drain helper for Gen3/Gen4 on web. Mirrors protocol
/// events into the external state mutex and fires the listener
/// dispatcher.
fn dispatch_gen34_events_web<W: Gen34Wire>(
    events: Vec<Gen34Event>,
    state: &Arc<Mutex<Cube3x3x3>>,
    battery_percentage: &Arc<Mutex<Option<u32>>>,
    synced: &Arc<Mutex<bool>>,
    protocol: &Arc<Mutex<Gen34Protocol<W>>>,
    listeners: &Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) {
    for event in events {
        match event {
            Gen34Event::Move { moves, state: new_state } => {
                *state.lock().unwrap() = new_state.clone();
                dispatch_moves(listeners, moves, new_state);
            }
            Gen34Event::Battery(pct) => {
                *battery_percentage.lock().unwrap() = Some(pct);
            }
            Gen34Event::Disconnected | Gen34Event::SyncLost => {
                *synced.lock().unwrap() = false;
            }
        }
    }
    *state.lock().unwrap() = protocol.lock().unwrap().state();
}

async fn try_gan_v4_connect(
    server: &web_sys::BluetoothRemoteGattServer,
    read_char: web_sys::BluetoothRemoteGattCharacteristic,
    write_char: web_sys::BluetoothRemoteGattCharacteristic,
    user_device_key: Option<[u8; 6]>,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let device_key: [u8; 6] = if let Some(key) = user_device_key {
        key
    } else {
        match read_gan_v2_device_key(server).await {
            Ok(key) => key,
            Err(_) => {
                web_sys::console::log_1(
                    &"GAN v4: no device key available, using zeros. \
                      Set your GAN cube MAC address in Settings for web support."
                        .into(),
                );
                [0u8; 6]
            }
        }
    };

    let cipher = GanV2Cipher::from_device_key(&device_key);

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let battery_percentage: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let synced = Arc::new(Mutex::new(true));
    let protocol: Arc<Mutex<Gen34Protocol<Gen4Wire>>> =
        Arc::new(Mutex::new(Gen34Protocol::new()));

    let cipher_copy = cipher.clone();
    let state_copy = state.clone();
    let battery_percentage_copy = battery_percentage.clone();
    let synced_copy = synced.clone();
    let protocol_copy = protocol.clone();
    let write_for_handler = write_char.clone();
    let listeners_copy = listeners.clone();

    subscribe_characteristic(&read_char, move |value| {
        if value.len() < 16 {
            return;
        }
        let decrypted = match cipher_copy.decrypt(&value) {
            Ok(d) => d,
            Err(_) => return,
        };

        let (events, outgoing) = {
            let mut proto = protocol_copy.lock().unwrap();
            proto.handle_decrypted(&decrypted);
            (proto.take_events(), proto.take_outgoing())
        };

        dispatch_gen34_events_web(
            events,
            &state_copy,
            &battery_percentage_copy,
            &synced_copy,
            &protocol_copy,
            &listeners_copy,
        );

        for msg in outgoing {
            if let Ok(encrypted) = cipher_copy.encrypt(&msg.bytes) {
                let write = write_for_handler.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = write_characteristic(&write, &encrypted).await;
                });
            }
        }
    })
    .await?;

    // Request initial cube state
    let mut loop_count = 0;
    loop {
        let cmd = Gen34Protocol::<Gen4Wire>::build_state_request();
        let encrypted = cipher.encrypt(&cmd)?;
        write_characteristic(&write_char, &encrypted).await?;

        sleep_ms(200).await;

        if protocol.lock().unwrap().state_set() {
            *state.lock().unwrap() = protocol.lock().unwrap().state();
            break;
        }

        loop_count += 1;
        if loop_count > 10 {
            return Err(anyhow!("Did not receive initial cube state"));
        }
    }

    // Request battery state
    let cmd = Gen34Protocol::<Gen4Wire>::build_battery_request();
    let encrypted = cipher.encrypt(&cmd)?;
    write_characteristic(&write_char, &encrypted).await?;

    Ok(Box::new(GANCubeVersion4Web {
        server: server.clone(),
        state,
        battery_percentage,
        synced,
        write: write_char,
        cipher,
    }))
}

async fn try_gan_v3_connect(
    server: &web_sys::BluetoothRemoteGattServer,
    read_char: web_sys::BluetoothRemoteGattCharacteristic,
    write_char: web_sys::BluetoothRemoteGattCharacteristic,
    user_device_key: Option<[u8; 6]>,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let device_key: [u8; 6] = if let Some(key) = user_device_key {
        key
    } else {
        match read_gan_v2_device_key(server).await {
            Ok(key) => key,
            Err(_) => {
                web_sys::console::log_1(
                    &"GAN v3: no device key available, using zeros. \
                      Set your GAN cube MAC address in Settings for web support."
                        .into(),
                );
                [0u8; 6]
            }
        }
    };

    let cipher = GanV3Cipher::from_device_key(&device_key);

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let battery_percentage: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let synced = Arc::new(Mutex::new(true));
    let protocol: Arc<Mutex<Gen34Protocol<Gen3Wire>>> =
        Arc::new(Mutex::new(Gen34Protocol::new()));

    let cipher_copy = cipher.clone();
    let state_copy = state.clone();
    let battery_percentage_copy = battery_percentage.clone();
    let synced_copy = synced.clone();
    let protocol_copy = protocol.clone();
    let write_for_handler = write_char.clone();
    let listeners_copy = listeners.clone();

    subscribe_characteristic(&read_char, move |value| {
        if value.len() != 16 {
            return;
        }
        let decrypted = match cipher_copy.decrypt(&value) {
            Ok(d) => d,
            Err(_) => return,
        };

        let (events, outgoing) = {
            let mut proto = protocol_copy.lock().unwrap();
            proto.handle_decrypted(&decrypted);
            (proto.take_events(), proto.take_outgoing())
        };

        dispatch_gen34_events_web(
            events,
            &state_copy,
            &battery_percentage_copy,
            &synced_copy,
            &protocol_copy,
            &listeners_copy,
        );

        for msg in outgoing {
            let encrypted = encrypt_gen3_cmd_web(&cipher_copy, &msg.bytes);
            let write = write_for_handler.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = write_characteristic(&write, &encrypted).await;
            });
        }
    })
    .await?;

    // Request initial cube state
    let mut loop_count = 0;
    loop {
        let cmd = Gen34Protocol::<Gen3Wire>::build_state_request();
        let encrypted = encrypt_gen3_cmd_web(&cipher, &cmd);
        write_characteristic(&write_char, &encrypted).await?;

        sleep_ms(200).await;

        if protocol.lock().unwrap().state_set() {
            *state.lock().unwrap() = protocol.lock().unwrap().state();
            break;
        }

        loop_count += 1;
        if loop_count > 10 {
            return Err(anyhow!("Did not receive initial cube state"));
        }
    }

    // Request battery state
    let cmd = Gen34Protocol::<Gen3Wire>::build_battery_request();
    let encrypted = encrypt_gen3_cmd_web(&cipher, &cmd);
    write_characteristic(&write_char, &encrypted).await?;

    Ok(Box::new(GANCubeVersion3Web {
        server: server.clone(),
        state,
        battery_percentage,
        synced,
        write: write_char,
        cipher,
    }))
}

// ---- GAN Smart Timer ----

struct GANSmartTimerWeb {
    server: web_sys::BluetoothRemoteGattServer,
}

impl BluetoothCubeDevice for GANSmartTimerWeb {
    fn timer_only(&self) -> bool {
        true
    }

    fn cube_state(&self) -> Cube3x3x3 {
        Cube3x3x3::new()
    }

    fn battery_percentage(&self) -> Option<u32> {
        None
    }

    fn battery_charging(&self) -> Option<bool> {
        None
    }

    fn reset_cube_state(&self) {}

    fn synced(&self) -> bool {
        true
    }

    fn disconnect(&self) {
        self.server.disconnect();
    }
}

// ---- GAN v1 (polling-based, older cubes) ----
// Note: GAN v1 cubes use a polling model which doesn't translate well to Web Bluetooth.
// Web Bluetooth works best with notifications. For v1 cubes we can still read
// characteristics but we won't have real-time move updates without polling.
// For now, v1 is not supported on web - users should use newer GAN cubes.

// ---- Connection logic ----

pub(crate) async fn gan_web_connect(
    server: web_sys::BluetoothRemoteGattServer,
    _device_name: String,
    user_device_key: Option<[u8; 6]>,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    // Discover all characteristics, same approach as native btleplug code
    let all_chars = discover_all_characteristics(&server).await;

    // Match characteristics by UUID, mirroring native gan_cube_connect
    let v1_version = find_characteristic(&all_chars, "00002a28-0000-1000-8000-00805f9b34fb");
    let v2_write = find_characteristic(&all_chars, "28be4a4a-cd67-11e9-a32f-2a2ae2dbcce4");
    let v2_read = find_characteristic(&all_chars, "28be4cb6-cd67-11e9-a32f-2a2ae2dbcce4");
    let v3_write = find_characteristic(&all_chars, "8653000c-43e6-47b7-9cb0-5fc21d4ae340");
    let v3_read = find_characteristic(&all_chars, "8653000b-43e6-47b7-9cb0-5fc21d4ae340");

    // Gen4 uses characteristic UUIDs 0000fff5 and 0000fff6 under a different service.
    // We detect Gen4 by checking for the Gen4 service UUID 00000010-0000-fff7-fff6-fff5fff4fff0.
    // Web Bluetooth characteristics include service info, so we check the service.
    let v4_service = try_get_service(&server, "00000010-0000-fff7-fff6-fff5fff4fff0").await;
    let (v4_write, v4_read) = if let Some(ref svc) = v4_service {
        let w = try_get_char(svc, "0000fff5-0000-1000-8000-00805f9b34fb").await;
        let r = try_get_char(svc, "0000fff6-0000-1000-8000-00805f9b34fb").await;
        (w, r)
    } else {
        (None, None)
    };

    // For v1, only use 0000fff5 if we did NOT detect Gen4 (since they share the UUID)
    let v1_last_moves = if v4_write.is_none() {
        find_characteristic(&all_chars, "0000fff5-0000-1000-8000-00805f9b34fb")
    } else {
        None
    };

    // GAN v4 cube (Gen4 protocol) - check before v2 for backward compatibility
    if let (Some(write_char), Some(read_char)) = (v4_write, v4_read) {
        return try_gan_v4_connect(&server, read_char, write_char, user_device_key, listeners).await;
    }

    // GAN v3 cube (Gen3 protocol)
    if let (Some(write_char), Some(read_char)) = (v3_write, v3_read) {
        return try_gan_v3_connect(&server, read_char, write_char, user_device_key, listeners).await;
    }

    // GAN v2 cube (notification-based)
    if let (Some(write_char), Some(read_char)) = (v2_write, v2_read) {
        return try_gan_v2_connect(&server, read_char, write_char, user_device_key, listeners).await;
    }

    // GAN Smart Timer (v1 service, version 2.0)
    if let (Some(version_char), Some(updates_char)) = (v1_version, v1_last_moves) {
        let version = read_characteristic(&version_char).await?;
        if version.len() >= 3 && version[0] == 2 && version[1] == 0 {
            return try_gan_v1_as_timer_with_char(updates_char, listeners).await;
        }
    }

    Err(anyhow!(
        "Could not connect to GAN cube. Check the browser console for details."
    ))
}

/// Try to get a service by UUID, returning None on failure instead of Err.
async fn try_get_service(
    server: &web_sys::BluetoothRemoteGattServer,
    uuid: &str,
) -> Option<web_sys::BluetoothRemoteGattService> {
    get_service(server, uuid).await.ok()
}

/// Try to get a characteristic from a service, returning None on failure.
async fn try_get_char(
    service: &web_sys::BluetoothRemoteGattService,
    uuid: &str,
) -> Option<web_sys::BluetoothRemoteGattCharacteristic> {
    get_characteristic(service, uuid).await.ok()
}



async fn try_gan_v2_connect(
    server: &web_sys::BluetoothRemoteGattServer,
    read_char: web_sys::BluetoothRemoteGattCharacteristic,
    write_char: web_sys::BluetoothRemoteGattCharacteristic,
    user_device_key: Option<[u8; 6]>,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {

    // Derive 6-byte device key for AES encryption. Try sources in priority order:
    // 1. User-provided device key (MAC address from Settings)
    // 2. System ID characteristic
    // 3. All zeros (will likely fail to decrypt)
    let device_key: [u8; 6] = if let Some(key) = user_device_key {
        key
    } else {
        match read_gan_v2_device_key(server).await {
            Ok(key) => key,
            Err(_) => {
                web_sys::console::log_1(
                    &"GAN v2: no device key available, using zeros. \
                      Set your GAN cube MAC address in Settings for web support."
                        .into(),
                );
                [0u8; 6]
            }
        }
    };

    const GAN_V2_KEY: [u8; 16] = [
        0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11,
        0x12, 0x53,
    ];
    const GAN_V2_IV: [u8; 16] = [
        0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12,
        0x02, 0x43,
    ];
    let mut key = GAN_V2_KEY;
    let mut iv = GAN_V2_IV;
    for (idx, byte) in device_key.iter().enumerate() {
        key[idx] = ((key[idx] as u16 + *byte as u16) % 255) as u8;
        iv[idx] = ((iv[idx] as u16 + *byte as u16) % 255) as u8;
    }
    let cipher = GANCubeVersion2Cipher {
        device_key: key,
        device_iv: iv,
    };

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let state_set = Arc::new(Mutex::new(false));
    let battery_percentage = Arc::new(Mutex::new(None));
    let battery_charging = Arc::new(Mutex::new(None));
    let last_move_count: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(None));
    let synced = Arc::new(Mutex::new(true));

    let cipher_copy = cipher.clone();
    let state_copy = state.clone();
    let state_set_copy = state_set.clone();
    let battery_percentage_copy = battery_percentage.clone();
    let battery_charging_copy = battery_charging.clone();
    let synced_copy = synced.clone();
    let last_move_count_copy = last_move_count.clone();

    subscribe_characteristic(&read_char, move |value| {
        if let Ok(value) = cipher_copy.decrypt(&value) {
            let message_type = GANCubeVersion2Web::extract_bits(&value, 0, 4) as u8;
            match message_type {
                GANCubeVersion2Web::CUBE_MOVES_MESSAGE => {
                    let current_move_count =
                        GANCubeVersion2Web::extract_bits(&value, 4, 8) as u8;

                    let mut last_move_count_option = last_move_count_copy.lock().unwrap();
                    if let Some(last_move_count) = *last_move_count_option {
                        let move_count =
                            current_move_count.wrapping_sub(last_move_count) as usize;
                        if move_count > 7 {
                            *synced_copy.lock().unwrap() = false;
                            *last_move_count_option = None;
                            return;
                        }

                        let mut moves = Vec::with_capacity(move_count);
                        for j in 0..move_count {
                            let i = (move_count - 1) - j;
                            let move_num =
                                GANCubeVersion2Web::extract_bits(&value, 12 + i * 5, 5) as usize;
                            let move_time =
                                GANCubeVersion2Web::extract_bits(&value, 12 + 7 * 5 + i * 16, 16);
                            const MOVES: &[Move] = &[
                                Move::U,
                                Move::Up,
                                Move::R,
                                Move::Rp,
                                Move::F,
                                Move::Fp,
                                Move::D,
                                Move::Dp,
                                Move::L,
                                Move::Lp,
                                Move::B,
                                Move::Bp,
                            ];
                            if move_num >= MOVES.len() {
                                *synced_copy.lock().unwrap() = false;
                                *last_move_count_option = None;
                                break;
                            }
                            let mv = MOVES[move_num];
                            moves.push(TimedMove::new(mv, move_time));

                            state_copy.lock().unwrap().do_move(mv);
                        }

                        if !moves.is_empty() && *synced_copy.lock().unwrap() {
                            *last_move_count_option = Some(current_move_count);
                            dispatch_moves(
                                &listeners,
                                moves,
                                state_copy.lock().unwrap().clone(),
                            );
                        }
                    }
                }
                GANCubeVersion2Web::CUBE_STATE_MESSAGE => {
                    *last_move_count_copy.lock().unwrap() =
                        Some(GANCubeVersion2Web::extract_bits(&value, 4, 8) as u8);

                    let mut corners = [0u32; 8];
                    let mut corner_twist = [0u32; 8];
                    let mut corners_left: HashSet<u32> =
                        HashSet::from_iter([0, 1, 2, 3, 4, 5, 6, 7].iter().cloned());
                    let mut edges = [0u32; 12];
                    let mut edge_parity = [0u32; 12];
                    let mut edges_left: HashSet<u32> = HashSet::from_iter(
                        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].iter().cloned(),
                    );
                    let mut total_corner_twist = 0u32;
                    let mut total_edge_parity = 0u32;

                    let mut valid = true;
                    for i in 0..7 {
                        corners[i] = GANCubeVersion2Web::extract_bits(&value, 12 + i * 3, 3);
                        corner_twist[i] =
                            GANCubeVersion2Web::extract_bits(&value, 33 + i * 2, 2);
                        total_corner_twist += corner_twist[i];
                        if !corners_left.remove(&corners[i]) || corner_twist[i] >= 3 {
                            valid = false;
                            break;
                        }
                    }

                    if valid {
                        for i in 0..11 {
                            edges[i] = GANCubeVersion2Web::extract_bits(&value, 47 + i * 4, 4);
                            edge_parity[i] =
                                GANCubeVersion2Web::extract_bits(&value, 91 + i, 1);
                            total_edge_parity += edge_parity[i];
                            if !edges_left.remove(&edges[i]) || edge_parity[i] >= 2 {
                                valid = false;
                                break;
                            }
                        }
                    }

                    if valid {
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

                        *state_copy.lock().unwrap() = cube;
                        *state_set_copy.lock().unwrap() = true;
                    }
                }
                GANCubeVersion2Web::BATTERY_STATE_MESSAGE => {
                    *battery_charging_copy.lock().unwrap() =
                        Some(GANCubeVersion2Web::extract_bits(&value, 4, 4) != 0);
                    *battery_percentage_copy.lock().unwrap() =
                        Some(GANCubeVersion2Web::extract_bits(&value, 8, 8));
                }
                _ => (),
            }
        }
    })
    .await?;

    // Request initial cube state
    let mut loop_count = 0;
    loop {
        let mut message: [u8; 20] = [0; 20];
        message[0] = GANCubeVersion2Web::CUBE_STATE_MESSAGE;
        let message = cipher.encrypt(&message)?;
        write_characteristic(&write_char, &message).await?;

        sleep_ms(200).await;

        if *state_set.lock().unwrap() {
            break;
        }

        loop_count += 1;
        if loop_count > 10 {
            return Err(anyhow!("Did not receive initial cube state"));
        }
    }

    // Request battery state
    let mut message: [u8; 20] = [0; 20];
    message[0] = GANCubeVersion2Web::BATTERY_STATE_MESSAGE;
    let message = cipher.encrypt(&message)?;
    write_characteristic(&write_char, &message).await?;

    Ok(Box::new(GANCubeVersion2Web {
        server: server.clone(),
        state,
        battery_percentage,
        battery_charging,
        synced,
        write: write_char,
        cipher,
    }))
}

async fn try_gan_v1_as_timer(
    server: &web_sys::BluetoothRemoteGattServer,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    // Try the v1 service for the GAN Smart Timer
    let service = get_service(server, "0000fff0-0000-1000-8000-00805f9b34fb").await?;

    // Read version characteristic
    let dev_info_service = get_service(server, "0000180a-0000-1000-8000-00805f9b34fb").await?;
    let version_char =
        get_characteristic(&dev_info_service, "00002a28-0000-1000-8000-00805f9b34fb").await?;
    let version = read_characteristic(&version_char).await?;
    if version.len() < 3 {
        return Err(anyhow!("Device version invalid"));
    }
    let major = version[0];
    let minor = version[1];

    if major == 2 && minor == 0 {
        // GAN Smart Timer
        let updates_char =
            get_characteristic(&service, "0000fff5-0000-1000-8000-00805f9b34fb").await?;

        subscribe_characteristic(&updates_char, move |value| {
            if value.len() >= 4 {
                match value[3] {
                    1 => dispatch_event(&listeners, BluetoothCubeEvent::TimerReady),
                    2 => dispatch_event(&listeners, BluetoothCubeEvent::TimerStartCancel),
                    3 => dispatch_event(&listeners, BluetoothCubeEvent::TimerStarted),
                    4 => {
                        if value.len() >= 8 {
                            let min = value[4] as u32;
                            let sec = value[5] as u32;
                            let msec =
                                ((value[7] as u32) << 8) | (value[6] as u32);
                            dispatch_event(
                                &listeners,
                                BluetoothCubeEvent::TimerFinished(
                                    min * 60000 + sec * 1000 + msec,
                                ),
                            );
                        }
                    }
                    6 => dispatch_event(&listeners, BluetoothCubeEvent::HandsOnTimer),
                    _ => (),
                }
            }
        })
        .await?;

        Ok(Box::new(GANSmartTimerWeb {
            server: server.clone(),
        }))
    } else {
        Err(anyhow!(
            "GAN v1 cubes (version {}.{}) are not supported on web",
            major,
            minor
        ))
    }
}

/// Simplified v1 timer connection using a pre-discovered characteristic.
async fn try_gan_v1_as_timer_with_char(
    updates_char: web_sys::BluetoothRemoteGattCharacteristic,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    subscribe_characteristic(&updates_char, move |value| {
        if value.len() >= 4 {
            match value[3] {
                1 => dispatch_event(&listeners, BluetoothCubeEvent::TimerReady),
                2 => dispatch_event(&listeners, BluetoothCubeEvent::TimerStartCancel),
                3 => dispatch_event(&listeners, BluetoothCubeEvent::TimerStarted),
                4 => {
                    if value.len() >= 8 {
                        let min = value[4] as u32;
                        let sec = value[5] as u32;
                        let msec = ((value[7] as u32) << 8) | (value[6] as u32);
                        dispatch_event(
                            &listeners,
                            BluetoothCubeEvent::TimerFinished(min * 60000 + sec * 1000 + msec),
                        );
                    }
                }
                6 => dispatch_event(&listeners, BluetoothCubeEvent::HandsOnTimer),
                _ => (),
            }
        }
    })
    .await?;

    // Get the server reference from the characteristic's service chain
    let service = updates_char.service();
    let device = service.device();
    let server = device.gatt().unwrap();
    Ok(Box::new(GANSmartTimerWeb { server }))
}

/// Try to read the 6-byte device key from the device.
/// GAN v2 cubes include this in manufacturer data, but Web Bluetooth doesn't
/// expose manufacturer data after connection. We try to get it from device info.
async fn read_gan_v2_device_key(
    server: &web_sys::BluetoothRemoteGattServer,
) -> Result<[u8; 6]> {
    // Try reading the System ID characteristic from Device Information service
    if let Ok(dev_info) = get_service(server, "0000180a-0000-1000-8000-00805f9b34fb").await {
        if let Ok(sys_id_char) =
            get_characteristic(&dev_info, "00002a23-0000-1000-8000-00805f9b34fb").await
        {
            let data = read_characteristic(&sys_id_char).await?;
            if data.len() >= 6 {
                let mut result = [0u8; 6];
                result.copy_from_slice(&data[0..6]);
                return Ok(result);
            }
        }
    }
    Err(anyhow!("Could not read device key"))
}
