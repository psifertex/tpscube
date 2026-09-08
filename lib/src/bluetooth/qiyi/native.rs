//! btleplug transport for QiYi smart cubes.
//!
//! Everything protocol shaped — decryption, framing, CRC, facelet and
//! move decoding, acknowledgements — lives in
//! [`crate::bluetooth::qiyi::protocol`] and is unit tested there against
//! real captures. This file only:
//!
//!   * locates the cube characteristic,
//!   * determines the cube's MAC (advertisement manufacturer data, with
//!     a name-derived fallback) for the hello packet,
//!   * pumps notifications through the protocol machine and writes back
//!     whatever it asks to send, and
//!   * implements [`BluetoothCubeDevice`].

use crate::bluetooth::qiyi::protocol::{
    mac_candidates_from_device_name, mac_from_manufacturer_data, QiyiEvent, QiyiProtocol,
    QIYI_CHARACTERISTIC_UUID, QIYI_MANUFACTURER_CIC, QIYI_SERVICE_UUID,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent};
use crate::common::{InitialCubeState, TimedMove};
use crate::cube3x3x3::Cube3x3x3;
use anyhow::{anyhow, Result};
use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures::StreamExt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

/// How long to wait for the cube to answer the hello before giving up.
const HELLO_TIMEOUT_MS: usize = 3000;
const HELLO_RETRY_MS: u64 = 300;

struct QiyiCube {
    device: Peripheral,
    protocol: Arc<Mutex<QiyiProtocol>>,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
    write: Characteristic,
}

impl BluetoothCubeDevice for QiyiCube {
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
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| {
            handle.block_on(
                self.device
                    .write(&self.write, &hello, WriteType::WithResponse),
            )
        });
    }

    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }

    fn disconnect(&self) {
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| handle.block_on(self.device.disconnect()));
    }
}

/// Determine the cube's MAC address, which the hello packet has to echo
/// back. The advertisement carries it under company identifier 0x0504;
/// if that is unavailable the name suffix is a reliable fallback for the
/// hardware lines we know about.
async fn read_device_mac(device: &Peripheral) -> Result<[u8; 6]> {
    let props = device
        .properties()
        .await?
        .ok_or_else(|| anyhow!("Could not read peripheral properties"))?;

    if let Some(data) = props.manufacturer_data.get(&QIYI_MANUFACTURER_CIC) {
        if let Some(mac) = mac_from_manufacturer_data(data) {
            return Ok(mac);
        }
    }

    let name = props.local_name.unwrap_or_default();
    mac_candidates_from_device_name(&name)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Could not determine QiYi cube address"))
}

pub(crate) async fn qiyi_cube_connect(
    device: Peripheral,
    move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let service_uuid = Uuid::from_str(QIYI_SERVICE_UUID).unwrap();
    let characteristic_uuid = Uuid::from_str(QIYI_CHARACTERISTIC_UUID).unwrap();

    // Match on the service too: GAN Gen4 cubes expose a characteristic
    // with the same 0000fff6 UUID under a different service.
    let cube_characteristic = device
        .characteristics()
        .into_iter()
        .find(|c| c.uuid == characteristic_uuid && c.service_uuid == service_uuid)
        .ok_or_else(|| anyhow!("QiYi cube characteristic not found"))?;

    let mac = read_device_mac(&device).await?;
    let protocol = Arc::new(Mutex::new(QiyiProtocol::new(mac)));

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let battery_percentage: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let synced = Arc::new(Mutex::new(true));

    let protocol_copy = protocol.clone();
    let state_copy = state.clone();
    let battery_percentage_copy = battery_percentage.clone();
    let device_copy = device.clone();
    let characteristic_copy = cube_characteristic.clone();

    device.subscribe(&cube_characteristic).await?;
    let mut notification_stream = device.notifications().await?;

    // The listener only needs Send, so a mutex is enough to move it into
    // the notification task.
    let move_listener = Arc::new(Mutex::new(move_listener));

    tokio::spawn(async move {
        while let Some(value) = notification_stream.next().await {
            let (events, outgoing) = {
                let mut proto = protocol_copy.lock().unwrap();
                proto.handle_notification(&value.value);
                (proto.take_events(), proto.take_outgoing())
            };

            // Acknowledgements first: the cube retransmits and stalls if
            // it does not hear back promptly.
            for msg in outgoing {
                let device_c = device_copy.clone();
                let characteristic_c = characteristic_copy.clone();
                tokio::spawn(async move {
                    let _ = device_c
                        .write(&characteristic_c, &msg.bytes, WriteType::WithResponse)
                        .await;
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
                let listener = move_listener.lock().unwrap();
                listener(BluetoothCubeEvent::Move(moves, new_state));
            }
        }
    });

    // Ask the cube for its state. This doubles as the handshake — until
    // it is answered the cube sends nothing at all.
    let mut elapsed = 0;
    loop {
        let hello = protocol.lock().unwrap().hello_message();
        device
            .write(&cube_characteristic, &hello, WriteType::WithResponse)
            .await?;

        tokio::time::sleep(Duration::from_millis(HELLO_RETRY_MS)).await;

        if protocol.lock().unwrap().state_set() {
            *state.lock().unwrap() = protocol.lock().unwrap().state();
            *battery_percentage.lock().unwrap() =
                protocol.lock().unwrap().battery_percentage();
            break;
        }

        elapsed += HELLO_RETRY_MS as usize;
        if elapsed > HELLO_TIMEOUT_MS {
            return Err(anyhow!("Did not receive initial cube state"));
        }
    }

    Ok(Box::new(QiyiCube {
        device,
        protocol,
        state,
        battery_percentage,
        synced,
        write: cube_characteristic,
    }))
}
