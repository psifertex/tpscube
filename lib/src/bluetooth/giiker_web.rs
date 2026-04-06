use crate::bluetooth::web::{
    dispatch_moves, get_characteristic, get_service, subscribe_characteristic,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent, MoveListenerHandle};
use crate::common::{Cube, InitialCubeState, Move, TimedMove};
use crate::cube3x3x3::Cube3x3x3;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[allow(dead_code)]
struct GiikerCubeWeb {
    server: web_sys::BluetoothRemoteGattServer,
    state: Arc<Mutex<Cube3x3x3>>,
    synced: Arc<Mutex<bool>>,
}

impl GiikerCubeWeb {
    const KEY_STREAM: &'static [u8] = &[
        0xb0, 0x51, 0x68, 0xe0, 0x56, 0x89, 0xed, 0x77, 0x26, 0x1a, 0xc1, 0xa1, 0xd2, 0x7e,
        0x96, 0x51, 0x5d, 0x0d, 0xec, 0xf9, 0x59, 0xeb, 0x58, 0x18, 0x71, 0x51, 0xd6, 0x83,
        0x82, 0xc7, 0x02, 0xa9, 0x27, 0xa5, 0xab, 0x29,
    ];
}

impl BluetoothCubeDevice for GiikerCubeWeb {
    fn cube_state(&self) -> Cube3x3x3 {
        self.state.lock().unwrap().clone()
    }

    fn battery_percentage(&self) -> Option<u32> {
        None
    }

    fn battery_charging(&self) -> Option<bool> {
        None
    }

    fn reset_cube_state(&self) {
        *self.state.lock().unwrap() = Cube3x3x3::new();
    }

    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }

    fn disconnect(&self) {
        self.server.disconnect();
    }
}

pub(crate) async fn giiker_web_connect(
    server: web_sys::BluetoothRemoteGattServer,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let service = get_service(&server, "0000aadb-0000-1000-8000-00805f9b34fb").await?;
    let move_data =
        get_characteristic(&service, "0000aadc-0000-1000-8000-00805f9b34fb").await?;

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let synced = Arc::new(Mutex::new(true));

    let state_copy = state.clone();
    let synced_copy = synced.clone();
    let first = Arc::new(Mutex::new(true));
    let last_time = Arc::new(Mutex::new(0.0f64));

    subscribe_characteristic(&move_data, move |value| {
        let mut value = value;
        if value.len() < 20 {
            *synced_copy.lock().unwrap() = false;
            return;
        }

        if *first.lock().unwrap() {
            *first.lock().unwrap() = false;
            *last_time.lock().unwrap() = js_sys::Date::now();
            return;
        }

        // Check for encoded packets
        if value[18] == 0xa7 {
            let key_offset_a = (value[19] >> 4) as usize;
            let key_offset_b = (value[19] & 0xf) as usize;
            for i in 0..18 {
                value[i] = value[i].wrapping_add(
                    GiikerCubeWeb::KEY_STREAM[i + key_offset_a]
                        .wrapping_add(GiikerCubeWeb::KEY_STREAM[i + key_offset_b]),
                );
            }
        }

        let mv = match value[16] {
            0x11 => Move::B,
            0x12 => Move::B2,
            0x13 => Move::Bp,
            0x21 => Move::D,
            0x22 => Move::D2,
            0x23 => Move::Dp,
            0x31 => Move::L,
            0x32 => Move::L2,
            0x33 => Move::Lp,
            0x41 => Move::U,
            0x42 => Move::U2,
            0x43 => Move::Up,
            0x51 => Move::R,
            0x52 => Move::R2,
            0x53 => Move::Rp,
            0x61 => Move::F,
            0x62 => Move::F2,
            0x63 => Move::Fp,
            _ => {
                *synced_copy.lock().unwrap() = false;
                return;
            }
        };

        state_copy.lock().unwrap().do_move(mv);

        let now = js_sys::Date::now();
        let mut prev = last_time.lock().unwrap();
        let delta = (now - *prev) as u32;
        *prev = now;

        dispatch_moves(
            &listeners,
            vec![TimedMove::new(mv, delta)],
            state_copy.lock().unwrap().clone(),
        );
    })
    .await?;

    Ok(Box::new(GiikerCubeWeb {
        server,
        state,
        synced,
    }))
}
