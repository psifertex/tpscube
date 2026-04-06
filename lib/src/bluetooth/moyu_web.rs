use crate::bluetooth::web::{
    dispatch_moves, get_characteristic, get_service, subscribe_characteristic,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent, MoveListenerHandle};
use crate::common::{Cube, CubeFace, InitialCubeState, Move, TimedMove};
use crate::cube3x3x3::Cube3x3x3;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[allow(dead_code)]
struct MoYuCubeWeb {
    server: web_sys::BluetoothRemoteGattServer,
    state: Arc<Mutex<Cube3x3x3>>,
    synced: Arc<Mutex<bool>>,
}

impl MoYuCubeWeb {
    const FACES: [CubeFace; 6] = [
        CubeFace::Bottom,
        CubeFace::Left,
        CubeFace::Back,
        CubeFace::Right,
        CubeFace::Front,
        CubeFace::Top,
    ];
}

impl BluetoothCubeDevice for MoYuCubeWeb {
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

pub(crate) async fn moyu_web_connect(
    server: web_sys::BluetoothRemoteGattServer,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let service = get_service(&server, "00001000-0000-1000-8000-00805f9b34fb").await?;
    let turn = get_characteristic(&service, "00001003-0000-1000-8000-00805f9b34fb").await?;
    let gyro = get_characteristic(&service, "00001004-0000-1000-8000-00805f9b34fb").await?;
    let read = get_characteristic(&service, "00001002-0000-1000-8000-00805f9b34fb").await?;

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let synced = Arc::new(Mutex::new(true));

    let state_copy = state.clone();
    let synced_copy = synced.clone();
    let face_rotations = Arc::new(Mutex::new([0i8; 6]));
    let last_move_time: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));

    // We only care about turn notifications; subscribe to gyro and read to keep the
    // cube sending data, but ignore their payloads.
    let _turn_uuid = turn.uuid();

    subscribe_characteristic(&turn, move |value| {
        // Get count of turn reports and check lengths
        if value.len() < 1 {
            *synced_copy.lock().unwrap() = false;
            return;
        }
        let count = value[0];
        if value.len() < 1 + count as usize * 6 {
            *synced_copy.lock().unwrap() = false;
            return;
        }

        let mut face_rots = face_rotations.lock().unwrap();
        for i in 0..count {
            let offset = 1 + i as usize * 6;
            let turn = &value[offset..offset + 6];
            let timestamp = (((turn[1] as u32) << 24)
                | ((turn[0] as u32) << 16)
                | ((turn[3] as u32) << 8)
                | (turn[2] as u32)) as f64
                / 65536.0;
            let face = turn[4] as usize;
            let direction = turn[5] as i8 / 36;

            if face >= 6 {
                *synced_copy.lock().unwrap() = false;
                return;
            }

            let old_rotation = face_rots[face];
            let new_rotation = old_rotation + direction;
            face_rots[face] = (new_rotation + 9) % 9;
            let mv = if old_rotation >= 5 && new_rotation <= 4 {
                Some(
                    Move::from_face_and_rotation(MoYuCubeWeb::FACES[face], -1).unwrap(),
                )
            } else if old_rotation <= 4 && new_rotation >= 5 {
                Some(
                    Move::from_face_and_rotation(MoYuCubeWeb::FACES[face], 1).unwrap(),
                )
            } else {
                None
            };

            if let Some(mv) = mv {
                let mut prev = last_move_time.lock().unwrap();
                let prev_time = prev.unwrap_or(timestamp);
                let time_passed = timestamp - prev_time;
                let time_passed_ms = (time_passed * 1000.0) as u32;
                *prev = Some(prev_time + time_passed_ms as f64 / 1000.0);

                state_copy.lock().unwrap().do_move(mv);
                dispatch_moves(
                    &listeners,
                    vec![TimedMove::new(mv, time_passed_ms)],
                    state_copy.lock().unwrap().clone(),
                );
            }
        }
    })
    .await?;

    // Subscribe to gyro and read (ignore data) to keep device streaming
    subscribe_characteristic(&gyro, |_| {}).await?;
    subscribe_characteristic(&read, |_| {}).await?;

    Ok(Box::new(MoYuCubeWeb {
        server,
        state,
        synced,
    }))
}
