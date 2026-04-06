use crate::bluetooth::web::{
    dispatch_moves, get_characteristic, get_service, sleep_ms, subscribe_characteristic,
    write_characteristic,
};
use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent, MoveListenerHandle};
use crate::common::{Color, Cube, CubeFace, InitialCubeState, Move, TimedMove};
use crate::cube3x3x3::{Cube3x3x3, Cube3x3x3Faces};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[allow(dead_code)]
struct GoCubeWeb {
    server: web_sys::BluetoothRemoteGattServer,
    write: web_sys::BluetoothRemoteGattCharacteristic,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
}

impl GoCubeWeb {
    const REQUEST_BATTERY_MESSAGE: u8 = 0x32;
    const REQUEST_STATE_MESSAGE: u8 = 0x33;
    const RESET_STATE_MESSAGE: u8 = 0x35;
    const DISABLE_ORIENTATION_MESSAGE: u8 = 0x37;

    fn decode_cube_state(data: &[u8]) -> Result<Cube3x3x3> {
        const FACES: [CubeFace; 6] = [
            CubeFace::Back,
            CubeFace::Front,
            CubeFace::Top,
            CubeFace::Bottom,
            CubeFace::Right,
            CubeFace::Left,
        ];
        const COLORS: [Color; 6] = [
            Color::Blue,
            Color::Green,
            Color::White,
            Color::Yellow,
            Color::Red,
            Color::Orange,
        ];
        const ORDER: [usize; 8] = [
            0 * 3 + 0,
            0 * 3 + 1,
            0 * 3 + 2,
            1 * 3 + 2,
            2 * 3 + 2,
            2 * 3 + 1,
            2 * 3 + 0,
            1 * 3 + 0,
        ];
        const ORDER_OFFSET: [usize; 6] = [0, 0, 6, 2, 0, 0];
        let mut state: [Color; 6 * 9] = [Color::White; 6 * 9];

        for face in 0..6 {
            let target_face_idx = FACES[face] as u8 as usize;
            let offset = target_face_idx * 9;
            state[offset + 1 * 3 + 1] = COLORS[face];
            for i in 0..8 {
                let color_idx = data[4 + face * 9 + i];
                if color_idx >= 6 {
                    return Err(anyhow!("Invalid cube state"));
                }
                state[offset + ORDER[(i + ORDER_OFFSET[face]) % 8]] = COLORS[color_idx as usize];
            }
        }

        Ok(Cube3x3x3Faces::from_colors(state).as_pieces())
    }
}

impl BluetoothCubeDevice for GoCubeWeb {
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
        let write = self.write.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = write_characteristic(&write, &[GoCubeWeb::RESET_STATE_MESSAGE]).await;
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

pub(crate) async fn gocube_web_connect(
    server: web_sys::BluetoothRemoteGattServer,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let service = get_service(&server, "6e400001-b5a3-f393-e0a9-e50e24dcca9e").await?;
    let write_char =
        get_characteristic(&service, "6e400002-b5a3-f393-e0a9-e50e24dcca9e").await?;
    let read_char =
        get_characteristic(&service, "6e400003-b5a3-f393-e0a9-e50e24dcca9e").await?;

    let state = Arc::new(Mutex::new(Cube3x3x3::new()));
    let state_set = Arc::new(Mutex::new(false));
    let battery_percentage = Arc::new(Mutex::new(None));
    let synced = Arc::new(Mutex::new(true));

    let state_copy = state.clone();
    let state_set_copy = state_set.clone();
    let battery_copy = battery_percentage.clone();
    let synced_copy = synced.clone();
    let last_time = Arc::new(Mutex::new(0.0f64));

    subscribe_characteristic(&read_char, move |value| {
        if value.len() < 4 {
            *synced_copy.lock().unwrap() = false;
            return;
        }
        if value.len() < value[1] as usize {
            *synced_copy.lock().unwrap() = false;
            return;
        }
        if value[1] < 4 {
            *synced_copy.lock().unwrap() = false;
            return;
        }

        match value[2] {
            0x01 => {
                // ROTATE_MESSAGE
                let count = (value[1] as usize - 4) / 2;
                let mut moves = Vec::new();
                let mut bad_move = false;
                for i in 0..count {
                    let move_idx = value[3 + i * 2] as usize;
                    let mv = match move_idx {
                        0 => Move::B,
                        1 => Move::Bp,
                        2 => Move::F,
                        3 => Move::Fp,
                        4 => Move::U,
                        5 => Move::Up,
                        6 => Move::D,
                        7 => Move::Dp,
                        8 => Move::R,
                        9 => Move::Rp,
                        0xa => Move::L,
                        0xb => Move::Lp,
                        _ => {
                            *synced_copy.lock().unwrap() = false;
                            bad_move = true;
                            break;
                        }
                    };
                    state_copy.lock().unwrap().do_move(mv);
                    moves.push(mv);
                }

                if bad_move {
                    return;
                }

                let now = js_sys::Date::now();
                let mut prev = last_time.lock().unwrap();
                let move_time = if *prev == 0.0 {
                    0
                } else {
                    (now - *prev) as u32
                };
                *prev = now;

                let mut timed_moves = Vec::new();
                for (idx, mv) in moves.iter().enumerate() {
                    timed_moves.push(TimedMove::new(
                        *mv,
                        if idx == 0 { move_time } else { 0 },
                    ));
                }

                dispatch_moves(
                    &listeners,
                    timed_moves,
                    state_copy.lock().unwrap().clone(),
                );
            }
            0x02 => {
                // STATE_MESSAGE
                if value.len() < 64 {
                    *synced_copy.lock().unwrap() = false;
                    return;
                }
                if let Ok(cube_state) = GoCubeWeb::decode_cube_state(&value) {
                    *state_copy.lock().unwrap() = cube_state;
                    *state_set_copy.lock().unwrap() = true;
                } else {
                    *synced_copy.lock().unwrap() = false;
                }
            }
            0x05 => {
                // BATTERY_MESSAGE
                *battery_copy.lock().unwrap() = Some(value[3] as u32);
            }
            _ => (),
        }
    })
    .await?;

    // Turn off orientation messages
    write_characteristic(&write_char, &[GoCubeWeb::DISABLE_ORIENTATION_MESSAGE]).await?;

    // Request initial cube state
    let mut loop_count = 0;
    loop {
        write_characteristic(&write_char, &[GoCubeWeb::REQUEST_STATE_MESSAGE]).await?;
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
    write_characteristic(&write_char, &[GoCubeWeb::REQUEST_BATTERY_MESSAGE]).await?;

    Ok(Box::new(GoCubeWeb {
        server,
        write: write_char,
        state,
        battery_percentage,
        synced,
    }))
}
