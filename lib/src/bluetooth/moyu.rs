use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent};
use crate::common::{Cube, CubeFace, InitialCubeState, Move, TimedMove};
use crate::cube3x3x3::Cube3x3x3;
use anyhow::{anyhow, Result};
use btleplug::api::{Characteristic, Peripheral as _};
use btleplug::platform::Peripheral;
use futures::StreamExt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

struct MoYuCube {
    device: Peripheral,
    state: Arc<Mutex<Cube3x3x3>>,
    synced: Arc<Mutex<bool>>,
}

impl MoYuCube {
    const FACES: [CubeFace; 6] = [
        CubeFace::Bottom,
        CubeFace::Left,
        CubeFace::Back,
        CubeFace::Right,
        CubeFace::Front,
        CubeFace::Top,
    ];

    pub async fn new(
        device: Peripheral,
        turn: Characteristic,
        gyro: Characteristic,
        read: Characteristic,
        move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
    ) -> Result<Self> {
        let state = Arc::new(Mutex::new(Cube3x3x3::new()));
        let synced = Arc::new(Mutex::new(true));

        let state_copy = state.clone();
        let synced_copy = synced.clone();
        let turn_uuid = turn.uuid.clone();

        // Subscribe to all characteristics
        device.subscribe(&turn).await?;
        device.subscribe(&gyro).await?;
        device.subscribe(&read).await?;

        let mut notification_stream = device.notifications().await?;

        tokio::spawn(async move {
            let mut last_move_time: Option<f64> = None;
            let mut face_rotations: [i8; 6] = [0, 0, 0, 0, 0, 0];

            while let Some(value) = notification_stream.next().await {
                if value.uuid == turn_uuid {
                    // Get count of turn reports and check lengths
                    if value.value.len() < 1 {
                        *synced_copy.lock().unwrap() = false;
                        continue;
                    }
                    let count = value.value[0];
                    if value.value.len() < 1 + count as usize * 6 {
                        *synced_copy.lock().unwrap() = false;
                        continue;
                    }

                    // Parse each turn report
                    for i in 0..count {
                        let offset = 1 + i as usize * 6;
                        let turn = &value.value[offset..offset + 6];
                        let timestamp = (((turn[1] as u32) << 24)
                            | ((turn[0] as u32) << 16)
                            | ((turn[3] as u32) << 8)
                            | (turn[2] as u32)) as f64
                            / 65536.0;
                        let face = turn[4] as usize;
                        let direction = turn[5] as i8 / 36;

                        // A corrupt face byte would panic the indexing below and
                        // silently kill this notification task, taking the cube
                        // offline mid-solve. Treat it as a desync instead.
                        if face >= Self::FACES.len() {
                            *synced_copy.lock().unwrap() = false;
                            continue;
                        }

                        // Decode face rotation into moves
                        let old_rotation = face_rotations[face];
                        let new_rotation = old_rotation + direction;
                        face_rotations[face] = (new_rotation + 9) % 9;
                        let mv = if old_rotation >= 5 && new_rotation <= 4 {
                            Some(
                                Move::from_face_and_rotation(Self::FACES[face], -1)
                                    .unwrap(),
                            )
                        } else if old_rotation <= 4 && new_rotation >= 5 {
                            Some(
                                Move::from_face_and_rotation(Self::FACES[face], 1).unwrap(),
                            )
                        } else {
                            None
                        };

                        if let Some(mv) = mv {
                            // There was a move, get time since last move
                            let prev_move_time = if let Some(time) = last_move_time {
                                time
                            } else {
                                timestamp
                            };
                            let time_passed = timestamp - prev_move_time;
                            let time_passed_ms = (time_passed * 1000.0) as u32;
                            last_move_time =
                                Some(prev_move_time + time_passed_ms as f64 / 1000.0);

                            // Report the new move
                            state_copy.lock().unwrap().do_move(mv);
                            move_listener(BluetoothCubeEvent::Move(
                                vec![TimedMove::new(mv, time_passed_ms)],
                                state_copy.lock().unwrap().clone(),
                            ));
                        }
                    }
                }
            }
        });

        // We can't request state because the Bluetooth library is incompatible with
        // making writes to this device.

        Ok(Self {
            device,
            state,
            synced,
        })
    }
}

impl BluetoothCubeDevice for MoYuCube {
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
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| handle.block_on(self.device.disconnect()));
    }
}

pub(crate) async fn moyu_connect(
    device: Peripheral,
    move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let characteristics = device.characteristics();

    let mut turn = None;
    let mut gyro = None;
    let mut read = None;
    for characteristic in characteristics {
        if characteristic.uuid == Uuid::from_str("00001003-0000-1000-8000-00805f9b34fb").unwrap() {
            turn = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("00001004-0000-1000-8000-00805f9b34fb").unwrap()
        {
            gyro = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("00001002-0000-1000-8000-00805f9b34fb").unwrap()
        {
            read = Some(characteristic);
        }
    }
    if turn.is_some() && gyro.is_some() && read.is_some() {
        Ok(Box::new(
            MoYuCube::new(
                device,
                turn.unwrap(),
                gyro.unwrap(),
                read.unwrap(),
                move_listener,
            )
            .await?,
        ))
    } else {
        Err(anyhow!("Unrecognized MoYu cube version"))
    }
}
