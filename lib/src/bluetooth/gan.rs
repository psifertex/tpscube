use crate::bluetooth::{BluetoothCubeDevice, BluetoothCubeEvent};
use crate::common::{
    Color, Corner, CornerPiece, Cube, CubeFace, InitialCubeState, Move, TimedMove,
};
use crate::cube3x3x3::{Cube3x3x3, Cube3x3x3Faces, Edge3x3x3, EdgePiece3x3x3};
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Block,
};
use anyhow::{anyhow, Result};
use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures::StreamExt;
use std::collections::{HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::iter::FromIterator;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

struct GANCubeVersion1Characteristics {
    version: Characteristic,
    hardware: Characteristic,
    cube_state: Characteristic,
    last_moves: Characteristic,
    timing: Characteristic,
    battery: Characteristic,
}

struct GANCubeVersion1 {
    device: Peripheral,
    state: Mutex<Cube3x3x3>,
    battery_percentage: Mutex<u32>,
    battery_charging: Mutex<bool>,
    synced: Mutex<bool>,
    last_move_count: Mutex<u8>,
    characteristics: GANCubeVersion1Characteristics,
    cipher: GANCubeVersion1Cipher,
    move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
}

struct GANCubeVersion1Cipher {
    device_key: [u8; 16],
}

struct GANCubeVersion2 {
    device: Peripheral,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    battery_charging: Arc<Mutex<Option<bool>>>,
    synced: Arc<Mutex<bool>>,
    write: Characteristic,
    cipher: GANCubeVersion2Cipher,
}

#[derive(Clone)]
struct GANCubeVersion2Cipher {
    device_key: [u8; 16],
    device_iv: [u8; 16],
}

struct GANSmartTimer {
    device: Peripheral,
}

impl GANCubeVersion1 {
    const LAST_MOVE_COUNT_OFFSET: usize = 12;
    const LAST_MOVE_LIST_OFFSET: usize = 13;

    pub async fn new(
        device: Peripheral,
        characteristics: GANCubeVersion1Characteristics,
        move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
        minor_version: u8,
    ) -> Result<Self> {
        // Read device identifier, this is used to derive the key
        let device_id = device.read(&characteristics.hardware).await?;
        if device_id.len() < 6 {
            return Err(anyhow!("Device identifier invalid"));
        }

        // Derive the key
        const GAN_V1_KEYS: [[u8; 16]; 2] = [
            [
                0xc6, 0xca, 0x15, 0xdf, 0x4f, 0x6e, 0x13, 0xb6, 0x77, 0x0d, 0xe6, 0x59, 0x3a, 0xaf,
                0xba, 0xa2,
            ],
            [
                0x43, 0xe2, 0x5b, 0xd6, 0x7d, 0xdc, 0x78, 0xd8, 0x07, 0x60, 0xa3, 0xda, 0x82, 0x3c,
                0x01, 0xf1,
            ],
        ];
        let mut key = GAN_V1_KEYS[minor_version as usize].clone();
        for i in 0..6 {
            key[i] = key[i].wrapping_add(device_id[5 - i]);
        }
        let cipher = GANCubeVersion1Cipher { device_key: key };

        // Get initial cube state
        let state = device.read(&characteristics.cube_state).await?;
        if state.len() < 18 {
            return Err(anyhow!("Cube state is invalid"));
        }
        let state = cipher.decrypt(&state)?;
        let state = Self::decode_cube_state(&state)?;
        let state = Mutex::new(state);

        // Get the initial move count
        let moves = device.read(&characteristics.last_moves).await?;
        if moves.len() < 19 {
            return Err(anyhow!("Invalid last move data"));
        }
        let moves = cipher.decrypt(&moves)?;
        let last_move_count = Mutex::new(moves[Self::LAST_MOVE_COUNT_OFFSET]);

        // Get battery state
        let battery = device.read(&characteristics.battery).await?;
        if battery.len() < 8 {
            return Err(anyhow!("Battery state is invalid"));
        }
        let battery = cipher.decrypt(&battery)?;
        let battery_percentage = battery[7];
        let battery_charging = battery[6] != 0;

        Ok(GANCubeVersion1 {
            device,
            state,
            battery_percentage: Mutex::new(battery_percentage as u32),
            battery_charging: Mutex::new(battery_charging),
            synced: Mutex::new(true),
            last_move_count,
            characteristics,
            cipher,
            move_listener,
        })
    }

    fn decode_cube_state(data: &[u8]) -> Result<Cube3x3x3> {
        const FACES: [CubeFace; 6] = [
            CubeFace::Top,
            CubeFace::Right,
            CubeFace::Front,
            CubeFace::Bottom,
            CubeFace::Left,
            CubeFace::Back,
        ];
        const COLORS: [Color; 6] = [
            Color::White,
            Color::Red,
            Color::Green,
            Color::Yellow,
            Color::Orange,
            Color::Blue,
        ];
        let mut state: [Color; 6 * 9] = [Color::White; 6 * 9];

        for face in 0..6 {
            // Find face index in our representation using mapping
            let target_face_idx = FACES[face] as u8 as usize;
            state[target_face_idx * 9 + 1 * 3 + 1] = COLORS[face];

            // Decode face's data from buffer
            let face_data = ((data[(face * 3) ^ 1] as u32) << 16)
                | ((data[((face * 3) + 1) ^ 1] as u32) << 8)
                | data[((face * 3) + 2) ^ 1] as u32;

            // Place colors into the cube state array
            let mut offset = target_face_idx * 9;
            for i in 0..8 {
                if i == 4 {
                    // Skip center, not represented in data
                    offset += 1;
                }

                let color_idx = (face_data >> (3 * (7 - i))) & 7;
                if color_idx >= 6 {
                    return Err(anyhow!("Invalid cube state"));
                }

                state[offset] = COLORS[color_idx as usize];
                offset += 1;
            }
        }

        // Create cube state and convert to normal format
        Ok(Cube3x3x3Faces::from_colors(state).as_pieces())
    }

    fn move_poll(&self) -> Result<()> {
        if !*self.synced.lock().unwrap() {
            // Not synced, do not try to poll moves
            return Err(anyhow!("Not synced"));
        }

        // Read move data and move timing data (blocking from sync context)
        let handle = tokio::runtime::Handle::current();
        let move_data = tokio::task::block_in_place(|| handle.block_on(self.device.read(&self.characteristics.last_moves)))?;
        if move_data.len() < 19 {
            return Err(anyhow!("Invalid last move data"));
        }
        let move_data = self.cipher.decrypt(&move_data)?;

        let timing = tokio::task::block_in_place(|| handle.block_on(self.device.read(&self.characteristics.timing)))?;
        if timing.len() < 19 {
            return Err(anyhow!("Invalid timing data"));
        }
        let timing = self.cipher.decrypt(&timing)?;

        // Check number of moves since last message.
        let current_move_count = move_data[Self::LAST_MOVE_COUNT_OFFSET];
        let timestamp_move_count = timing[0];
        let mut last_move_count = self.last_move_count.lock().unwrap();
        let move_count = current_move_count.wrapping_sub(*last_move_count) as usize;
        if move_count > 6 {
            // There are too many moves since the last message. Our cube
            // state is out of sync. Let the client know and reset the
            // last move count such that we don't parse any more move
            // messages, since they aren't valid anymore.
            return Err(anyhow!("Move buffer exceeded"));
        }

        // Gather the moves
        let mut moves = Vec::with_capacity(move_count);
        for j in 0..move_count {
            let i = (6 - move_count) + j;

            // Decode move data
            let move_num = move_data[Self::LAST_MOVE_LIST_OFFSET + i] as usize;

            let timestamp_idx = (*last_move_count)
                .wrapping_add(j as u8)
                .wrapping_sub(timestamp_move_count.wrapping_sub(9));
            if timestamp_idx >= 9 {
                return Err(anyhow!("Timestamp not present for move"));
            }
            let move_time = timing[timestamp_idx as usize * 2 + 1] as u32
                | ((timing[timestamp_idx as usize * 2 + 2] as u32) << 8);

            const MOVES: &[Move] = &[
                Move::U,
                Move::U2,
                Move::Up,
                Move::R,
                Move::R2,
                Move::Rp,
                Move::F,
                Move::F2,
                Move::Fp,
                Move::D,
                Move::D2,
                Move::Dp,
                Move::L,
                Move::L2,
                Move::Lp,
                Move::B,
                Move::B2,
                Move::Bp,
            ];
            if move_num >= MOVES.len() {
                return Err(anyhow!("Invalid move"));
            }
            let mv = MOVES[move_num];
            moves.push(TimedMove::new(mv, move_time));

            // Apply move to the cube state.
            self.state.lock().unwrap().do_move(mv);
        }

        *last_move_count = current_move_count;

        if moves.len() != 0 {
            // Let clients know there is a new move
            let move_listener = self.move_listener.as_ref();
            move_listener(BluetoothCubeEvent::Move(
                moves,
                self.state.lock().unwrap().clone(),
            ));
        }

        Ok(())
    }
}

impl BluetoothCubeDevice for GANCubeVersion1 {
    fn cube_state(&self) -> Cube3x3x3 {
        self.state.lock().unwrap().clone()
    }

    fn battery_percentage(&self) -> Option<u32> {
        Some(*self.battery_percentage.lock().unwrap())
    }

    fn battery_charging(&self) -> Option<bool> {
        Some(*self.battery_charging.lock().unwrap())
    }

    fn reset_cube_state(&self) {
        // These bytes represent the cube state in the solved state.
        let message: [u8; 18] = [
            0x00, 0x00, 0x24, 0x00, 0x49, 0x92, 0x24, 0x49, 0x6d, 0x92, 0xdb, 0xb6, 0x49, 0x92,
            0xb6, 0x24, 0x6d, 0xdb,
        ];
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| handle.block_on(self.device.write(
            &self.characteristics.cube_state,
            &message,
            WriteType::WithResponse,
        )));

        *self.state.lock().unwrap() = Cube3x3x3::new();
    }

    fn synced(&self) -> bool {
        *self.synced.lock().unwrap()
    }

    fn update(&self) {
        if let Err(_) = self.move_poll() {
            *self.synced.lock().unwrap() = false;
        }
    }

    fn disconnect(&self) {
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| handle.block_on(self.device.disconnect()));
    }

    // Older GAN cubes have *very* uncalibrated clocks
    fn estimated_clock_ratio(&self) -> f64 {
        0.95
    }

    fn clock_ratio_range(&self) -> (f64, f64) {
        (0.9, 1.02)
    }
}

impl GANCubeVersion1Cipher {
    fn decrypt(&self, value: &[u8]) -> Result<Vec<u8>> {
        if value.len() <= 16 {
            return Err(anyhow!("Packet size less than expected length"));
        }

        // Packets are larger than block size. First decrypt the last 16 bytes
        // of the packet in place.
        let mut value = value.to_vec();
        let aes = Aes128::new_from_slice(&self.device_key).unwrap();
        let offset = value.len() - 16;
        let end_cipher = &value[offset..];
        let mut end_plain = Block::from(<[u8; 16]>::try_from(end_cipher).unwrap());
        aes.decrypt_block(&mut end_plain);
        for i in 0..16 {
            value[offset + i] = end_plain[i];
        }

        // Decrypt the first 16 bytes of the packet in place. This will overlap
        // with the decrypted block above.
        let start_cipher = &value[0..16];
        let mut start_plain = Block::from(<[u8; 16]>::try_from(start_cipher).unwrap());
        aes.decrypt_block(&mut start_plain);
        for i in 0..16 {
            value[i] = start_plain[i];
        }

        Ok(value)
    }
}

impl GANCubeVersion2 {
    const CUBE_MOVES_MESSAGE: u8 = 2;
    const CUBE_STATE_MESSAGE: u8 = 4;
    const BATTERY_STATE_MESSAGE: u8 = 9;
    const RESET_CUBE_STATE_MESSAGE: u8 = 10;

    const CUBE_STATE_TIMEOUT_MS: usize = 2000;

    pub async fn new(
        device: Peripheral,
        read: Characteristic,
        write: Characteristic,
        move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
    ) -> Result<Self> {
        // Derive keys. These are based on a 6 byte device identifier found in the
        // manufacturer data.
        let props = device
            .properties()
            .await?
            .ok_or_else(|| anyhow!("Could not read peripheral properties"))?;
        let device_key: [u8; 6] = if let Some(data) = props.manufacturer_data.get(&1) {
            if data.len() >= 9 {
                let mut result = [0; 6];
                result.copy_from_slice(&data[3..9]);
                result
            } else {
                return Err(anyhow!("Device identifier data invalid"));
            }
        } else {
            return Err(anyhow!("Manufacturer data missing device identifier"));
        };

        const GAN_V2_KEY: [u8; 16] = [
            0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11,
            0x12, 0x53,
        ];
        const GAN_V2_IV: [u8; 16] = [
            0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12,
            0x02, 0x43,
        ];
        let mut key = GAN_V2_KEY.clone();
        let mut iv = GAN_V2_IV.clone();
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
        let last_move_count = Arc::new(Mutex::new(None));
        let synced = Arc::new(Mutex::new(true));

        let cipher_copy = cipher.clone();
        let state_copy = state.clone();
        let state_set_copy = state_set.clone();
        let battery_percentage_copy = battery_percentage.clone();
        let battery_charging_copy = battery_charging.clone();
        let synced_copy = synced.clone();
        let last_move_count_copy = last_move_count.clone();

        // Subscribe and spawn notification handler
        device.subscribe(&read).await?;
        let mut notification_stream = device.notifications().await?;

        tokio::spawn(async move {
            while let Some(value) = notification_stream.next().await {
                if let Ok(value) = cipher_copy.decrypt(&value.value) {
                    let message_type = Self::extract_bits(&value, 0, 4) as u8;
                    match message_type {
                        Self::CUBE_MOVES_MESSAGE => {
                            let current_move_count = Self::extract_bits(&value, 4, 8) as u8;

                            let mut last_move_count_option = last_move_count_copy.lock().unwrap();
                            if let Some(last_move_count) = *last_move_count_option {
                                let move_count =
                                    current_move_count.wrapping_sub(last_move_count) as usize;
                                if move_count > 7 {
                                    *synced_copy.lock().unwrap() = false;
                                    *last_move_count_option = None;
                                    continue;
                                }

                                let mut moves = Vec::with_capacity(move_count);
                                for j in 0..move_count {
                                    let i = (move_count - 1) - j;

                                    let move_num = Self::extract_bits(&value, 12 + i * 5, 5) as usize;
                                    let move_time = Self::extract_bits(&value, 12 + 7 * 5 + i * 16, 16);
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
                                        // Can't use `return` from within the loop to break just this iteration
                                        // so we use a flag approach
                                        break;
                                    }
                                    let mv = MOVES[move_num];
                                    moves.push(TimedMove::new(mv, move_time));

                                    state_copy.lock().unwrap().do_move(mv);
                                }

                                // Only notify if we didn't break early due to bad data
                                if !moves.is_empty() && *synced_copy.lock().unwrap() {
                                    *last_move_count_option = Some(current_move_count);
                                    move_listener(BluetoothCubeEvent::Move(
                                        moves,
                                        state_copy.lock().unwrap().clone(),
                                    ));
                                }
                            }
                        }
                        Self::CUBE_STATE_MESSAGE => {
                            *last_move_count_copy.lock().unwrap() =
                                Some(Self::extract_bits(&value, 4, 8) as u8);

                            let mut corners = [0; 8];
                            let mut corner_twist = [0; 8];
                            let mut corners_left: HashSet<u32> =
                                HashSet::from_iter((&[0, 1, 2, 3, 4, 5, 6, 7]).iter().cloned());
                            let mut edges = [0; 12];
                            let mut edge_parity = [0; 12];
                            let mut edges_left: HashSet<u32> = HashSet::from_iter(
                                (&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]).iter().cloned(),
                            );
                            let mut total_corner_twist = 0;
                            let mut total_edge_parity = 0;

                            let mut valid = true;
                            for i in 0..7 {
                                corners[i] = Self::extract_bits(&value, 12 + i * 3, 3);
                                corner_twist[i] = Self::extract_bits(&value, 33 + i * 2, 2);
                                total_corner_twist += corner_twist[i];
                                if !corners_left.remove(&corners[i]) || corner_twist[i] >= 3 {
                                    valid = false;
                                    break;
                                }
                            }

                            if valid {
                                for i in 0..11 {
                                    edges[i] = Self::extract_bits(&value, 47 + i * 4, 4);
                                    edge_parity[i] = Self::extract_bits(&value, 91 + i, 1);
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
                        Self::BATTERY_STATE_MESSAGE => {
                            *battery_charging_copy.lock().unwrap() =
                                Some(Self::extract_bits(&value, 4, 4) != 0);
                            *battery_percentage_copy.lock().unwrap() =
                                Some(Self::extract_bits(&value, 8, 8));
                        }
                        _ => (),
                    }
                }
            }
        });

        // Request initial cube state
        let mut loop_count = 0;
        loop {
            let mut message: [u8; 20] = [0; 20];
            message[0] = Self::CUBE_STATE_MESSAGE;
            let message = cipher.encrypt(&message)?;
            device.write(&write, &message, WriteType::WithResponse).await?;

            tokio::time::sleep(Duration::from_millis(200)).await;

            if *state_set.lock().unwrap() {
                break;
            }

            loop_count += 1;
            if loop_count > Self::CUBE_STATE_TIMEOUT_MS / 200 {
                return Err(anyhow!("Did not receive initial cube state"));
            }
        }

        // Request battery state immediately
        let mut message: [u8; 20] = [0; 20];
        message[0] = Self::BATTERY_STATE_MESSAGE;
        let message = cipher.encrypt(&message)?;
        device.write(&write, &message, WriteType::WithResponse).await?;

        Ok(Self {
            device,
            state,
            battery_percentage,
            battery_charging,
            synced,
            cipher,
            write,
        })
    }

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

impl GANCubeVersion2Cipher {
    fn decrypt(&self, value: &[u8]) -> Result<Vec<u8>> {
        if value.len() <= 16 {
            return Err(anyhow!("Packet size less than expected length"));
        }

        // Packets are larger than block size. First decrypt the last 16 bytes
        // of the packet in place.
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

        // Decrypt the first 16 bytes of the packet in place. This will overlap
        // with the decrypted block above.
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

        // Packets are larger than block size. First encrypt the first 16 bytes
        // of the packet in place.
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

        // Encrypt the last 16 bytes of the packet in place. This will overlap
        // with the encrypted block above.
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

impl BluetoothCubeDevice for GANCubeVersion2 {
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
        // These bytes represent the cube state in the solved state.
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
        let message = self.cipher.encrypt(&message).unwrap();
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| handle.block_on(
            self.device
                .write(&self.write, &message, WriteType::WithResponse),
        ));

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

impl GANSmartTimer {
    pub async fn new(
        device: Peripheral,
        updates: Characteristic,
        move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
    ) -> Result<Self> {
        device.subscribe(&updates).await?;
        let mut notification_stream = device.notifications().await?;

        tokio::spawn(async move {
            while let Some(value) = notification_stream.next().await {
                if value.value.len() >= 4 {
                    match value.value[3] {
                        1 => move_listener(BluetoothCubeEvent::TimerReady),
                        2 => move_listener(BluetoothCubeEvent::TimerStartCancel),
                        3 => move_listener(BluetoothCubeEvent::TimerStarted),
                        4 => {
                            if value.value.len() >= 8 {
                                let min = value.value[4] as u32;
                                let sec = value.value[5] as u32;
                                let msec = ((value.value[7] as u32) << 8) | (value.value[6] as u32);
                                move_listener(BluetoothCubeEvent::TimerFinished(
                                    min * 60000 + sec * 1000 + msec,
                                ));
                            }
                        }
                        6 => move_listener(BluetoothCubeEvent::HandsOnTimer),
                        _ => (),
                    }
                }
            }
        });

        Ok(GANSmartTimer { device })
    }
}

impl BluetoothCubeDevice for GANSmartTimer {
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
    fn update(&self) {}

    fn synced(&self) -> bool {
        true
    }

    fn disconnect(&self) {
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| handle.block_on(self.device.disconnect()));
    }
}

// ---- GAN v3 (Gen3 protocol, GAN356 i Carry 2) ----

struct GANCubeVersion3 {
    device: Peripheral,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
    write: Characteristic,
    cipher: GANCubeVersion3Cipher,
}

#[derive(Clone)]
struct GANCubeVersion3Cipher {
    device_key: [u8; 16],
    device_iv: [u8; 16],
}

/// A buffered move awaiting delivery, used in the Gen3 FIFO buffer.
struct Gen3BufferedMove {
    serial: u8,
    mv: Move,
    timestamp: u32,
}

impl GANCubeVersion3Cipher {
    fn decrypt(&self, value: &[u8]) -> Result<[u8; 16]> {
        if value.len() != 16 {
            return Err(anyhow!("Gen3 packet must be exactly 16 bytes"));
        }
        let aes = Aes128::new_from_slice(&self.device_key).unwrap();
        let mut block = Block::from(<[u8; 16]>::try_from(value).unwrap());
        aes.decrypt_block(&mut block);
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = block[i] ^ self.device_iv[i];
        }
        Ok(result)
    }

    fn encrypt(&self, value: &[u8; 16]) -> [u8; 16] {
        let aes = Aes128::new_from_slice(&self.device_key).unwrap();
        let mut block = Block::default();
        for i in 0..16 {
            block[i] = value[i] ^ self.device_iv[i];
        }
        aes.encrypt_block(&mut block);
        let mut result = [0u8; 16];
        result.copy_from_slice(&block);
        result
    }
}

impl GANCubeVersion3 {
    const CUBE_STATE_TIMEOUT_MS: usize = 2000;

    pub async fn new(
        device: Peripheral,
        read: Characteristic,
        write: Characteristic,
        move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
    ) -> Result<Self> {
        // Derive keys from manufacturer data (same as Gen2)
        let props = device
            .properties()
            .await?
            .ok_or_else(|| anyhow!("Could not read peripheral properties"))?;
        let device_key: [u8; 6] = if let Some(data) = props.manufacturer_data.get(&1) {
            if data.len() >= 9 {
                let mut result = [0; 6];
                result.copy_from_slice(&data[3..9]);
                result
            } else {
                return Err(anyhow!("Device identifier data invalid"));
            }
        } else {
            return Err(anyhow!("Manufacturer data missing device identifier"));
        };

        const GAN_V3_KEY: [u8; 16] = [
            0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11,
            0x12, 0x53,
        ];
        const GAN_V3_IV: [u8; 16] = [
            0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12,
            0x02, 0x43,
        ];
        let mut key = GAN_V3_KEY;
        let mut iv = GAN_V3_IV;
        for (idx, byte) in device_key.iter().enumerate() {
            key[idx] = ((key[idx] as u16 + *byte as u16) % 255) as u8;
            iv[idx] = ((iv[idx] as u16 + *byte as u16) % 255) as u8;
        }
        let cipher = GANCubeVersion3Cipher {
            device_key: key,
            device_iv: iv,
        };

        let state = Arc::new(Mutex::new(Cube3x3x3::new()));
        let state_set = Arc::new(Mutex::new(false));
        let battery_percentage = Arc::new(Mutex::new(None));
        let synced = Arc::new(Mutex::new(true));

        let cipher_copy = cipher.clone();
        let state_copy = state.clone();
        let state_set_copy = state_set.clone();
        let battery_percentage_copy = battery_percentage.clone();
        let synced_copy = synced.clone();

        // Subscribe and spawn notification handler
        device.subscribe(&read).await?;
        let mut notification_stream = device.notifications().await?;

        // Shared state for FIFO buffer and serial tracking
        let last_serial: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(None));
        // Cube clock of the most recent live MOVE event we've seen. Used to
        // convert the cube's absolute (since-boot) timestamp into a per-move
        // delta, which is what the BluetoothCube calibration layer expects.
        // Same fix as Gen4 — see GANCubeVersion4::new for the rationale.
        let last_live_timestamp: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let fifo_buffer: Arc<Mutex<VecDeque<Gen3BufferedMove>>> =
            Arc::new(Mutex::new(VecDeque::new()));
        let pending_history: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let last_serial_copy = last_serial.clone();
        let last_live_timestamp_copy = last_live_timestamp.clone();
        let fifo_buffer_copy = fifo_buffer.clone();
        let pending_history_copy = pending_history.clone();

        // We need a clone of the write characteristic and cipher for sending
        // commands from within the notification handler
        let write_copy = write.clone();
        let device_copy = device.clone();
        let cipher_for_handler = cipher.clone();

        // Wrap the move_listener in Arc<Mutex<>> so it can be shared in the
        // async spawned task (the closure is Send but not Sync)
        let move_listener = Arc::new(Mutex::new(move_listener));

        tokio::spawn(async move {
            while let Some(value) = notification_stream.next().await {
                if value.value.len() != 16 {
                    continue;
                }
                let decrypted = match cipher_copy.decrypt(&value.value) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                // Validate magic byte and data length
                if decrypted[0] != 0x55 {
                    continue;
                }
                let event_type = decrypted[1];
                let data_length = decrypted[2];
                if data_length == 0 {
                    continue;
                }

                match event_type {
                    // MOVE event (0x01)
                    0x01 => {
                        // Must have initial state before processing moves
                        if !*state_set_copy.lock().unwrap() {
                            continue;
                        }

                        // Extract fields per spec
                        let timestamp = u32::from_le_bytes([
                            decrypted[3],
                            decrypted[4],
                            decrypted[5],
                            decrypted[6],
                        ]);
                        let serial_16 =
                            u16::from_le_bytes([decrypted[7], decrypted[8]]);
                        let serial = (serial_16 & 0xFF) as u8;

                        // Direction and face are in byte 9
                        // Bits 72-73: direction (2 bits), bits 74-79: face bitmask (6 bits)
                        let direction_and_face = decrypted[9];
                        let direction = (direction_and_face >> 6) & 0x03;
                        let face_bitmask = direction_and_face & 0x3F;

                        let mv = match Self::decode_live_move(face_bitmask, direction) {
                            Some(m) => m,
                            None => continue,
                        };

                        // First live move bootstraps last_serial. We don't
                        // trust the facelets event for this — see Gen4 for
                        // the full rationale (some cubes report serial=0 in
                        // periodic facelets, which causes a bogus history
                        // request and a phantom move).
                        {
                            let mut ls = last_serial_copy.lock().unwrap();
                            if ls.is_none() {
                                *ls = Some(serial.wrapping_sub(1));
                            }
                        }

                        // Convert the cube's absolute since-boot timestamp
                        // into a per-move delta. The calibration layer in
                        // bluetooth.rs expects raw_move.time() to be a
                        // delta (Gen2 protocol convention) and accumulates
                        // it; passing the absolute value inflates solve
                        // durations by orders of magnitude.
                        let move_delta = {
                            let mut last_ts = last_live_timestamp_copy.lock().unwrap();
                            let delta = match *last_ts {
                                Some(prev) => timestamp.wrapping_sub(prev),
                                None => 0,
                            };
                            *last_ts = Some(timestamp);
                            delta
                        };

                        // Add to FIFO buffer
                        {
                            let mut buffer = fifo_buffer_copy.lock().unwrap();
                            buffer.push_back(Gen3BufferedMove {
                                serial,
                                mv,
                                timestamp: move_delta,
                            });
                        }

                        // Try to evict/deliver
                        Self::try_evict(
                            &fifo_buffer_copy,
                            &last_serial_copy,
                            &state_copy,
                            &synced_copy,
                            &pending_history_copy,
                            &move_listener,
                            &write_copy,
                            &device_copy,
                            &cipher_for_handler,
                        );
                    }
                    // FACELETS event (0x02)
                    0x02 => {
                        let serial_16 =
                            u16::from_le_bytes([decrypted[3], decrypted[4]]);
                        let serial = (serial_16 & 0xFF) as u8;

                        // Parse corner/edge state using bit extraction
                        // Bit offsets are from start of 16-byte message
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
                        // Corner permutation: 7 x 3 bits starting at bit 40
                        for i in 0..7 {
                            corners[i] =
                                Self::extract_bits(&decrypted, 40 + i * 3, 3);
                            corner_twist[i] =
                                Self::extract_bits(&decrypted, 61 + i * 2, 2);
                            total_corner_twist += corner_twist[i];
                            if !corners_left.remove(&corners[i]) || corner_twist[i] >= 3
                            {
                                valid = false;
                                break;
                            }
                        }

                        if valid {
                            // Edge permutation: 11 x 4 bits starting at bit 77
                            // (note: 2-bit gap between corner orient end at 74 and edge perm start at 77)
                            for i in 0..11 {
                                edges[i] =
                                    Self::extract_bits(&decrypted, 77 + i * 4, 4);
                                edge_parity[i] =
                                    Self::extract_bits(&decrypted, 121 + i, 1);
                                total_edge_parity += edge_parity[i];
                                if !edges_left.remove(&edges[i]) || edge_parity[i] >= 2
                                {
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

                            // Do NOT initialize last_serial from the facelets
                            // event — see Gen4 for the rationale. last_serial
                            // is bootstrapped by the first live MOVE event
                            // instead.
                            //
                            // Periodic facelets still drive the gap-detector
                            // for the "missed last move" case, when the
                            // facelets serial exceeds last_serial.
                            {
                                // Skip gap check at serial 0 (rollover quirk
                                // and the always-zero periodic-facelets case
                                // observed on some Gen4 hardware).
                                if serial != 0 {
                                    let ls = *last_serial_copy.lock().unwrap();
                                    if let Some(last) = ls {
                                        let gap =
                                            (serial.wrapping_sub(last)) as u8;
                                        if gap > 1
                                            && !*pending_history_copy.lock().unwrap()
                                        {
                                            // Request `gap` moves ending at
                                            // the current facelets serial.
                                            // The history response packs
                                            // newest-first starting at
                                            // start_serial and going
                                            // backward, so we pass the head
                                            // (newest missing) serial and
                                            // the full gap count.
                                            Self::send_move_history_request(
                                                serial,
                                                gap,
                                                &write_copy,
                                                &device_copy,
                                                &cipher_for_handler,
                                                &pending_history_copy,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // MOVE_HISTORY event (0x06)
                    0x06 => {
                        if data_length < 2 {
                            continue;
                        }
                        let start_serial = decrypted[3];
                        let num_moves = ((data_length - 1) * 2) as usize;

                        // Parse history moves (4 bits each, starting at byte 4)
                        let mut history_moves = Vec::with_capacity(num_moves);
                        for i in 0..num_moves {
                            let byte_idx = 4 + i / 2;
                            if byte_idx >= 16 {
                                break;
                            }
                            let nibble = if i % 2 == 0 {
                                (decrypted[byte_idx] >> 4) & 0x0F
                            } else {
                                decrypted[byte_idx] & 0x0F
                            };
                            let face_idx = (nibble >> 1) & 0x07;
                            let direction = nibble & 0x01;
                            if let Some(mv) = Self::decode_history_move(face_idx, direction)
                            {
                                // History moves go from start_serial downward
                                let serial =
                                    start_serial.wrapping_sub(i as u8);
                                history_moves.push(Gen3BufferedMove {
                                    serial,
                                    mv,
                                    timestamp: 0, // No timestamps in history
                                });
                            }
                        }

                        // Inject history moves into FIFO buffer at the head
                        {
                            let mut buffer = fifo_buffer_copy.lock().unwrap();
                            let ls = *last_serial_copy.lock().unwrap();
                            for hm in history_moves {
                                // Only inject if serial is in the gap
                                let dominated_by_last = if let Some(last) = ls {
                                    let diff = hm.serial.wrapping_sub(last);
                                    diff == 0 || diff > 128
                                } else {
                                    false
                                };
                                if dominated_by_last {
                                    continue;
                                }
                                // Check if serial already in buffer
                                let already_in = buffer
                                    .iter()
                                    .any(|b| b.serial == hm.serial);
                                if already_in {
                                    continue;
                                }
                                // Insert at front of buffer
                                buffer.push_front(hm);
                            }
                        }

                        *pending_history_copy.lock().unwrap() = false;

                        // Try to evict again
                        Self::try_evict(
                            &fifo_buffer_copy,
                            &last_serial_copy,
                            &state_copy,
                            &synced_copy,
                            &pending_history_copy,
                            &move_listener,
                            &write_copy,
                            &device_copy,
                            &cipher_for_handler,
                        );
                    }
                    // BATTERY event (0x10)
                    0x10 => {
                        let level = decrypted[3] as u32;
                        *battery_percentage_copy.lock().unwrap() =
                            Some(level.min(100));
                    }
                    // DISCONNECT event (0x11)
                    0x11 => {
                        *synced_copy.lock().unwrap() = false;
                    }
                    _ => (),
                }
            }
        });

        // Request initial cube state
        let mut loop_count = 0;
        loop {
            Self::send_command(
                &[0x68, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                &write,
                &device,
                &cipher,
            )
            .await?;

            tokio::time::sleep(Duration::from_millis(200)).await;

            if *state_set.lock().unwrap() {
                break;
            }

            loop_count += 1;
            if loop_count > Self::CUBE_STATE_TIMEOUT_MS / 200 {
                return Err(anyhow!("Did not receive initial cube state"));
            }
        }

        // Request battery state
        Self::send_command(
            &[0x68, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &write,
            &device,
            &cipher,
        )
        .await?;

        Ok(Self {
            device,
            state,
            battery_percentage,
            synced,
            cipher,
            write,
        })
    }

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

    /// Decode a live move from face bitmask and direction.
    /// Bitmask: U=2, R=32, F=8, D=1, L=16, B=4
    /// Direction: 0=CW, 1=CCW
    fn decode_live_move(face_bitmask: u8, direction: u8) -> Option<Move> {
        let face_moves: &[(u8, Move, Move)] = &[
            (2, Move::U, Move::Up),
            (32, Move::R, Move::Rp),
            (8, Move::F, Move::Fp),
            (1, Move::D, Move::Dp),
            (16, Move::L, Move::Lp),
            (4, Move::B, Move::Bp),
        ];
        for &(mask, cw, ccw) in face_moves {
            if face_bitmask == mask {
                return Some(if direction == 0 { cw } else { ccw });
            }
        }
        None
    }

    /// Decode a history move from 3-bit face index and 1-bit direction.
    /// Face: 0=D, 1=U, 2=B, 3=F, 4=L, 5=R
    /// Direction: 0=CW, 1=CCW
    fn decode_history_move(face_idx: u8, direction: u8) -> Option<Move> {
        let face_moves: &[(Move, Move)] = &[
            (Move::D, Move::Dp),   // 0
            (Move::U, Move::Up),   // 1
            (Move::B, Move::Bp),   // 2
            (Move::F, Move::Fp),   // 3
            (Move::L, Move::Lp),   // 4
            (Move::R, Move::Rp),   // 5
        ];
        if (face_idx as usize) < face_moves.len() {
            let (cw, ccw) = face_moves[face_idx as usize];
            Some(if direction == 0 { cw } else { ccw })
        } else {
            None
        }
    }

    /// Try to evict moves from the FIFO buffer and deliver them.
    fn try_evict(
        fifo_buffer: &Arc<Mutex<VecDeque<Gen3BufferedMove>>>,
        last_serial: &Arc<Mutex<Option<u8>>>,
        state: &Arc<Mutex<Cube3x3x3>>,
        synced: &Arc<Mutex<bool>>,
        pending_history: &Arc<Mutex<bool>>,
        move_listener: &Arc<Mutex<Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>>>,
        write: &Characteristic,
        device: &Peripheral,
        cipher: &GANCubeVersion3Cipher,
    ) {
        loop {
            let mut buffer = fifo_buffer.lock().unwrap();
            if buffer.is_empty() {
                break;
            }

            // Check buffer overflow
            if buffer.len() > 16 {
                *synced.lock().unwrap() = false;
                buffer.clear();
                break;
            }

            let ls = match *last_serial.lock().unwrap() {
                Some(s) => s,
                None => break,
            };

            let head_serial = buffer.front().unwrap().serial;
            let diff = head_serial.wrapping_sub(ls);

            if diff == 1 {
                // Sequential - deliver
                let entry = buffer.pop_front().unwrap();
                drop(buffer); // Release lock before calling listener

                state.lock().unwrap().do_move(entry.mv);
                *last_serial.lock().unwrap() = Some(entry.serial);

                let listener = move_listener.lock().unwrap();
                listener(BluetoothCubeEvent::Move(
                    vec![TimedMove::new(entry.mv, entry.timestamp)],
                    state.lock().unwrap().clone(),
                ));
            } else if diff > 1 && diff < 128 {
                // Gap detected - request history
                drop(buffer);
                if !*pending_history.lock().unwrap() {
                    // Request the full gap of moves ending at the head
                    // serial. The cube packs the response newest-first
                    // starting at `head_serial` and going backward, so
                    // passing the head and the full diff returns moves
                    // with serials head, head-1, ..., head-(diff-1).
                    Self::send_move_history_request(
                        head_serial,
                        diff,
                        write,
                        device,
                        cipher,
                        pending_history,
                    );
                }
                break;
            } else {
                // diff == 0 or wrapped backwards - skip this entry
                buffer.pop_front();
            }
        }
    }

    /// Send a move history request command (blocking).
    fn send_move_history_request(
        start_serial: u8,
        count: u8,
        write: &Characteristic,
        device: &Peripheral,
        cipher: &GANCubeVersion3Cipher,
        pending_history: &Arc<Mutex<bool>>,
    ) {
        // The history response is byte-aligned, packed in 4-bit nibbles
        // starting from an odd serial. If `serial` is even, slide it back
        // one (we'll get one already-known move which is harmlessly
        // deduped). The reference implementation does NOT bump the count
        // here.
        let mut serial = start_serial;
        let mut count = count as u16;
        if serial % 2 == 0 {
            serial = serial.wrapping_sub(1);
        }
        if count % 2 == 1 {
            count += 1;
        }
        // Never cross the serial wraparound boundary (firmware bug).
        count = count.min(serial as u16 + 1);

        let count = count as u8;
        let mut cmd = [0u8; 16];
        cmd[0] = 0x68;
        cmd[1] = 0x03;
        cmd[2] = serial;
        cmd[4] = count;

        *pending_history.lock().unwrap() = true;
        let encrypted = cipher.encrypt(&cmd);
        // Fire and forget - spawn a task to send the command
        let device = device.clone();
        let write = write.clone();
        tokio::spawn(async move {
            let _ = device
                .write(&write, &encrypted, WriteType::WithResponse)
                .await;
        });
    }

    /// Send an encrypted command to the cube.
    async fn send_command(
        cmd: &[u8; 16],
        write: &Characteristic,
        device: &Peripheral,
        cipher: &GANCubeVersion3Cipher,
    ) -> Result<()> {
        let encrypted = cipher.encrypt(cmd);
        device
            .write(write, &encrypted, WriteType::WithResponse)
            .await?;
        Ok(())
    }
}

impl BluetoothCubeDevice for GANCubeVersion3 {
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
        let cmd: [u8; 16] = [
            0x68, 0x05, 0x05, 0x39, 0x77, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x00,
            0x00, 0x00,
        ];
        let encrypted = self.cipher.encrypt(&cmd);
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| {
            handle.block_on(
                self.device
                    .write(&self.write, &encrypted, WriteType::WithResponse),
            )
        });

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

// ---- GAN v4 (Gen4 protocol, GAN12 ui / GAN14 ui) ----

struct GANCubeVersion4 {
    device: Peripheral,
    state: Arc<Mutex<Cube3x3x3>>,
    battery_percentage: Arc<Mutex<Option<u32>>>,
    synced: Arc<Mutex<bool>>,
    write: Characteristic,
    cipher: GANCubeVersion2Cipher,
}

impl GANCubeVersion4 {
    const CUBE_STATE_TIMEOUT_MS: usize = 2000;

    pub async fn new(
        device: Peripheral,
        read: Characteristic,
        write: Characteristic,
        move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
    ) -> Result<Self> {
        // Derive keys from manufacturer data (same as Gen2/Gen3)
        let props = device
            .properties()
            .await?
            .ok_or_else(|| anyhow!("Could not read peripheral properties"))?;
        let device_key: [u8; 6] = if let Some(data) = props.manufacturer_data.get(&1) {
            if data.len() >= 9 {
                let mut result = [0; 6];
                result.copy_from_slice(&data[3..9]);
                result
            } else {
                return Err(anyhow!("Device identifier data invalid"));
            }
        } else {
            return Err(anyhow!("Manufacturer data missing device identifier"));
        };

        const GAN_V4_KEY: [u8; 16] = [
            0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11,
            0x12, 0x53,
        ];
        const GAN_V4_IV: [u8; 16] = [
            0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12,
            0x02, 0x43,
        ];
        let mut key = GAN_V4_KEY;
        let mut iv = GAN_V4_IV;
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
        let synced = Arc::new(Mutex::new(true));

        let cipher_copy = cipher.clone();
        let state_copy = state.clone();
        let state_set_copy = state_set.clone();
        let battery_percentage_copy = battery_percentage.clone();
        let synced_copy = synced.clone();

        // Subscribe and spawn notification handler
        device.subscribe(&read).await?;
        let mut notification_stream = device.notifications().await?;

        // Shared state for FIFO buffer and serial tracking
        let last_serial: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(None));
        // Cube clock of the most recent live MOVE event we've seen. Used to
        // convert the cube's absolute (since-boot) timestamp into a per-move
        // delta, which is what the BluetoothCube calibration layer expects.
        let last_live_timestamp: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let fifo_buffer: Arc<Mutex<VecDeque<Gen3BufferedMove>>> =
            Arc::new(Mutex::new(VecDeque::new()));
        let pending_history: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let last_serial_copy = last_serial.clone();
        let last_live_timestamp_copy = last_live_timestamp.clone();
        let fifo_buffer_copy = fifo_buffer.clone();
        let pending_history_copy = pending_history.clone();

        let write_copy = write.clone();
        let device_copy = device.clone();
        let cipher_for_handler = cipher.clone();

        let move_listener = Arc::new(Mutex::new(move_listener));

        tokio::spawn(async move {
            while let Some(value) = notification_stream.next().await {
                // Gen4 uses 20-byte messages with GANCubeVersion2Cipher
                if value.value.len() < 16 {
                    continue;
                }
                let decrypted = match cipher_copy.decrypt(&value.value) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                // Gen4 has no magic byte; event type is at byte 0
                let event_type = decrypted[0];
                let data_length = decrypted[1];

                match event_type {
                    // MOVE event (0x01)
                    0x01 => {
                        if data_length == 0 {
                            continue;
                        }
                        if !*state_set_copy.lock().unwrap() {
                            continue;
                        }

                        // Gen4 bit offsets (no magic byte, shifted by 8 bits from Gen3)
                        // Timestamp at bit 16 (bytes 2-5), serial at bit 48 (bytes 6-7)
                        // Direction at bit 64, face at bit 66
                        let timestamp = u32::from_le_bytes([
                            decrypted[2],
                            decrypted[3],
                            decrypted[4],
                            decrypted[5],
                        ]);
                        let serial_16 =
                            u16::from_le_bytes([decrypted[6], decrypted[7]]);
                        let serial = (serial_16 & 0xFF) as u8;

                        // Direction and face are in byte 8
                        // Bits 64-65: direction (2 bits), bits 66-71: face bitmask (6 bits)
                        let direction_and_face = decrypted[8];
                        let direction = (direction_and_face >> 6) & 0x03;
                        let face_bitmask = direction_and_face & 0x3F;

                        let mv = match Self::decode_live_move(face_bitmask, direction) {
                            Some(m) => m,
                            None => continue,
                        };

                        // First live move bootstraps last_serial. We don't
                        // trust the facelets event for this because some
                        // Gen4 cubes report serial=0 in periodic facelets
                        // unconditionally. Setting last_serial = serial - 1
                        // makes try_evict treat this move as the next
                        // expected one (diff=1) and accept it without
                        // requesting bogus history.
                        {
                            let mut ls = last_serial_copy.lock().unwrap();
                            if ls.is_none() {
                                *ls = Some(serial.wrapping_sub(1));
                            }
                        }

                        // Convert the cube's absolute since-boot timestamp
                        // into a per-move delta. The BluetoothCube
                        // calibration layer expects raw_move.time() to be a
                        // delta from the previous move (Gen2 protocol
                        // convention) and accumulates it; passing the raw
                        // absolute value inflates solve durations by
                        // several orders of magnitude.
                        let move_delta = {
                            let mut last_ts = last_live_timestamp_copy.lock().unwrap();
                            let delta = match *last_ts {
                                Some(prev) => timestamp.wrapping_sub(prev),
                                None => 0,
                            };
                            *last_ts = Some(timestamp);
                            delta
                        };

                        {
                            let mut buffer = fifo_buffer_copy.lock().unwrap();
                            buffer.push_back(Gen3BufferedMove {
                                serial,
                                mv,
                                timestamp: move_delta,
                            });
                        }

                        Self::try_evict(
                            &fifo_buffer_copy,
                            &last_serial_copy,
                            &state_copy,
                            &synced_copy,
                            &pending_history_copy,
                            &move_listener,
                            &write_copy,
                            &device_copy,
                            &cipher_for_handler,
                        );
                    }
                    // FACELETS event (0xED)
                    0xED => {
                        // Serial at bit 16 (bytes 2-3)
                        let serial_16 =
                            u16::from_le_bytes([decrypted[2], decrypted[3]]);
                        let serial = (serial_16 & 0xFF) as u8;

                        // Corner permutation at bit 32, corner orientation at bit 53
                        // Edge permutation at bit 69 (note: spec says 69), edge orientation at bit 113
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
                            corners[i] =
                                Self::extract_bits(&decrypted, 32 + i * 3, 3);
                            corner_twist[i] =
                                Self::extract_bits(&decrypted, 53 + i * 2, 2);
                            total_corner_twist += corner_twist[i];
                            if !corners_left.remove(&corners[i]) || corner_twist[i] >= 3
                            {
                                valid = false;
                                break;
                            }
                        }

                        if valid {
                            for i in 0..11 {
                                edges[i] =
                                    Self::extract_bits(&decrypted, 69 + i * 4, 4);
                                edge_parity[i] =
                                    Self::extract_bits(&decrypted, 113 + i, 1);
                                total_edge_parity += edge_parity[i];
                                if !edges_left.remove(&edges[i]) || edge_parity[i] >= 2
                                {
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

                            // Do NOT initialize last_serial from the facelets
                            // event. On at least some Gen4 cubes (e.g.
                            // GANic4) the periodic facelets event reports
                            // serial=0 unconditionally — using it as a
                            // baseline causes a phony history-recovery
                            // request on the first real move, which returns
                            // garbage data for the stale slots and decodes
                            // as a phantom move. Instead, last_serial is
                            // set by the first live MOVE event below.
                            //
                            // The serial==0 guard below also covers the
                            // common case: the periodic facelets reports
                            // 0, so the gap check is a no-op for those
                            // cubes. For Gen4 cubes that DO populate the
                            // facelets serial, this still catches the
                            // "missed last move" case as long as the first
                            // live move set last_serial first.
                            {
                                // Skip gap check at serial 0 (rollover quirk
                                // and the always-zero periodic facelets
                                // case).
                                if serial != 0 {
                                    let ls = *last_serial_copy.lock().unwrap();
                                    if let Some(last) = ls {
                                        let gap =
                                            (serial.wrapping_sub(last)) as u8;
                                        if gap > 1
                                            && !*pending_history_copy.lock().unwrap()
                                        {
                                            // Request `gap` moves ending at the
                                            // current facelets serial. The history
                                            // response packs newest-first starting
                                            // at `start_serial` and going backward,
                                            // so we pass the head (newest missing)
                                            // serial and the full gap count.
                                            Self::send_move_history_request(
                                                serial,
                                                gap,
                                                &write_copy,
                                                &device_copy,
                                                &cipher_for_handler,
                                                &pending_history_copy,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // MOVE_HISTORY event (0xD1)
                    0xD1 => {
                        if data_length < 2 {
                            continue;
                        }
                        // Start serial at bit 16 (byte 2), moves at bit 24 (byte 3)
                        let start_serial = decrypted[2];
                        let num_moves = ((data_length - 1) * 2) as usize;

                        let mut history_moves = Vec::with_capacity(num_moves);
                        for i in 0..num_moves {
                            let byte_idx = 3 + i / 2;
                            if byte_idx >= decrypted.len() {
                                break;
                            }
                            let nibble = if i % 2 == 0 {
                                (decrypted[byte_idx] >> 4) & 0x0F
                            } else {
                                decrypted[byte_idx] & 0x0F
                            };
                            let face_idx = (nibble >> 1) & 0x07;
                            let direction = nibble & 0x01;
                            if let Some(mv) = Self::decode_history_move(face_idx, direction)
                            {
                                let serial =
                                    start_serial.wrapping_sub(i as u8);
                                history_moves.push(Gen3BufferedMove {
                                    serial,
                                    mv,
                                    timestamp: 0,
                                });
                            }
                        }

                        {
                            let mut buffer = fifo_buffer_copy.lock().unwrap();
                            let ls = *last_serial_copy.lock().unwrap();
                            for hm in history_moves {
                                let dominated_by_last = if let Some(last) = ls {
                                    let diff = hm.serial.wrapping_sub(last);
                                    diff == 0 || diff > 128
                                } else {
                                    false
                                };
                                if dominated_by_last {
                                    continue;
                                }
                                let already_in = buffer
                                    .iter()
                                    .any(|b| b.serial == hm.serial);
                                if already_in {
                                    continue;
                                }
                                buffer.push_front(hm);
                            }
                        }

                        *pending_history_copy.lock().unwrap() = false;

                        Self::try_evict(
                            &fifo_buffer_copy,
                            &last_serial_copy,
                            &state_copy,
                            &synced_copy,
                            &pending_history_copy,
                            &move_listener,
                            &write_copy,
                            &device_copy,
                            &cipher_for_handler,
                        );
                    }
                    // BATTERY event (0xEF)
                    0xEF => {
                        // Battery level byte at offset 1 + dataLength
                        let battery_idx = 1 + data_length as usize;
                        if battery_idx < decrypted.len() {
                            let level = decrypted[battery_idx] as u32;
                            *battery_percentage_copy.lock().unwrap() =
                                Some(level.min(100));
                        }
                    }
                    // DISCONNECT event (0xEA)
                    0xEA => {
                        *synced_copy.lock().unwrap() = false;
                    }
                    // Gyroscope (0xEC), Hardware info (0xFA-0xFE) - ignored for now
                    _ => (),
                }
            }
        });

        // Request initial cube state
        // Gen4 command: DD 04 00 ED 00 00 (20 bytes, zero-padded)
        let mut loop_count = 0;
        loop {
            Self::send_command(
                &[0xDD, 0x04, 0x00, 0xED, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                &write,
                &device,
                &cipher,
            )
            .await?;

            tokio::time::sleep(Duration::from_millis(200)).await;

            if *state_set.lock().unwrap() {
                break;
            }

            loop_count += 1;
            if loop_count > Self::CUBE_STATE_TIMEOUT_MS / 200 {
                return Err(anyhow!("Did not receive initial cube state"));
            }
        }

        // Request battery state
        // Gen4 command: DD 04 00 EF 00 00
        Self::send_command(
            &[0xDD, 0x04, 0x00, 0xEF, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &write,
            &device,
            &cipher,
        )
        .await?;

        Ok(Self {
            device,
            state,
            battery_percentage,
            synced,
            cipher,
            write,
        })
    }

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

    /// Decode a live move from face bitmask and direction (same encoding as Gen3).
    fn decode_live_move(face_bitmask: u8, direction: u8) -> Option<Move> {
        let face_moves: &[(u8, Move, Move)] = &[
            (2, Move::U, Move::Up),
            (32, Move::R, Move::Rp),
            (8, Move::F, Move::Fp),
            (1, Move::D, Move::Dp),
            (16, Move::L, Move::Lp),
            (4, Move::B, Move::Bp),
        ];
        for &(mask, cw, ccw) in face_moves {
            if face_bitmask == mask {
                return Some(if direction == 0 { cw } else { ccw });
            }
        }
        None
    }

    /// Decode a history move from 3-bit face index and 1-bit direction (same as Gen3).
    fn decode_history_move(face_idx: u8, direction: u8) -> Option<Move> {
        let face_moves: &[(Move, Move)] = &[
            (Move::D, Move::Dp),   // 0
            (Move::U, Move::Up),   // 1
            (Move::B, Move::Bp),   // 2
            (Move::F, Move::Fp),   // 3
            (Move::L, Move::Lp),   // 4
            (Move::R, Move::Rp),   // 5
        ];
        if (face_idx as usize) < face_moves.len() {
            let (cw, ccw) = face_moves[face_idx as usize];
            Some(if direction == 0 { cw } else { ccw })
        } else {
            None
        }
    }

    /// Try to evict moves from the FIFO buffer and deliver them.
    fn try_evict(
        fifo_buffer: &Arc<Mutex<VecDeque<Gen3BufferedMove>>>,
        last_serial: &Arc<Mutex<Option<u8>>>,
        state: &Arc<Mutex<Cube3x3x3>>,
        synced: &Arc<Mutex<bool>>,
        pending_history: &Arc<Mutex<bool>>,
        move_listener: &Arc<Mutex<Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>>>,
        write: &Characteristic,
        device: &Peripheral,
        cipher: &GANCubeVersion2Cipher,
    ) {
        loop {
            let mut buffer = fifo_buffer.lock().unwrap();
            if buffer.is_empty() {
                break;
            }

            if buffer.len() > 16 {
                *synced.lock().unwrap() = false;
                buffer.clear();
                break;
            }

            let ls = match *last_serial.lock().unwrap() {
                Some(s) => s,
                None => break,
            };

            let head_serial = buffer.front().unwrap().serial;
            let diff = head_serial.wrapping_sub(ls);

            if diff == 1 {
                let entry = buffer.pop_front().unwrap();
                drop(buffer);

                state.lock().unwrap().do_move(entry.mv);
                *last_serial.lock().unwrap() = Some(entry.serial);

                let listener = move_listener.lock().unwrap();
                listener(BluetoothCubeEvent::Move(
                    vec![TimedMove::new(entry.mv, entry.timestamp)],
                    state.lock().unwrap().clone(),
                ));
            } else if diff > 1 && diff < 128 {
                drop(buffer);
                if !*pending_history.lock().unwrap() {
                    // Request the full gap of moves ending at the head serial.
                    // The cube packs the response newest-first starting at
                    // `head_serial` and going backward, so passing the head
                    // (and the full diff) returns moves with serials
                    // head, head-1, ..., head-(diff-1) — exactly the gap plus
                    // the head itself (which we already have, deduped on
                    // injection).
                    Self::send_move_history_request(
                        head_serial,
                        diff,
                        write,
                        device,
                        cipher,
                        pending_history,
                    );
                }
                break;
            } else {
                buffer.pop_front();
            }
        }
    }

    /// Send a move history request command (blocking).
    fn send_move_history_request(
        start_serial: u8,
        count: u8,
        write: &Characteristic,
        device: &Peripheral,
        cipher: &GANCubeVersion2Cipher,
        pending_history: &Arc<Mutex<bool>>,
    ) {
        let mut serial = start_serial;
        let mut count = count as u16;
        // The history response is byte-aligned, packed in 4-bit nibbles
        // starting from an odd serial. If `serial` is even, slide it back
        // one (we'll get one already-known move which is harmlessly deduped).
        // The reference implementation does NOT bump the count here.
        if serial % 2 == 0 {
            serial = serial.wrapping_sub(1);
        }
        if count % 2 == 1 {
            count += 1;
        }
        // Never cross the serial wraparound boundary (firmware bug; see
        // GAN_GEN4_PROTOCOL_SPEC.md section 8.1).
        count = count.min(serial as u16 + 1);

        let count = count as u8;
        // Gen4 history command: D1 04 SER 00 CNT 00
        let mut cmd = [0u8; 20];
        cmd[0] = 0xD1;
        cmd[1] = 0x04;
        cmd[2] = serial;
        cmd[4] = count;

        *pending_history.lock().unwrap() = true;
        let encrypted = cipher.encrypt(&cmd).unwrap();
        let device = device.clone();
        let write = write.clone();
        tokio::spawn(async move {
            let _ = device
                .write(&write, &encrypted, WriteType::WithResponse)
                .await;
        });
    }

    /// Send an encrypted command to the cube.
    async fn send_command(
        cmd: &[u8; 20],
        write: &Characteristic,
        device: &Peripheral,
        cipher: &GANCubeVersion2Cipher,
    ) -> Result<()> {
        let encrypted = cipher.encrypt(cmd)?;
        device
            .write(write, &encrypted, WriteType::WithResponse)
            .await?;
        Ok(())
    }
}

impl BluetoothCubeDevice for GANCubeVersion4 {
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
        // Gen4 reset command: D2 0D 05 39 77 00 00 01 23 45 67 89 AB 00 00 00 00 00 00 00
        let cmd: [u8; 20] = [
            0xD2, 0x0D, 0x05, 0x39, 0x77, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let encrypted = self.cipher.encrypt(&cmd).unwrap();
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| {
            handle.block_on(
                self.device
                    .write(&self.write, &encrypted, WriteType::WithResponse),
            )
        });

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

/// Returns true when verbose GAN BLE diagnostics are enabled. Set
/// `TPSCUBE_BT_DEBUG=1` in the environment to turn them on. The diagnostics
/// are off by default so the desktop UI doesn't fill stderr with connection
/// chatter on every pair.
fn gan_debug() -> bool {
    std::env::var("TPSCUBE_BT_DEBUG").is_ok()
}

pub(crate) async fn gan_cube_connect(
    device: Peripheral,
    move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
) -> Result<Box<dyn BluetoothCubeDevice>> {
    let characteristics = device.characteristics();
    if gan_debug() {
        eprintln!("GAN: found {} characteristics", characteristics.len());
        for c in &characteristics {
            eprintln!("  characteristic: uuid={} service={}", c.uuid, c.service_uuid);
        }
    }

    // Find characteristics for communicating with the cube. There are two different
    // versions of the GAN cubes with different characteristics.
    let mut v1_version = None;
    let mut v1_hardware = None;
    let mut v1_cube_state = None;
    let mut v1_last_moves = None;
    let mut v1_timing = None;
    let mut v1_battery = None;
    let mut v2_write = None;
    let mut v2_read = None;
    let mut v3_write = None;
    let mut v3_read = None;
    let mut v4_write = None;
    let mut v4_read = None;
    for characteristic in characteristics {
        if characteristic.uuid == Uuid::from_str("00002a28-0000-1000-8000-00805f9b34fb").unwrap() {
            v1_version = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("00002a23-0000-1000-8000-00805f9b34fb").unwrap()
        {
            v1_hardware = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("0000fff2-0000-1000-8000-00805f9b34fb").unwrap()
        {
            v1_cube_state = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("0000fff5-0000-1000-8000-00805f9b34fb").unwrap()
        {
            // Gen4 command characteristic shares UUID 0000fff5 but under service
            // 00000010-0000-fff7-fff6-fff5fff4fff0. Distinguish by service UUID.
            if characteristic.service_uuid
                == Uuid::from_str("00000010-0000-fff7-fff6-fff5fff4fff0").unwrap()
            {
                v4_write = Some(characteristic);
            } else {
                v1_last_moves = Some(characteristic);
            }
        } else if characteristic.uuid
            == Uuid::from_str("0000fff6-0000-1000-8000-00805f9b34fb").unwrap()
        {
            // Gen4 state characteristic shares UUID 0000fff6 but under service
            // 00000010-0000-fff7-fff6-fff5fff4fff0. Distinguish by service UUID.
            if characteristic.service_uuid
                == Uuid::from_str("00000010-0000-fff7-fff6-fff5fff4fff0").unwrap()
            {
                v4_read = Some(characteristic);
            } else {
                v1_timing = Some(characteristic);
            }
        } else if characteristic.uuid
            == Uuid::from_str("0000fff7-0000-1000-8000-00805f9b34fb").unwrap()
        {
            v1_battery = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("28be4a4a-cd67-11e9-a32f-2a2ae2dbcce4").unwrap()
        {
            v2_write = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("28be4cb6-cd67-11e9-a32f-2a2ae2dbcce4").unwrap()
        {
            v2_read = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("8653000c-43e6-47b7-9cb0-5fc21d4ae340").unwrap()
        {
            v3_write = Some(characteristic);
        } else if characteristic.uuid
            == Uuid::from_str("8653000b-43e6-47b7-9cb0-5fc21d4ae340").unwrap()
        {
            v3_read = Some(characteristic);
        }
    }

    // Create cube object based on available characteristics
    if gan_debug() {
        eprintln!("GAN: v1_version={} v1_hardware={} v1_cube_state={} v1_last_moves={} v1_timing={} v1_battery={} v2_write={} v2_read={} v3_write={} v3_read={} v4_write={} v4_read={}",
            v1_version.is_some(), v1_hardware.is_some(), v1_cube_state.is_some(),
            v1_last_moves.is_some(), v1_timing.is_some(), v1_battery.is_some(),
            v2_write.is_some(), v2_read.is_some(), v3_write.is_some(), v3_read.is_some(),
            v4_write.is_some(), v4_read.is_some());
    }
    if v1_version.is_some()
        && v1_hardware.is_some()
        && v1_cube_state.is_some()
        && v1_last_moves.is_some()
        && v1_timing.is_some()
        && v1_battery.is_some()
    {
        let characteristics = GANCubeVersion1Characteristics {
            version: v1_version.unwrap(),
            hardware: v1_hardware.unwrap(),
            cube_state: v1_cube_state.unwrap(),
            last_moves: v1_last_moves.unwrap(),
            timing: v1_timing.unwrap(),
            battery: v1_battery.unwrap(),
        };

        // Detect cube version
        let version = device.read(&characteristics.version).await?;
        if version.len() < 3 {
            return Err(anyhow!("Device version invalid"));
        }
        let major = version[0];
        let minor = version[1];
        if gan_debug() {
            eprintln!("GAN: version={:?} major={} minor={}", version, major, minor);
        }
        if major == 1 && minor <= 1 {
            Ok(Box::new(
                GANCubeVersion1::new(device, characteristics, move_listener, minor).await?,
            ))
        } else if major == 2 && minor == 0 {
            Ok(Box::new(
                GANSmartTimer::new(device, characteristics.last_moves, move_listener).await?,
            ))
        } else {
            Err(anyhow!(
                "GAN cube version {}.{} not supported",
                major,
                minor
            ))
        }
    } else if v4_read.is_some() && v4_write.is_some() {
        if gan_debug() {
            eprintln!("GAN: detected Gen4 cube (service 00000010)");
        }
        Ok(Box::new(
            GANCubeVersion4::new(device, v4_read.unwrap(), v4_write.unwrap(), move_listener).await?,
        ))
    } else if v2_read.is_some() && v2_write.is_some() {
        Ok(Box::new(
            GANCubeVersion2::new(device, v2_read.unwrap(), v2_write.unwrap(), move_listener).await?,
        ))
    } else if v3_read.is_some() && v3_write.is_some() {
        if gan_debug() {
            eprintln!("GAN: detected Gen3 cube (service 8653000a)");
        }
        Ok(Box::new(
            GANCubeVersion3::new(device, v3_read.unwrap(), v3_write.unwrap(), move_listener).await?,
        ))
    } else {
        Err(anyhow!("Unrecognized GAN cube version"))
    }
}
