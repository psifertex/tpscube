//! btletest — move-timing sanity check for the BluetoothCube API.
//!
//! Connects to the first smart cube it sees and prints, for every move, the
//! cube-reported cumulative time next to the host's own wall clock. The point
//! is to eyeball clock drift between the cube and real time; `btcli` is the
//! richer harness for protocol debugging.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tpscube_core::{BluetoothCube, BluetoothCubeEvent, BluetoothCubeState};

fn main() {
    let cube = BluetoothCube::new();

    // Set once on the first move, so cube time and host time share an origin.
    let real_time_start: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let total_time = Arc::new(Mutex::new(0u32));

    // The listener must be registered before connecting so the first move
    // (and any initial state event) is not missed.
    let real_time_start_copy = real_time_start.clone();
    let total_time_copy = total_time.clone();
    cube.register_move_listener(move |event| {
        let moves = match event {
            BluetoothCubeEvent::Move(moves, _state) => moves,
            _ => return,
        };
        let mut total_time = total_time_copy.lock().unwrap();
        let mut real_time_start = real_time_start_copy.lock().unwrap();
        match *real_time_start {
            Some(start) => {
                let elapsed = Instant::now() - start;
                for mv in moves {
                    *total_time += mv.time();
                    println!(
                        "Move {}@{}  received at {}",
                        mv.move_().to_string(),
                        *total_time,
                        elapsed.as_millis()
                    );
                }
            }
            None => {
                *real_time_start = Some(Instant::now());
                for mv in moves {
                    println!("Move {}  (initial)", mv.move_().to_string());
                }
            }
        }
    });

    // Wait for a cube to show up. Note that `available_devices` only returns
    // devices whose advertised name is recognized by `BluetoothCubeType`; use
    // `btcli scan-raw` if a cube never appears here.
    let device = loop {
        let devices = cube.available_devices().unwrap();
        if let Some(device) = devices.into_iter().next() {
            break device;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    println!(
        "Connecting to {:?} (type {:?})",
        device.name, device.cube_type
    );
    cube.connect(device.id).unwrap();

    loop {
        match cube.state().unwrap() {
            BluetoothCubeState::Connected => break,
            BluetoothCubeState::Error => {
                println!("Connection failed");
                return;
            }
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    println!("Connected");

    // Stream until the cube desyncs; ctrl-c otherwise.
    loop {
        if !cube.synced().unwrap() {
            println!("Lost cube sync");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
