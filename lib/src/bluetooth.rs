// The `gan` module contains shared Gen3/Gen4 protocol code (plus the
// existing native btleplug and web-sys transport layers). Both the native
// and wasm variants live inside `gan/` and are cfg-gated internally so we
// only have one module declaration at this level.
#[cfg(any(feature = "bluetooth", feature = "web-bluetooth"))]
mod gan;

// The `qiyi` module is laid out the same way: a shared, transport-agnostic
// protocol state machine plus cfg-gated native and web transports.
#[cfg(any(feature = "bluetooth", feature = "web-bluetooth"))]
mod qiyi;

// MoYu's `WCU_MY3*` cubes (WeiLong V10/V11 AI). Same layout as `gan`: a
// shared transport-agnostic protocol module plus cfg-gated native and
// wasm transports.
#[cfg(any(feature = "bluetooth", feature = "web-bluetooth"))]
mod moyu32;

#[cfg(not(target_arch = "wasm32"))]
mod giiker;
#[cfg(not(target_arch = "wasm32"))]
mod gocube;
#[cfg(not(target_arch = "wasm32"))]
mod moyu;

// Move-timing calibration is transport-agnostic and used by both backends.
#[cfg(any(feature = "bluetooth", feature = "web-bluetooth"))]
mod clock_calibration;

#[cfg(target_arch = "wasm32")]
pub(crate) mod web;
#[cfg(target_arch = "wasm32")]
mod giiker_web;
#[cfg(target_arch = "wasm32")]
mod gocube_web;
#[cfg(target_arch = "wasm32")]
mod moyu_web;

use crate::common::TimedMove;
use crate::cube3x3x3::Cube3x3x3;

#[cfg(not(target_arch = "wasm32"))]
use anyhow::{anyhow, Result};
#[cfg(not(target_arch = "wasm32"))]
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
#[cfg(not(target_arch = "wasm32"))]
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
#[cfg(not(target_arch = "wasm32"))]
use gan::gan_cube_connect;
#[cfg(not(target_arch = "wasm32"))]
use giiker::giiker_connect;
#[cfg(not(target_arch = "wasm32"))]
use gocube::gocube_connect;
#[cfg(not(target_arch = "wasm32"))]
use moyu::moyu_connect;
#[cfg(not(target_arch = "wasm32"))]
use qiyi::qiyi_cube_connect;
#[cfg(not(target_arch = "wasm32"))]
use moyu32::moyu32_connect;
#[cfg(not(target_arch = "wasm32"))]
use clock_calibration::ClockCalibration;
#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::ops::Deref;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait BluetoothCubeDevice: Send {
    fn cube_state(&self) -> Cube3x3x3;
    fn battery_percentage(&self) -> Option<u32>;
    fn battery_charging(&self) -> Option<bool>;
    fn reset_cube_state(&self);
    fn synced(&self) -> bool;
    fn update(&self) {}
    fn disconnect(&self);
    fn timer_only(&self) -> bool {
        false
    }

    fn estimated_clock_ratio(&self) -> f64 {
        1.0
    }
    fn clock_ratio_range(&self) -> (f64, f64) {
        (0.98, 1.02)
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
pub(crate) trait BluetoothCubeDevice {
    fn cube_state(&self) -> Cube3x3x3;
    fn battery_percentage(&self) -> Option<u32>;
    fn battery_charging(&self) -> Option<bool>;
    fn reset_cube_state(&self);
    fn synced(&self) -> bool;
    fn update(&self) {}
    fn disconnect(&self);
    fn timer_only(&self) -> bool {
        false
    }

    fn estimated_clock_ratio(&self) -> f64 {
        1.0
    }
    fn clock_ratio_range(&self) -> (f64, f64) {
        (0.98, 1.02)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct AvailableDevice {
    pub id: PeripheralId,
    pub name: String,
    pub cube_type: BluetoothCubeType,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BluetoothCubeType {
    GAN,
    GoCube,
    Giiker,
    MoYu,
    QiYi,
    /// MoYu WeiLong V10 AI / V11 AI, advertised as `WCU_MY3*`.
    MoYu32,
}

impl BluetoothCubeType {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        // GAN firmware is inconsistent about capitalization: the Smart Timer and
        // Halo advertise as `Gan`/`gan` on some units, which upstream drivers all
        // match (cstimer `gantimer.js` filters `['GAN', 'Gan', 'gan']`).
        //
        // MoYu's `AiCube` line (MoYu AI V2 / WeiLong WRM V10 AI) speaks the GAN
        // Gen2 protocol, so it routes through the GAN implementation; only the
        // AES base key/IV differ, and those are chosen from the name in
        // `gan::cipher::GanKeySet::from_device_name`.
        if name.starts_with("GAN")
            || name.starts_with("Gan")
            || name.starts_with("gan")
            || name.starts_with("MG")
            || name.starts_with("AiCube")
        {
            Some(BluetoothCubeType::GAN)
        } else if name.starts_with("GoCube") || name.starts_with("Rubiks") {
            Some(BluetoothCubeType::GoCube)
        // `Hi-` is a rebrand of the Giiker protocol; upstream drivers treat it as
        // the same family (cstimer `giikercube.js`).
        } else if name.starts_with("Gi") || name.starts_with("Mi Smart") || name.starts_with("Hi-") {
            Some(BluetoothCubeType::Giiker)
        // Some MoYu MHC firmware omits the hyphen, so match the bare prefix.
        } else if name.starts_with("MHC") {
            Some(BluetoothCubeType::MoYu)
        } else if qiyi::is_qiyi_device_name(name) {
            // The QiYi Smart Cube and the XMD Tornado V4 share a protocol.
            // Their advertised names are space padded, so the check trims.
            Some(BluetoothCubeType::QiYi)
        } else if name.starts_with("WCU_MY3") {
            // MoYu's WeiLong AI line. The vendor's own filter is the
            // broader `WCU_`, but that also matches the WeiPo V5 AI 2x2
            // and tpscube's Bluetooth cube state is 3x3 only, so stay
            // narrow enough to exclude it.
            Some(BluetoothCubeType::MoYu32)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BluetoothCubeState {
    Discovering,
    Connecting,
    Connected,
    Desynced,
    Error,
}

#[derive(Clone)]
pub enum BluetoothCubeEvent {
    Move(Vec<TimedMove>, Cube3x3x3),
    HandsOnTimer,
    TimerStartCancel,
    TimerReady,
    TimerStarted,
    TimerFinished(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MoveListenerHandle {
    id: u64,
}

impl MoveListenerHandle {
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn new(id: u64) -> Self {
        Self { id }
    }
}

// ============================================================
// Native (non-WASM) implementation using btleplug
// ============================================================
#[cfg(not(target_arch = "wasm32"))]
pub struct BluetoothCube {
    discovered_devices: Arc<Mutex<Vec<AvailableDevice>>>,
    to_connect: Arc<Mutex<Option<PeripheralId>>>,
    state: Arc<Mutex<BluetoothCubeState>>,
    connected_device: Arc<Mutex<Option<Box<dyn BluetoothCubeDevice>>>>,
    connected_name: Arc<Mutex<Option<String>>>,
    battery: Arc<Mutex<(Option<u32>, Option<bool>)>>,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + Send>>>>,
    next_listener_id: AtomicU64,
    error: Arc<Mutex<Option<String>>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl BluetoothCube {
    pub fn new() -> Self {
        let discovered_devices = Arc::new(Mutex::new(Vec::new()));
        let to_connect = Arc::new(Mutex::new(None));
        let state = Arc::new(Mutex::new(BluetoothCubeState::Discovering));
        let connected_device = Arc::new(Mutex::new(None));
        let connected_name = Arc::new(Mutex::new(None));
        let battery = Arc::new(Mutex::new((None, None)));
        let listeners = Arc::new(Mutex::new(HashMap::new()));
        let error = Arc::new(Mutex::new(None));

        let discovered_devices_copy = discovered_devices.clone();
        let to_connect_copy = to_connect.clone();
        let state_copy = state.clone();
        let connected_device_copy = connected_device.clone();
        let connected_name_copy = connected_name.clone();
        let battery_copy = battery.clone();
        let listeners_copy = listeners.clone();
        let error_copy = error.clone();
        std::thread::spawn(move || {
            // Create a new tokio runtime for the bluetooth thread
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    *state_copy.lock().unwrap() = BluetoothCubeState::Error;
                    *error_copy.lock().unwrap() = Some(e.to_string());
                    return;
                }
            };
            match rt.block_on(Self::discovery_handler(
                discovered_devices_copy,
                to_connect_copy,
                state_copy.clone(),
                connected_device_copy,
                connected_name_copy,
                battery_copy,
                listeners_copy,
            )) {
                Err(error) => {
                    *state_copy.lock().unwrap() = BluetoothCubeState::Error;
                    *error_copy.lock().unwrap() = Some(error.to_string());
                }
                _ => (),
            }
        });

        Self {
            discovered_devices,
            to_connect,
            state,
            connected_device,
            connected_name,
            battery,
            listeners,
            next_listener_id: AtomicU64::new(0),
            error,
        }
    }

    async fn discovery_handler(
        discovered_devices: Arc<Mutex<Vec<AvailableDevice>>>,
        to_connect: Arc<Mutex<Option<PeripheralId>>>,
        state: Arc<Mutex<BluetoothCubeState>>,
        connected_device: Arc<Mutex<Option<Box<dyn BluetoothCubeDevice>>>>,
        connected_name: Arc<Mutex<Option<String>>>,
        battery: Arc<Mutex<(Option<u32>, Option<bool>)>>,
        listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + Send>>>>,
    ) -> Result<()> {
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        let central: Adapter = adapters
            .into_iter()
            .nth(0)
            .ok_or_else(|| anyhow!("No Bluetooth adapters found"))?;
        central.start_scan(ScanFilter::default()).await?;

        loop {
            // See if the client asked to connect to a cube
            let to_connect_id = to_connect.lock().unwrap().clone();
            if let Some(to_connect_id) = to_connect_id {
                // Look for the cube in the device list to get the Peripheral object
                for device in central.peripherals().await? {
                    if to_connect_id == device.id() {
                        let listeners_copy = listeners.clone();

                        // Set up time calibration state. The logic is shared
                        // with the web backend in `clock_calibration`.
                        let calibration_state = Arc::new(Mutex::new(
                            ClockCalibration::new(1.0, (0.98, 1.02)),
                        ));
                        let init_calibration_state = calibration_state.clone();

                        let _ = Self::connect_handler(
                            state.clone(),
                            connected_device.clone(),
                            connected_name.clone(),
                            battery.clone(),
                            device,
                            Box::new(move |cube| {
                                *init_calibration_state.lock().unwrap() = ClockCalibration::new(
                                    cube.estimated_clock_ratio(),
                                    cube.clock_ratio_range(),
                                );
                            }),
                            Box::new(move |event| {
                                match event {
                                    BluetoothCubeEvent::Move(moves, state) => {
                                        // We can't use the move timing data directly. Some
                                        // cubes have very uncalibrated clocks and we must
                                        // adjust the timing to match real time, with the
                                        // host device as the reference source.
                                        let adjusted_moves =
                                            calibration_state.lock().unwrap().adjust(moves);

                                        // Notify clients of the move information
                                        for listener in listeners_copy.lock().unwrap().iter() {
                                            listener.1(BluetoothCubeEvent::Move(
                                                adjusted_moves.clone(),
                                                state.clone(),
                                            ));
                                        }
                                    }
                                    event => {
                                        // Notify clients of the event
                                        for listener in listeners_copy.lock().unwrap().iter() {
                                            listener.1(event.clone());
                                        }
                                    }
                                }
                            }),
                        )
                        .await;
                    }
                }
            }

            // Enumerate devices
            let peripherals = central.peripherals().await?;
            let mut new_devices = Vec::new();
            for device in &peripherals {
                if let Some(props) = device.properties().await? {
                    if let Some(name) = props.local_name {
                        if let Some(cube_type) = BluetoothCubeType::from_name(&name) {
                            new_devices.push(AvailableDevice {
                                id: device.id(),
                                name: name.clone(),
                                cube_type,
                            });
                        }
                    }
                }
            }
            *discovered_devices.lock().unwrap() = new_devices;

            // Wait before checking devices again. We can't use the event-based system
            // since we also need to check for client connection requests.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn connect_handler(
        state: Arc<Mutex<BluetoothCubeState>>,
        connected_device: Arc<Mutex<Option<Box<dyn BluetoothCubeDevice>>>>,
        connected_name: Arc<Mutex<Option<String>>>,
        battery: Arc<Mutex<(Option<u32>, Option<bool>)>>,
        peripheral: Peripheral,
        init: Box<dyn Fn(&dyn BluetoothCubeDevice) + Send + 'static>,
        move_listener: Box<dyn Fn(BluetoothCubeEvent) + Send + 'static>,
    ) -> Result<()> {
        // Determine cube type
        let props = peripheral
            .properties()
            .await?
            .ok_or_else(|| anyhow!("Could not read peripheral properties"))?;
        let name = props.local_name.clone();
        let cube_type = if let Some(name) = &name {
            match BluetoothCubeType::from_name(&name) {
                Some(cube_type) => cube_type,
                None => return Err(anyhow!("Cube type not recognized")),
            }
        } else {
            return Err(anyhow!("Cube name missing"));
        };

        *state.lock().unwrap() = BluetoothCubeState::Connecting;

        // Connect to the cube
        peripheral.connect().await?;
        peripheral.discover_services().await?;

        let cube = match cube_type {
            BluetoothCubeType::GAN => gan_cube_connect(peripheral, move_listener).await?,
            BluetoothCubeType::GoCube => gocube_connect(peripheral, move_listener).await?,
            BluetoothCubeType::Giiker => giiker_connect(peripheral, move_listener).await?,
            BluetoothCubeType::MoYu => moyu_connect(peripheral, move_listener).await?,
            BluetoothCubeType::QiYi => qiyi_cube_connect(peripheral, move_listener).await?,
            BluetoothCubeType::MoYu32 => moyu32_connect(peripheral, move_listener).await?,
        };

        init(cube.as_ref());

        *connected_device.lock().unwrap() = Some(cube);
        *connected_name.lock().unwrap() = name;
        *state.lock().unwrap() = BluetoothCubeState::Connected;

        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Some(device) = connected_device.lock().unwrap().deref() {
                device.update();
                if !device.synced() {
                    *state.lock().unwrap() = BluetoothCubeState::Desynced;
                }
                *battery.lock().unwrap() = (device.battery_percentage(), device.battery_charging())
            } else {
                // Connection was closed
                break;
            }
        }

        *state.lock().unwrap() = BluetoothCubeState::Discovering;
        *connected_device.lock().unwrap() = None;
        *connected_name.lock().unwrap() = None;
        *battery.lock().unwrap() = (None, None);

        Ok(())
    }

    fn check_for_error(&self) -> Result<()> {
        match self.error.lock().unwrap().deref() {
            Some(error) => Err(anyhow!("{}", error)),
            None => Ok(()),
        }
    }

    pub fn state(&self) -> Result<BluetoothCubeState> {
        self.check_for_error()?;
        Ok(*self.state.lock().unwrap())
    }

    pub fn available_devices(&self) -> Result<Vec<AvailableDevice>> {
        self.check_for_error()?;
        Ok(self.discovered_devices.lock().unwrap().clone())
    }

    pub fn connect(&self, id: PeripheralId) -> Result<()> {
        self.check_for_error()?;
        *self.to_connect.lock().unwrap() = Some(id);
        Ok(())
    }

    pub fn disconnect(&self) {
        match self.connected_device.lock().unwrap().deref() {
            Some(device) => device.disconnect(),
            _ => (),
        }

        *self.to_connect.lock().unwrap() = None;
        *self.connected_device.lock().unwrap() = None;
    }

    pub fn name(&self) -> Result<Option<String>> {
        self.check_for_error()?;
        Ok(self.connected_name.lock().unwrap().clone())
    }

    pub fn timer_only(&self) -> Result<bool> {
        self.check_for_error()?;
        match self.connected_device.lock().unwrap().deref() {
            Some(device) => Ok(device.timer_only()),
            None => Err(anyhow!("Cube not connected")),
        }
    }

    pub fn cube_state(&self) -> Result<Cube3x3x3> {
        self.check_for_error()?;
        match self.connected_device.lock().unwrap().deref() {
            Some(device) => Ok(device.cube_state()),
            None => Err(anyhow!("Cube not connected")),
        }
    }

    pub fn battery_percentage(&self) -> Result<Option<u32>> {
        self.check_for_error()?;
        Ok(self.battery.lock().unwrap().0)
    }

    pub fn battery_charging(&self) -> Result<Option<bool>> {
        self.check_for_error()?;
        Ok(self.battery.lock().unwrap().1)
    }

    pub fn reset_cube_state(&self) -> Result<()> {
        self.check_for_error()?;
        match self.connected_device.lock().unwrap().deref() {
            Some(device) => {
                device.reset_cube_state();
                Ok(())
            }
            None => Err(anyhow!("Cube not connected")),
        }
    }

    pub fn synced(&self) -> Result<bool> {
        self.check_for_error()?;
        Ok(*self.state.lock().unwrap() == BluetoothCubeState::Connected)
    }

    pub fn register_move_listener<F: Fn(BluetoothCubeEvent) + Send + 'static>(
        &self,
        func: F,
    ) -> MoveListenerHandle {
        let id = self.next_listener_id.fetch_add(1, Ordering::SeqCst);
        let handle = MoveListenerHandle { id };
        self.listeners
            .lock()
            .unwrap()
            .insert(handle.clone(), Box::new(func));
        handle
    }

    pub fn unregister_move_listener(&self, handle: MoveListenerHandle) {
        self.listeners.lock().unwrap().remove(&handle);
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for BluetoothCube {
    fn drop(&mut self) {
        // Clear connected device to force any polling threads to stop
        *self.connected_device.lock().unwrap() = None;
    }
}

// ============================================================
// WASM implementation - re-export from web module
// ============================================================
#[cfg(target_arch = "wasm32")]
pub use web::BluetoothCube;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cube_type_from_advertised_name() {
        use BluetoothCubeType::*;

        // MoYu's AiCube line speaks the GAN Gen2 protocol, so it must route to
        // the GAN implementation rather than the MHC-era MoYu one. Regression
        // test: an `AiCube2MT` previously returned None and was silently
        // dropped from the device list.
        assert_eq!(BluetoothCubeType::from_name("AiCube2MT"), Some(GAN));
        assert_eq!(BluetoothCubeType::from_name("AiCubeXXX"), Some(GAN));

        assert_eq!(BluetoothCubeType::from_name("GAN-a1b2c3"), Some(GAN));
        assert_eq!(BluetoothCubeType::from_name("MG12ui"), Some(GAN));

        // GAN firmware varies in capitalization; the Smart Timer and Halo are
        // reported to advertise lowercase on some units.
        assert_eq!(BluetoothCubeType::from_name("Gan Halo"), Some(GAN));
        assert_eq!(BluetoothCubeType::from_name("gan timer"), Some(GAN));

        assert_eq!(BluetoothCubeType::from_name("GoCube_ABC"), Some(GoCube));
        assert_eq!(BluetoothCubeType::from_name("Rubiks-XYZ"), Some(GoCube));
        assert_eq!(BluetoothCubeType::from_name("Gi123456"), Some(Giiker));
        assert_eq!(BluetoothCubeType::from_name("Mi Smart Magic Cube"), Some(Giiker));

        // `Hi-` is the same protocol as Giiker.
        assert_eq!(BluetoothCubeType::from_name("Hi-A1B2"), Some(Giiker));

        // The original MoYu AI (2023) uses MoYu's own 0x1000 service. Some
        // firmware omits the hyphen after MHC.
        assert_eq!(BluetoothCubeType::from_name("MHC-1234"), Some(MoYu));
        assert_eq!(BluetoothCubeType::from_name("MHC1234"), Some(MoYu));

        // QiYi cubes pad their advertised name with spaces. The XMD
        // Tornado V4 ships the same firmware protocol.
        assert_eq!(BluetoothCubeType::from_name("QY-QYSC-S-A0E6       "), Some(QiYi));
        assert_eq!(BluetoothCubeType::from_name("QY-QYSC-A-1234"), Some(QiYi));
        assert_eq!(BluetoothCubeType::from_name("XMD-TornadoV4-i-034C "), Some(QiYi));

        // MoYu's WeiLong V10 AI / V11 AI line speaks its own protocol.
        assert_eq!(BluetoothCubeType::from_name("WCU_MY32_A388"), Some(MoYu32));
        assert_eq!(BluetoothCubeType::from_name("WCU_MY33_AF9E"), Some(MoYu32));

        // Non-cubes must stay unmatched.
        assert_eq!(BluetoothCubeType::from_name("Rivian Phone Key"), None);
        assert_eq!(BluetoothCubeType::from_name(""), None);
    }
}
