use crate::bluetooth::{
    BluetoothCubeDevice, BluetoothCubeEvent, BluetoothCubeState, BluetoothCubeType,
    MoveListenerHandle,
};
use crate::common::TimedMove;
use crate::cube3x3x3::Cube3x3x3;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// Web Bluetooth implementation of BluetoothCube.
///
/// Unlike the native version, Web Bluetooth does not support background scanning.
/// The UI must call `request_device()` in response to a user gesture, which opens
/// the browser's device picker. After the user selects a device, connection and
/// communication proceed similarly to the native version.
pub struct BluetoothCube {
    state: Arc<Mutex<BluetoothCubeState>>,
    connected_device: Arc<Mutex<Option<Box<dyn BluetoothCubeDevice>>>>,
    connected_name: Arc<Mutex<Option<String>>>,
    battery: Arc<Mutex<(Option<u32>, Option<bool>)>>,
    listeners: Arc<Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>>,
    next_listener_id: AtomicU64,
    error: Arc<Mutex<Option<String>>>,
    /// Optional 6-byte device key for GAN v2 cubes, provided by the user
    /// when Web Bluetooth cannot read manufacturer data from advertisements.
    gan_device_key: Arc<Mutex<Option<[u8; 6]>>>,
}

impl BluetoothCube {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(BluetoothCubeState::Discovering)),
            connected_device: Arc::new(Mutex::new(None)),
            connected_name: Arc::new(Mutex::new(None)),
            battery: Arc::new(Mutex::new((None, None))),
            listeners: Arc::new(Mutex::new(HashMap::new())),
            next_listener_id: AtomicU64::new(0),
            error: Arc::new(Mutex::new(None)),
            gan_device_key: Arc::new(Mutex::new(None)),
        }
    }

    /// Set the GAN device key from a MAC address string (e.g. "B0:48:1E:3B:6E:47").
    /// The 6 bytes of the MAC address are used as the device key for GAN v2
    /// encryption when manufacturer data is not available via Web Bluetooth.
    ///
    /// The MAC is entered by the user in human-readable forward order
    /// (e.g. `B0:48:1E:3B:6E:47`) but the GAN cipher salt derivation expects
    /// the bytes **reversed** — matching the byte order that native
    /// btleplug reads out of the BLE advertisement's manufacturer data,
    /// where GAN cubes encode the MAC in reverse. See
    /// `GAN_GEN4_PROTOCOL_SPEC.md` §2.3.
    pub fn set_gan_device_key_from_mac(&self, mac: &str) {
        let bytes: Vec<u8> = mac
            .split(':')
            .filter_map(|s| u8::from_str_radix(s.trim(), 16).ok())
            .collect();
        if bytes.len() == 6 {
            let mut key = [0u8; 6];
            for (i, b) in bytes.iter().enumerate() {
                key[5 - i] = *b;
            }
            *self.gan_device_key.lock().unwrap() = Some(key);
        } else {
            *self.gan_device_key.lock().unwrap() = None;
        }
    }

    fn check_for_error(&self) -> Result<()> {
        match &*self.error.lock().unwrap() {
            Some(error) => Err(anyhow!("{}", error)),
            None => Ok(()),
        }
    }

    pub fn state(&self) -> Result<BluetoothCubeState> {
        self.check_for_error()?;
        Ok(*self.state.lock().unwrap())
    }

    pub fn name(&self) -> Result<Option<String>> {
        self.check_for_error()?;
        Ok(self.connected_name.lock().unwrap().clone())
    }

    pub fn timer_only(&self) -> Result<bool> {
        self.check_for_error()?;
        match &*self.connected_device.lock().unwrap() {
            Some(device) => Ok(device.timer_only()),
            None => Err(anyhow!("Cube not connected")),
        }
    }

    pub fn cube_state(&self) -> Result<Cube3x3x3> {
        self.check_for_error()?;
        match &*self.connected_device.lock().unwrap() {
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
        match &*self.connected_device.lock().unwrap() {
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

    pub fn disconnect(&self) {
        if let Some(device) = self.connected_device.lock().unwrap().take() {
            device.disconnect();
        }
        *self.state.lock().unwrap() = BluetoothCubeState::Discovering;
        *self.connected_name.lock().unwrap() = None;
        *self.battery.lock().unwrap() = (None, None);
    }

    pub fn register_move_listener<F: Fn(BluetoothCubeEvent) + 'static>(
        &self,
        func: F,
    ) -> MoveListenerHandle {
        let id = self.next_listener_id.fetch_add(1, Ordering::SeqCst);
        let handle = MoveListenerHandle::new(id);
        self.listeners
            .lock()
            .unwrap()
            .insert(handle, Box::new(func));
        handle
    }

    pub fn unregister_move_listener(&self, handle: MoveListenerHandle) {
        self.listeners.lock().unwrap().remove(&handle);
    }

    /// Trigger the Web Bluetooth device picker. This must be called from a user
    /// gesture (click handler). It opens the browser's native device picker dialog
    /// filtered to known cube name prefixes.
    pub fn request_device(&self) {
        let state = self.state.clone();
        let connected_device = self.connected_device.clone();
        let connected_name = self.connected_name.clone();
        let battery = self.battery.clone();
        let listeners = self.listeners.clone();
        let error = self.error.clone();

        *state.lock().unwrap() = BluetoothCubeState::Connecting;
        *error.lock().unwrap() = None;

        let gan_device_key = self.gan_device_key.lock().unwrap().clone();

        wasm_bindgen_futures::spawn_local(async move {
            match Self::request_and_connect(
                state.clone(),
                connected_device.clone(),
                connected_name.clone(),
                battery.clone(),
                listeners.clone(),
                gan_device_key,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    let err_string = format!("{}", e);
                    if err_string.contains("cancelled")
                        || err_string.contains("canceled")
                        || err_string.contains("User cancelled")
                    {
                        *state.lock().unwrap() = BluetoothCubeState::Discovering;
                    } else {
                        *error.lock().unwrap() = Some(err_string);
                        *state.lock().unwrap() = BluetoothCubeState::Error;
                    }
                }
            }
        });
    }

    async fn request_and_connect(
        state: Arc<Mutex<BluetoothCubeState>>,
        connected_device: Arc<Mutex<Option<Box<dyn BluetoothCubeDevice>>>>,
        connected_name: Arc<Mutex<Option<String>>>,
        battery: Arc<Mutex<(Option<u32>, Option<bool>)>>,
        listeners: Arc<
            Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>,
        >,
        gan_device_key: Option<[u8; 6]>,
    ) -> Result<()> {
        let window = web_sys::window().ok_or_else(|| anyhow!("No window object"))?;
        let navigator = window.navigator();
        let bluetooth = navigator
            .bluetooth()
            .ok_or_else(|| anyhow!("Web Bluetooth not available. Use Chrome or Edge."))?;

        // Build name prefix filters for all supported cube types
        let name_prefixes = [
            "GAN", "MG", "GoCube", "Rubiks", "Gi", "Mi Smart", "MHC-",
        ];
        let mut filters_vec: Vec<web_sys::BluetoothLeScanFilterInit> = Vec::new();
        for prefix in &name_prefixes {
            let filter = web_sys::BluetoothLeScanFilterInit::new();
            filter.set_name_prefix(prefix);
            filters_vec.push(filter);
        }

        let options = web_sys::RequestDeviceOptions::new();
        options.set_filters(&filters_vec);

        // Request optional manufacturer data for GAN cubes.
        // GAN cubes use company IDs of the form (i << 8) | 0x01 for i in 0..256.
        // This field is not yet in web-sys bindings, so we set it via Reflect.
        let cic_array = js_sys::Array::new();
        for i in 0u32..256 {
            cic_array.push(&((i << 8 | 0x01).into()));
        }
        let _ = js_sys::Reflect::set(
            &options,
            &"optionalManufacturerData".into(),
            &cic_array,
        );

        // Request optional services that the cubes use
        let service_uuids: Vec<js_sys::JsString> = [
            "0000fff0-0000-1000-8000-00805f9b34fb",
            "0000180a-0000-1000-8000-00805f9b34fb",
            "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
            "6e400001-b5a3-f393-e0a9-e50e24dc4179",
            "f95a48e6-a721-11e9-a2a3-022ae2dbcce4",
            "0000aadb-0000-1000-8000-00805f9b34fb",
            "00001000-0000-1000-8000-00805f9b34fb",
            "0000fd50-0000-1000-8000-00805f9b34fb",
            "8653000a-43e6-47b7-9cb0-5fc21d4ae340",
            "00000010-0000-fff7-fff6-fff5fff4fff0",
        ]
        .iter()
        .map(|s| js_sys::JsString::from(*s))
        .collect();
        options.set_optional_services(&service_uuids);

        // Request device (shows browser picker)
        let device: web_sys::BluetoothDevice =
            JsFuture::from(bluetooth.request_device(&options))
                .await
                .map_err(|e| anyhow!("Device request failed: {}", js_error_string(&e)))?;

        let device_name = device.name().unwrap_or_default();
        let cube_type = BluetoothCubeType::from_name(&device_name)
            .ok_or_else(|| anyhow!("Unknown cube type: {}", device_name))?;

        *connected_name.lock().unwrap() = Some(device_name.clone());

        // For GAN cubes we need the device's MAC-derived key to build the
        // cipher. We always attempt the `watchAdvertisements()` capture —
        // where it works, it's authoritative, and it reveals whether the
        // user-supplied MAC in settings is wrong. The user-supplied MAC
        // is only used as a fallback when capture returns nothing.
        //
        // The capture is bounded by a ~5s timeout internally, which is the
        // source of the "7-second stall before connect" observed on some
        // browsers. That's acceptable on desktop Chrome (where capture
        // usually succeeds early) but painful on iOS Safari / Bluefy
        // where the API is either unimplemented or unreliable. See
        // `try_capture_manufacturer_data` for the timeout.
        let captured_device_key: Option<[u8; 6]> = if matches!(cube_type, BluetoothCubeType::GAN) {
            Self::try_capture_manufacturer_data(&device).await
        } else {
            None
        };

        // Log both sources so the user can compare via DevTools if the
        // cipher is producing the wrong key. Don't log if neither is
        // set (not informative).
        #[cfg(target_arch = "wasm32")]
        if matches!(cube_type, BluetoothCubeType::GAN) {
            let fmt = |k: &[u8; 6]| -> String {
                format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    k[0], k[1], k[2], k[3], k[4], k[5]
                )
            };
            match (&captured_device_key, &gan_device_key) {
                (Some(c), Some(u)) if c != u => {
                    web_sys::console::warn_1(
                        &format!(
                            "[tpscube] GAN MAC mismatch — captured {} vs user-set {}. \
                             Captured is authoritative; check your Settings → Bluetooth \
                             → GAN Cube MAC Address. Note: both are shown in the salt \
                             byte order (reversed from the MAC string you entered).",
                            fmt(c),
                            fmt(u)
                        )
                        .into(),
                    );
                }
                (Some(c), _) => {
                    web_sys::console::log_1(
                        &format!("[tpscube] GAN MAC from advertisement: {}", fmt(c)).into(),
                    );
                }
                (None, Some(u)) => {
                    web_sys::console::log_1(
                        &format!(
                            "[tpscube] GAN MAC from settings (capture failed): {} \
                             (salt byte order, reversed from the MAC string you entered)",
                            fmt(u)
                        )
                        .into(),
                    );
                }
                (None, None) => {
                    web_sys::console::warn_1(
                        &"[tpscube] No GAN MAC available (capture failed, no setting). \
                          Cipher will use zeros and likely fail. Set your MAC in \
                          Settings → Bluetooth → GAN Cube MAC Address."
                            .into(),
                    );
                }
            }
        }

        // Connect to GATT server
        let gatt = device
            .gatt()
            .ok_or_else(|| anyhow!("No GATT server on device"))?;
        let server: web_sys::BluetoothRemoteGattServer =
            JsFuture::from(gatt.connect())
                .await
                .map_err(|e| anyhow!("GATT connect failed: {}", js_error_string(&e)))?;

        // Captured MAC is authoritative when available; user MAC is the
        // fallback for platforms where the advertisement capture doesn't
        // work (e.g. iOS Safari / Bluefy).
        let effective_device_key = captured_device_key.or(gan_device_key);

        // Connect to the specific cube type
        let cube: Box<dyn BluetoothCubeDevice> = match cube_type {
            BluetoothCubeType::GAN => {
                super::gan::gan_web_connect(server, device_name, effective_device_key, listeners.clone()).await?
            }
            BluetoothCubeType::GoCube => {
                super::gocube_web::gocube_web_connect(server, listeners.clone()).await?
            }
            BluetoothCubeType::Giiker => {
                super::giiker_web::giiker_web_connect(server, listeners.clone()).await?
            }
            BluetoothCubeType::MoYu => {
                super::moyu_web::moyu_web_connect(server, listeners.clone()).await?
            }
        };

        *battery.lock().unwrap() = (cube.battery_percentage(), cube.battery_charging());
        *connected_device.lock().unwrap() = Some(cube);
        *state.lock().unwrap() = BluetoothCubeState::Connected;

        Ok(())
    }

    /// Try to capture manufacturer data from BLE advertisements using the
    /// experimental `watchAdvertisements()` API. This must be called BEFORE
    /// GATT connection, as the cube stops advertising once connected.
    ///
    /// Returns `Some([u8; 6])` device key if successful, `None` if the API
    /// is unavailable or no advertisement is received within the timeout.
    async fn try_capture_manufacturer_data(device: &web_sys::BluetoothDevice) -> Option<[u8; 6]> {
        // GAN cubes use company IDs of the form (i << 8) | 0x01 for i in 0..256
        const GAN_CIC_MASK: u16 = 0x01;

        // Set up an AbortController so we can stop watching after we get data
        let abort_controller = match web_sys::AbortController::new() {
            Ok(ac) => ac,
            Err(_) => return None,
        };
        let signal = abort_controller.signal();

        // Create a promise that resolves when we receive an advertisement
        let device_clone = device.clone();
        let abort_clone = abort_controller.clone();

        // Use a channel pattern: store result in a shared cell
        let result: Arc<Mutex<Option<[u8; 6]>>> = Arc::new(Mutex::new(None));
        let result_clone = result.clone();

        let got_data = Arc::new(Mutex::new(false));
        let got_data_clone = got_data.clone();

        // Set up the advertisementreceived event listener
        let closure = Closure::wrap(Box::new(move |event: web_sys::Event| {
            let adv_event: web_sys::BluetoothAdvertisingEvent = event.unchecked_into();
            let manufacturer_data = adv_event.manufacturer_data();

            web_sys::console::log_1(
                &format!("GAN: received advertisement, manufacturer_data size={}", manufacturer_data.size()).into(),
            );

            // Search for a matching GAN company ID
            // GAN cubes use CICs of the form (i << 8) | 0x01
            for i in 0u16..256 {
                let cic = (i << 8) | (GAN_CIC_MASK as u16);
                if manufacturer_data.has(cic) {
                    if let Some(data_view) = manufacturer_data.get(cic) {
                        let len = data_view.byte_length() as usize;
                        web_sys::console::log_1(
                            &format!("GAN: found CIC 0x{:04x}, data length={}", cic, len).into(),
                        );
                        if len >= 9 {
                            // Extract device key from bytes 3..9 in forward order,
                            // matching the native btleplug code which reads
                            // manufacturer_data[company_id=1] bytes 3..9.
                            let mut key = [0u8; 6];
                            for j in 0..6 {
                                key[j] = data_view.get_uint8(3 + j);
                            }
                            web_sys::console::log_1(
                                &format!(
                                    "GAN: captured device key from advertisement: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    key[0], key[1], key[2], key[3], key[4], key[5]
                                ).into(),
                            );
                            *result_clone.lock().unwrap() = Some(key);
                            *got_data_clone.lock().unwrap() = true;
                            abort_clone.abort();
                            return;
                        }
                    }
                }
            }
            web_sys::console::log_1(&"GAN: advertisement received but no matching CIC found".into());
        }) as Box<dyn Fn(web_sys::Event)>);

        device
            .add_event_listener_with_callback(
                "advertisementreceived",
                closure.as_ref().unchecked_ref(),
            )
            .ok()?;

        // Start watching for advertisements
        let options = web_sys::WatchAdvertisementsOptions::new();
        options.set_signal(&signal);

        let watch_result = device_clone.watch_advertisements_with_options(&options);
        match JsFuture::from(watch_result).await {
            Ok(_) => {
                web_sys::console::log_1(&"GAN: watchAdvertisements started, waiting for data...".into());
            }
            Err(e) => {
                web_sys::console::log_1(
                    &format!("GAN: watchAdvertisements not available ({:?}), skipping auto-detect", e).into(),
                );
                closure.forget();
                return None;
            }
        }

        // Wait up to 5 seconds for an advertisement
        for _ in 0..25 {
            sleep_ms(200).await;
            if *got_data.lock().unwrap() {
                break;
            }
        }

        if !*got_data.lock().unwrap() {
            web_sys::console::log_1(
                &"GAN: no advertisement received within timeout, falling back to user key".into(),
            );
            abort_controller.abort();
        }

        // Leak the closure (it's already been aborted so won't fire again)
        closure.forget();

        let captured = result.lock().unwrap().clone();
        captured
    }
}

impl Drop for BluetoothCube {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Extract a human-readable string out of a JS value that we got from a
/// rejected Promise or a failed wasm-bindgen call.
///
/// `{:?}` on a [`JsValue`] prints the wasm-bindgen handle index (e.g.
/// `JsValue(2)`), not the actual JS value, so naive error messages like
/// `anyhow!("Write failed: {:?}", e)` are useless for debugging. This
/// helper tries a few decodings in order:
///
///   1. `DOMException` — Web Bluetooth errors are almost always this. We
///      surface `name: message` (e.g. `NetworkError: GATT operation failed`).
///   2. JS `Error` — same pattern.
///   3. A plain string via `JsValue::as_string()`.
///   4. `js_sys::JSON.stringify` as a last resort.
///   5. `{:?}` as a final fallback so we never lose information entirely.
///
/// Also logs the raw JS value to the browser console via `console.log`
/// so the full object is inspectable in DevTools.
pub(crate) fn js_error_string(err: &JsValue) -> String {
    web_sys::console::log_2(&"[tpscube] JS error:".into(), err);

    if let Some(exc) = err.dyn_ref::<web_sys::DomException>() {
        return format!("{}: {}", exc.name(), exc.message());
    }
    if let Some(e) = err.dyn_ref::<js_sys::Error>() {
        let name: String = e.name().into();
        let message: String = e.message().into();
        if name.is_empty() && message.is_empty() {
            return format!("{:?}", err);
        }
        return format!("{}: {}", name, message);
    }
    if let Some(s) = err.as_string() {
        return s;
    }
    if let Ok(json) = js_sys::JSON::stringify(err) {
        if let Some(s) = json.as_string() {
            return s;
        }
    }
    format!("{:?}", err)
}

/// Helper: read a characteristic value, returning bytes.
pub(crate) async fn read_characteristic(
    characteristic: &web_sys::BluetoothRemoteGattCharacteristic,
) -> Result<Vec<u8>> {
    let data_view: js_sys::DataView =
        JsFuture::from(characteristic.read_value())
            .await
            .map_err(|e| anyhow!("Read failed: {}", js_error_string(&e)))?;
    let len = data_view.byte_length() as usize;
    let mut bytes = vec![0u8; len];
    for i in 0..len {
        bytes[i] = data_view.get_uint8(i);
    }
    Ok(bytes)
}

/// Helper: write bytes to a characteristic.
///
/// Uses the plain `writeValue()` method (not `writeValueWithResponse` or
/// `writeValueWithoutResponse`) so the browser picks the right mode based
/// on the characteristic's declared properties. Matches the reference
/// `gan-web-bluetooth` implementation.
///
/// The historical reason we weren't doing this: `writeValue()` is marked
/// deprecated in the Web Bluetooth spec in favor of the two explicit
/// variants. But the explicit variants require the characteristic to
/// declare the matching property — and on at least iOS Safari / Bluefy,
/// the GAN Gen4 command characteristic is surfaced with only
/// `writeWithoutResponse`, so `writeValueWithResponse` fails immediately.
/// Plain `writeValue` adapts transparently and still works on desktop
/// Chrome.
pub(crate) async fn write_characteristic(
    characteristic: &web_sys::BluetoothRemoteGattCharacteristic,
    data: &[u8],
) -> Result<()> {
    // Copy data into a standalone JS Uint8Array, then pass its ArrayBuffer.
    // We must NOT pass a view into wasm linear memory (which is what
    // write_value_with_u8_slice does), because if wasm memory grows between
    // creating the Promise and the BLE stack consuming the bytes, the view
    // becomes detached and the write fails or sends garbage. cstimer avoids
    // this the same way: `new Uint8Array(data).buffer`.
    let js_array = js_sys::Uint8Array::new_with_length(data.len() as u32);
    js_array.copy_from(data);
    let promise = characteristic
        .write_value_with_buffer_source(&js_array.buffer())
        .map_err(|e| anyhow!("Write call failed: {}", js_error_string(&e)))?;
    JsFuture::from(promise)
        .await
        .map_err(|e| anyhow!("Write failed: {}", js_error_string(&e)))?;
    Ok(())
}

/// Helper: discover all characteristics across all services. This mirrors the
/// native btleplug approach of calling `device.characteristics()` to get a flat
/// list, rather than searching by service UUID. Web Bluetooth requires services
/// to be listed in `optionalServices` during `requestDevice()` to be accessible.
pub(crate) async fn discover_all_characteristics(
    server: &web_sys::BluetoothRemoteGattServer,
) -> Vec<web_sys::BluetoothRemoteGattCharacteristic> {
    use wasm_bindgen::JsCast;
    let mut all_chars = Vec::new();
    if let Ok(services_js) = JsFuture::from(server.get_primary_services()).await {
        let services: js_sys::Array = services_js.unchecked_into();
        for i in 0..services.length() {
            let service: web_sys::BluetoothRemoteGattService = services.get(i).unchecked_into();
            if let Ok(chars_js) = JsFuture::from(service.get_characteristics()).await {
                let chars: js_sys::Array = chars_js.unchecked_into();
                for j in 0..chars.length() {
                    let c: web_sys::BluetoothRemoteGattCharacteristic = chars.get(j).unchecked_into();
                    all_chars.push(c);
                }
            }
        }
    }
    all_chars
}

/// Find a characteristic by UUID from a list of discovered characteristics.
pub(crate) fn find_characteristic(
    chars: &[web_sys::BluetoothRemoteGattCharacteristic],
    uuid: &str,
) -> Option<web_sys::BluetoothRemoteGattCharacteristic> {
    chars.iter().find(|c| c.uuid() == uuid).cloned()
}

/// Helper: get a service by UUID string.
pub(crate) async fn get_service(
    server: &web_sys::BluetoothRemoteGattServer,
    uuid: &str,
) -> Result<web_sys::BluetoothRemoteGattService> {
    JsFuture::from(server.get_primary_service_with_str(uuid))
        .await
        .map_err(|e| anyhow!("Service {} not found: {}", uuid, js_error_string(&e)))
}

/// Helper: get a characteristic by UUID string from a service.
pub(crate) async fn get_characteristic(
    service: &web_sys::BluetoothRemoteGattService,
    uuid: &str,
) -> Result<web_sys::BluetoothRemoteGattCharacteristic> {
    JsFuture::from(service.get_characteristic_with_str(uuid))
        .await
        .map_err(|e| anyhow!("Characteristic {} not found: {}", uuid, js_error_string(&e)))
}

/// Helper: subscribe to notifications on a characteristic.
pub(crate) async fn subscribe_characteristic(
    characteristic: &web_sys::BluetoothRemoteGattCharacteristic,
    callback: impl Fn(Vec<u8>) + 'static,
) -> Result<()> {
    let _: web_sys::BluetoothRemoteGattCharacteristic =
        JsFuture::from(characteristic.start_notifications())
            .await
            .map_err(|e| anyhow!("Start notifications failed: {}", js_error_string(&e)))?;

    let closure = Closure::wrap(Box::new(move |event: web_sys::Event| {
        let target = event.target().unwrap();
        let char: web_sys::BluetoothRemoteGattCharacteristic = target.unchecked_into();
        if let Some(data_view) = char.value() {
            let len = data_view.byte_length() as usize;
            let mut bytes = vec![0u8; len];
            for i in 0..len {
                bytes[i] = data_view.get_uint8(i);
            }
            callback(bytes);
        }
    }) as Box<dyn Fn(web_sys::Event)>);

    characteristic
        .add_event_listener_with_callback(
            "characteristicvaluechanged",
            closure.as_ref().unchecked_ref(),
        )
        .map_err(|e| anyhow!("Failed to add event listener: {}", js_error_string(&e)))?;

    // Leak the closure so it lives for the lifetime of the connection.
    closure.forget();

    Ok(())
}

/// Helper: sleep for a number of milliseconds using setTimeout.
pub(crate) async fn sleep_ms(ms: u32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let window = web_sys::window().unwrap();
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32);
    });
    let _ = JsFuture::from(promise).await;
}

/// Helper: dispatch a BluetoothCubeEvent to all listeners.
pub(crate) fn dispatch_event(
    listeners: &Arc<
        Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>,
    >,
    event: BluetoothCubeEvent,
) {
    let listeners_guard = listeners.lock().unwrap();
    for (_, listener) in listeners_guard.iter() {
        listener(event.clone());
    }
}

/// Helper: dispatch move events.
pub(crate) fn dispatch_moves(
    listeners: &Arc<
        Mutex<HashMap<MoveListenerHandle, Box<dyn Fn(BluetoothCubeEvent) + 'static>>>,
    >,
    moves: Vec<TimedMove>,
    state: Cube3x3x3,
) {
    dispatch_event(listeners, BluetoothCubeEvent::Move(moves, state));
}
