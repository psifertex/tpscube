# TPS Cube

This is an open source application for tracking cube solves. This is the code that runs on [tpscube.xyz](https://tpscube.xyz).

It is written in pure Rust using the [egui](https://github.com/emilk/egui) framework.

* Automatic scramble generation.
* Streamlined session tracking optimized for quick practice sessions.
* Solve history that isn't lost when quick resetting sessions.
* Bluetooth cube support with split timing and advanced stats.
* Graphical reports for tracking progress.
* Automatic cloud sync across all your devices without any privacy concerns. Your data is completely anonymous, is shared only when you explicitly share solves, and there are no ads of any kind.
* (Planned) Algorithm library and practice mode.

# Supported platforms

* Anything that runs a web browser with WebGL support
* Windows / MacOS / Linux with a native binary (and without Electron!)

# Building from source

## Prerequisites

### macOS
- Install SDL2 via Homebrew: `brew install sdl2`
- Create a `.cargo/config.toml` file in the project root with the following content:
  ```toml
  [target.aarch64-apple-darwin]
  rustflags = ["-L", "/opt/homebrew/lib"]

  [target.x86_64-apple-darwin]
  rustflags = ["-L", "/opt/homebrew/lib"]
  ```
  Note: This file is gitignored as paths may vary between systems.

### Other platforms
- SDL2 should be available through your system's package manager

## Building
```bash
cargo build --release
make mac  # macOS only - creates app bundle
```

Run the binary directly:
```bash
./target/release/tpscube
```

Note: On macOS with Apple Silicon, you may see OpenGL texture warnings in the console (`GLD_TEXTURE_INDEX_2D is unloadable`). These can be safely ignored if the UI renders correctly.

## Running the web build locally

The web target compiles the app to WebAssembly and serves it from the `web/`
directory.

```bash
make web      # build the wasm bundle
make server   # serve on http://localhost:8000/ (plain HTTP, localhost only)
```

`make server` is enough for quick desktop smoke tests, but WebGPU (used by
the renderer) and Web Bluetooth (used to pair GAN smart cubes) require a
**secure origin**. `http://localhost` is treated as secure, but
`http://192.168.x.y` is not — so testing from a phone, tablet or another
computer on your LAN needs TLS.

### Serving over HTTPS for LAN / mobile testing

```bash
make secure   # builds web/, starts https://<lan-ip>:8443/
```

On first run this invokes `https-server.py` at the repo root, which will:

1. Auto-detect the machine's primary LAN IP.
2. Try to generate a cert with [mkcert](https://github.com/FiloSottile/mkcert)
   if it's on PATH. mkcert-signed certs are trusted automatically on the
   local machine after a one-time `mkcert -install`, and can be made trusted
   on iOS/Android by transferring the root CA to the device.
3. Fall back to an `openssl`-generated self-signed cert if mkcert isn't
   available. These are not trusted by any browser, so WebGPU/Web Bluetooth
   on iOS are likely to refuse to run — use mkcert if at all possible.

The generated cert and key live in `.http-server/` at the repo root
(gitignored). Delete that directory to force regeneration, e.g. if your LAN
IP changes.

### One-time mkcert setup (recommended)

```bash
brew install mkcert
mkcert -install        # adds the mkcert root CA to the macOS keychain
```

`make secure` will then automatically pick up the trusted root when it
generates the cert on first run. No further action is needed for desktop
browsers on the same machine.

### Trusting the mkcert root on iOS

Once mkcert is installed on your Mac:

1. Find the root CA: `open "$(mkcert -CAROOT)"`
2. Copy `rootCA.pem` somewhere and rename it to `rootCA.crt` — iOS only
   treats the `.crt` extension as an installable configuration profile.
3. AirDrop (or email / iMessage) the `.crt` file to your iPhone.
4. On the iPhone: open the file → **Settings → General → VPN & Device
   Management → Install** the profile.
5. **Settings → General → About → Certificate Trust Settings** → toggle the
   mkcert root CA to **on**. iOS 10.3+ requires this last step separately
   from profile installation.

Browse to `https://<your-lan-ip>:8443/` from the iPhone. The URL bar padlock
should show no warnings. If it does, step 5 didn't take.

### iOS Web Bluetooth

Safari on iOS does not implement Web Bluetooth, and Chrome/Edge on iOS use
WebKit under the hood so they don't either. The only iOS app that supports
Web Bluetooth is [Bluefy](https://apps.apple.com/app/bluefy-web-ble-browser/id1492822055),
a free third-party browser. Load `https://<your-lan-ip>:8443/` in Bluefy to
pair a cube from iOS. The rest of the UI works fine in Safari — only the
Bluetooth pairing path requires Bluefy.

# Scrambling algortihms

Popular scrambling algorithms, including the official WCA scramble, are licensed under GPLv3. Normally
this would not be an issue, as this project is fully open source. Unfortunately, the GPLv3 license is
incompatible with the iOS App Store, even if the application is entirely open source. Because of this,
the scrambling algorithm implementations in this program are new and licensed under the MIT license.
These algorithms are free to use anywhere (even in commercial products) and are fully compatible with
all app store licensing restrictions.

Please note that the scrambles are _not_ competition legal. Use
[tnoodle](https://www.worldcubeassociation.org/regulations/scrambles/) for competitions.
