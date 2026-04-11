//! btcli — minimal CLI test harness for the BluetoothCube API in tpscube_core.
//!
//! Use this to pair with and exercise smart cubes (GAN Gen2/Gen3/Gen4, GoCube,
//! Giiker, MoYu) without having to launch the full desktop app. The whole
//! point is to drive the same code paths the UI uses, so the protocol code in
//! `lib/src/bluetooth/` is the only thing under test.
//!
//! Examples:
//!   cargo run -p btcli -- scan --timeout 8
//!   cargo run -p btcli -- connect GAN
//!   cargo run -p btcli -- battery MG
//!   cargo run -p btcli -- reset GAN12
//!   cargo run -p btcli -- raw GAN

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use tpscube_core::{
    AvailableDevice, BluetoothCube, BluetoothCubeEvent, BluetoothCubeState,
};

#[derive(Parser)]
#[command(name = "btcli", about = "Test harness for tpscube_core BluetoothCube")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan for nearby smart cubes and print what we see.
    Scan {
        /// How long to scan, in seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
    /// Connect to a cube and stream move events until Ctrl-C or desync.
    Connect {
        /// Substring of device name (or Debug repr of id).
        needle: String,
        /// Maximum seconds to wait for the device to appear.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Connect, read the battery level once, disconnect.
    Battery {
        needle: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Connect, send the cube-state reset command, disconnect.
    Reset {
        needle: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Connect and verbose-dump every BluetoothCubeEvent we receive,
    /// plus periodic state/battery snapshots. The most useful subcommand
    /// for debugging the protocol implementation.
    Raw {
        needle: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { timeout } => cmd_scan(timeout),
        Command::Connect { needle, timeout } => cmd_stream(&needle, timeout, false),
        Command::Battery { needle, timeout } => cmd_battery(&needle, timeout),
        Command::Reset { needle, timeout } => cmd_reset(&needle, timeout),
        Command::Raw { needle, timeout } => cmd_stream(&needle, timeout, true),
    }
}

// ----- Helpers --------------------------------------------------------------

fn install_ctrlc(flag: Arc<AtomicBool>) {
    let f = flag.clone();
    let _ = ctrlc::set_handler(move || {
        eprintln!("[ctrl-c] shutdown requested");
        f.store(true, Ordering::SeqCst);
    });
}

fn matches_needle(dev: &AvailableDevice, needle: &str) -> bool {
    if dev.name.contains(needle) {
        return true;
    }
    let id_dbg = format!("{:?}", dev.id);
    id_dbg.contains(needle)
}

/// Wait for a device whose name (or id Debug repr) contains `needle`. Returns
/// the AvailableDevice once seen, or errors after `timeout_secs`.
fn wait_for_device(
    cube: &BluetoothCube,
    needle: &str,
    timeout_secs: u64,
    quit: &AtomicBool,
) -> Result<AvailableDevice> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last_log = Instant::now() - Duration::from_secs(2);
    loop {
        if quit.load(Ordering::SeqCst) {
            bail!("interrupted");
        }
        let devices = cube.available_devices()?;
        for d in &devices {
            if matches_needle(d, needle) {
                println!(
                    "[dev] match: name={:?} type={:?} id={:?}",
                    d.name, d.cube_type, d.id
                );
                return Ok(d.clone());
            }
        }
        if last_log.elapsed() >= Duration::from_secs(2) {
            println!(
                "[scan] waiting for '{}' ({} device(s) visible)…",
                needle,
                devices.len()
            );
            last_log = Instant::now();
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for device matching '{}'", needle);
        }
        thread::sleep(Duration::from_millis(150));
    }
}

/// Drive the cube from `Discovering` through `Connected`. Errors if it goes
/// to `Desynced` or `Error` before reaching Connected, or on timeout.
fn wait_until_connected(
    cube: &BluetoothCube,
    timeout_secs: u64,
    quit: &AtomicBool,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if quit.load(Ordering::SeqCst) {
            bail!("interrupted");
        }
        match cube.state()? {
            BluetoothCubeState::Connected => return Ok(()),
            BluetoothCubeState::Desynced => bail!("desynced before initial Connected"),
            BluetoothCubeState::Error => bail!("cube reported Error"),
            _ => (),
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for Connected state");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

// ----- Subcommands ----------------------------------------------------------

fn cmd_scan(timeout: u64) -> Result<()> {
    let quit = Arc::new(AtomicBool::new(false));
    install_ctrlc(quit.clone());

    let cube = BluetoothCube::new();
    let deadline = Instant::now() + Duration::from_secs(timeout);
    println!("[scan] scanning for {}s (Ctrl-C to stop early)…", timeout);

    let mut seen: Vec<String> = Vec::new();
    while Instant::now() < deadline && !quit.load(Ordering::SeqCst) {
        let devices = cube.available_devices()?;
        for d in &devices {
            let key = format!("{:?}", d.id);
            if !seen.contains(&key) {
                seen.push(key.clone());
                println!(
                    "[scan] {} type={:?} id={:?}",
                    d.name, d.cube_type, d.id
                );
            }
        }
        thread::sleep(Duration::from_millis(250));
    }

    println!("[scan] done; {} device(s) seen", seen.len());
    Ok(())
}

fn cmd_stream(needle: &str, timeout: u64, raw: bool) -> Result<()> {
    let quit = Arc::new(AtomicBool::new(false));
    install_ctrlc(quit.clone());

    let cube = BluetoothCube::new();

    let device = wait_for_device(&cube, needle, timeout, &quit)?;

    // Listener: must be installed BEFORE the connection completes so we
    // don't miss the first FACELETS-driven state event. The library wires
    // listeners up at registration, so registering before `connect()` is
    // safe — the move-handler thread is created when the connect actually
    // proceeds.
    let move_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let move_count_inner = move_count.clone();
    cube.register_move_listener(move |event| {
        let now_ms = wall_clock_ms();
        match event {
            BluetoothCubeEvent::Move(moves, state) => {
                move_count_inner.fetch_add(moves.len() as u64, Ordering::SeqCst);
                for mv in &moves {
                    println!(
                        "[move] t={} mv={} dt_ms={}",
                        now_ms,
                        mv.move_().to_string(),
                        mv.time()
                    );
                }
                if raw {
                    println!("[state] t={}\n{}", now_ms, state);
                }
            }
            BluetoothCubeEvent::HandsOnTimer => {
                println!("[timer] t={} hands-on", now_ms);
            }
            BluetoothCubeEvent::TimerStartCancel => {
                println!("[timer] t={} start-cancel", now_ms);
            }
            BluetoothCubeEvent::TimerReady => {
                println!("[timer] t={} ready", now_ms);
            }
            BluetoothCubeEvent::TimerStarted => {
                println!("[timer] t={} started", now_ms);
            }
            BluetoothCubeEvent::TimerFinished(ms) => {
                println!("[timer] t={} finished_ms={}", now_ms, ms);
            }
        }
    });

    println!("[conn] connecting to {:?}…", device.id);
    cube.connect(device.id.clone())?;
    wait_until_connected(&cube, timeout, &quit)?;
    println!(
        "[conn] connected name={:?}",
        cube.name()?.as_deref().unwrap_or("?")
    );

    // Stream loop. Print periodic battery/state snapshots when in raw mode.
    let mut last_snapshot = Instant::now() - Duration::from_secs(5);
    let mut last_state = BluetoothCubeState::Connected;
    while !quit.load(Ordering::SeqCst) {
        let state = cube.state()?;
        if state != last_state {
            println!("[conn] state {:?} -> {:?}", last_state, state);
            last_state = state;
        }
        match state {
            BluetoothCubeState::Connected => (),
            BluetoothCubeState::Desynced => {
                println!("[conn] DESYNC after {} moves", move_count.load(Ordering::SeqCst));
                break;
            }
            BluetoothCubeState::Error => {
                println!("[conn] ERROR");
                break;
            }
            _ => (),
        }

        if raw && last_snapshot.elapsed() >= Duration::from_secs(5) {
            last_snapshot = Instant::now();
            let bat = cube.battery_percentage()?;
            let chg = cube.battery_charging()?;
            println!(
                "[snap] t={} battery={:?} charging={:?} moves={}",
                wall_clock_ms(),
                bat,
                chg,
                move_count.load(Ordering::SeqCst)
            );
        }

        thread::sleep(Duration::from_millis(50));
    }

    println!("[conn] disconnecting");
    cube.disconnect();
    Ok(())
}

fn cmd_battery(needle: &str, timeout: u64) -> Result<()> {
    let quit = Arc::new(AtomicBool::new(false));
    install_ctrlc(quit.clone());

    let cube = BluetoothCube::new();
    let device = wait_for_device(&cube, needle, timeout, &quit)?;
    println!("[conn] connecting to {:?}…", device.id);
    cube.connect(device.id.clone())?;
    wait_until_connected(&cube, timeout, &quit)?;
    println!("[conn] connected");

    // The lib polls and updates battery in a loop; give it a moment to
    // populate after the initial battery request goes out.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bat = None;
    while Instant::now() < deadline {
        if quit.load(Ordering::SeqCst) {
            break;
        }
        bat = cube.battery_percentage()?;
        if bat.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let chg = cube.battery_charging()?;
    println!("[battery] level={:?} charging={:?}", bat, chg);

    cube.disconnect();
    Ok(())
}

fn cmd_reset(needle: &str, timeout: u64) -> Result<()> {
    let quit = Arc::new(AtomicBool::new(false));
    install_ctrlc(quit.clone());

    let cube = BluetoothCube::new();
    let device = wait_for_device(&cube, needle, timeout, &quit)?;
    println!("[conn] connecting to {:?}…", device.id);
    cube.connect(device.id.clone())?;
    wait_until_connected(&cube, timeout, &quit)?;
    println!("[conn] connected; sending reset…");
    cube.reset_cube_state()?;
    // Brief grace period so the encrypted write makes it out before we tear
    // down the connection.
    thread::sleep(Duration::from_millis(500));
    println!("[reset] sent");
    cube.disconnect();
    Ok(())
}

// ----- Misc -----------------------------------------------------------------

fn wall_clock_ms() -> u128 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

