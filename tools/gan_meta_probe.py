#!/usr/bin/env python3
"""
GAN Cube Meta Service Probe Tool

Tests the theory that the GAN meta service (f95a48e6) can be used to query
device identifiers. Connects to a GAN cube via BLE, discovers services,
subscribes to notifications on ec4cff6d, and writes probe commands to f95a5034.

Requirements: pip install bleak

Usage:
    python gan_meta_probe.py                  # Scan, connect, and probe
    python gan_meta_probe.py --scan-only      # Just scan for GAN cubes
    python gan_meta_probe.py --address XX:XX  # Connect to specific address
    python gan_meta_probe.py --dump           # Dump all services/characteristics
"""

import argparse
import asyncio
import struct
import sys
from datetime import datetime

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError:
    print("ERROR: bleak not installed. Run: pip install bleak")
    sys.exit(1)


# Known GAN service UUIDs
META_SERVICE_UUID = "f95a48e6-a721-11e9-a2a3-022ae2dbcce4"

# Partial UUIDs for the meta service characteristics - we'll match by substring
# since we don't know the full UUIDs yet
META_READ_PARTIAL = "ec4cff6d"
META_WRITE_PARTIAL = "f95a5034"

# GAN v2 service/characteristics (for reference/detection)
GAN_V2_WRITE = "28be4a4a-cd67-11e9-a32f-2a2ae2dbcce4"
GAN_V2_READ = "28be4cb6-cd67-11e9-a32f-2a2ae2dbcce4"

# GAN v1 service
GAN_V1_SERVICE = "0000fff0-0000-1000-8000-00805f9b34fb"

# Device info service
DEVICE_INFO_SERVICE = "0000180a-0000-1000-8000-00805f9b34fb"
SYSTEM_ID_CHAR = "00002a23-0000-1000-8000-00805f9b34fb"
FIRMWARE_REV_CHAR = "00002a26-0000-1000-8000-00805f9b34fb"
HARDWARE_REV_CHAR = "00002a27-0000-1000-8000-00805f9b34fb"
SOFTWARE_REV_CHAR = "00002a28-0000-1000-8000-00805f9b34fb"
MANUFACTURER_CHAR = "00002a29-0000-1000-8000-00805f9b34fb"


def hex_dump(data: bytes, prefix: str = "") -> str:
    """Format bytes as hex dump with ASCII."""
    hex_str = " ".join(f"{b:02x}" for b in data)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{prefix}{hex_str}  |{ascii_str}|"


def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


class GANMetaProbe:
    def __init__(self):
        self.meta_read_uuid = None
        self.meta_write_uuid = None
        self.notifications = []
        self.notification_event = asyncio.Event()

    def notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Handle incoming notifications."""
        ts = timestamp()
        print(f"\n  [{ts}] NOTIFY on {characteristic.uuid}:")
        print(hex_dump(bytes(data), "    "))
        print(f"    Length: {len(data)} bytes")
        self.notifications.append((ts, bytes(data)))
        self.notification_event.set()

    async def scan_for_gan_cubes(self, timeout: float = 10.0):
        """Scan for GAN cubes."""
        print(f"Scanning for GAN cubes ({timeout}s)...")
        print("(Look for devices with 'GAN' in the name or known service UUIDs)\n")

        gan_devices = []

        def detection_callback(device, adv_data):
            name = adv_data.local_name or device.name or ""
            is_gan = (
                "gan" in name.lower()
                or "smart" in name.lower()
                or META_SERVICE_UUID in (adv_data.service_uuids or [])
                or any("fff0" in str(u).lower() for u in (adv_data.service_uuids or []))
            )
            if is_gan:
                mfr = adv_data.manufacturer_data
                mfr_str = ""
                if mfr:
                    for company_id, data in mfr.items():
                        mfr_str += f" MfrData[{company_id:#06x}]={data.hex()}"
                print(f"  Found: {name or '(unnamed)'} [{device.address}] RSSI={adv_data.rssi}{mfr_str}")
                if adv_data.service_uuids:
                    print(f"    Services: {', '.join(adv_data.service_uuids)}")
                gan_devices.append((device, adv_data))

        scanner = BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()

        if not gan_devices:
            print("\nNo GAN cubes found. Make sure your cube is:")
            print("  - Powered on (rotate a face to wake it)")
            print("  - Not connected to another device")
            print("  - Within Bluetooth range")
        return gan_devices

    async def dump_services(self, client: BleakClient):
        """Dump all services and characteristics."""
        print("\n=== ALL SERVICES AND CHARACTERISTICS ===\n")
        for service in client.services:
            print(f"Service: {service.uuid}")
            if service.description:
                print(f"  Description: {service.description}")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"  Char: {char.uuid}  [{props}]")
                if char.description:
                    print(f"    Description: {char.description}")
                # Try to read readable characteristics
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        print(hex_dump(bytes(value), "    Value: "))
                        # Also try to decode as string
                        try:
                            text = value.decode("utf-8").rstrip("\x00")
                            if text and all(32 <= ord(c) < 127 for c in text):
                                print(f"    As string: \"{text}\"")
                        except (UnicodeDecodeError, ValueError):
                            pass
                    except Exception as e:
                        print(f"    Read error: {e}")
            print()

    def find_meta_characteristics(self, client: BleakClient):
        """Find the meta service characteristics by partial UUID match."""
        meta_service = None
        for service in client.services:
            if META_SERVICE_UUID in service.uuid.lower():
                meta_service = service
                break

        if not meta_service:
            # Also try matching by the short form
            for service in client.services:
                if "f95a48e6" in service.uuid.lower():
                    meta_service = service
                    break

        if not meta_service:
            print(f"\n*** Meta service {META_SERVICE_UUID} NOT FOUND ***")
            print("Available services:")
            for service in client.services:
                print(f"  {service.uuid}")
            return False

        print(f"\nFound meta service: {meta_service.uuid}")
        print(f"Characteristics:")
        for char in meta_service.characteristics:
            props = ", ".join(char.properties)
            print(f"  {char.uuid}  [{props}]")
            if META_READ_PARTIAL in char.uuid.lower():
                self.meta_read_uuid = char.uuid
                print(f"    ^ Matched as READ/NOTIFY characteristic")
            if META_WRITE_PARTIAL in char.uuid.lower():
                self.meta_write_uuid = char.uuid
                print(f"    ^ Matched as WRITE characteristic")

        # If we didn't match by partial UUID, try by properties
        if not self.meta_read_uuid or not self.meta_write_uuid:
            print("\nPartial UUID match incomplete, trying property-based matching...")
            for char in meta_service.characteristics:
                if not self.meta_read_uuid and ("notify" in char.properties or "indicate" in char.properties):
                    self.meta_read_uuid = char.uuid
                    print(f"  Read/Notify: {char.uuid}")
                elif not self.meta_write_uuid and ("write" in char.properties or "write-without-response" in char.properties):
                    self.meta_write_uuid = char.uuid
                    print(f"  Write: {char.uuid}")

        if not self.meta_read_uuid:
            print("\n*** Could not identify read/notify characteristic ***")
            return False
        if not self.meta_write_uuid:
            print("\n*** Could not identify write characteristic ***")
            return False

        return True

    async def read_device_info(self, client: BleakClient):
        """Try to read standard device info characteristics."""
        print("\n=== DEVICE INFO SERVICE ===\n")
        info_chars = {
            SYSTEM_ID_CHAR: "System ID",
            FIRMWARE_REV_CHAR: "Firmware Rev",
            HARDWARE_REV_CHAR: "Hardware Rev",
            SOFTWARE_REV_CHAR: "Software Rev",
            MANUFACTURER_CHAR: "Manufacturer",
        }
        for uuid, name in info_chars.items():
            try:
                value = await client.read_gatt_char(uuid)
                print(f"  {name}: {hex_dump(bytes(value))}")
                try:
                    text = value.decode("utf-8").rstrip("\x00")
                    if text and all(32 <= ord(c) < 127 for c in text):
                        print(f"    As string: \"{text}\"")
                except (UnicodeDecodeError, ValueError):
                    pass
            except Exception as e:
                print(f"  {name}: not available ({e})")

    async def probe_meta_service(self, client: BleakClient):
        """Send probe commands to the meta service and listen for responses."""
        print("\n=== PROBING META SERVICE ===\n")

        # Try subscribing to notifications, but handle failure gracefully
        notify_active = False
        print(f"Subscribing to notifications on {self.meta_read_uuid}...")
        try:
            await client.start_notify(self.meta_read_uuid, self.notification_handler)
            notify_active = True
            print("Subscribed.\n")
        except Exception as e:
            print(f"Notify subscription failed: {e}")
            print("Will poll via read instead.\n")

        # Try reading the characteristic directly first
        try:
            value = await client.read_gatt_char(self.meta_read_uuid)
            print(f"Direct read of notify char (before writes):")
            print(hex_dump(bytes(value), "  "))
            print(f"  Length: {len(value)} bytes\n")
        except Exception as e:
            print(f"Direct read of notify char: {e}\n")

        # Also read the version characteristic
        version_uuid = None
        for service in client.services:
            if META_SERVICE_UUID in service.uuid.lower():
                for char in service.characteristics:
                    if char.uuid != self.meta_read_uuid and char.uuid != self.meta_write_uuid:
                        if "read" in char.properties:
                            version_uuid = char.uuid
        if version_uuid:
            try:
                value = await client.read_gatt_char(version_uuid)
                print(f"Version characteristic ({version_uuid}):")
                print(hex_dump(bytes(value), "  "))
                try:
                    text = value.decode("utf-8").rstrip("\x00")
                    print(f"  As string: \"{text}\"")
                except (UnicodeDecodeError, ValueError):
                    pass
                print()
            except Exception as e:
                print(f"Version char read error: {e}\n")

        # Now we know: commands must be padded to 16 bytes to get responses.
        # Sweep all single-byte commands 0x00-0x1f padded to 16 bytes,
        # plus variations with sub-commands in byte 1.
        probe_commands = []

        # Sweep command bytes 0x00 through 0x20 (padded to 16 bytes)
        for i in range(0x21):
            cmd = bytes([i]) + b"\x00" * 15
            probe_commands.append((cmd, f"cmd=0x{i:02x} (16-byte padded)"))

        # Also try sub-command variations for commands that responded
        # (we know 0x01 and 0x04 responded, try sub-commands for those)
        for main_cmd in [0x01, 0x04]:
            for sub in range(1, 0x10):
                cmd = bytes([main_cmd, sub]) + b"\x00" * 14
                probe_commands.append((cmd, f"cmd=0x{main_cmd:02x} sub=0x{sub:02x} (16-byte)"))

        # Try 20-byte padded versions too
        for i in range(0x10):
            cmd = bytes([i]) + b"\x00" * 19
            probe_commands.append((cmd, f"cmd=0x{i:02x} (20-byte padded)"))

        for cmd, desc in probe_commands:
            self.notification_event.clear()
            self.notifications.clear()

            try:
                # Try write-with-response first, fall back to write-without-response
                try:
                    await client.write_gatt_char(self.meta_write_uuid, cmd, response=True)
                except Exception:
                    await client.write_gatt_char(self.meta_write_uuid, cmd, response=False)

                # Always wait briefly for notification (since they work even without start_notify)
                try:
                    await asyncio.wait_for(self.notification_event.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass

                if self.notifications:
                    print(f"--- {desc} ---")
                    print(hex_dump(cmd[:max(4, len(cmd) - cmd[::-1].index(next(b for b in reversed(cmd) if b != 0)) if any(b != 0 for b in cmd) else 1)], "  TX: "))
                    for ts, data in self.notifications:
                        print(f"  [{ts}] RX: {hex_dump(bytes(data))}")
                        try:
                            text = data.decode("utf-8").rstrip("\x00")
                            if text and len(text) > 1 and all(32 <= ord(c) < 127 for c in text):
                                print(f"    As string: \"{text}\"")
                        except (UnicodeDecodeError, ValueError):
                            pass
                    print()

                if not notify_active:
                    # Also poll by reading
                    await asyncio.sleep(0.3)
                    try:
                        value = await client.read_gatt_char(self.meta_read_uuid)
                        if len(value) > 0 and any(b != 0 for b in value):
                            print(f"  RX (read):")
                            print(hex_dump(bytes(value), "    "))
                            print(f"    Length: {len(value)} bytes")
                        else:
                            print("  (read returned empty/zeros)")
                    except Exception as e:
                        print(f"  Read error: {e}")

            except Exception as e:
                print(f"  Write error: {e}")

            print()

        if notify_active:
            # Keep listening for a bit in case of delayed responses
            print("Listening for any additional notifications (5s)...")
            await asyncio.sleep(5.0)
            await client.stop_notify(self.meta_read_uuid)

        print("\nDone probing.")

    async def run(self, address: str = None, scan_only: bool = False, dump: bool = False):
        """Main entry point."""
        if not address:
            devices = await self.scan_for_gan_cubes()
            if scan_only or not devices:
                return
            # Use the first found device
            device, adv_data = devices[0]
            address = device.address
            print(f"\nUsing first found device: {address}")

        print(f"\nConnecting to {address}...")
        async with BleakClient(address, timeout=15.0) as client:
            print(f"Connected! MTU={client.mtu_size if hasattr(client, 'mtu_size') else 'unknown'}")

            if dump:
                await self.dump_services(client)
                return

            # Always dump services first for diagnostics
            await self.dump_services(client)

            # Read standard device info
            await self.read_device_info(client)

            # Find and probe the meta service
            if self.find_meta_characteristics(client):
                await self.probe_meta_service(client)
            else:
                print("\nMeta service not found. Check the service dump above for available services.")
                print("The cube may not expose this service, or it may use different UUIDs.")


async def main():
    parser = argparse.ArgumentParser(description="GAN Cube Meta Service Probe Tool")
    parser.add_argument("--address", "-a", help="BLE device address to connect to directly")
    parser.add_argument("--scan-only", "-s", action="store_true", help="Only scan, don't connect")
    parser.add_argument("--dump", "-d", action="store_true", help="Dump all services and characteristics")
    parser.add_argument("--timeout", "-t", type=float, default=10.0, help="Scan timeout in seconds")
    args = parser.parse_args()

    probe = GANMetaProbe()
    await probe.run(address=args.address, scan_only=args.scan_only, dump=args.dump)


if __name__ == "__main__":
    asyncio.run(main())
