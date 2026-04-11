#!/usr/bin/env python3
"""
GAN Cube Meta Service Probe Tool v2

Extended probing of the GAN meta service to try to extract device identifiers.
Builds on findings from gan_meta_probe.py:
  - Commands 0x00-0x05 are recognized (produce non-zero byte[4])
  - All previous probes used zero-filled parameter bytes
  - Response is always 8 bytes: [cmd, 0, 0, 0, value, 0, 0, 0]

This script tries:
  1. Non-zero parameter bytes (including MAC address bytes)
  2. Multiple rapid reads after a write (multi-part responses)
  3. Command sequences (handshake patterns)
  4. Different packet sizes (8, 12, 16, 20, 32)
  5. Writing the version string
  6. Writing manufacturer data bytes

Only prints results that differ from the known echo pattern.

Requirements: pip install bleak
"""

import asyncio
import sys
from datetime import datetime

try:
    from bleak import BleakClient
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError:
    print("ERROR: bleak not installed. Run: pip install bleak")
    sys.exit(1)

# Target device
DEVICE_ADDRESS = "5E705124-7D46-41E6-579D-0E13B2F239FF"

# UUIDs
META_SERVICE_UUID = "f95a48e6-a721-11e9-a2a3-022ae2dbcce4"
WRITE_UUID = "f95a5034-a721-11e9-a2a3-022ae2dbcce4"
READ_UUID = "ec4cff6d-81fc-4e5b-91e0-8103885c9ae3"
VERSION_UUID = "f95a4b66-a721-11e9-a2a3-022ae2dbcce4"

# Known cube info
MAC_BYTES = bytes([0xB0, 0x48, 0x1E, 0x3B, 0x6E, 0x47])
MFR_DATA = bytes([0x00, 0x00, 0x00, 0xE1, 0x15, 0x02, 0x34, 0x12, 0xAB])

# Known "boring" responses for each command (byte[4] values from previous probing)
# Map cmd -> expected byte[4] value. If we don't know it, we won't filter.
KNOWN_BYTE4 = {}  # Will be populated during run


def hex_str(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)


def is_boring(cmd_byte: int, response: bytes) -> bool:
    """Check if response matches the known echo pattern: [cmd, 0, 0, 0, val, 0, 0, 0]."""
    if len(response) != 8:
        return False  # Different length is interesting
    if response[0] != cmd_byte:
        return False  # Different echo is interesting
    if response[1] != 0 or response[2] != 0 or response[3] != 0:
        return False  # Non-zero bytes 1-3 are interesting
    if response[5] != 0 or response[6] != 0 or response[7] != 0:
        return False  # Non-zero bytes 5-7 are interesting
    # byte[4] being same as baseline is boring
    if cmd_byte in KNOWN_BYTE4 and response[4] == KNOWN_BYTE4[cmd_byte]:
        return True
    return False


def is_all_zeros(response: bytes) -> bool:
    return all(b == 0 for b in response)


class MetaProbe2:
    def __init__(self):
        self.notifications: list[tuple[str, bytes]] = []
        self.event = asyncio.Event()

    def on_notify(self, char: BleakGATTCharacteristic, data: bytearray):
        self.notifications.append((datetime.now().strftime("%H:%M:%S.%f")[:-3], bytes(data)))
        self.event.set()

    async def write_and_read(self, client: BleakClient, cmd: bytes, wait: float = 0.5) -> list[bytes]:
        """Write a command and collect notification responses."""
        self.notifications.clear()
        self.event.clear()

        try:
            await client.write_gatt_char(WRITE_UUID, cmd, response=True)
        except Exception:
            await client.write_gatt_char(WRITE_UUID, cmd, response=False)

        try:
            await asyncio.wait_for(self.event.wait(), timeout=wait)
        except asyncio.TimeoutError:
            pass

        return [data for _, data in self.notifications]

    async def write_and_multi_read(self, client: BleakClient, cmd: bytes, reads: int = 5) -> list[bytes]:
        """Write a command, then rapidly read the notify char multiple times."""
        self.notifications.clear()
        self.event.clear()

        try:
            await client.write_gatt_char(WRITE_UUID, cmd, response=True)
        except Exception:
            await client.write_gatt_char(WRITE_UUID, cmd, response=False)

        # Wait for first notification
        try:
            await asyncio.wait_for(self.event.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            pass

        # Also do rapid direct reads
        direct_reads = []
        for _ in range(reads):
            try:
                val = await client.read_gatt_char(READ_UUID)
                direct_reads.append(bytes(val))
            except Exception:
                break
            await asyncio.sleep(0.05)

        return self.notifications[:], direct_reads

    def print_interesting(self, label: str, cmd: bytes, responses: list[bytes]):
        """Print only if response is interesting."""
        if not responses:
            return  # No response at all - not interesting (already known for invalid cmds)

        cmd_byte = cmd[0] if cmd else 0xFF

        for resp in responses:
            if is_all_zeros(resp):
                continue  # Completely zero response, skip
            if is_boring(cmd_byte, resp):
                continue  # Known pattern, skip
            # This is interesting!
            print(f"  [{label}]")
            print(f"    TX ({len(cmd):2d}B): {hex_str(cmd)}")
            print(f"    RX ({len(resp):2d}B): {hex_str(resp)}")
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in resp)
            print(f"    ASCII: |{ascii_str}|")

    async def find_cube(self) -> str:
        """Scan for GAN cube and return its address."""
        from bleak import BleakScanner
        print("Scanning for GAN cube (10s)... rotate a face to wake it!")
        devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
        for d, (dev, adv) in devices.items():
            name = adv.local_name or dev.name or ""
            if "gan" in name.lower() or "smart" in name.lower():
                print(f"  Found: {name} [{dev.address}]")
                return dev.address
            # Also check for the meta service UUID
            if META_SERVICE_UUID in (adv.service_uuids or []):
                print(f"  Found by service UUID: {name or '(unnamed)'} [{dev.address}]")
                return dev.address
        return None

    async def run(self):
        # Try direct address first, fall back to scanning
        address = DEVICE_ADDRESS
        try:
            print(f"Trying direct connect to {address}...")
            client = BleakClient(address, timeout=5.0)
            await client.connect()
            await client.disconnect()
        except Exception:
            print("Direct connect failed, scanning...")
            found = await self.find_cube()
            if found:
                address = found
            else:
                print("No GAN cube found. Wake the cube and try again.")
                return

        print(f"Connecting to {address}...")
        async with BleakClient(address, timeout=15.0) as client:
            print(f"Connected!")

            # Subscribe to notifications
            await client.start_notify(READ_UUID, self.on_notify)
            print("Subscribed to notifications.\n")

            # Phase 0: Establish baselines
            print("=" * 60)
            print("PHASE 0: Establishing baselines for commands 0x00-0x05")
            print("=" * 60)
            for cmd_byte in range(6):
                cmd = bytes([cmd_byte]) + b"\x00" * 15
                responses = await self.write_and_read(client, cmd)
                for resp in responses:
                    if len(resp) == 8:
                        KNOWN_BYTE4[cmd_byte] = resp[4]
                        print(f"  cmd 0x{cmd_byte:02x}: response byte[4] = 0x{resp[4]:02x}  (full: {hex_str(resp)})")
                await asyncio.sleep(0.1)
            print()

            # Phase 1: Non-zero parameter bytes
            print("=" * 60)
            print("PHASE 1: Non-zero parameter bytes for commands 0x00-0x05")
            print("=" * 60)

            interesting_count = 0

            for cmd_byte in range(6):
                # Try single non-zero bytes in positions 1-7
                for pos in range(1, 8):
                    for val in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF]:
                        cmd = bytearray(16)
                        cmd[0] = cmd_byte
                        cmd[pos] = val
                        responses = await self.write_and_read(client, bytes(cmd), wait=0.3)
                        for resp in responses:
                            if not is_all_zeros(resp) and not is_boring(cmd_byte, resp):
                                interesting_count += 1
                                self.print_interesting(
                                    f"cmd=0x{cmd_byte:02x} byte[{pos}]=0x{val:02x}",
                                    bytes(cmd), [resp])
                        await asyncio.sleep(0.05)

                # Try MAC address in bytes 1-6
                cmd = bytearray(16)
                cmd[0] = cmd_byte
                cmd[1:7] = MAC_BYTES
                responses = await self.write_and_read(client, bytes(cmd), wait=0.3)
                self.print_interesting(f"cmd=0x{cmd_byte:02x} + MAC in [1:7]", bytes(cmd), responses)

                # Try MAC reversed
                cmd = bytearray(16)
                cmd[0] = cmd_byte
                cmd[1:7] = MAC_BYTES[::-1]
                responses = await self.write_and_read(client, bytes(cmd), wait=0.3)
                self.print_interesting(f"cmd=0x{cmd_byte:02x} + MAC_rev in [1:7]", bytes(cmd), responses)

                # Try MAC in bytes 2-7
                cmd = bytearray(16)
                cmd[0] = cmd_byte
                cmd[2:8] = MAC_BYTES
                responses = await self.write_and_read(client, bytes(cmd), wait=0.3)
                self.print_interesting(f"cmd=0x{cmd_byte:02x} + MAC in [2:8]", bytes(cmd), responses)

                await asyncio.sleep(0.1)

            if interesting_count == 0:
                print("  (no interesting responses found)")
            print()

            # Phase 2: Multiple rapid reads after write
            print("=" * 60)
            print("PHASE 2: Multi-read after write (looking for multi-part responses)")
            print("=" * 60)

            found_multi = False
            for cmd_byte in range(6):
                cmd = bytes([cmd_byte]) + b"\x00" * 15
                notifs, direct_reads = await self.write_and_multi_read(client, cmd, reads=5)

                # Check if any direct read differs from the notification
                baseline = None
                for _, data in notifs:
                    baseline = data
                    break

                for i, rd in enumerate(direct_reads):
                    if baseline is not None and rd != baseline and not is_all_zeros(rd):
                        found_multi = True
                        print(f"  cmd=0x{cmd_byte:02x}: read[{i}] differs from notification!")
                        print(f"    Notif:    {hex_str(baseline)}")
                        print(f"    Read[{i}]:  {hex_str(rd)}")
                    elif baseline is None and not is_all_zeros(rd):
                        found_multi = True
                        print(f"  cmd=0x{cmd_byte:02x}: direct read[{i}] = {hex_str(rd)}")

                # Check if we got multiple different notifications
                if len(notifs) > 1:
                    unique = set(data for _, data in notifs)
                    if len(unique) > 1:
                        found_multi = True
                        print(f"  cmd=0x{cmd_byte:02x}: got {len(notifs)} notifications with {len(unique)} unique values!")
                        for ts, data in notifs:
                            print(f"    [{ts}] {hex_str(data)}")

                await asyncio.sleep(0.1)

            if not found_multi:
                print("  (no multi-part or varying responses found)")
            print()

            # Phase 3: Command sequences
            print("=" * 60)
            print("PHASE 3: Command sequences (handshake patterns)")
            print("=" * 60)

            sequences = [
                ([0x01, 0x02], "0x01 -> 0x02"),
                ([0x00, 0x01, 0x02], "0x00 -> 0x01 -> 0x02"),
                ([0x00, 0x01, 0x02, 0x03, 0x04, 0x05], "0x00 -> 0x01 -> ... -> 0x05"),
                ([0x05, 0x04, 0x03, 0x02, 0x01, 0x00], "0x05 -> 0x04 -> ... -> 0x00"),
                ([0x00, 0x00, 0x01], "0x00 -> 0x00 -> 0x01 (repeat first)"),
                ([0x03, 0x00], "0x03 -> 0x00"),
                ([0x04, 0x05], "0x04 -> 0x05"),
            ]

            found_seq = False
            for seq, desc in sequences:
                all_responses = []
                for cmd_byte in seq:
                    cmd = bytes([cmd_byte]) + b"\x00" * 15
                    responses = await self.write_and_read(client, cmd, wait=0.2)
                    all_responses.append((cmd_byte, responses))
                    await asyncio.sleep(0.05)

                # Check if any response in the sequence differs from baseline
                for cmd_byte, responses in all_responses:
                    for resp in responses:
                        if not is_all_zeros(resp) and not is_boring(cmd_byte, resp):
                            found_seq = True
                            print(f"  Sequence [{desc}]: cmd=0x{cmd_byte:02x} gave non-baseline response!")
                            print(f"    RX: {hex_str(resp)}")

                await asyncio.sleep(0.2)

            if not found_seq:
                print("  (no sequence-dependent behavior found)")
            print()

            # Phase 4: Different packet sizes
            print("=" * 60)
            print("PHASE 4: Different packet sizes (8, 12, 16, 20, 32 bytes)")
            print("=" * 60)

            sizes = [8, 12, 16, 20, 32]
            found_size = False

            for size in sizes:
                for cmd_byte in range(6):
                    cmd = bytes([cmd_byte]) + b"\x00" * (size - 1)
                    responses = await self.write_and_read(client, cmd, wait=0.3)

                    for resp in responses:
                        if not is_all_zeros(resp) and not is_boring(cmd_byte, resp):
                            found_size = True
                            print(f"  size={size:2d}, cmd=0x{cmd_byte:02x}: {hex_str(resp)}")
                    await asyncio.sleep(0.05)
                await asyncio.sleep(0.1)

            if not found_size:
                print("  (all sizes produce same baseline responses)")
            print()

            # Phase 5: Write version string
            print("=" * 60)
            print("PHASE 5: Writing version string as command")
            print("=" * 60)

            version_bytes = b"1.1.4-pre"

            # Padded to 16 bytes
            cmd = version_bytes + b"\x00" * (16 - len(version_bytes))
            responses = await self.write_and_read(client, cmd, wait=0.5)
            if responses:
                for resp in responses:
                    print(f"  Version (16B pad): TX={hex_str(cmd)}")
                    print(f"                     RX={hex_str(resp)}")
            else:
                print(f"  Version (16B pad): no response")
            await asyncio.sleep(0.1)

            # Padded to 20 bytes
            cmd = version_bytes + b"\x00" * (20 - len(version_bytes))
            responses = await self.write_and_read(client, cmd, wait=0.5)
            if responses:
                for resp in responses:
                    print(f"  Version (20B pad): TX={hex_str(cmd)}")
                    print(f"                     RX={hex_str(resp)}")
            else:
                print(f"  Version (20B pad): no response")
            await asyncio.sleep(0.1)

            # As raw bytes (not ASCII)
            cmd = version_bytes + b"\x00" * 7  # 16 bytes total
            responses = await self.write_and_read(client, cmd, wait=0.5)
            if responses:
                for resp in responses:
                    if not is_all_zeros(resp):
                        print(f"  Version (raw 16B): TX={hex_str(cmd)}")
                        print(f"                     RX={hex_str(resp)}")
            print()

            # Phase 6: Write manufacturer data
            print("=" * 60)
            print("PHASE 6: Writing manufacturer data bytes as command")
            print("=" * 60)

            # MFR data padded to 16 bytes
            cmd = MFR_DATA + b"\x00" * (16 - len(MFR_DATA))
            responses = await self.write_and_read(client, cmd, wait=0.5)
            if responses:
                for resp in responses:
                    print(f"  MfrData (16B pad): TX={hex_str(cmd)}")
                    print(f"                     RX={hex_str(resp)}")
            else:
                print(f"  MfrData (16B pad): no response")
            await asyncio.sleep(0.1)

            # MFR data with company ID prefix (0x01, 0x00)
            cmd = bytes([0x01, 0x00]) + MFR_DATA + b"\x00" * (16 - 2 - len(MFR_DATA))
            responses = await self.write_and_read(client, cmd, wait=0.5)
            if responses:
                for resp in responses:
                    if not is_boring(0x01, resp):
                        print(f"  MfrData+compID:    TX={hex_str(cmd)}")
                        print(f"                     RX={hex_str(resp)}")
            await asyncio.sleep(0.1)

            # MFR data padded to 20 bytes
            cmd = MFR_DATA + b"\x00" * (20 - len(MFR_DATA))
            responses = await self.write_and_read(client, cmd, wait=0.5)
            if responses:
                for resp in responses:
                    print(f"  MfrData (20B pad): TX={hex_str(cmd)}")
                    print(f"                     RX={hex_str(resp)}")
            else:
                print(f"  MfrData (20B pad): no response")

            # Try each of the MFR data bytes as command byte 0, with rest as params
            for i, mfr_byte in enumerate(MFR_DATA):
                if mfr_byte == 0:
                    continue  # Already tested 0x00 command
                cmd = bytes([mfr_byte]) + b"\x00" * 15
                responses = await self.write_and_read(client, cmd, wait=0.3)
                for resp in responses:
                    if not is_all_zeros(resp):
                        print(f"  MfrData[{i}]=0x{mfr_byte:02x} as cmd: RX={hex_str(resp)}")
                await asyncio.sleep(0.05)

            print()

            # Cleanup
            await client.stop_notify(READ_UUID)
            print("=" * 60)
            print("DONE. All experiments complete.")
            print("=" * 60)


if __name__ == "__main__":
    asyncio.run(MetaProbe2().run())
