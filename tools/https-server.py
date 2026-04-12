#!/usr/bin/env python3
"""
Serve the generated web/ directory over HTTPS.

WebGPU (used by the renderer) and Web Bluetooth (used to pair GAN cubes) are
only available on secure origins. `http://localhost` counts as secure, but
`http://192.168.x.y` does not — so testing from a phone, tablet or other LAN
device requires TLS.

This script picks a cert in the following order, and caches the result in
`.http-server/` under the repo root (gitignored):

  1. Existing `cert.pem` + `key.pem` in `.http-server/`.
  2. Generated via `mkcert` if that binary is on PATH. The resulting root CA
     is trusted automatically on this machine (after `mkcert -install`) and
     can be trusted on iOS by transferring `$(mkcert -CAROOT)/rootCA.pem` to
     the phone and enabling it in Certificate Trust Settings.
  3. Generated via `openssl req -x509` as a last-resort self-signed cert.
     Browsers will show a warning and iOS Safari may refuse WebGPU / Web
     Bluetooth entirely — only useful for basic smoke testing.

All paths are resolved relative to this script's location, so it can be
invoked from any working directory.

Environment:
  TPSCUBE_HTTPS_PORT   Port to listen on            (default 8443)
  TPSCUBE_HTTPS_BIND   Interface to bind            (default 0.0.0.0)
  TPSCUBE_HTTPS_IP     Override the detected LAN IP used for cert SAN and
                       the "serving on …" message. Useful if you have
                       multiple interfaces and autodetection picks the
                       wrong one.

Usage:
  python3 tools/https-server.py
  make secure
"""

import http.server
import ipaddress
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys

# This script lives at `tools/https-server.py`, so the repo root is one
# level up. Everything else (`web/`, `.http-server/`) is resolved relative
# to the repo root, not to wherever the script was invoked from.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB_DIR = REPO_ROOT / "web"
CERT_DIR = REPO_ROOT / ".http-server"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"
PORT = int(os.environ.get("TPSCUBE_HTTPS_PORT", "8443"))
BIND = os.environ.get("TPSCUBE_HTTPS_BIND", "0.0.0.0")


# Interface name prefixes we treat as "not a real LAN interface": VPN
# tunnels, point-to-point pseudo-interfaces, Apple-internal radios, and
# bridges. We filter these out so cert SANs and the "serving on ..."
# display aren't hijacked by a WireGuard / Tailscale / IKEv2 / etc. tunnel.
_TUNNEL_IFACE_PREFIXES = (
    "utun",    # macOS generic tunnel (Tailscale, Cloudflare WARP, Wireguard, ...)
    "tun",     # Linux generic tunnel
    "tap",     # layer-2 tunnel
    "ppp",     # PPP link
    "wg",      # Wireguard
    "awdl",    # Apple Wireless Direct Link
    "llw",     # macOS low-latency WLAN
    "anpi",    # Apple Network Privacy Interface
    "ap",      # AP mode / tethering
    "bridge",  # macOS bridge interfaces
    "ipsec",   # IPsec tunnels
    "gif",     # Generic tunnel
    "stf",     # 6to4
    "lo",      # loopback
)


def _detect_lan_ip_from_ifconfig():
    """Parse `ifconfig` output to find the primary LAN IPv4.

    Picks the first interface with a non-loopback, non-tunnel name that has
    an `inet` address assigned. This is our preferred detection path
    because it's deterministic even when a VPN is hijacking the default
    route.
    """
    try:
        out = subprocess.run(
            ["ifconfig"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    current_iface = None
    for line in out.splitlines():
        if line and not line[0].isspace() and ":" in line:
            # Interface header: "en0: flags=..."
            current_iface = line.split(":", 1)[0]
            continue
        if current_iface is None:
            continue
        stripped = line.strip()
        if not stripped.startswith("inet "):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.is_loopback:
            continue
        if any(current_iface.startswith(p) for p in _TUNNEL_IFACE_PREFIXES):
            continue
        return ip
    return None


def _detect_lan_ip_via_socket():
    """Fallback: ask the kernel which interface it would use for outbound
    traffic. Subject to VPN routing — may return a tunnel IP when a VPN
    is active, which is exactly why `ifconfig` is tried first.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))  # TEST-NET-1, never routable
        ip = s.getsockname()[0]
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return None
        return ip
    except OSError:
        return None
    finally:
        s.close()


def detect_lan_ip():
    """Best-effort detection of this machine's primary LAN IP.

    Order:
      1. `TPSCUBE_HTTPS_IP` environment variable (explicit override).
      2. `ifconfig` output, filtering out tunnel-like interface names.
      3. Kernel-picked outbound interface via UDP getsockname().
      4. 127.0.0.1 as a last resort.
    """
    override = os.environ.get("TPSCUBE_HTTPS_IP")
    if override:
        try:
            ipaddress.IPv4Address(override)
            return override
        except ValueError:
            print(
                f"[https-server] warning: TPSCUBE_HTTPS_IP={override!r} is "
                "not a valid IPv4 address; ignoring",
                file=sys.stderr,
            )

    ip = _detect_lan_ip_from_ifconfig()
    if ip:
        return ip
    ip = _detect_lan_ip_via_socket()
    if ip:
        return ip
    return "127.0.0.1"


def detect_hostnames():
    """Return the set of DNS hostnames this machine answers to.

    Covers both the short (`jmbp`) and Bonjour (`jmbp.local`) forms so the
    cert works regardless of which URL the user types. Sources:
      * `socket.gethostname()` — on macOS this often already returns the
        `.local` form; on Linux it's usually the short form.
      * `scutil --get LocalHostName` on macOS for the canonical Bonjour
        name. Skipped silently on non-macOS.
    """
    names = set()

    try:
        h = socket.gethostname()
    except OSError:
        h = ""
    if h:
        names.add(h)
        if h.endswith(".local"):
            names.add(h[: -len(".local")])
        else:
            names.add(f"{h}.local")

    # macOS Bonjour: prefer LocalHostName when we can read it.
    try:
        out = subprocess.run(
            ["scutil", "--get", "LocalHostName"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        ).stdout.strip()
        if out:
            names.add(out)
            names.add(f"{out}.local")
    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        pass

    # Filter out obviously bad entries.
    names = {n for n in names if n and " " not in n}
    return sorted(names)


def target_sans(lan_ip):
    """Return the list of SANs we want on the cert.

    The shape is a list of ``(kind, value)`` tuples where ``kind`` is one
    of ``"DNS"`` or ``"IP"``. Both cert generators consume this same list,
    and the freshness check compares against it, so there's exactly one
    source of truth for "which names/IPs should this cert cover".
    """
    sans = [
        ("DNS", "localhost"),
        ("IP", "127.0.0.1"),
        ("IP", "::1"),
    ]
    for name in detect_hostnames():
        entry = ("DNS", name)
        if entry not in sans:
            sans.append(entry)
    if lan_ip and lan_ip != "127.0.0.1":
        entry = ("IP", lan_ip)
        if entry not in sans:
            sans.append(entry)
    return sans


def _normalize_ip(s):
    """Parse an IP string to its canonical form, or return the input on
    failure. Used so that ``::1`` compares equal to ``0:0:0:0:0:0:0:1`` —
    openssl prints the expanded form, but we generate the compressed form.
    """
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


def _run(cmd, **kwargs):
    """Run a subprocess and raise on failure with the stderr surfaced."""
    return subprocess.run(cmd, check=True, **kwargs)


def _generate_with_mkcert(mkcert_bin, sans):
    """Generate a cert signed by the locally-trusted mkcert root CA.

    `mkcert` takes SANs as positional arguments (DNS or IP — it figures out
    which based on whether the arg parses as an IP). Passing each entry
    from our unified SAN list works directly.

    If mkcert's root CA has not been installed yet (`mkcert -install`), the
    generated cert will be usable but untrusted — we remind the user.
    """
    flat = [value for _kind, value in sans]
    print(
        f"[https-server] generating mkcert cert for: {', '.join(flat)}",
        file=sys.stderr,
    )
    _run(
        [
            mkcert_bin,
            "-cert-file",
            str(CERT_FILE),
            "-key-file",
            str(KEY_FILE),
            *flat,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # mkcert -install writes a "The local CA is already installed" marker.
    # Rather than parse that, just remind the user if the root CA doesn't
    # live in the system trust store yet; they'll see this once per machine.
    caroot = subprocess.run(
        [mkcert_bin, "-CAROOT"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if caroot:
        installed_marker = pathlib.Path(caroot) / "rootCA.pem"
        if installed_marker.exists():
            # Still remind the user about the iOS step — easy to forget.
            print(
                "[https-server] mkcert root CA: "
                f"{installed_marker}\n"
                "[https-server]   to trust on iOS:\n"
                "[https-server]     1. AirDrop rootCA.pem to the iPhone "
                "(rename to rootCA.crt first)\n"
                "[https-server]     2. Settings → General → VPN & Device "
                "Management → install\n"
                "[https-server]     3. Settings → General → About → "
                "Certificate Trust Settings → enable"
            )


def _generate_self_signed(sans):
    """Fallback: openssl-generated self-signed cert.

    Encodes the provided SAN list into the `subjectAltName` extension so
    the cert at least passes hostname verification, though no browser will
    trust the signature without manual overrides.
    """
    print(
        "[https-server] mkcert not found — generating self-signed cert via "
        "openssl.\n"
        "[https-server]   install mkcert for a cert your devices will trust:\n"
        "[https-server]     brew install mkcert && mkcert -install",
        file=sys.stderr,
    )

    san_parts = []
    for kind, value in sans:
        prefix = "DNS:" if kind == "DNS" else "IP:"
        san_parts.append(f"{prefix}{value}")
    san_ext = "subjectAltName=" + ",".join(san_parts)

    try:
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(KEY_FILE),
                "-out",
                str(CERT_FILE),
                "-days",
                "365",
                "-subj",
                "/CN=tpscube-dev",
                "-addext",
                san_ext,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        print(
            "[https-server] ERROR: neither mkcert nor openssl is on PATH.\n"
            "[https-server]   install one of:\n"
            "[https-server]     brew install mkcert   (recommended)\n"
            "[https-server]     brew install openssl",
            file=sys.stderr,
        )
        sys.exit(1)


def _parse_cert_sans(cert_path):
    """Parse SANs out of a cert as a set of ``(kind, value)`` tuples.

    Returns ``None`` on any openssl failure — callers should treat that as
    "can't check, reuse whatever is cached".
    """
    try:
        out = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(cert_path),
                "-noout",
                "-ext",
                "subjectAltName",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    present = set()
    # openssl prints things like:
    #   X509v3 Subject Alternative Name:
    #       DNS:localhost, IP Address:127.0.0.1, IP Address:10.41.0.21
    # Match "DNS:<value>" and "IP Address:<value>" up to the next comma or
    # whitespace. The value for IPv6 contains colons but no commas/spaces,
    # so the greedy [^,\s]+ is fine.
    for kind, value in re.findall(r"(DNS|IP Address):([^,\s]+)", out):
        if kind == "DNS":
            present.add(("DNS", value))
        else:
            present.add(("IP", _normalize_ip(value)))
    return present


def _cert_covers_sans(cert_path, wanted):
    """Return True if the cert's SANs cover every entry in `wanted`."""
    present = _parse_cert_sans(cert_path)
    if present is None:
        # Couldn't parse — don't regenerate in a loop, just reuse.
        return True
    for kind, value in wanted:
        if kind == "IP":
            needle = ("IP", _normalize_ip(value))
        else:
            needle = ("DNS", value)
        if needle not in present:
            return False
    return True


def ensure_cert(sans):
    """Ensure `.http-server/cert.pem` and `key.pem` exist and cover `sans`.

    Regenerates the cert when:
      * the files don't exist at all
      * the cached cert's SAN list is missing anything in `sans` (usually
        because the machine moved networks or the hostname changed since
        the cert was last generated)
    """
    CERT_DIR.mkdir(exist_ok=True)

    if CERT_FILE.exists() and KEY_FILE.exists():
        if _cert_covers_sans(CERT_FILE, sans):
            return
        print(
            "[https-server] cached cert is missing required SANs — "
            "regenerating",
            file=sys.stderr,
        )
        CERT_FILE.unlink(missing_ok=True)
        KEY_FILE.unlink(missing_ok=True)

    mkcert_bin = shutil.which("mkcert")
    if mkcert_bin:
        _generate_with_mkcert(mkcert_bin, sans)
    else:
        _generate_self_signed(sans)

    if not (CERT_FILE.exists() and KEY_FILE.exists()):
        print(
            "[https-server] ERROR: cert generation produced no files.",
            file=sys.stderr,
        )
        sys.exit(1)


def main():
    if not WEB_DIR.is_dir():
        print(
            f"[https-server] ERROR: {WEB_DIR.relative_to(REPO_ROOT)} does not "
            "exist.\n[https-server] run `make web` first to build the wasm "
            "bundle.",
            file=sys.stderr,
        )
        sys.exit(1)

    lan_ip = detect_lan_ip()
    sans = target_sans(lan_ip)
    ensure_cert(sans)

    os.chdir(WEB_DIR)

    srv = http.server.HTTPServer((BIND, PORT), http.server.SimpleHTTPRequestHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

    print("[https-server] serving web/ over https on:")
    shown = set()
    shown.add("localhost")
    print(f"[https-server]   https://localhost:{PORT}/")
    # Also show every `.local` hostname we advertised in the cert SANs.
    for kind, value in sans:
        if kind != "DNS":
            continue
        if value in shown:
            continue
        if not value.endswith(".local"):
            continue
        shown.add(value)
        print(f"[https-server]   https://{value}:{PORT}/")
    if lan_ip and lan_ip != "127.0.0.1":
        print(f"[https-server]   https://{lan_ip}:{PORT}/   (LAN)")
    print("[https-server] press Ctrl-C to stop")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[https-server] stopped")


if __name__ == "__main__":
    main()
