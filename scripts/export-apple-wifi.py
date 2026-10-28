#!/usr/bin/env python3
"""Export the Wi-Fi networks this Mac knows, with their passwords, for OnePass's Wi-Fi import.

Run it yourself in Terminal, with administrator rights (the passwords live in the System keychain):

    sudo /usr/bin/python3 scripts/export-apple-wifi.py ~/Desktop/wifi-onepass.txt
    sudo /usr/bin/python3 scripts/export-apple-wifi.py ~/Desktop/wifi-onepass.txt "Home" "Office"

macOS asks once per network for an administrator password (System keychain): name only the
networks you want to keep it short.

It writes one `WIFI:S:<ssid>;T:<WPA|WEP|nopass>;P:<password>;H:true;;` line per network (the
Wi-Fi QR code format OnePass imports), readable by you only (0600). Import the file in OnePass
(Réglages, Importer), then delete it: `rm -P ~/Desktop/wifi-onepass.txt`.

Nothing leaves the Mac: the script reads the system's list of known networks and asks the
System keychain for each password, nothing else.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys

KNOWN = "/Library/Preferences/com.apple.wifi.known-networks.plist"
KEYCHAIN = "/Library/Keychains/System.keychain"


def escape(value: str) -> str:
    """Wi-Fi QR escaping: backslash before \\ ; , : and "."""
    for ch in '\\;,:"':
        value = value.replace(ch, "\\" + ch)
    return value


def security_type(entry: dict) -> str:
    """"WPA2 Personal", "WPA3 Personal", "WEP", "Open"... as the system stores it."""
    upper = str(entry.get("SupportedSecurityTypes", "")).upper()
    if "WEP" in upper:
        return "WEP"
    if "OPEN" in upper or upper.strip() in ("", "NONE"):
        return "nopass"
    return "WPA"


def password(ssid: str) -> str | None:
    # macOS shows one "security wants to use the System keychain" dialog per network: approve it
    # with an administrator password ("Always Allow"). Two minutes per dialog, then the network is skipped.
    try:
        out = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-D", "AirPort network password", "-a", ssid, "-w", KEYCHAIN],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return None
    return out.stdout.rstrip("\n") if out.returncode == 0 and out.stdout else None


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    if os.geteuid() != 0:
        print("Lance le script avec sudo : les mots de passe Wi-Fi sont dans le trousseau Système.", file=sys.stderr)
        return 1
    target = os.path.expanduser(sys.argv[1])
    if os.environ.get("SUDO_USER") and sys.argv[1].startswith("~"):
        target = os.path.join(os.path.expanduser(f"~{os.environ['SUDO_USER']}"), sys.argv[1][2:])
    try:
        with open(KNOWN, "rb") as f:
            known = plistlib.load(f)
    except PermissionError:
        # macOS protects this file even from root unless Terminal has Full Disk Access: fall back
        # to the preferred networks list (names only; security type guessed from the password).
        known = {}
        for iface in ("en0", "en1"):
            out = subprocess.run(["/usr/sbin/networksetup", "-listpreferredwirelessnetworks", iface], capture_output=True, text=True)
            if out.returncode == 0 and "Preferred networks" in out.stdout:
                for name in out.stdout.splitlines()[1:]:
                    name = name.strip()
                    if name:
                        known[f"wifi.network.ssid.{name}"] = {"SupportedSecurityTypes": "WPA2 Personal", "Guessed": True}
                break

    only = set(sys.argv[2:])  # optional: the network names to export, all of them when empty
    lines, missing = [], []
    entries = sorted(known.items())
    for n, (key, entry) in enumerate(entries, 1):
        raw = entry.get("SSID")
        ssid = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else key.removeprefix("wifi.network.ssid.")
        if only and ssid not in only:
            continue
        print(f"({n}/{len(entries)}) {ssid}", flush=True)
        kind = security_type(entry)
        pw = password(ssid) if kind != "nopass" else None
        if pw is None and entry.get("Guessed"):
            kind = "nopass"  # no password in the keychain: an open network
        if kind != "nopass" and pw is None:
            missing.append(ssid)
            continue
        line = f"WIFI:S:{escape(ssid)};T:{kind};"
        if pw is not None:
            line += f"P:{escape(pw)};"
        if entry.get("Hidden"):
            line += "H:true;"
        lines.append(line + ";")

    old_umask = os.umask(0o077)
    try:
        with open(target, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    finally:
        os.umask(old_umask)
    os.chmod(target, 0o600)
    user = os.environ.get("SUDO_USER")
    if user:
        import pwd

        info = pwd.getpwnam(user)
        os.chown(target, info.pw_uid, info.pw_gid)

    print(f"{len(lines)} réseau(x) écrit(s) dans {target}")
    if missing:
        print(f"{len(missing)} réseau(x) sans mot de passe lisible, ignoré(s) : {', '.join(missing)}")
    print("Importe le fichier dans OnePass, puis supprime-le : rm -P " + target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
