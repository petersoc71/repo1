#!/usr/bin/env python3
"""
MAC Address Validator
Validates, classifies, and looks up the vendor for a hardware / MAC address.

Overview of modules used
-------------------------
re           – validates MAC address format via regex
json         – decodes JSON responses from the OUI lookup API
urllib       – keyless OUI vendor lookup via maclookup.app
urllib.parse – encodes the vendor name into a search URL
"""

import re
import sys
import csv
import argparse
import json
import urllib.request
import urllib.error
import urllib.parse


# ─────────────────────────────────────────────────────────────────────────────
# COLOUR HELPERS
# Only applied when stdout is an interactive terminal; suppressed when piped.
# ─────────────────────────────────────────────────────────────────────────────

def _c(text, code):
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def _red(t):    return _c(t, "31")
def _yellow(t): return _c(t, "33")
def _green(t):  return _c(t, "32")
def _bold(t):   return _c(t, "1")


# ─────────────────────────────────────────────────────────────────────────────
# WELL-KNOWN VIRTUAL / SPECIAL OUI PREFIXES
# Maps the first three octets (upper-case, colon-separated) to a description.
# Checked before the live API call so virtual MACs are flagged even offline.
# ─────────────────────────────────────────────────────────────────────────────

_VIRTUAL_OUIS = {
    "00:50:56": "VMware (vSphere/ESXi assigned)",
    "00:0C:29": "VMware (auto-generated for VMs)",
    "00:05:69": "VMware (legacy)",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1C:42": "Parallels Desktop",
    "52:54:00": "QEMU / KVM (libvirt)",
    "54:52:00": "QEMU / KVM (alternative)",
    "00:16:3E": "Xen Hypervisor",
    "02:42:00": "Docker (container bridge)",  # Docker uses 02:42:xx:xx:xx:xx
}

# Well-known multicast OUI prefixes and their meaning.
_MULTICAST_OUIS = {
    "01:00:5E": "IPv4 multicast (RFC 1112)",
    "33:33:00": "IPv6 multicast (RFC 2464)",
    "01:80:C2": "IEEE 802.1D Spanning Tree / LACP",
    "01:00:0C": "Cisco proprietary multicast (CDP/VTP)",
    "FF:FF:FF": "Broadcast",
}


# ─────────────────────────────────────────────────────────────────────────────
# MAC ADDRESS NORMALISATION & VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def normalise_mac(raw):
    """
    Accept any common MAC address format and return a canonical
    upper-case colon-separated string (e.g. "00:50:56:C0:00:08").

    Accepted formats:
        00:50:56:C0:00:08   (colon-separated, zero-padded)
        1:0:5e:0:0:fb       (colon-separated, abbreviated octets — zero-padded automatically)
        00-50-56-C0-00-08   (hyphen-separated, zero-padded)
        1-0-5e-0-0-fb       (hyphen-separated, abbreviated octets — zero-padded automatically)
        0050.56C0.0008      (Cisco dot-notation)
        005056C00008        (plain hex, no separator)

    Returns (normalised_str, error_message).  error_message is None on success.
    """
    # Strip whitespace and convert to upper case.
    s = raw.strip().upper()

    # If the input uses colon or hyphen separators, split into tokens and
    # zero-pad each one to two digits before rejoining.  This handles
    # abbreviated forms like "1:0:5e:0:0:fb" alongside the standard
    # "01:00:5E:00:00:FB".  Dot-notation and bare hex are already
    # fixed-width so they don't need this treatment.
    sep = None
    if ":" in s:
        sep = ":"
    elif "-" in s:
        sep = "-"

    if sep:
        tokens = s.split(sep)
        if len(tokens) == 6 and all(re.fullmatch(r"[0-9A-F]{1,2}", t) for t in tokens):
            s = "".join(t.zfill(2) for t in tokens)
        else:
            # Wrong number of octets or non-hex characters — fall through to
            # the length check below which will produce the correct error.
            s = s.replace(sep, "")
    else:
        # Dot-notation or bare hex: just strip remaining separators.
        s = s.replace(".", "")

    if not re.fullmatch(r"[0-9A-F]{12}", s):
        return None, f"'{raw}' is not a valid MAC address"

    # Re-insert colons every two characters.
    octets = [s[i:i+2] for i in range(0, 12, 2)]
    return ":".join(octets), None


# ─────────────────────────────────────────────────────────────────────────────
# BIT-LEVEL CLASSIFICATION
# Determined entirely from the first octet — no network call required.
# ─────────────────────────────────────────────────────────────────────────────

def classify_mac(mac):
    """
    Classify a normalised MAC address by inspecting flag bits in the first
    octet and matching against well-known OUI prefixes.

    Bit definitions (first / most-significant octet):
        Bit 0 (LSB) = 1  →  Multicast address
        Bit 1       = 1  →  Locally Administered Address (LAA)
        Both bits   = 0  →  Globally Unique Address (UAA) — vendor-assigned

    Returns a dict with classification detail.
    """
    # Special cases first.
    if mac == "00:00:00:00:00:00":
        return {
            "address_type":   "Unspecified",
            "scope":          "N/A",
            "is_multicast":   False,
            "is_local":       False,
            "is_virtual":     False,
            "is_broadcast":   False,
            "virtual_hint":   None,
            "multicast_hint": None,
            "note": "All-zeros MAC - not a real address",
        }
    if mac == "FF:FF:FF:FF:FF:FF":
        return {
            "address_type":   "Broadcast",
            "scope":          "Link-local",
            "is_multicast":   True,
            "is_local":       False,
            "is_virtual":     False,
            "is_broadcast":   True,
            "virtual_hint":   None,
            "multicast_hint": "Broadcast - sent to all devices on the segment",
            "note": "Layer-2 broadcast address",
        }

    first_octet = int(mac.split(":")[0], 16)
    is_multicast = bool(first_octet & 0x01)
    is_local     = bool(first_octet & 0x02)   # Locally Administered

    oui3 = ":".join(mac.split(":")[:3])

    # Check well-known multicast OUIs.
    multicast_hint = None
    if is_multicast:
        for prefix, desc in _MULTICAST_OUIS.items():
            if mac.upper().startswith(prefix):
                multicast_hint = desc
                break
        if not multicast_hint:
            multicast_hint = "Unknown multicast group"

    # Check well-known virtual OUIs.
    # Docker uses the LAA flag AND starts with 02:42 — match on first five chars.
    virtual_hint = None
    is_virtual = False
    docker_prefix = ":".join(mac.split(":")[:2])   # first two octets
    if docker_prefix == "02:42":
        virtual_hint = _VIRTUAL_OUIS.get("02:42:00", "Docker (container bridge)")
        is_virtual = True
    elif oui3 in _VIRTUAL_OUIS:
        virtual_hint = _VIRTUAL_OUIS[oui3]
        is_virtual = True
    elif is_local and not is_multicast:
        # LAA but not a known VM prefix — likely OS-randomised (e.g. iOS/Android privacy MACs).
        virtual_hint = "Locally administered - possibly OS-randomised (privacy MAC)"
        is_virtual = True

    # Determine the human-readable address type.
    if is_multicast and is_local:
        address_type = "Multicast (Locally Administered)"
    elif is_multicast:
        address_type = "Multicast"
    elif is_local:
        address_type = "Locally Administered (LAA)"
    else:
        address_type = "Globally Unique (UAA)"

    scope = "Link-local" if is_multicast else "Global"

    return {
        "address_type":   address_type,
        "scope":          scope,
        "is_multicast":   is_multicast,
        "is_local":       is_local,
        "is_virtual":     is_virtual,
        "is_broadcast":   False,
        "virtual_hint":   virtual_hint,
        "multicast_hint": multicast_hint,
        "note":           None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# OUI VENDOR LOOKUP
# Uses the keyless maclookup.app API — returns JSON with company name,
# registered address, country, and block range.  No API key required.
# Falls back to None on any error so the rest of the output is unaffected.
#
# API reference: https://maclookup.app/api-v2/documentation
# ─────────────────────────────────────────────────────────────────────────────

def lookup_vendor(mac):
    """
    Look up the registered vendor for a MAC address via maclookup.app.

    Args:
        mac: normalised MAC string e.g. "00:50:56:C0:00:08"

    Returns:
        dict with keys:
            company   (str)  – registered company name
            address   (str)  – registered street address
            country   (str)  – two-letter country code
            website   (str)  – constructed search URL for the company
            is_rand   (bool) – True if flagged as a random/private OUI
            is_private(bool) – True if marked as a private block
        or None if no record exists or the call fails.
    """
    try:
        req = urllib.request.Request(
            f"https://api.maclookup.app/v2/macs/{mac}",
            headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            d = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return None

    if not d.get("success") or not d.get("found"):
        return None

    company = d.get("company", "").strip()
    if not company:
        return None

    # Build a DuckDuckGo search URL for the company name — the closest we
    # can get to a "vendor website" without a separate lookup.
    search_url = "https://duckduckgo.com/?q=" + urllib.parse.quote_plus(company)

    return {
        "company":    company,
        "address":    d.get("address", "").strip(),
        "country":    d.get("country", "").strip(),
        "website":    search_url,
        "is_rand":    d.get("isRand", False),
        "is_private": d.get("isPrivate", False),
    }


# ─────────────────────────────────────────────────────────────────────────────
# TABLE RENDERER
# ─────────────────────────────────────────────────────────────────────────────

def print_mac_table(mac, classification, vendor):
    """
    Print a formatted two-column table summarising the MAC address analysis.
    """
    COL1  = 22
    COL2  = 50
    TOTAL = COL1 + COL2 + 1   # 1 = centre separator only; outer borders added separately

    inner1 = COL1 - 2
    inner2 = COL2 - 2

    def _wrap(text, width):
        words, lines, current = str(text).split(), [], ""
        for word in words:
            if current and len(current) + 1 + len(word) > width:
                lines.append(current)
                current = word
            else:
                current = (current + " " + word).strip()
        if current:
            lines.append(current)
        return lines or [""]

    def row(label, value):
        label_str   = str(label)[:inner1].ljust(inner1)
        value_str   = str(value)
        value_lines = _wrap(value_str, inner2)
        print(f"│ {label_str} │ {value_lines[0]}")
        for extra in value_lines[1:]:
            print(f"│ {''.ljust(inner1)} │ {extra}")

    def section(title):
        inner = COL1 + COL2 - 1
        print(f"├─{'─'*(COL1-2)}─┴─{'─'*(COL2-2)}─")
        print(f"│ {title}")
        print(f"├─{'─'*(COL1-2)}─┬─{'─'*(COL2-2)}─")

    def divider():
        print(f"├─{'─'*(COL1-2)}─┬─{'─'*(COL2-2)}─")

    # ── top border ────────────────────────────────────────────────────────
    title = f"  MAC Address Report: {mac}"
    print(f"┌─{'─'*(TOTAL-2)}─")
    print(f"│{title}")
    print(f"├─{'─'*(COL1-2)}─┬─{'─'*(COL2-2)}─")

    # ── address type & scope ──────────────────────────────────────────────
    row("Address Type",  classification["address_type"])
    row("Scope",         classification["scope"])
    row("Multicast",     "Yes" if classification["is_multicast"] else "No")
    row("Locally Admin", "Yes" if classification["is_local"]     else "No")
    row("Broadcast",     "Yes" if classification["is_broadcast"] else "No")

    # ── virtual / randomised hint ──────────────────────────────────────────
    if classification["virtual_hint"]:
        divider()
        # Colour-code: virtual/random addresses get yellow, broadcast gets red.
        hint = classification["virtual_hint"]
        if classification["is_broadcast"]:
            hint = _red(hint)
        else:
            hint = _yellow(hint)
        row("Virtual / LAA",  hint)

    if classification["multicast_hint"]:
        divider()
        row("Multicast Group", classification["multicast_hint"])

    if classification["note"]:
        divider()
        row("Note", classification["note"])

    # ── vendor lookup ──────────────────────────────────────────────────────
    section("Vendor / Manufacturer")
    oui = ":".join(mac.split(":")[:3])
    row("Manufacturer Prefix", oui)
    if vendor:
        row("Company",          _green(vendor["company"]))
        if vendor["address"]:
            row("Registered Address", vendor["address"])
        if vendor["country"]:
            row("Country",      vendor["country"])
        row("Search / Website", vendor["website"])
        if classification["is_virtual"] and not classification["is_local"]:
            row("Hardware Type", _yellow("Virtual - known hypervisor manufacturer"))
        elif classification["is_virtual"]:
            row("Hardware Type", _yellow("Virtual or software-assigned (randomised)"))
        else:
            row("Hardware Type", _green("Physical - vendor-assigned hardware address"))
    else:
        if classification["is_local"]:
            row("Company",       "Not registered (locally administered address)")
            row("Hardware Type", _yellow("Virtual or software-assigned (LAA bit set)"))
        elif classification["is_virtual"]:
            row("Company",       "Not in public registry")
            row("Hardware Type", _yellow("Virtual - matches known hypervisor prefix"))
        else:
            row("Company",       "Not found in public OUI registry")
            row("Hardware Type", "Unknown - may be a private or custom NIC")

    # ── bottom border ──────────────────────────────────────────────────────
    print(f"└─{'─'*(TOTAL-2)}─")


# ─────────────────────────────────────────────────────────────────────────────
# BATCH / CSV MODE
# ─────────────────────────────────────────────────────────────────────────────

# Ordered column definitions used by write_csv_report().
# Each tuple is (csv_header, callable(mac, classification, vendor) -> value).
_CSV_COLUMNS = [
    ("Input",              lambda m, c, v: m),
    ("Valid",              lambda m, c, v: True),
    ("Address Type",       lambda m, c, v: c["address_type"]),
    ("Scope",              lambda m, c, v: c["scope"]),
    ("Multicast",          lambda m, c, v: c["is_multicast"]),
    ("Locally Admin",      lambda m, c, v: c["is_local"]),
    ("Broadcast",          lambda m, c, v: c["is_broadcast"]),
    ("Virtual / LAA",      lambda m, c, v: c["virtual_hint"] or ""),
    ("Multicast Group",    lambda m, c, v: c["multicast_hint"] or ""),
    ("Note",               lambda m, c, v: c["note"] or ""),
    ("Manufacturer Prefix",lambda m, c, v: ":".join(m.split(":")[:3])),
    ("Company",            lambda m, c, v: (v["company"] if v else "")),
    ("Registered Address", lambda m, c, v: (v["address"] if v else "")),
    ("Country",            lambda m, c, v: (v["country"] if v else "")),
    ("Search / Website",   lambda m, c, v: (v["website"] if v else "")),
]

# Sentinel row used when normalise_mac() rejects the input.
# Built as a plain dict to allow mixed str/bool values (same as valid rows).
_INVALID_ROW: dict = {h: "" for h, _ in _CSV_COLUMNS}
_INVALID_ROW["Valid"] = False


def write_csv_report(rows, output_path):
    """
    Write a list of pre-built row dicts to a CSV file.

    Args:
        rows        – list of dicts keyed by the headers in _CSV_COLUMNS
        output_path – destination file path
    """
    headers = [col[0] for col in _CSV_COLUMNS]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def batch_mode(mac_sources, output_path):
    """
    Process a list of MAC address strings and write results to a CSV file.

    Args:
        mac_sources – list of raw strings (may be comma-separated or one-per-item)
        output_path – destination .csv path
    """
    # Normalise: split on commas, strip whitespace, skip blanks.
    raw_tokens = []
    for item in mac_sources:
        raw_tokens.extend(item.split(","))
    macs_raw = [t.strip() for t in raw_tokens if t.strip()]

    if not macs_raw:
        print("Error: no MAC addresses supplied.", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {len(macs_raw)} address(es)…")
    rows = []
    for raw in macs_raw:
        print(f"  {raw}", end="  ", flush=True)
        mac, error = normalise_mac(raw)
        if error:
            print("✗ (invalid)")
            row = dict(_INVALID_ROW)
            row["Input"] = raw
            rows.append(row)
            continue

        classification = classify_mac(mac)
        vendor = None
        if not classification["is_broadcast"] and mac != "00:00:00:00:00:00":
            vendor = lookup_vendor(mac)

        row = {header: extractor(mac, classification, vendor)
               for header, extractor in _CSV_COLUMNS}
        rows.append(row)
        print("✓")

    write_csv_report(rows, output_path)
    print(f"\nReport written to: {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """
    MAC Address Validator — interactive mode or batch CSV mode.

    Batch mode (--macs or --file):
        mac_validator.py --macs "00:50:56:C0:00:08, 00-15-5D-01-02-03" --output report.csv
        mac_validator.py --file macs.txt --output report.csv

    Interactive mode (no arguments):
        mac_validator.py
    """
    parser = argparse.ArgumentParser(
        prog="mac_validator",
        description="MAC Address Validator — interactive or batch CSV mode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Interactive mode (no arguments)\n"
            "  mac_validator.py\n"
            "\n"
            "  # Comma-separated list inline\n"
            "  mac_validator.py --macs \"00:50:56:C0:00:08, 00-15-5D-01-02-03\"\n"
            "\n"
            "  # One MAC per line in a text file\n"
            "  mac_validator.py --file macs.txt\n"
            "\n"
            "  # Custom output path (default: mac_report.csv)\n"
            "  mac_validator.py --macs \"52:54:00:12:34:56\" --output /tmp/results.csv\n"
            "\n"
            "  # Combine inline list and file into one report\n"
            "  mac_validator.py --macs \"FF:FF:FF:FF:FF:FF\" --file extra_macs.txt --output combined.csv\n"
            "\n"
            "Accepted MAC formats:\n"
            "  00:50:56:C0:00:08   (colon-separated)\n"
            "  00-50-56-C0-00-08   (hyphen-separated)\n"
            "  0050.56C0.0008      (Cisco dot-notation)\n"
            "  005056C00008        (plain hex, no separator)\n"
        ),
        add_help=True,
    )
    parser.add_argument(
        "--macs",
        metavar="MAC_LIST",
        help="Comma-separated list of MAC addresses to validate.",
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="Path to a text file containing one MAC address per line "
             "(or comma-separated on any line).",
    )
    parser.add_argument(
        "--output",
        metavar="CSV_PATH",
        default="mac_report.csv",
        help="Output CSV file path (default: mac_report.csv).",
    )
    args = parser.parse_args()

    # ── Batch mode ────────────────────────────────────────────────────────
    if args.macs or args.file:
        mac_sources = []
        if args.macs:
            mac_sources.append(args.macs)
        if args.file:
            try:
                with open(args.file, encoding="utf-8") as fh:
                    mac_sources.extend(fh.read().splitlines())
            except OSError as exc:
                print(f"Error reading file: {exc}", file=sys.stderr)
                sys.exit(1)
        batch_mode(mac_sources, args.output)
        return

    # ── Interactive mode ──────────────────────────────────────────────────
    print("=" * 76)
    print("  MAC ADDRESS VALIDATOR")
    print("=" * 76)

    try:
        import readline
        readline.clear_history()
    except ImportError:
        pass

    print("\nInteractive Mode (type 'quit' to exit)")
    print("Enter a MAC address in any common format:")
    print("  00:50:56:C0:00:08  |  00-50-56-C0-00-08  |  0050.56C0.0008  |  005056C00008")
    print("You can also run this application in batch mode. use mac_validator.py --help for details")
    print("-" * 76)

    while True:
        user_input = input("\nEnter MAC address: ").strip()

        if user_input.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break

        if not user_input:
            continue

        mac, error = normalise_mac(user_input)
        if error:
            print(f"  {_red('✗')}  {error}")
            continue

        classification = classify_mac(mac)

        # Only call the vendor API for non-broadcast, non-unspecified addresses.
        vendor = None
        if not classification["is_broadcast"] and mac != "00:00:00:00:00:00":
            print("  Looking up OUI vendor…", end="\r")
            vendor = lookup_vendor(mac)
            print(" " * 30, end="\r")   # clear the status line

        print()
        print_mac_table(mac, classification, vendor)


if __name__ == "__main__":
    main()
