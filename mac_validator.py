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
        00:50:56:C0:00:08   (colon-separated)
        00-50-56-C0-00-08   (hyphen-separated)
        0050.56C0.0008      (Cisco dot-notation)
        005056C00008        (plain hex, no separator)

    Returns (normalised_str, error_message).  error_message is None on success.
    """
    # Strip whitespace and convert to upper case.
    s = raw.strip().upper()

    # Remove separators to get a raw 12-hex-digit string.
    s = s.replace(":", "").replace("-", "").replace(".", "")

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
            "note": "All-zeros MAC — not a real address",
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
            "multicast_hint": "Broadcast — sent to all devices on the segment",
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
        virtual_hint = "Locally administered — possibly OS-randomised (privacy MAC)"
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
        # Word-wrap long values; for unbreakable strings (e.g. URLs) truncate
        # hard at inner2 so the right border never overflows.
        value_lines = _wrap(value_str, inner2)
        value_lines = [ln[:inner2] for ln in value_lines]
        print(f"│ {label_str} │ {value_lines[0].ljust(inner2)} │")
        for extra in value_lines[1:]:
            print(f"│ {''.ljust(inner1)} │ {extra.ljust(inner2)} │")

    def section(title):
        inner = COL1 + COL2 - 1   # usable chars between '│ ' and ' │'
        print(f"├─{'─'*(COL1-2)}─┴─{'─'*(COL2-2)}─┤")
        print(f"│ {title.ljust(inner)} │")
        print(f"├─{'─'*(COL1-2)}─┬─{'─'*(COL2-2)}─┤")

    def divider():
        print(f"├─{'─'*(COL1-2)}─┬─{'─'*(COL2-2)}─┤")

    # ── top border ────────────────────────────────────────────────────────
    title = f"  MAC Address Report: {mac}"
    print(f"┌─{'─'*(TOTAL-2)}─┐")
    print(f"│{title:<{TOTAL}}│")
    print(f"├─{'─'*(COL1-2)}─┬─{'─'*(COL2-2)}─┤")

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
            row("Hardware Type", _yellow("Virtual — known hypervisor manufacturer"))
        elif classification["is_virtual"]:
            row("Hardware Type", _yellow("Virtual or software-assigned (randomised)"))
        else:
            row("Hardware Type", _green("Physical — vendor-assigned hardware address"))
    else:
        if classification["is_local"]:
            row("Company",       "Not registered (locally administered address)")
            row("Hardware Type", _yellow("Virtual or software-assigned (LAA bit set)"))
        elif classification["is_virtual"]:
            row("Company",       "Not in public registry")
            row("Hardware Type", _yellow("Virtual — matches known hypervisor prefix"))
        else:
            row("Company",       "Not found in public OUI registry")
            row("Hardware Type", "Unknown — may be a private or custom NIC")

    # ── bottom border ──────────────────────────────────────────────────────
    print(f"└─{'─'*(TOTAL-2)}─┘")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
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
