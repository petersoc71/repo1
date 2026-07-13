#!/usr/bin/env python3
"""
IP Address Validator
Validates both IPv4 and IPv6 addresses

Overview of modules used
-------------------------
re           – regular-expression engine; used for the regex-based IPv4 validator
ipaddress    – stdlib module that parses, validates, and classifies IP addresses
               and networks for both IPv4 and IPv6
json         – decodes JSON responses returned by the external REST APIs
os           – reads API keys from the environment
base64       – encodes the X-Force Basic Auth credential header
socket       – provides gethostbyaddr() for reverse DNS (PTR record) lookups
urllib       – stdlib HTTP client used to call RDAP and threat-intel APIs
               without requiring any third-party packages
dotenv       – loads .env file credentials into os.environ at startup
"""

import re
import ipaddress
import json
import os
import base64
import socket
import urllib.request
import urllib.error

# Load .env file if present (silently ignored when the file does not exist).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass   # python-dotenv not installed — fall back to pure environment variables


# ─────────────────────────────────────────────────────────────────────────────
# COLOUR HELPERS
# Wrap text in ANSI escape codes only when stdout is an interactive terminal.
# When output is piped or redirected the raw text is returned unchanged so
# downstream tools are not polluted with escape sequences.
# ─────────────────────────────────────────────────────────────────────────────

import sys as _sys

def _c(text, code):
    """Return text wrapped in ANSI colour `code`, or plain text if not a tty."""
    if _sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def _red(text):    return _c(text, "31")
def _yellow(text): return _c(text, "33")
def _green(text):  return _c(text, "32")


# ─────────────────────────────────────────────────────────────────────────────
# BASIC VALIDATION HELPERS
# These three functions provide low-level building blocks used by the higher-
# level parse_network_input() and get_ip_info() functions further below.
# ─────────────────────────────────────────────────────────────────────────────

def validate_ip_basic(ip_string):
    """
    Validate IP address using Python's ipaddress module (recommended method)
    
    Args:
        ip_string (str): IP address to validate
        
    Returns:
        tuple: (is_valid, ip_type, ip_object)
    """
    # ipaddress.ip_address() raises ValueError for any string that is not a
    # well-formed IPv4 or IPv6 address, so we catch that and return False.
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return (True, "IPv4", ip_obj)
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return (True, "IPv6", ip_obj)
    except ValueError:
        return (False, None, None)


def get_default_prefix(ip_obj):
    """
    Return the default host prefix when no CIDR is provided.
    IPv4 defaults to /32 and IPv6 defaults to /128.

    A /32 (IPv4) or /128 (IPv6) represents a single host — i.e., no subnet at
    all.  This is used when the user types a bare address like "8.8.8.8"
    instead of "8.8.8.8/24".
    """
    return 32 if isinstance(ip_obj, ipaddress.IPv4Address) else 128


def get_ipv4_class(ip_obj):
    """
    Return the classful IPv4 subnet class based on the first octet.

    Classful addressing is a legacy concept (superseded by CIDR in 1993) but
    is still commonly referenced.  The class is determined entirely by the
    value of the first octet:
        1–126   → Class A  (large networks, /8 default mask)
        127     → Class A Loopback
        128–191 → Class B  (medium networks, /16 default mask)
        192–223 → Class C  (small networks, /24 default mask)
        224–239 → Class D  (multicast, not assigned to hosts)
        240–255 → Class E  (experimental/reserved)
    """
    first_octet = int(str(ip_obj).split('.')[0])

    if 1 <= first_octet <= 126:
        return "Class A"
    if first_octet == 127:
        return "Class A (Loopback)"
    if 128 <= first_octet <= 191:
        return "Class B"
    if 192 <= first_octet <= 223:
        return "Class C"
    if 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    return "Class E (Experimental)"


# ─────────────────────────────────────────────────────────────────────────────
# INPUT PARSING
# Accepts a bare address ("1.2.3.4") or a CIDR-notated network ("1.2.3.4/24").
# Returns both the host address object and the network object so callers can
# derive subnet mask, network address, broadcast, and host range from one call.
# ─────────────────────────────────────────────────────────────────────────────

def parse_network_input(ip_string):
    """
    Parse an IP address with optional CIDR notation.
    
    If no CIDR is provided, default to /32 for IPv4 and /128 for IPv6.
    
    Returns:
        tuple: (is_valid, ip_type, ip_obj, network_obj)
    """
    candidate = ip_string.strip()

    try:
        if '/' in candidate:
            # CIDR notation supplied — parse the network (strict=False allows
            # host bits to be set, e.g. "192.168.1.5/24" is accepted).
            network_obj = ipaddress.ip_network(candidate, strict=False)
            # Also parse just the host address portion (left of the slash) so
            # we can inspect its individual flags (is_private, is_loopback…).
            ip_obj = ipaddress.ip_address(candidate.split('/')[0])
        else:
            # No CIDR — treat as a single host and synthesise a /32 or /128.
            ip_obj = ipaddress.ip_address(candidate)
            network_obj = ipaddress.ip_network(
                f"{ip_obj}/{get_default_prefix(ip_obj)}",
                strict=False
            )

        ip_type = "IPv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "IPv6"
        return (True, ip_type, ip_obj, network_obj)
    except ValueError:
        return (False, None, None, None)


# ─────────────────────────────────────────────────────────────────────────────
# ALTERNATIVE VALIDATORS (IPv4 only)
# These two functions demonstrate different techniques for validating an IPv4
# address string.  They are not called by the main pipeline (which uses
# parse_network_input instead) but are kept here as reference implementations.
# ─────────────────────────────────────────────────────────────────────────────

def validate_ipv4_regex(ip_string):
    """
    Validate IPv4 address using regex pattern
    
    Args:
        ip_string (str): IP address to validate
        
    Returns:
        bool: True if valid IPv4, False otherwise
    """
    # The pattern matches exactly four dot-separated octets, each in 0–255.
    # It uses three alternations per octet to cover the full range precisely:
    #   25[0-5]        → 250–255
    #   2[0-4][0-9]    → 200–249
    #   [01]?[0-9][0-9]? → 0–199 (with optional leading digit)
    # Pattern for IPv4: 0-255.0-255.0-255.0-255
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip_string))


def validate_ipv4_manual(ip_string):
    """
    Validate IPv4 address manually without regex
    
    Args:
        ip_string (str): IP address to validate
        
    Returns:
        bool: True if valid IPv4, False otherwise
    """
    parts = ip_string.split('.')
    
    # Must have exactly 4 parts
    if len(parts) != 4:
        return False
    
    # Each part must be a number between 0 and 255
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
            # Check for leading zeros (e.g., "192.168.01.1" is invalid)
            # Python's int() would silently strip them, so we check the raw string.
            if len(part) > 1 and part[0] == '0':
                return False
        except ValueError:
            return False
    
    return True


# ─────────────────────────────────────────────────────────────────────────────
# IPV4 → IPV6 CONVERSION HELPERS
# These produce the two most common ways an IPv4 address appears in IPv6
# contexts.  Both are informational only — not used for routing decisions.
# ─────────────────────────────────────────────────────────────────────────────

def ipv4_to_ipv6_mapped(ipv4_obj):
    """
    Convert an IPv4 address to its IPv6-mapped equivalent.
    IPv4-mapped IPv6 addresses use the format ::ffff:x.x.x.x
    
    Args:
        ipv4_obj: IPv4Address object
        
    Returns:
        str: IPv6-mapped address

    IPv4-mapped addresses (::ffff:0:0/96) are used by dual-stack systems to
    represent an IPv4 address in an IPv6 socket API, e.g. when a server
    listening on an IPv6 socket receives a connection from an IPv4 client.
    """
    # Prepend the well-known ::ffff: prefix and let the ipaddress module
    # normalise the result into compact colon-hex notation.
    # Convert IPv4 to IPv6-mapped format (::ffff:x.x.x.x)
    ipv6_mapped = ipaddress.IPv6Address('::ffff:' + str(ipv4_obj))
    return str(ipv6_mapped)


def ipv4_to_ipv6_6to4(ipv4_obj):
    """
    Convert an IPv4 address to 6to4 IPv6 address format.
    6to4 uses the format 2002:xxxx:xxxx::/48 where xxxx:xxxx is the hex of the IPv4.
    
    Args:
        ipv4_obj: IPv4Address object
        
    Returns:
        str: 6to4 IPv6 address

    6to4 (RFC 3056) was a transition mechanism that let IPv6 traffic travel
    over an IPv4 network without explicit tunnels.  The IPv4 address is encoded
    directly in the IPv6 prefix, making the mapping deterministic.
    """
    # Split the IPv4 address into its four integer octets, convert each to a
    # two-digit hex string, then pair them as the two 16-bit groups required by
    # the 2002::/16 prefix.
    # Convert IPv4 octets to hex
    octets = [int(x) for x in str(ipv4_obj).split('.')]
    hex_addr = ''.join(f'{octet:02x}' for octet in octets)
    # Format as 2002:xxxx:xxxx::
    ipv6_6to4 = f"2002:{hex_addr[:4]}:{hex_addr[4:]}::"
    return ipv6_6to4


# ─────────────────────────────────────────────────────────────────────────────
# REVERSE DNS LOOKUP
# Queries the system's DNS resolver for a PTR record associated with the IP.
# Works for any valid address — loopback, private, and public alike.
# No external service or API key is needed; the OS resolver is used directly.
# ─────────────────────────────────────────────────────────────────────────────

def reverse_dns_lookup(ip_obj):
    """
    Perform a reverse DNS (PTR record) lookup for an IP address.

    Uses socket.gethostbyaddr(), which queries the system resolver — the same
    DNS infrastructure used by dig/nslookup.  Works for both IPv4 and IPv6.

    Args:
        ip_obj: IPv4Address or IPv6Address object

    Returns:
        list[str]: One or more hostnames associated with the address, or an
        empty list if no PTR record exists or the lookup times out.
    """
    try:
        hostname, aliases, _ = socket.gethostbyaddr(str(ip_obj))
        # Deduplicate while preserving order; primary hostname first.
        # Filter out raw arpa PTR names (e.g. "8.8.8.8.in-addr.arpa") — callers
        # want human-readable FQDNs, not the PTR query form itself.
        seen = set()
        results = []
        for name in [hostname] + aliases:
            if name not in seen and not name.endswith(".arpa"):
                seen.add(name)
                results.append(name)
        return results
    except (socket.herror, socket.gaierror, OSError):
        # herror  → host not found / no PTR record
        # gaierror → network unreachable or resolver error
        # OSError  → catch-all for unexpected socket failures
        return []


# ─────────────────────────────────────────────────────────────────────────────
# RDAP / REGISTRATION LOOKUP
# RDAP (Registration Data Access Protocol) is the modern, JSON-based successor
# to WHOIS.  It tells us which organisation owns a given IP block and what that
# block's registered CIDR range is.
#
# We use ARIN's bootstrap endpoint because it automatically issues an HTTP
# 3xx redirect to the correct Regional Internet Registry (RIR) for any IP:
#   ARIN   → North America
#   RIPE   → Europe / Middle East / Central Asia
#   APNIC  → Asia-Pacific
#   LACNIC → Latin America
#   AFRINIC → Africa
#
# No API key is required.
# ─────────────────────────────────────────────────────────────────────────────

def lookup_rdap(ip_obj):
    """
    Look up the registered owner of a publicly routable IP address using RDAP
    (Registration Data Access Protocol), the modern JSON-based successor to WHOIS.

    Uses ARIN's bootstrap endpoint (https://rdap.arin.net/registry/ip/<address>)
    which automatically follows 3xx redirects to the correct Regional Internet
    Registry (RIPE, APNIC, LACNIC, AFRINIC) for non-ARIN addresses.
    No API key is required.

    Args:
        ip_obj: IPv4Address or IPv6Address object

    Returns:
        dict with keys 'org', 'network_name', 'cidr_block' on success,
        or None if the lookup fails.
    """
    url = f"https://rdap.arin.net/registry/ip/{ip_obj}"
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/rdap+json"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())

        # The 'name' field is the short network/registry name (e.g. "GOGL")
        network_name = data.get("name", "")

        # Build a CIDR string from the cidr0_cidrs extension when present,
        # otherwise fall back to startAddress/endAddress range.
        # cidr0_cidrs is an ARIN extension that lists the exact CIDR blocks
        # rather than just a start/end address pair — more precise and useful.
        cidrs = data.get("cidr0_cidrs", [])
        if cidrs:
            # IPv6 uses "v6prefix"; IPv4 uses "v4prefix"
            prefix_key = "v6prefix" if isinstance(ip_obj, ipaddress.IPv6Address) else "v4prefix"
            cidr_block = ", ".join(
                f"{c[prefix_key]}/{c['length']}" for c in cidrs if prefix_key in c
            )
        else:
            # Fallback: express the allocation as a start–end range
            start = data.get("startAddress", "")
            end = data.get("endAddress", "")
            cidr_block = f"{start} - {end}" if start else ""

        # Walk the 'entities' list for the registrant organisation name.
        # The RDAP entities array contains contacts with assigned roles.
        # We prefer 'registrant' (the IP block owner) over 'administrative'.
        # Each entity's name lives inside a vCard array under the "fn" property.
        org = ""
        for role_pref in ("registrant", "administrative"):
            for entity in data.get("entities", []):
                if role_pref not in entity.get("roles", []):
                    continue
                vcard = entity.get("vcardArray", [])
                # vcardArray structure: ["vcard", [[prop, params, type, value], ...]]
                if len(vcard) >= 2:
                    for prop in vcard[1]:
                        if prop[0] == "fn":   # "fn" is the formatted name property
                            org = prop[3]
                            break
                if org:
                    break
            if org:
                break

        return {
            "org": org or network_name,   # fall back to short name if no vCard
            "network_name": network_name,
            "cidr_block": cidr_block,
        }
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
        # Any network or parse error is treated as a graceful miss — the caller
        # receives None and simply skips the RDAP section in the output table.
        return None


# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN REGISTRANT LOOKUP
# When a reverse DNS hostname is available, we can look up who owns that domain
# using RDAP for domains.  rdap.org is a public bootstrap resolver maintained
# by the RDAP community that routes to the correct registry (Verisign for .com,
# RIPE for .eu, etc.) — effectively the ICANN-backed replacement for WHOIS.
# No API key required.
# ─────────────────────────────────────────────────────────────────────────────

def lookup_domain_registrant(hostname):
    """
    Look up the registrant (owner) of a domain name using RDAP.

    Strips the hostname down to its registrable domain (e.g. "dns.google.com"
    becomes "google.com") and queries rdap.org, which bootstraps to the correct
    registry for any TLD.

    Args:
        hostname (str): A fully-qualified domain name, e.g. "dns.google.com"

    Returns:
        str: Registrant name, or empty string if not found / lookup failed.
    """
    # Extract the registrable domain (last two labels, e.g. "google.com")
    parts = hostname.rstrip(".").split(".")
    if len(parts) < 2:
        return ""
    domain = ".".join(parts[-2:])

    url = f"https://rdap.org/domain/{domain}"
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/rdap+json"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())

        # Walk entities for a name, preferring registrant/administrative then
        # falling back to registrar (registrant vCards are often blank due to
        # WHOIS privacy protections, but registrar is nearly always populated).
        def _fn_for_roles(roles):
            for role in roles:
                for entity in data.get("entities", []):
                    if role not in entity.get("roles", []):
                        continue
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) >= 2:
                        for prop in vcard[1]:
                            if prop[0] == "fn" and prop[3]:
                                return prop[3]
            return ""

        return (
            _fn_for_roles(("registrant", "administrative"))
            or _fn_for_roles(("registrar",))
        )
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
        pass
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE LOOKUP
# Queries two free, keyless public APIs to surface threat signals for public
# IP addresses.  Results are merged into a single dict so the caller only needs
# to check one place regardless of which services responded.
#
# Sources:
#   1. ip-api.com  — proxy/VPN/hosting flags, ISP, ASN, geo  (IPv4 only)
#   2. StopForumSpam — crowdsourced abuse/spam reports, Tor exit flag
#
# Both services are free with no registration required.  All network errors
# are silently swallowed; the function returns None if both calls fail so the
# caller can safely skip the threat section in the output.
# ─────────────────────────────────────────────────────────────────────────────

def lookup_threat_intel(ip_obj):
    """
    Check a publicly routable IP against two free, keyless threat-intelligence
    services and return a consolidated threat summary.

    Sources
    -------
    1. ip-api.com  (http://ip-api.com/json/<ip>)
       Returns proxy/VPN/hosting/mobile flags, ISP, ASN, and geolocation.
       Free tier; no API key required.  IPv4 only.

    2. StopForumSpam  (https://api.stopforumspam.org/api?ip=<ip>&json)
       Crowdsourced database of IPs seen in forum spam, brute-force attacks,
       and similar abuse.  Returns appearance count, confidence score (0–100),
       and a Tor-exit flag.  No API key required.

    Args:
        ip_obj: IPv4Address or IPv6Address object

    Returns:
        dict with the following keys (all may be None/empty if unavailable):
            is_proxy    (bool)   – flagged as proxy or VPN by ip-api
            is_hosting  (bool)   – flagged as datacenter/hosting by ip-api
            is_tor      (bool)   – confirmed Tor exit node (either source)
            isp         (str)    – ISP name from ip-api
            asn         (str)    – AS number + name from ip-api
            geo         (str)    – "City, Region, Country" from ip-api
            abuse_score (float)  – StopForumSpam confidence score (0–100)
            abuse_freq  (int)    – number of times seen in abuse reports
            abuse_last  (str)    – date last seen in abuse reports
            flags       (list)   – human-readable threat tags e.g. ["Proxy/VPN", "Tor exit"]
        or None if both lookups fail.
    """
    # Initialise the result dict with safe defaults so that partial responses
    # (only one of the two APIs succeeds) still produce a usable output dict.
    result = {
        "is_proxy":    None,
        "is_hosting":  None,
        "is_tor":      False,
        "isp":         "",
        "asn":         "",
        "geo":         "",
        "abuse_score": None,
        "abuse_freq":  None,
        "abuse_last":  "",
        "flags":       [],
    }
    # Track whether at least one API call succeeded so we can return None
    # instead of an empty dict when both sources are unreachable.
    any_success = False

    # ── 1. ip-api.com ── IPv4 only; silently skip for IPv6
    # ip-api.com does not support IPv6 on its free tier, so we guard here
    # to avoid a guaranteed failure for IPv6 addresses.
    if isinstance(ip_obj, ipaddress.IPv4Address):
        # Request only the fields we actually use to keep the response small.
        fields = "status,country,regionName,city,isp,org,as,proxy,hosting,mobile,query"
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{ip_obj}?fields={fields}",
                headers={"Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                d = json.loads(resp.read().decode())
            if d.get("status") == "success":
                any_success = True
                result["is_proxy"]   = d.get("proxy", False)
                result["is_hosting"] = d.get("hosting", False)
                result["isp"]        = d.get("isp", "")
                result["asn"]        = d.get("as", "")
                # Build a single human-readable geo string from the three parts,
                # omitting any that are empty (some IPs have no city/region).
                city    = d.get("city", "")
                region  = d.get("regionName", "")
                country = d.get("country", "")
                result["geo"] = ", ".join(p for p in [city, region, country] if p)
                # Populate the flags list with human-readable labels for any
                # signals that are active on this address.
                if result["is_proxy"]:
                    result["flags"].append("Proxy / VPN")
                if result["is_hosting"]:
                    result["flags"].append("Hosting / datacenter")
                if d.get("mobile"):
                    result["flags"].append("Mobile network")
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            pass   # network error — continue to next source

    # ── 2. StopForumSpam ──
    # StopForumSpam maintains a crowdsourced list of IPs reported for spam,
    # brute-force login attempts, and similar abuse.  It also flags known Tor
    # exit nodes.  The confidence score (0–100) reflects how reliably an IP
    # has been associated with abuse; we only flag it if >= 25 to reduce noise.
    try:
        req = urllib.request.Request(
            f"https://api.stopforumspam.org/api?ip={ip_obj}&json",
            headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            d = json.loads(resp.read().decode())
        ip_data = d.get("ip", {})
        if d.get("success") and ip_data:
            any_success = True
            result["abuse_score"] = ip_data.get("confidence")
            result["abuse_freq"]  = ip_data.get("frequency", 0)
            result["abuse_last"]  = ip_data.get("lastseen", "")
            # torexit=1 in the response means StopForumSpam has independently
            # confirmed this as a Tor exit node (cross-checked against the
            # official Tor exit list).
            if ip_data.get("torexit"):
                result["is_tor"] = True
                if "Tor exit node" not in result["flags"]:
                    result["flags"].append("Tor exit node")
            # Only add the abuse flag if the IP has actually appeared in reports
            # AND the confidence score is high enough to be meaningful.
            if ip_data.get("appears") and ip_data.get("confidence", 0) >= 25:
                tag = f"Abuse reports (confidence {ip_data['confidence']:.0f}%)"
                result["flags"].append(tag)
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        pass   # network error — result dict already has safe defaults

    # Return None if every API call failed so the caller can skip the section.
    return result if any_success else None


# ─────────────────────────────────────────────────────────────────────────────
# WELL-KNOWN ADDRESS COMMENT LOOKUP
# Maps an IP address to a plain-English description of its reserved or special
# purpose.  Checks are ordered most-specific → most-general so that, for
# example, 127.0.0.1 is caught by the loopback check before falling through
# to any broader range check.
# ─────────────────────────────────────────────────────────────────────────────

def get_ip_comment(ip_obj, ip_type):
    """
    Return a human-readable comment describing the well-known role of an IP address.

    Checks are ordered from most-specific to most-general so that, for example,
    127.0.0.1 is identified as loopback before it would match anything else.

    Args:
        ip_obj:  IPv4Address or IPv6Address object
        ip_type: "IPv4" or "IPv6"

    Returns:
        str: Descriptive comment, or empty string for ordinary public addresses.
    """
    # ----- Loopback -----
    # The is_loopback property covers the entire 127.0.0.0/8 range for IPv4
    # and ::1 for IPv6, so we check it first before any range comparisons.
    if ip_obj.is_loopback:
        if ip_type == "IPv4":
            return "Loopback address (127.0.0.0/8) — used to refer to the local host itself"
        return "IPv6 loopback address (::1) — equivalent to IPv4 127.0.0.1"

    # ----- Unspecified / all-zeros -----
    # 0.0.0.0 and :: mean "any local interface" in socket APIs and are used
    # as a placeholder source address before a real address is assigned (DHCP).
    if ip_obj == ipaddress.ip_address("0.0.0.0") or ip_obj == ipaddress.ip_address("::"):
        return "Unspecified address — represents 'any' interface; not routable"

    # ----- IPv4-specific well-known ranges -----
    # Each check uses the 'in network' membership test which is O(1) and
    # avoids string manipulation on every comparison.
    if ip_type == "IPv4":
        ip4 = ipaddress.IPv4Address(ip_obj)

        # RFC 1918 private ranges — the three blocks reserved for private
        # networks that must not be routed on the public internet.
        if ip4 in ipaddress.IPv4Network("10.0.0.0/8"):
            return "RFC 1918 private address (10.0.0.0/8) — Class A private range, not routable on the public internet"

        if ip4 in ipaddress.IPv4Network("172.16.0.0/12"):
            return "RFC 1918 private address (172.16.0.0/12) — Class B private range, not routable on the public internet"

        if ip4 in ipaddress.IPv4Network("192.168.0.0/16"):
            return "RFC 1918 private address (192.168.0.0/16) — Class C private range, commonly used in home and office networks"

        # Link-local (APIPA) — auto-assigned by the OS when DHCP fails
        if ip4 in ipaddress.IPv4Network("169.254.0.0/16"):
            return "Link-local address (169.254.0.0/16, RFC 3927) — auto-assigned when no DHCP server is reachable; not routable beyond the local link"

        # Carrier-grade NAT shared space — used by ISPs for NAT444 deployments
        if ip4 in ipaddress.IPv4Network("100.64.0.0/10"):
            return "Shared address space (100.64.0.0/10, RFC 6598) — used by ISPs for carrier-grade NAT; not routable on the public internet"

        # TEST-NET documentation ranges — must never appear on a live network
        if ip4 in ipaddress.IPv4Network("192.0.2.0/24"):
            return "Documentation / example address (192.0.2.0/24, RFC 5737) — TEST-NET-1, for use in documentation and examples only"

        if ip4 in ipaddress.IPv4Network("198.51.100.0/24"):
            return "Documentation / example address (198.51.100.0/24, RFC 5737) — TEST-NET-2, for use in documentation and examples only"

        if ip4 in ipaddress.IPv4Network("203.0.113.0/24"):
            return "Documentation / example address (203.0.113.0/24, RFC 5737) — TEST-NET-3, for use in documentation and examples only"

        # Multicast — not assigned to individual hosts; used for group traffic
        if ip4 in ipaddress.IPv4Network("224.0.0.0/4"):
            return "Multicast address (224.0.0.0/4, RFC 5771) — used for one-to-many group communication, not a host address"

        # Class E reserved/experimental — never deployed in practice
        if ip4 in ipaddress.IPv4Network("240.0.0.0/4"):
            return "Reserved / experimental address (240.0.0.0/4, RFC 1112) — Class E range; not used in practice"

        # Limited broadcast — delivered to all hosts on the local segment only
        if ip4 == ipaddress.IPv4Address("255.255.255.255"):
            return "Limited broadcast address — sent to all hosts on the local network segment"

        # Legacy 6to4 anycast relay — the rendezvous point for 6to4 tunnels
        if ip4 in ipaddress.IPv4Network("192.88.99.0/24"):
            return "6to4 anycast relay address (192.88.99.0/24, RFC 7526) — formerly used for IPv6-over-IPv4 tunnelling"

        # Ordinary public address — none of the special ranges matched
        return "Public / globally routable IPv4 address"

    # ----- IPv6-specific well-known ranges -----
    ip6 = ipaddress.IPv6Address(ip_obj)

    # Unique local (fc00::/7) — the IPv6 equivalent of RFC 1918 private space
    if ip6 in ipaddress.IPv6Network("fc00::/7"):
        return "Unique local address (fc00::/7, RFC 4193) — IPv6 equivalent of RFC 1918 private space; not routable on the public internet"

    # Link-local (fe80::/10) — auto-configured on every IPv6 interface
    if ip6 in ipaddress.IPv6Network("fe80::/10"):
        return "Link-local address (fe80::/10, RFC 4291) — auto-configured on every IPv6 interface; only valid on the local link"

    # IPv4-mapped (::ffff:0:0/96) — IPv4 address expressed in IPv6 form
    if ip6 in ipaddress.IPv6Network("::ffff:0:0/96"):
        return "IPv4-mapped IPv6 address (::ffff:0:0/96, RFC 4291) — represents an IPv4 address in IPv6 notation"

    # 6to4 (2002::/16) — transition mechanism embedding an IPv4 address
    if ip6 in ipaddress.IPv6Network("2002::/16"):
        return "6to4 address (2002::/16, RFC 3056) — embeds an IPv4 address for IPv6-over-IPv4 tunnelling"

    # Documentation range — like 192.0.2.0/24 but for IPv6
    if ip6 in ipaddress.IPv6Network("2001:db8::/32"):
        return "Documentation / example address (2001:db8::/32, RFC 3849) — for use in documentation and examples only"

    # IPv6 multicast (ff00::/8) — group communication, not a host address
    if ip6 in ipaddress.IPv6Network("ff00::/8"):
        return "IPv6 multicast address (ff00::/8, RFC 4291) — used for one-to-many group communication"

    # Teredo (2001::/32) — tunnels IPv6 through IPv4 NAT via UDP
    if ip6 in ipaddress.IPv6Network("2001::/32"):
        return "Teredo tunnelling address (2001::/32, RFC 4380) — encapsulates IPv6 packets within IPv4 UDP"

    # NAT64 (64:ff9b::/96) — maps IPv4 addresses for IPv6-only clients
    if ip6 in ipaddress.IPv6Network("64:ff9b::/96"):
        return "IPv4/IPv6 translation address (64:ff9b::/96, RFC 6052) — used by NAT64 gateways"

    return "Public / globally routable IPv6 address"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN INFO AGGREGATOR
# get_ip_info() is the single entry point that callers should use.  It:
#   1. Parses and validates the input (bare address or CIDR)
#   2. Computes subnet geometry (mask, range, host count, class)
#   3. Derives IPv6 representations for IPv4 addresses
#   4. Runs the reverse DNS lookup (all addresses)
#   5. Runs RDAP and threat-intel lookups (public addresses only)
# and returns everything as a flat dict.
# ─────────────────────────────────────────────────────────────────────────────

def get_ip_info(ip_string):
    """
    Get detailed information about an IP address or CIDR network
    
    Args:
        ip_string (str): IP address or CIDR to analyze
        
    Returns:
        dict: Information about the IP address and subnet
    """
    is_valid, ip_type, ip_obj, network_obj = parse_network_input(ip_string)
    
    # If the input could not be parsed as any valid IP address or CIDR,
    # return a minimal dict with valid=False so the caller can handle it
    # gracefully without needing to catch an exception.
    if not is_valid:
        return {
            "valid": False,
            "ip": ip_string,
            "type": None,
            "is_private": None,
            "is_loopback": None,
            "is_multicast": None,
            "is_reserved": None,
            "cidr": None,
            "subnet_class": None,
            "subnet_mask": None,
            "network_address": None,
            "ip_range": None,
            "host_count": None
        }

    assert ip_obj is not None and network_obj is not None

    # ── Subnet geometry ──────────────────────────────────────────────────────
    # IPv4 and IPv6 are handled separately because classful naming only applies
    # to IPv4, and host count rules differ (IPv6 does not reserve network/
    # broadcast addresses from the usable count).
    # Calculate host count
    # For IPv4: total addresses minus network and broadcast (except /31 and /32)
    # For IPv6: all addresses are usable
    if ip_type == "IPv4":
        subnet_class = get_ipv4_class(ip_obj)
        subnet_mask = str(network_obj.netmask)
        
        if network_obj.prefixlen == 32:
            # /32 = single host — network address and broadcast are the same address
            # Single host
            host_count = 1
            ip_range = f"{network_obj.network_address} - {network_obj.broadcast_address}"
        elif network_obj.prefixlen == 31:
            # /31 point-to-point links (RFC 3021) treat both addresses as usable
            # hosts; there is no separate network or broadcast address.
            # Point-to-point link (RFC 3021) - both addresses usable
            host_count = 2
            ip_range = f"{network_obj.network_address} - {network_obj.broadcast_address}"
        else:
            # Standard subnets reserve the first address (network) and the last
            # (broadcast), so usable host count = total - 2.
            # Standard subnet: total - network - broadcast
            host_count = network_obj.num_addresses - 2
            ip_range = f"{network_obj.network_address + 1} - {network_obj.broadcast_address - 1}"
    else:
        # IPv6 has no concept of broadcast; every address in the prefix is usable.
        subnet_class = "N/A"
        subnet_mask = str(network_obj.netmask)
        host_count = network_obj.num_addresses
        ip_range = f"{network_obj.network_address} - {network_obj.broadcast_address}"

    # ── IPv6 representations of this IPv4 address ────────────────────────────
    # Compute both the IPv4-mapped and 6to4 forms so the output table can show
    # how this address would appear in mixed IPv4/IPv6 environments.
    # Add IPv6 conversion info for IPv4 addresses
    ipv6_mapped = None
    ipv6_6to4 = None
    if ip_type == "IPv4":
        ipv6_mapped = ipv4_to_ipv6_mapped(ip_obj)
        ipv6_6to4 = ipv4_to_ipv6_6to4(ip_obj)
    
    # ── Assemble the result dict ──────────────────────────────────────────────
    # Reverse DNS is run for all addresses (PTR records exist for private and
    # loopback ranges too).  RDAP and threat-intel are deferred until after the
    # is_public check below, since calling those APIs for 192.168.x.x would
    # waste a round-trip and return no useful data.
    result = {
        "valid": True,
        "ip": str(ip_obj),
        "type": ip_type,
        "is_private": ip_obj.is_private,
        "is_loopback": ip_obj.is_loopback,
        "is_multicast": ip_obj.is_multicast,
        "is_reserved": ip_obj.is_reserved,
        "is_global": ip_obj.is_global if ip_type == "IPv6" else not ip_obj.is_private,
        "cidr": f"/{network_obj.prefixlen}",
        "subnet_class": subnet_class,
        "subnet_mask": subnet_mask,
        "network_address": str(network_obj.network_address),
        "ip_range": ip_range,
        "host_count": host_count,
        "ipv6_mapped": ipv6_mapped,
        "ipv6_6to4": ipv6_6to4,
        "comment": get_ip_comment(ip_obj, ip_type),
        "reverse_dns": reverse_dns_lookup(ip_obj),
        "domain_registrant": "",  # populated below if reverse DNS found a hostname
        "rdap": None,             # populated below for public addresses
        "threat_intel": None,     # populated on demand via enrich_threat_intel()
        "abuseipdb": None,        # populated on demand via enrich_threat_intel()
        "xforce": None,           # populated on demand via enrich_threat_intel()
        "_ip_obj": ip_obj,        # retained so enrich_threat_intel() can use it
    }

    # ── Network lookups (public addresses only) ───────────────────────────────
    # We only call RDAP when the address is actually reachable on the public
    # internet.  Threat intel is deferred — called separately on user request.
    is_public = (
        not ip_obj.is_private
        and not ip_obj.is_loopback
        and not ip_obj.is_multicast
        and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )
    # Look up the domain registrant for the first reverse DNS hostname found,
    # regardless of whether the IP is public (PTR records exist for private IPs too).
    if result["reverse_dns"]:
        result["domain_registrant"] = lookup_domain_registrant(result["reverse_dns"][0])

    if is_public:
        result["rdap"] = lookup_rdap(ip_obj)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# ON-DEMAND THREAT ENRICHMENT
# Three lookup functions (ip-api/SFS already in lookup_threat_intel above,
# AbuseIPDB, and IBM X-Force) plus enrich_threat_intel() which calls all three
# and writes the results back into the info dict in-place.
# ─────────────────────────────────────────────────────────────────────────────

# AbuseIPDB category ID → human-readable name (from their docs).
_ABUSEIPDB_CATS = {
    1:  "DNS Compromise",   2:  "DNS Poisoning",   3:  "Fraud Orders",
    4:  "DDoS Attack",      5:  "FTP Brute-Force",  6:  "Ping of Death",
    7:  "Phishing",         8:  "Fraud VoIP",       9:  "Open Proxy",
    10: "Web Spam",         11: "Email Spam",       12: "Blog Spam",
    13: "VPN IP",           14: "Port Scan",        15: "Hacking",
    16: "SQL Injection",    17: "Spoofing",         18: "Brute-Force",
    19: "Bad Web Bot",      20: "Exploited Host",   21: "Web App Attack",
    22: "SSH",              23: "IoT Targeted",
}

def lookup_abuseipdb(ip_obj):
    """Query AbuseIPDB (ABUSEIPDB_API_KEY) for abuse confidence and categories."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check"
            f"?ipAddress={ip_obj}&maxAgeInDays=90&verbose",
            headers={"Accept": "application/json", "Key": api_key}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            d = json.loads(resp.read().decode()).get("data", {})
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return None
    score = d.get("abuseConfidenceScore")
    if score is None:
        return None
    seen_cats = set()
    for report in (d.get("reports") or []):
        for cid in report.get("categories", []):
            name = _ABUSEIPDB_CATS.get(cid)
            if name:
                seen_cats.add(name)
    total  = d.get("totalReports", 0)
    last   = (d.get("lastReportedAt") or "")[:10]
    if score >= 75:
        reason = "High confidence malicious"
    elif score >= 25:
        reason = "Moderate abuse activity"
    elif total > 0:
        reason = "Low-level abuse reports"
    else:
        reason = "No abuse reports"
    return {
        "score": score, "cats": sorted(seen_cats),
        "isp": d.get("isp", ""), "country": d.get("countryName", ""),
        "total_reports": total, "last_reported": last, "reason": reason,
    }


def lookup_xforce(ip_obj):
    """Query IBM X-Force Exchange (XFORCE_API_KEY + XFORCE_API_PASSWORD)."""
    api_key = os.environ.get("XFORCE_API_KEY", "").strip()
    api_pwd = os.environ.get("XFORCE_API_PASSWORD", "").strip()
    if not api_key or not api_pwd:
        return None
    token = base64.b64encode(f"{api_key}:{api_pwd}".encode()).decode()
    try:
        req = urllib.request.Request(
            f"https://apps.xforce.quit/ipr/{ip_obj}",
            headers={"Accept": "application/json", "Authorization": f"Basic {token}"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            d = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return None
    score = d.get("score")
    if score is None:
        return None
    raw_cats = d.get("cats", {})
    cats = sorted(raw_cats.keys()) if isinstance(raw_cats, dict) else []
    country = d.get("geo", {}).get("country", "")
    subnets = d.get("subnets", [])
    subnet  = subnets[0].get("subnet", "") if subnets else ""
    if cats:
        reason = cats[0] + (f" (+{len(cats)-1} more)" if len(cats) > 1 else "")
    elif score >= 1:
        reason = "Reported malicious activity"
    else:
        reason = "No threats reported"
    return {
        "score": score, "cats": cats,
        "country": country, "subnet": subnet, "reason": reason,
    }


def enrich_threat_intel(info):
    """
    Populate threat_intel, abuseipdb, and xforce fields of a get_ip_info()
    result dict in-place.  Called separately so the caller controls when to
    pay the network cost of these lookups.
    """
    ip_obj = info.get("_ip_obj")
    if ip_obj is None:
        return info
    is_public = (
        not ip_obj.is_private   and not ip_obj.is_loopback
        and not ip_obj.is_multicast and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )
    if is_public:
        info["threat_intel"] = lookup_threat_intel(ip_obj)
        info["abuseipdb"]    = lookup_abuseipdb(ip_obj)
        info["xforce"]       = lookup_xforce(ip_obj)   # None unless on IBM network
    return info


# ─────────────────────────────────────────────────────────────────────────────
# TABLE RENDERER
# print_ip_table() takes the dict produced by get_ip_info() and renders it as
# a formatted two-column ASCII box table.  All presentation logic lives here so
# the data functions above stay clean and testable without side effects.
#
# Column widths are defined as constants (COL1, COL2) at the top of the
# function.  Three inner helpers handle the three types of output row:
#   row()     — a standard label/value pair (with value word-wrapping)
#   section() — a full-width section header that spans both columns
#   divider() — a horizontal rule between groups of related rows
# ─────────────────────────────────────────────────────────────────────────────

def print_ip_table(info, show_threat=True):
    """
    Print a formatted two-column table for the result of get_ip_info().

    Args:
        info:         dict returned by get_ip_info() (optionally enriched).
        show_threat:  if False, the Threat Intelligence section is omitted.

    Layout
    ------
    ┌─────────────────────────────────────────────────────────────────────┐
    │  IP Address Report: <ip>                                            │
    ├──────────────────────┬──────────────────────────────────────────────┤
    │  Label               │  Value                                       │
    │  ...                 │  ...                                         │
    ├──────────────────────┴──────────────────────────────────────────────┤
    │  Section header                                                     │
    ├──────────────────────┬──────────────────────────────────────────────┤
    │  ...                 │  ...                                         │
    └──────────────────────┴──────────────────────────────────────────────┘

    Long values are word-wrapped to fit inside the right column.
    """
    COL1 = 22   # width of the label column (including one padding space each side)
    COL2 = 48   # width of the value column (including one padding space each side)
    TOTAL = COL1 + COL2 + 3  # 3 = left border + separator + right border

    def _wrap(text, width):
        """Split text into lines of at most `width` characters."""
        # Word-wrap by accumulating words onto the current line until the next
        # word would overflow, then start a new line.
        words, lines, current = text.split(), [], ""
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
        """Print a single data row, wrapping the value if necessary."""
        inner1 = COL1 - 2   # usable chars inside padding
        inner2 = COL2 - 2
        # Truncate labels that are too long (shouldn't happen in practice)
        # and left-pad the value column.
        label_str = str(label)[:inner1].ljust(inner1)
        value_lines = _wrap(str(value), inner2)
        # Print the first line with its label; continuation lines get a blank label.
        print(f"│ {label_str} │ {value_lines[0].ljust(inner2)} │")
        for extra in value_lines[1:]:
            print(f"│ {''.ljust(inner1)} │ {extra.ljust(inner2)} │")

    def section(title):
        """Print a full-width section divider row."""
        # The section header spans the full table width by temporarily merging
        # the two columns: the ┴ and ┬ separators are replaced with a plain ─.
        inner = TOTAL - 4   # 4 = '│ ' + ' │'
        print(f"├─{'─' * (COL1 - 2)}─┴─{'─' * (COL2 - 2)}─┤")
        print(f"│ {title.ljust(inner)} │")
        print(f"├─{'─' * (COL1 - 2)}─┬─{'─' * (COL2 - 2)}─┤")

    def divider():
        # A horizontal rule using ├, ┤, and ─ characters to visually separate
        # groups of related rows within the same section.
        print(f"├─{'─' * (COL1 - 2)}─┬─{'─' * (COL2 - 2)}─┤")

    # ── top border + title ───────────────────────────────────────────────
    # The title row spans the full table width like a section header, but uses
    # the outer ┌/┐ corners because it is the very first row.
    title = f"  IP Address Report: {info['ip']}"
    print(f"┌─{'─' * (TOTAL - 2)}─┐")
    print(f"│{title:<{TOTAL}}│")
    print(f"├─{'─' * (COL1 - 2)}─┬─{'─' * (COL2 - 2)}─┤")

    # Short-circuit for invalid addresses — just show the error and close.
    if not info['valid']:
        row("Valid", "✗  Invalid IP address")
        print(f"└─{'─' * (COL1 - 2)}─┴─{'─' * (COL2 - 2)}─┘")
        return

    # ── core fields ──────────────────────────────────────────────────────
    # These fields are always present for a valid address.
    row("Valid",           "✓  " + info['type'] + " address")
    row("CIDR",            info['cidr'])
    row("Subnet Mask",     info['subnet_mask'])
    row("Subnet Class",    info['subnet_class'])
    row("Network Address", info['network_address'])
    row("IP Range",        info['ip_range'])
    row("Host Count",      f"{info['host_count']:,}")
    # ── address-type flags ────────────────────────────────────────────────
    divider()
    row("Private",         info['is_private'])
    row("Loopback",        info['is_loopback'])
    row("Multicast",       info['is_multicast'])
    row("Reserved",        info['is_reserved'])
    # ── well-known address note (conditional) ─────────────────────────────
    # Only shown when the address falls in a named/special range.
    if info['comment']:
        divider()
        row("Note", info['comment'])
    # ── reverse DNS (conditional) ─────────────────────────────────────────
    # Multiple hostnames are listed on separate rows under the same label.
    if info['reverse_dns']:
        divider()
        for i, name in enumerate(info['reverse_dns']):
            row("Reverse DNS" if i == 0 else "", name)
        if info.get('domain_registrant'):
            row("Domain Registrar", info['domain_registrant'])
    # ── IPv6 representations (conditional, IPv4 only) ─────────────────────
    if info['ipv6_mapped']:
        divider()
        row("IPv6 Mapped",  info['ipv6_mapped'])
        row("IPv6 6to4",    info['ipv6_6to4'])

    # ── RDAP / registration ───────────────────────────────────────────────
    # Only present for public addresses where the RDAP lookup succeeded.
    if info.get('rdap'):
        rdap = info['rdap']
        section("RDAP / Registration (ARIN)")
        row("Owner",            rdap['org'])
        row("Network Name",     rdap['network_name'])
        row("Registered Block", rdap['cidr_block'])

    # ── Threat intelligence (optional) ───────────────────────────────────
    # Superscript markers on labels show which service provided each field:
    #   ¹ ip-api.com  ² StopForumSpam  ³ AbuseIPDB  ⁴ IBM X-Force
    # A sources legend is printed at the foot of the section so the reader
    # can trace every labelled field back to its origin.
    ti = info.get('threat_intel')
    ab = info.get('abuseipdb')
    xf = info.get('xforce')

    if show_threat and (ti or ab or xf):
        sources_used = []
        section("Threat Intelligence")

        if ti:
            sources_used += [1, 2]
            if ti['geo']:
                row("Geo ¹",           ti['geo'])
            if ti['isp']:
                row("ISP ¹",           ti['isp'])
            if ti['asn']:
                row("ASN ¹",           ti['asn'])
            row("Proxy / VPN ¹",       "Yes" if ti['is_proxy']   else "No")
            row("Hosting / DC ¹",      "Yes" if ti['is_hosting'] else "No")
            row("Tor Exit ²",          "Yes" if ti['is_tor']     else "No")
            if ti['abuse_freq'] is not None:
                if ti['abuse_freq'] > 0:
                    abuse_str = (f"{ti['abuse_freq']} reports,"
                                 f" confidence {ti['abuse_score']:.0f}%,"
                                 f" last seen {ti['abuse_last']}")
                else:
                    abuse_str = "None"
                row("Abuse Reports ²", abuse_str)
            if ti['flags']:
                row("⚑  Flags",        ", ".join(ti['flags']))
            else:
                row("⚑  Flags",        "none")

        if ab:
            sources_used.append(3)
            if ti:
                divider()
            score = ab['score']
            if score >= 75:
                lbl = _red(f"{score}%  ⚠  HIGH RISK")
            elif score > 0:
                lbl = _yellow(f"{score}%  –  Moderate risk" if score >= 25 else f"{score}%  –  Low risk")
            else:
                lbl = _green(f"{score}%  –  No risk")
            row("Abuse Score ³",    lbl)
            row("Summary ³",        ab['reason'])
            if ab['cats']:
                row("Categories ³",    ", ".join(ab['cats']))
            if ab['total_reports']:
                last = f"  (last: {ab['last_reported']})" if ab['last_reported'] else ""
                row("Reports ³",       f"{ab['total_reports']}{last}")
            if ab['isp']:
                row("ISP ³",           ab['isp'])
            if ab['country']:
                row("Country ³",       ab['country'])

        if xf:
            sources_used.append(4)
            divider()
            score = xf['score']
            if score >= 7:
                lbl = _red(f"{score:.1f} / 10  ⚠  HIGH RISK")
            elif score > 0:
                lbl = _yellow(f"{score:.1f} / 10  –  Medium risk" if score >= 4 else f"{score:.1f} / 10  –  Low risk")
            else:
                lbl = _green(f"{score:.1f} / 10  –  No risk")
            row("XF Risk Score ⁴",  lbl)
            row("XF Summary ⁴",     xf['reason'])
            if xf['cats']:
                row("XF Categories ⁴",  ", ".join(xf['cats']))
            if xf['country']:
                row("XF Geo ⁴",         xf['country'])
            if xf['subnet']:
                row("XF Subnet ⁴",      xf['subnet'])

        # ── Sources legend ────────────────────────────────────────────────
        _legend_map = {
            1: "¹ ip-api.com    – geo, ISP, ASN, proxy/VPN, hosting flags",
            2: "² StopForumSpam – Tor exit node, abuse report frequency",
            3: "³ AbuseIPDB     – abuse confidence score, attack categories",
            4: "⁴ IBM X-Force   – risk score, threat categories (IBM network)",
        }
        inner = TOTAL - 4
        print(f"├─{'─' * (TOTAL - 2)}─┤")
        print(f"│ {'Sources':<{inner}} │")
        for n in sorted(set(sources_used)):
            print(f"│  {_legend_map[n]:<{inner - 1}} │")

    # ── bottom border ─────────────────────────────────────────────────────
    print(f"└─{'─' * (TOTAL - 2)}─┘")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# main() runs in two phases:
#   1. Batch mode  — loops over a hard-coded list of test IPs and prints a
#                    table for each one so you can see the full range of output
#                    formats (private, public, invalid, IPv6, etc.) at a glance.
#   2. Interactive — prompts the user to enter addresses one at a time until
#                    they type 'quit', 'exit', or 'q'.
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# CONNECTIVITY HEALTH CHECK
# check_connectivity() probes each external data source used by the tool and
# prints a formatted status report showing reachability, credential status, and
# response latency for every service.  Called from the interactive prompt when
# the user types '!check'.
# ─────────────────────────────────────────────────────────────────────────────

def check_connectivity():
    """
    Probe every external API / data source and print a health-check table.

    Checks performed
    ----------------
    1. ip-api.com           – keyless geo/proxy lookup (IPv4 only)
    2. StopForumSpam        – keyless abuse database
    3. ARIN RDAP            – keyless registration data
    4. AbuseIPDB            – keyed API  (ABUSEIPDB_API_KEY in .env)
    5. IBM X-Force Exchange – keyed API  (XFORCE_API_KEY + XFORCE_API_PASSWORD)

    Each probe uses the real endpoint with a benign test IP (8.8.8.8) so the
    result reflects actual end-to-end connectivity, not just DNS resolution.
    """
    import time

    TEST_IP = "8.8.8.8"   # Google DNS — globally reachable, always has records
    W  = 76               # total line width (matches the === header)
    W2 = 22               # width of the service-name column

    def _probe(label, url, headers=None, expect_key=None):
        """
        Make one GET request and return a (status, latency_ms, note) tuple.
        status is one of: 'OK', 'AUTH', 'UNREACH', 'NO KEY'.
        """
        if expect_key == "missing":
            return ("NO KEY", None, "API key not configured in .env")

        t0 = time.monotonic()
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=8) as resp:
                resp.read()   # consume body so the socket closes cleanly
            ms = int((time.monotonic() - t0) * 1000)
            return ("OK", ms, "Reachable")
        except urllib.error.HTTPError as e:
            ms = int((time.monotonic() - t0) * 1000)
            if e.code in (401, 403):
                return ("AUTH", ms, f"HTTP {e.code} — credentials rejected")
            return ("UNREACH", ms, f"HTTP {e.code}")
        except Exception as e:
            return ("UNREACH", None, str(e)[:60])

    # ── build the probe list ──────────────────────────────────────────────────
    probes = []

    # 1. ip-api.com (keyless)
    probes.append((
        "ip-api.com ¹",
        f"http://ip-api.com/json/{TEST_IP}?fields=status",
        {"Accept": "application/json"},
        None,
    ))

    # 2. StopForumSpam (keyless)
    probes.append((
        "StopForumSpam ²",
        f"https://api.stopforumspam.org/api?ip={TEST_IP}&json",
        {"Accept": "application/json"},
        None,
    ))

    # 3. ARIN RDAP (keyless)
    probes.append((
        "ARIN RDAP",
        f"https://rdap.arin.net/registry/ip/{TEST_IP}",
        {"Accept": "application/json"},
        None,
    ))

    # 4. AbuseIPDB (keyed)
    ab_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if ab_key:
        probes.append((
            "AbuseIPDB ³",
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={TEST_IP}&maxAgeInDays=1",
            {"Accept": "application/json", "Key": ab_key},
            None,
        ))
    else:
        probes.append(("AbuseIPDB ³", None, {}, "missing"))

    # 5. IBM X-Force (keyed — Basic Auth)
    xf_key = os.environ.get("XFORCE_API_KEY", "").strip()
    xf_pwd = os.environ.get("XFORCE_API_PASSWORD", "").strip()
    if xf_key and xf_pwd:
        xf_token = base64.b64encode(f"{xf_key}:{xf_pwd}".encode()).decode()
        probes.append((
            "IBM X-Force ⁴",
            f"https://apps.xforce.ibmcloud.com/ipr/{TEST_IP}",
            {"Accept": "application/json", "Authorization": f"Basic {xf_token}"},
            None,
        ))
    else:
        probes.append(("IBM X-Force ⁴", None, {}, "missing"))

    # ── print the results table ───────────────────────────────────────────────
    STATUS_ICON = {
        "OK":      "✓  OK",
        "AUTH":    "✗  Auth failed",
        "UNREACH": "✗  Unreachable",
        "NO KEY":  "–  Not configured",
    }

    print()
    print("=" * W)
    print("  External Source Connectivity Check")
    print("=" * W)
    print(f"  {'Service':<{W2}}  {'Status':<18}  {'Latency':>8}  Note")
    print(f"  {'-'*W2}  {'-'*18}  {'-'*8}  {'-'*18}")

    for label, url, headers, expect_key in probes:
        status, ms, note = _probe(label, url, headers, expect_key)
        icon     = STATUS_ICON[status]
        latency  = f"{ms} ms" if ms is not None else "—"
        print(f"  {label:<{W2}}  {icon:<18}  {latency:>8}  {note}")

    print("=" * W)
    print()
    print("  Key:  ¹ ip-api.com  ² StopForumSpam  ³ AbuseIPDB  ⁴ IBM X-Force")
    print("  API keys are read from your .env file (ABUSEIPDB_API_KEY,")
    print("  XFORCE_API_KEY, XFORCE_API_PASSWORD).")
    print()


def main():
    """
    IP Address Validator — interactive mode.
    """
    print("=" * 76)
    print("  IP ADDRESS VALIDATOR")
    print("=" * 76)

    # Clear any history that leaked in from the shell / previous runs so the
    # interactive session starts clean, but within-session recall still works.
    try:
        import readline
        readline.clear_history()
    except ImportError:
        pass

    # Interactive mode — keep prompting until the user quits.
    # Two-phase flow per IP:
    #   Phase 1: fast table immediately (RDAP + reverse DNS, no threat calls).
    #   Phase 2: prompt — [T] fetch threat intel, [Enter] new IP, [Q] quit.
    print("\nInteractive Mode (type 'quit' to exit)")
    print("This tool takes an IP with or without a CIDR mask and returns info about it.")
    print("Type '!check' to test connectivity to all external data sources.")
    print("-" * 76)

    while True:
        user_input = input("\nEnter IP address or CIDR to validate: ").strip()

        if user_input.lower() in ['quit', 'exit', 'q']:
            print("Goodbye!")
            break

        if not user_input:
            continue

        if user_input.lower() == '!check':
            check_connectivity()
            continue

        # ── Phase 1: fast lookup ──────────────────────────────────────────
        print()
        info = get_ip_info(user_input)
        print_ip_table(info, show_threat=False)

        # Only offer threat intel for valid public addresses.
        ip_obj = info.get("_ip_obj")
        is_public = (
            info.get("valid") and ip_obj is not None
            and not ip_obj.is_private   and not ip_obj.is_loopback
            and not ip_obj.is_multicast and not ip_obj.is_reserved
            and not ip_obj.is_unspecified
        )

        if is_public:
            # ── Phase 2: optional threat intel ───────────────────────────
            ti_input = input(
                "\n  [T] Show Threat Intelligence  "
                "[Enter] New IP  "
                "[Q] Quit  › "
            ).strip().lower()

            if ti_input in ('q', 'quit', 'exit'):
                print("Goodbye!")
                break

            if ti_input == 't':
                print("\n  Fetching threat intelligence…\n")
                enrich_threat_intel(info)
                print_ip_table(info, show_threat=True)


if __name__ == "__main__":
    main()

# Made with Bob
