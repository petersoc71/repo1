# IP & MAC Address Validator

A pair of command-line tools for validating and investigating network addresses.

- **`ip_validator.py`** — IPv4 / IPv6 deep-inspection: subnet geometry, reverse DNS, RDAP registration, and on-demand threat intelligence.
- **`mac_validator.py`** — MAC address classification and OUI vendor lookup: bit-level flags, virtual/hypervisor detection, and manufacturer data.

Both tools run **interactively** (one address at a time) or in **batch mode** (list of addresses → CSV report).

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/petersoc71/repo1.git
cd repo1
```

### 2. Create a virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure API keys (ip_validator only)

Create a `.env` file in the project root:

```
ABUSEIPDB_API_KEY=your-abuseipdb-key-here
XFORCE_API_KEY=your-xforce-key-here
XFORCE_API_PASSWORD=your-xforce-password-here
```

- **AbuseIPDB** — free key at [abuseipdb.com/register](https://www.abuseipdb.com/register)
- **IBM X-Force** — requires an IBM account at [exchange.xforce.ibmcloud.com](https://exchange.xforce.ibmcloud.com) and access from an IBM network / VPN

> The script loads `.env` automatically at startup via `python-dotenv`. The `.env` file is git-ignored and never committed.
> `mac_validator.py` requires no API keys — it uses the keyless [maclookup.app](https://maclookup.app) API.

---

---

# ip_validator.py

## Features

- IPv4 and IPv6 validation with subnet geometry (mask, range, host count, class)
- Reverse DNS and domain registrar lookup
- RDAP / ARIN registration data (owner, network name, registered block)
- IPv6 mapped / 6to4 representations for IPv4 addresses
- **On-demand threat intelligence** — fetched only when you ask for it
- **Batch mode** — validate a list of IPs from the command line or a file and export results to CSV
- Connectivity health check for all external data sources (`!check`)

## Threat Intelligence Sources

| # | Source | Data | API Key |
|---|--------|------|---------|
| `¹` | [ip-api.com](http://ip-api.com) | Geo, ISP, ASN, proxy/VPN, hosting flags | Not required |
| `²` | [StopForumSpam](https://www.stopforumspam.com) | Tor exit node, abuse frequency | Not required |
| `³` | [AbuseIPDB](https://www.abuseipdb.com) | Confidence score, attack categories, report count | Required (free) |
| `⁴` | [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com) | Risk score, threat categories | Required (IBM network) |

## Usage

### Interactive mode

```bash
.venv/bin/python ip_validator.py
```

**Interactive prompt commands:**

| Input | Action |
|-------|--------|
| `192.168.1.1` | Validate an IP address |
| `8.8.8.8/24` | Validate an IP with CIDR notation |
| `T` | Fetch threat intelligence for the last looked-up IP |
| `!check` | Test connectivity to all external data sources |
| `q` / `quit` / `exit` | Exit the application |

---

### Batch mode

Pass IPs directly on the command line or point to a file. Results are written to a CSV.

```bash
# Comma-separated list inline
.venv/bin/python ip_validator.py --ips "8.8.8.8, 192.168.1.0/24, 10.0.0.1"

# One IP per line in a text file
.venv/bin/python ip_validator.py --file ips.txt

# Custom output path (default: ip_report.csv)
.venv/bin/python ip_validator.py --ips "1.2.3.4" --output /tmp/results.csv

# Combine both sources into one report
.venv/bin/python ip_validator.py --ips "8.8.8.8" --file extra_ips.txt --output combined.csv

# Show all options
.venv/bin/python ip_validator.py --help
```

**Batch mode flags:**

| Flag | Description |
|------|-------------|
| `--ips "IP_LIST"` | Comma-separated IPs / CIDR ranges |
| `--file PATH` | Text file — one IP per line (comma-separated lines also supported) |
| `--output CSV_PATH` | Output file path (default: `ip_report.csv`) |

**CSV columns:**

| Column | Description |
|--------|-------------|
| `Input` | The original IP or CIDR string as supplied |
| `Valid` | `True` / `False` |
| `Type` | `IPv4` or `IPv6` |
| `CIDR` | Prefix length (e.g. `/24`) |
| `Subnet Mask` | Dotted-decimal mask |
| `Subnet Class` | Classful class (IPv4 only) |
| `Network Address` | First address of the subnet |
| `IP Range` | Usable host range |
| `Host Count` | Number of usable hosts |
| `Private` / `Loopback` / `Multicast` / `Reserved` | Address-type flags |
| `Note` | Well-known range description, if applicable |
| `Reverse DNS` | PTR record(s), semicolon-separated |
| `Domain Registrar` | Registrar of the first reverse-DNS hostname |
| `IPv6 Mapped` / `IPv6 6to4` | IPv6 representations (IPv4 addresses only) |
| `RDAP Owner` | Registered organisation (public IPs only) |
| `RDAP Network` | ARIN network name |
| `RDAP Block` | Registered CIDR block |

## Example Output

```
┌─────────────────────────────────────────────────────────────────────────┐
│  IP Address Report: 8.8.8.8                                             │
├──────────────────────┬────────────────────────────────────────────────┤
│ Valid                │ ✓  IPv4 address                                │
│ CIDR                 │ /32                                            │
│ Subnet Mask          │ 255.255.255.255                                │
│ Subnet Class         │ Class A                                        │
│ Network Address      │ 8.8.8.8                                        │
│ Reverse DNS          │ dns.google                                     │
│ Domain Registrar     │ MarkMonitor Inc.                               │
├──────────────────────┴────────────────────────────────────────────────┤
│ RDAP / Registration (ARIN)                                            │
├──────────────────────┬────────────────────────────────────────────────┤
│ Owner                │ Google LLC                                     │
│ Network Name         │ GOGL                                           │
│ Registered Block     │ 8.8.8.0/24                                     │
└─────────────────────────────────────────────────────────────────────────┘

  [T] Show Threat Intelligence  [Enter] New IP  [Q] Quit  ›
```

## Test IPs

Well-known high-risk addresses useful for testing threat intelligence output:

| IP | Why it's flagged |
|----|-----------------|
| `80.82.77.139` | Shodan scanner — typically 100% AbuseIPDB confidence |
| `89.248.167.131` | Shodan scanner — consistently high risk scores |
| `185.220.101.1` | Tor exit node — botnet / scanning categories |
| `198.20.69.74` | ShadowServer scanning IP |

## Risk Score Colours

Abuse and X-Force risk scores are colour-coded in the terminal:

- 🟢 **Green** — no risk (`0%`)
- 🟡 **Yellow** — low to moderate risk (`1–74%`)
- 🔴 **Red** — high risk (`75–100%`)

> Colours are automatically suppressed when output is piped or redirected.

---

---

# mac_validator.py

## Features

- Validates MAC addresses in any common format, including abbreviated (single-digit) octets
- Bit-level classification: Unicast / Multicast, Globally Unique (UAA) / Locally Administered (LAA)
- Detects virtual and hypervisor-assigned addresses (VMware, Hyper-V, VirtualBox, QEMU/KVM, Xen, Docker, Parallels)
- Identifies OS-randomised privacy MACs (iOS, Android, Windows)
- Well-known multicast group identification (IPv4/IPv6 multicast, STP, Cisco CDP/VTP, broadcast)
- OUI vendor lookup via [maclookup.app](https://maclookup.app) — no API key required
- **Batch mode** — validate a list of MACs from the command line or a file and export results to CSV

## Accepted MAC Formats

| Format | Example |
|--------|---------|
| Colon-separated (zero-padded) | `00:50:56:C0:00:08` |
| Colon-separated (abbreviated octets) | `1:0:5e:0:0:fb` ← zero-padded automatically |
| Hyphen-separated (zero-padded) | `00-50-56-C0-00-08` |
| Hyphen-separated (abbreviated octets) | `1-0-5e-0-0-fb` ← zero-padded automatically |
| Cisco dot-notation | `0050.56C0.0008` |
| Plain hex (no separator) | `005056C00008` |

## Usage

### Interactive mode

```bash
.venv/bin/python mac_validator.py
```

**Interactive prompt commands:**

| Input | Action |
|-------|--------|
| `00:50:56:C0:00:08` | Validate a MAC address |
| `1:0:5e:0:0:fb` | Abbreviated octets — accepted and zero-padded automatically |
| `q` / `quit` / `exit` | Exit the application |

---

### Batch mode

Pass MACs directly on the command line or point to a file. Results are written to a CSV.

```bash
# Comma-separated list inline
.venv/bin/python mac_validator.py --macs "00:50:56:C0:00:08, 00-15-5D-01-02-03"

# One MAC per line in a text file
.venv/bin/python mac_validator.py --file macs.txt

# Custom output path (default: mac_report.csv)
.venv/bin/python mac_validator.py --macs "52:54:00:12:34:56" --output /tmp/results.csv

# Combine both sources into one report
.venv/bin/python mac_validator.py --macs "FF:FF:FF:FF:FF:FF" --file extra_macs.txt --output combined.csv

# Show all options
.venv/bin/python mac_validator.py --help
```

**Batch mode flags:**

| Flag | Description |
|------|-------------|
| `--macs "MAC_LIST"` | Comma-separated MAC addresses |
| `--file PATH` | Text file — one MAC per line (comma-separated lines also supported) |
| `--output CSV_PATH` | Output file path (default: `mac_report.csv`) |

**CSV columns:**

| Column | Description |
|--------|-------------|
| `Input` | The original MAC string as supplied (normalised to `XX:XX:XX:XX:XX:XX`) |
| `Valid` | `True` / `False` |
| `Address Type` | e.g. `Globally Unique (UAA)`, `Locally Administered (LAA)`, `Multicast`, `Broadcast` |
| `Scope` | `Global` or `Link-local` |
| `Multicast` | `True` / `False` |
| `Locally Admin` | `True` / `False` — LAA bit set |
| `Broadcast` | `True` / `False` |
| `Virtual / LAA` | Hypervisor name or randomisation hint, if applicable |
| `Multicast Group` | Well-known multicast group description, if applicable |
| `Note` | Special-case note (e.g. all-zeros, broadcast) |
| `Manufacturer Prefix` | First three octets (OUI) |
| `Company` | Registered vendor name from the OUI registry |
| `Registered Address` | Vendor's registered street address |
| `Country` | Two-letter country code |
| `Search / Website` | DuckDuckGo search URL for the vendor name |

## Example Output

```
┌─────────────────────────────────────────────────────────────────────
│  MAC Address Report: 00:50:56:C0:00:08
├────────────────────┬────────────────────────────────────────────────
│ Address Type       │ Globally Unique (UAA)
│ Scope              │ Global
│ Multicast          │ No
│ Locally Admin      │ No
│ Broadcast          │ No
├────────────────────┬────────────────────────────────────────────────
│ Virtual / LAA      │ VMware (vSphere/ESXi assigned)
├────────────────────┴────────────────────────────────────────────────
│ Vendor / Manufacturer
├────────────────────┬────────────────────────────────────────────────
│ Manufacturer Prefix│ 00:50:56
│ Company            │ VMware, Inc.
│ Registered Address │ 3401 Hillview Avenue, PALO ALTO CA 94304, US
│ Country            │ US
│ Hardware Type      │ Virtual - known hypervisor manufacturer
└─────────────────────────────────────────────────────────────────────
```

---

---

## License

MIT
