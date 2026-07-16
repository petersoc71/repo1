# IP Address Validator

A command-line tool for validating and investigating IPv4 and IPv6 addresses. It provides subnet geometry, reverse DNS, RDAP registration data, and on-demand threat intelligence from multiple sources.

---

## Features

- IPv4 and IPv6 validation with subnet geometry (mask, range, host count, class)
- Reverse DNS and domain registrar lookup
- RDAP / ARIN registration data (owner, network name, registered block)
- IPv6 mapped / 6to4 representations for IPv4 addresses
- **On-demand threat intelligence** — fetched only when you ask for it
- Connectivity health check for all external data sources (`!check`)

---

## Threat Intelligence Sources

| # | Source | Data | API Key |
|---|--------|------|---------|
| `¹` | [ip-api.com](http://ip-api.com) | Geo, ISP, ASN, proxy/VPN, hosting flags | Not required |
| `²` | [StopForumSpam](https://www.stopforumspam.com) | Tor exit node, abuse frequency | Not required |
| `³` | [AbuseIPDB](https://www.abuseipdb.com) | Confidence score, attack categories, report count | Required (free) |
| `⁴` | [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com) | Risk score, threat categories | Required (IBM network) |

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

### 3. Configure API keys

Create a `.env` file in the project root:

```
ABUSEIPDB_API_KEY=your-abuseipdb-key-here
XFORCE_API_KEY=your-xforce-key-here
XFORCE_API_PASSWORD=your-xforce-password-here
```

- **AbuseIPDB** — free key at [abuseipdb.com/register](https://www.abuseipdb.com/register)
- **IBM X-Force** — requires an IBM account at [exchange.xforce.ibmcloud.com](https://exchange.xforce.ibmcloud.com) and access from an IBM network / VPN

> The script loads `.env` automatically at startup via `python-dotenv`. The `.env` file is git-ignored and never committed.

---

## Usage

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

---

## Test IPs

Well-known high-risk addresses useful for testing threat intelligence output:

| IP | Why it's flagged |
|----|-----------------|
| `80.82.77.139` | Shodan scanner — typically 100% AbuseIPDB confidence |
| `89.248.167.131` | Shodan scanner — consistently high risk scores |
| `185.220.101.1` | Tor exit node — botnet / scanning categories |
| `198.20.69.74` | ShadowServer scanning IP |

---

## Risk Score Colours

Abuse and X-Force risk scores are colour-coded in the terminal:

- 🟢 **Green** — no risk (`0%`)
- 🟡 **Yellow** — low to moderate risk (`1–74%`)
- 🔴 **Red** — high risk (`75–100%`)

> Colours are automatically suppressed when output is piped or redirected.

---

## License

MIT
