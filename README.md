# SeeYouCM Thief

![Tests](https://github.com/trustedsec/SeeYouCM-Thief/actions/workflows/pytest.yaml/badge.svg)
![Python](https://img.shields.io/badge/python-3.13+-blue)

Multi-threaded tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials. Features intelligent caching, automatic backoff protection, and MAC address brute forcing capabilities.

## Features

- **Multi-threaded downloads**: 40 parallel worker threads for fast credential extraction
- **Intelligent caching**: SQLite database prevents redundant TFTP requests
- **Automatic protocol fallback**: TFTP by default with automatic HTTP fallback
- **TFTP server protection**: Automatic backoff manager prevents server overload
- **MAC address brute forcing**: Try 4,096 MAC variations (3 hex characters) per detected phone
- **Gowitness integration**: Load phone targets directly from gowitness database
- **CSV export**: Export discovered credentials to CSV format
- **User enumeration**: Extract usernames via CUCM User Data Services (UDS) API
- **Password spray**: HTTP Basic Auth spray against the UDS user endpoint with persistent per-username rate limiting and a pre-flight oracle probe

## Usage

### Basic Usage

Download configs from CUCM server (will attempt to get list of all phones):

```bash
./thief.py -H <CUCM Server IP>
```

### Single Phone Target

Specify a phone IP address to detect CUCM and discover credentials:

```bash
./thief.py -p <Cisco Phone IP>
```

### Multiple Phone Targets

Specify multiple phones (repeatable):

```bash
./thief.py -p 192.168.1.10 -p 192.168.1.11 -p 192.168.1.12
```

### Gowitness Integration

Load phone targets from gowitness database:

```bash
./thief.py --gowitness /path/to/gowitness.sqlite3
```

### MAC Address Brute Force

Brute force 4,096 MAC variations for each detected phone:

```bash
./thief.py -p <Phone IP> -b
./thief.py --gowitness <DB> -b -H <CUCM Server>
```

### Subnet Enumeration

Enumerate and attack entire subnet:

```bash
./thief.py --subnet 192.168.1.0/24
```

### User Enumeration

Extract usernames via CUCM UDS API:

```bash
./thief.py -H <CUCM Server> --userenum
```

### Password Spray

Spray a single password across every UDS-enumerated user, with a default 1-hour-per-user rate limit:

```bash
./thief.py -H <CUCM Server> --spray --spray-password 'Summer2025!'
```

Iterate a password list, sleeping ~1 hour between rounds so each user is attempted at most once per hour:

```bash
./thief.py -H <CUCM Server> --spray -P passwords.txt
```

A pre-flight oracle probe sends one bogus credential to verify the endpoint validates auth. If the server returns 200 to a known-bad password, the run aborts before any real password is sent. Skip the probe with `--no-spray-probe` only after manually verifying the target. Every attempt is logged to the `spray_attempts` table; hits surface in `--show-db`.

**Operator safety:** If CUCM is configured with LDAP Authentication, end-user spray attempts pass through to AD. Confirm domain lockout policy before running and tighten `--spray-rate-limit-hours` if needed.

### Database Operations

View cached results:

```bash
./thief.py --show-db
./thief.py --show-db -H <CUCM Server>  # Filter by CUCM
```

Extract all cached configs to disk for offline review:

```bash
./thief.py --extract-configs ./configs
./thief.py --extract-configs ./configs --db custom.db
```

Files are written to `./configs/<cucm_host>/<filename>`. Existing files are
preserved (re-runs are safe and incremental). Only successful downloads
with non-empty content are extracted.

Force re-download (bypass cache):

```bash
./thief.py -p <Phone IP> -b --force
```

Use custom database file:

```bash
./thief.py -p <Phone IP> --db custom.db
```

Disable database caching:

```bash
./thief.py -p <Phone IP> --no-db
```

### Export Options

Export to CSV:

```bash
./thief.py -p <Phone IP> -b --csv results.csv
```

## Command-Line Options

### Target Specification
- `-H, --host`: Specify CUCM server IP address
- `-p, --phone`: Specify Cisco phone IP (repeatable for multiple targets)
- `--gowitness DB_FILE`: Load phone targets from gowitness SQLite database
- `-e, --enumsubnet`: Enumerate and attack subnet in CIDR notation

### Attack Options
- `-b, --brute-mac`: Brute force MAC variations (4,096 combinations per phone)
- `--force`: Bypass cache and force re-download of all configuration files
- `--userenum`: Extract usernames via CUCM User Data Services (UDS) API (paginates the full directory)
- `--servers`: Enumerate CUCM cluster members (hostnames + IPs) via UDS `/cucm-uds/servers` — requires `-H`
- `--http`: Use HTTP (port 6970) as the primary config download protocol with TFTP fallback (default: TFTP first, HTTP fallback)
- `--uds-port PORT`: Override the CUCM UDS API HTTPS port for `--userenum` (default: 8443)
- `--spray`: Password-spray the UDS API (requires `-H`; mutually exclusive with `--brute-mac`)
- `--spray-password PASSWORD`: Single password to spray across all eligible users
- `-P, --passwords FILE`: Password list file; sprays each password in turn, sleeping ~1h between rounds
- `--spray-threads N`: Concurrent spray workers (default: 10)
- `--spray-rate-limit-hours N`: Per-username rate-limit window in hours (default: 1)
- `--no-spray-probe`: Skip the pre-flight oracle probe (use only after manual verification)

### Output Options
- `--csv FILENAME`: Export discovered credentials to CSV file
- `--outfile FILENAME`: Specify output file for enumerated usernames (default: cucm_users.txt)

### Database Options
- `--db FILENAME`: Specify SQLite database for caching results (default: thief.db)
- `--no-db`: Disable database caching and operate without persistent storage
- `--show-db`: Display summary of credentials stored in database and exit
- `--extract-configs DIR`: Extract all cached configuration files from the database into `DIR/<cucm_host>/<filename>` and exit

### Debugging
- `-d, --debug`: Enable verbose output including all failed attempts and TFTP operations

## How It Works

1. **Target Discovery**: Detects phones via direct IP, gowitness database, or subnet enumeration
2. **CUCM Detection**: Automatically identifies CUCM server from phone configuration
3. **MAC Detection**: Extracts MAC addresses from phone hostnames (SEP format)
4. **Multi-threaded Brute Force**: 40 workers simultaneously try TFTP/HTTP downloads
   - Cache check: Skips previously attempted files
   - Backoff protection: Automatically slows down if TFTP server shows errors
   - Protocol fallback: Tries TFTP first, falls back to HTTP
5. **Credential Extraction**: Parses XML configs for SSH credentials, passwords, usernames
6. **Database Storage**: Caches all results to prevent redundant requests

### Default TFTP File Enumeration

In addition to per-device `SEP<MAC>.cnf.xml` files, the tool always attempts to pull these well-known CUCM default files from each discovered TFTP server — no extra flag required:

- `XMLDefault.cnf.xml`
- `SEPDefault.cnf.xml`
- `SIPDefault.cnf`
- `ITLFile.tlv`
- `CTLFile.tlv`
- `RingList.xml`
- `Ringlist-wb.xml`
- `DistinctiveRingList.xml`
- `jabber-config.xml`

These can surface firmware versions, trust-list presence, Jabber bootstrap configuration, and other recon-relevant metadata. Results are cached in the SQLite database and visible via `--show-db`. Credentials found in default files are keyed by filename (e.g. `XMLDefault`, `ITLFile.tlv`) rather than a device MAC address.

## Setup

### Using uv (recommended)

```bash
uv sync
uv run thief --help
```

Or install as a global CLI tool:

```bash
uv tool install .
thief --help
```

### Using pip

```bash
pip install .
thief --help
```

## Performance

- **Multi-threading**: 40 parallel workers process 4,096 MAC variations efficiently
- **Intelligent caching**: Database prevents re-downloading the same files
- **Automatic throttling**: Backoff manager protects TFTP server from overload
- **Protocol optimization**: TFTP (fast) with HTTP fallback (reliable)
