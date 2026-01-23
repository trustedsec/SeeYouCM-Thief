# SeeYouCM Thief

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

### Database Operations

View cached results:

```bash
./thief.py --show-db
./thief.py --show-db -H <CUCM Server>  # Filter by CUCM
```

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
- `--userenum`: Extract usernames via CUCM User Data Services (UDS) API

### Output Options
- `--csv FILENAME`: Export discovered credentials to CSV file
- `--outfile FILENAME`: Specify output file for enumerated usernames (default: cucm_users.txt)

### Database Options
- `--db FILENAME`: Specify SQLite database for caching results (default: thief.db)
- `--no-db`: Disable database caching and operate without persistent storage
- `--show-db`: Display summary of credentials stored in database and exit

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

## Setup

### Using uv (recommended)

```bash
uv pip install -r requirements.txt
```

### Using pip

```bash
python3 -m pip install -r requirements.txt
```

## Performance

- **Multi-threading**: 40 parallel workers process 4,096 MAC variations efficiently
- **Intelligent caching**: Database prevents re-downloading the same files
- **Automatic throttling**: Backoff manager protects TFTP server from overload
- **Protocol optimization**: TFTP (fast) with HTTP fallback (reliable)
