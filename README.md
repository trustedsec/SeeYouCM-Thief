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
- **Credential verification**: replay harvested credential pairs against the CUCM CCMAdmin portal, with a full audit trail of timestamped attempts

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

`--userenum` also harvests the full corporate directory from `/cucm-uds/users` — names (including nickname), phone/home/mobile/pager numbers, email, directory URI, MS URI, department, title, manager, and the per-user UUID — and stores it in the database (`uds_directory` table). This is the same anonymously-readable data phones use for the Directory button, so it works without credentials. View it later with `--show-db`. The directory is always written to `cucm_directory.csv` (override with `--directory-outfile`).

### Harvest the unauthenticated directory (`--directory`)

Pull the CUCM corporate directory from the unauthenticated UDS endpoint
`/cucm-uds/users`, without the device probing, config downloads, or password
spraying that `--userenum` performs. Every field the endpoint exposes is
captured: username, first/middle/last/nick/display name, extension
(`phoneNumber`), home/mobile/pager numbers, email, directory URI, MS URI,
department, title, manager, and the per-user UUID.

```bash
uv run thief --directory -H <cucm-host>
```

Results are always written to `cucm_directory.csv` (override with
`--directory-outfile`), printed as a console summary table, and stored in the
`uds_directory` table unless `--no-db` is set.

**Note on DIDs:** the unauthenticated UDS directory has no dedicated DID field.
The `phoneNumber` element is the directory number / extension, which in some
dial plans is itself the full DID. True external DIDs require authenticated AXL
access and are out of scope for this unauthenticated path.

### Authenticated Device Discovery

Authenticate to the UDS API with a single end-user credential, enumerate **all** users from `/cucm-uds/users`, then query each user's associated SEP devices with that one credential. The discovered SEPs are deduped, and every config is downloaded and parsed for credentials:

```bash
./thief.py -H <CUCM Server> --uds-devices --uds-user jdoe --uds-password 'Passw0rd!'
```

Authorization reality: a standard end user can usually only read their own record, so on a strict server most users return *denied* and you mainly recover the authenticated user's own devices; on permissive or privileged setups you get the full set. The run prints an ok/denied/error tally so you can see how the server responded.

For each user the sweep queries **both** `/cucm-uds/user/{id}` and `/cucm-uds/user/{id}/devices` and unions the SEP names, so a host that misconfigures authorization on one endpoint but not the other still yields devices. This roughly doubles the request volume per user — tune with `-T/--threads`.

`--uds-devices` requires `-H/--host`, `--uds-user`, and `--uds-password`. It needs **only end-user credentials** — no CCM Admin or AXL access is required. It honors `--uds-port` (default: 8443), `--no-db`, and `-T/--threads` for sweep concurrency.

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

### Verify Credentials

Take the credential pairs already harvested into the database and test them against the CUCM administration portal (CCMAdmin), recording every attempt for auditing:

```bash
./thief.py --verify                     # every stored pair vs every known host
./thief.py --verify -H <CUCM Server>    # restrict to a single host
./thief.py --verify --verify-port 443   # CCMAdmin on 443 instead of the 8443 default
```

`--verify` reads every `credentials` row that has both a username and a password, dedupes to distinct pairs, and attempts a CCMAdmin form login (Tomcat `j_security_check`) for the **cross-product** of those pairs against every CUCM host known to the database (the union of harvested credential hosts, phone→CUCM mappings, and discovered cluster members). Pass `-H/--host` to narrow the host set to one target.

Every attempt — valid, invalid, or error — is written with a timestamp to the `verification_attempts` table for auditing. A `(host, username, password)` combination that already has a definitive result (`valid`/`invalid`) is skipped on later runs; `error` results (network failures, unexpected responses) are retried. Confirmed admin logins print live (`[+] VALID admin: user@host`) and surface in `--show-db` under "Verified Admin Credentials". Tune concurrency with `--verify-threads` (default: 10).

`--verify` requires the database (incompatible with `--no-db`) and is mutually exclusive with `--brute-mac` and `--spray`. As with the other features, plaintext passwords are stored in `thief.db`, which is created `chmod 0600`.

**Operator safety:** CCMAdmin login failures count against CUCM/AD account-lockout policy. Confirm the lockout threshold before running broad cross-product verification against production.

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
- `-b, --brute-mac`: Brute force MAC variations (4,096 combinations per phone). If no `-p` phones are given, reuses MAC prefixes discovered on a previous scan from the database (unless `--no-db`)
- `--force`: Bypass cache and force re-download of all configuration files
- `--userenum`: Extract usernames via CUCM User Data Services (UDS) API (paginates the full directory) and harvest the full directory records (names incl. nickname, phone/home/mobile/pager numbers, email, directory URI, MS URI, department, title, manager, UUID) into the `uds_directory` table; always writes `cucm_directory.csv` (override with `--directory-outfile`)
- `--directory`: Harvest the unauthenticated CUCM corporate directory from `/cucm-uds/users` without any device probing or config downloads — requires `-H`; always writes `cucm_directory.csv` (override with `--directory-outfile`), prints a console table, and stores to `uds_directory` unless `--no-db`
- `--directory-outfile FILENAME`: Override the default CSV output path for `--directory` and `--userenum` (default: `cucm_directory.csv`)
- `--servers`: Enumerate CUCM cluster members (hostnames + IPs) via UDS `/cucm-uds/servers` — requires `-H`
- `--http`: Use HTTP (port 6970) as the primary config download protocol with TFTP fallback (default: TFTP first, HTTP fallback)
- `--uds-port PORT`: Override the CUCM UDS API HTTPS port for `--userenum` (default: 8443)
- `--uds-devices`: Authenticate to the UDS API with one end-user credential, enumerate **all** users, query each user's associated SEP devices with that credential, then dedupe and download + parse every discovered config (requires `-H`, `--uds-user`, and `--uds-password`; needs only end-user credentials — no admin/AXL access; prints an ok/denied/error tally)
- `--uds-user USERNAME`: End-user username for `--uds-devices` authentication
- `--uds-password PASSWORD`: End-user password for `--uds-devices` authentication
- `--spray`: Password-spray the UDS API (requires `-H`; mutually exclusive with `--brute-mac`)
- `--spray-password PASSWORD`: Single password to spray across all eligible users
- `-P, --passwords FILE`: Password list file; sprays each password in turn, sleeping ~1h between rounds
- `--spray-threads N`: Concurrent spray workers (default: 10)
- `--spray-rate-limit-hours N`: Per-username rate-limit window in hours (default: 1)
- `--no-spray-probe`: Skip the pre-flight oracle probe (use only after manual verification)
- `--verify`: Verify stored credential pairs against each known CUCM CCMAdmin portal (requires the database; mutually exclusive with `--brute-mac` and `--spray`)
- `--verify-port PORT`: CCMAdmin HTTPS port for `--verify` (default: 8443; some clusters use 443)
- `--verify-threads N`: Concurrent verification workers (default: 10)

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
