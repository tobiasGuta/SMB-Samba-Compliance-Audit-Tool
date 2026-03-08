# SMB Audit Tool

A command-line SMB/Samba compliance and audit tool built on top of [impacket](https://github.com/fortra/impacket). It connects to a target over SMB, enumerates shares, tests read/write permissions, retrieves password policies, discovers users and groups, identifies active sessions, spiders for sensitive files, runs vulnerability heuristics, and can view remote files directly in the terminal all from a single script.

Output is rendered with [rich](https://github.com/Textualize/rich) tables, panels, and trees. Findings can also be exported to structured JSON for further processing.

---

## Features

- **Share enumeration and permission auditing** lists every share and tests read/write access.
- **Password policy retrieval** queries minimum length, complexity, lockout thresholds via SAMR.
- **User and group enumeration** discovers local accounts and group memberships via SAMR.
- **Active session enumeration** lists connected users, source IPs, and idle times via SRVSVC.
- **Backup / sensitive file discovery (spider)** recursively walks shares matching a regex for high-value files (.bak, .sql, .kdbx, .pem, .key, id_rsa, web.config, etc.).
- **Auto-download** optionally downloads matched files under a configurable size limit.
- **Vulnerability heuristics** flags NTLM relay risk (signing disabled), MS17-010 (SMBv1), and CVE-2020-0796 / SMBGhost (SMBv3.1.1).
- **Remote file viewer** view a remote file in the terminal with syntax highlighting (--cat).
- **SMB dialect and signing detection** detects the negotiated dialect and whether signing is enforced.
- **Multiple auth methods** password, NTLM pass-the-hash, null session, and guest login.
- **Threaded spidering** concurrent share crawling for faster results.
- **JSON export** structured output for integration with other tools or reporting pipelines.

---

## Requirements

- Python 3.10+
- [impacket](https://github.com/fortra/impacket)
- [rich](https://github.com/Textualize/rich)

### Install dependencies

```bash
pip install impacket rich
```

---

## Usage

```
python3 smb_audit.py <TARGET> [options]
```

The only required argument is the target IP or hostname. If no audit module is specified, `--shares` is run by default.

---

## Authentication

| Flag | Description |
|------|-------------|
| `-u`, `--username` | Username for authentication |
| `-p`, `--password` | Password for authentication |
| `-d`, `--domain` | Domain or workgroup (default: `.`) |
| `--hashes LMHASH:NTHASH` | NTLM hash pair for pass-the-hash |
| `--null-session` | Attempt anonymous / null session login |
| `--guest` | Fall back to Guest account if primary auth fails |

Authentication is attempted in order: explicit credentials first, then null session, then guest.

---

## Audit Modules

| Flag | Description |
|------|-------------|
| `--shares` | Enumerate shares and test read/write permissions |
| `--policy` | Query domain/local password policy via SAMR |
| `--users` | Enumerate local users and groups via SAMR |
| `--sessions` | List active SMB sessions (requires admin) |
| `--vulns` | Run vulnerability heuristics (signing, legacy dialects) |
| `--spider` | Spider accessible shares for sensitive/backup files |
| `--all` | Run every module above at once |

---

## Protocol Options

| Flag | Description |
|------|-------------|
| `--smb-version` | Force a specific dialect: `SMBv1`, `SMBv2`, `SMBv2.1`, `SMBv3`, `SMBv3.1.1` |
| `--timeout` | Connection timeout in seconds (default: 10) |
| `--port` | SMB port (default: 445) |

---

## Spider / Backup Discovery Options

| Flag | Description |
|------|-------------|
| `--spider` | Enable recursive share spidering |
| `--spider-regex PATTERN` | Custom regex for matching filenames. If omitted, a built-in set of high-value signatures is used |
| `--spider-depth N` | Maximum recursion depth (default: 5) |
| `--spider-exclude SHARE [...]` | Shares to skip (default: `IPC$`) |
| `--download` | Download matched files that are under `--max-size` |
| `--max-size BYTES` | Max file size for auto-download (default: 10485760 / 10 MB) |
| `--download-dir DIR` | Where to save downloaded files (default: `./loot`) |
| `--list-files` | Also list every file found while spidering, not only regex matches |

The default regex matches: `.bak`, `.sql`, `.db`, `.kdbx`, `.config`, `.xml`, `.env`, `.ps1`, `.pem`, `.key`, `.pfx`, `id_rsa`, `web.config`, `unattend.xml`.

---

## File Operations

| Flag | Description |
|------|-------------|
| `--cat SHARE/PATH` | View a remote file in the terminal with syntax highlighting |

Files larger than 1 MB are rejected with a warning -- use `--download` for large files. Format: `SHARE_NAME/path/to/file`.

---

## Output Options

| Flag | Description |
|------|-------------|
| `--json FILE` | Export all findings to a JSON file |
| `-v` | Increase verbosity (INFO level) |
| `-vv` | Debug verbosity |

---

## Performance

| Flag | Description |
|------|-------------|
| `--threads N` | Number of threads for concurrent share spidering (default: 4) |

---

## Examples

### Basic share enumeration with password auth

```bash
python3 smb_audit.py 192.168.1.10 -u admin -p Password1
```

### Pass-the-hash authentication

```bash
python3 smb_audit.py 10.0.0.5 -u admin --hashes aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
```

### Null session with forced SMBv1

```bash
python3 smb_audit.py 10.0.0.5 --null-session --smb-version SMBv1
```

### Run all audit modules and export to JSON

```bash
python3 smb_audit.py 10.0.0.5 -u admin -p Pass1 --all --json report.json
```

### Spider shares and auto-download matches

```bash
python3 smb_audit.py 10.0.0.5 -u admin -p Pass1 --spider --download --json report.json
```

### Spider with a custom regex and size limit

```bash
python3 smb_audit.py 10.0.0.5 -u admin -p Pass1 --spider --spider-regex '(?i).*\.(docx|xlsx|pdf)$' --download --max-size 5242880
```

### Spider and list every file (not just matches)

```bash
python3 smb_audit.py 10.0.0.5 -u admin -p Pass1 --spider --list-files
```

### Enumerate shares only

```bash
python3 smb_audit.py 192.168.1.10 -u admin -p Pass1 --shares
```

### Retrieve password policy

```bash
python3 smb_audit.py 192.168.1.10 -u admin -p Pass1 --policy
```

### Enumerate users and groups

```bash
python3 smb_audit.py 192.168.1.10 -u admin -p Pass1 --users
```

### List active sessions (requires admin)

```bash
python3 smb_audit.py 192.168.1.10 -u admin -p Pass1 --sessions
```

### Run vulnerability heuristics only

```bash
python3 smb_audit.py 192.168.1.10 -u admin -p Pass1 --vulns
```

### View a remote file

```bash
python3 smb_audit.py 192.168.1.10 -u admin -p Pass1 --cat Data/config/web.config
```

### Guest login with verbose output

```bash
python3 smb_audit.py 192.168.1.10 --guest -v
```

### Combine multiple modules

```bash
python3 smb_audit.py 10.0.0.5 -u admin -p Pass1 --shares --policy --vulns --json audit.json
```

---

## Screenshot

<img width="1765" height="464" alt="image" src="https://github.com/user-attachments/assets/01975e4f-98ec-45ea-9fb1-0b118bcb3187" />

<img width="1762" height="542" alt="image" src="https://github.com/user-attachments/assets/36182697-2c57-4f83-9739-491e2a5985c3" />

<img width="1766" height="573" alt="image" src="https://github.com/user-attachments/assets/d9be73d4-aef9-4407-9411-a34c57c5c700" />

<img width="1765" height="559" alt="image" src="https://github.com/user-attachments/assets/801f9362-c09b-48b1-a523-109a87b9f0b6" />

<img width="1765" height="671" alt="image" src="https://github.com/user-attachments/assets/2e051e14-7993-4cb4-af5f-f5856e975ca7" />

## Output

The tool prints a structured report to the terminal:

- **Header panel** target, negotiated dialect, signing status (with risk annotations), auth method, timestamp.
- **Shares table** share name, type/remark, read and write access.
- **Password policy table** minimum length, complexity, lockout settings. Risky values are highlighted.
- **Users table**  RID, username, active/disabled status. Large domains show a summary panel instead.
- **Groups table**  RID, group name, member SIDs.
- **Sessions table**  username, source machine, active and idle times.
- **Spider tree**  matched sensitive files grouped by share, with download status.
- **All files tree**  full directory listing when `--list-files` is active.
- **Vulnerability table** detected issues with severity and remediation guidance.

When `--json` is specified, the same data is written to a structured JSON file.

---

## Disclaimer

This tool is intended for authorized security assessments and compliance audits only. Do not use it against systems you do not have explicit permission to test. The author is not responsible for any misuse.

---

## License

MIT
