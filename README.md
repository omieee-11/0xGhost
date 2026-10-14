# 0xGhost

> Automated OSINT and web security report generator for authorized security assessments.

0xGhost is a Python-based reconnaissance and web-security scanning toolkit. It combines passive OSINT, subdomain discovery, live-host probing, network-service enumeration, vulnerability checks, web-security audits, and content discovery into a single pipeline. Results are exported as structured JSON files and can also be viewed through a lightweight Flask dashboard.

> **Important:** Only scan systems, domains, and IP addresses that you own or have explicit permission to test. Some features perform active probing, directory brute-forcing, vulnerability testing, and network scanning. Unauthorized scanning may be illegal or disruptive.

## Contents

- [Features](#features)
- [Project architecture](#project-architecture)
- [Repository structure](#repository-structure)
- [Scan pipeline](#scan-pipeline)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the command-line pipeline](#running-the-command-line-pipeline)
- [Running individual phases](#running-individual-phases)
- [Running the web dashboard](#running-the-web-dashboard)
- [Running with Docker](#running-with-docker)
- [Using GitHub Actions](#using-github-actions)
- [Output files](#output-files)
- [Configuration and tuning](#configuration-and-tuning)
- [Troubleshooting](#troubleshooting)
- [Security and responsible use](#security-and-responsible-use)
- [Development notes](#development-notes)
- [License](#license)

## Features

### Passive OSINT and subdomain discovery

`OSINT.PY` collects subdomains from several passive sources:

- ProjectDiscovery Subfinder
- crt.sh certificate-transparency data
- OWASP Amass in passive mode

It then probes discovered hosts with HTTPX to identify live services, titles, status codes, IP addresses, and detected technologies. The phase also checks for possible subdomain takeover indicators with Subzy.

### Network-service scanning

`NET.py` provides Nmap-based scanning through three profiles:

- `FAST_TOP_100` — fast scan of common ports with service detection.
- `WEB_DB_SERVICE` — focused scan of common web, SSH, FTP, and database ports.
- `DEEP_VULN` — Nmap vulnerability-script scan.

The scanner can use the `python-nmap` bindings and falls back to the Nmap command-line interface when the Python binding is unavailable or fails.

### Vulnerability scanning

`VULN.py` wraps Nuclei and CORStest for common web-application checks:

- Exposed admin panels
- Exposed secrets, Git repositories, configuration files, tokens, and backups
- XSS detection
- SQL injection detection
- SSRF detection
- CORS misconfiguration checks

### Web-security auditing

`SECURITY.py` performs application-security checks including:

- HTTP security-header auditing
- SSL/TLS certificate and configuration checks through testssl.sh
- Clickjacking checks using Nuclei

The HTTP audit checks headers such as `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.

### Content and historical discovery

`LAST.py` discovers additional attack-surface information with:

- FFUF directory and file brute-forcing
- Katana JavaScript and endpoint extraction
- Waybackurls archived URLs
- Gau historical URLs from public archives

### Web dashboard and API

`app.py` serves `index.html` through Flask. The dashboard allows an operator to submit a target, monitor a background job, and display the generated JSON report.

Available endpoints include:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Serves the dashboard. |
| `POST` | `/api/scan` | Starts a scan. JSON body: `{ "target": "example.com" }`. |
| `GET` | `/api/status/<job_id>` | Returns the current job status. |
| `GET` | `/api/result/<job_id>` | Returns the completed report. |
| `GET` | `/api/latest` | Returns the latest root-level `results.json`, when present. |

## Project architecture

The project has two main execution modes:

1. **CLI mode** — `main.py` runs the five phase scripts sequentially and creates a master `results.json` report.
2. **Dashboard mode** — `app.py` accepts a scan request through Flask, starts the pipeline in a background thread, and exposes status and results through HTTP endpoints.

The normal CLI pipeline is:

```text
Target
  |
  v
main.py
  |
  +--> OSINT.PY     Phase 1: passive OSINT and subdomains
  +--> NET.py       Phase 2: Nmap network scanning
  +--> VULN.py      Phase 3: vulnerability checks
  +--> SECURITY.py  Phase 4: web-security audits
  +--> LAST.py      Phase 5: content and historical discovery
  |
  v
scan_results/*.json + results.json
```

Each phase writes structured JSON into `scan_results/`. `main.py` then loads all JSON files in that directory and places them under the `scans` field of the master report.

## Repository structure

```text
0xGhost/
├── README.md              # Project documentation
├── main.py                # Master CLI orchestrator and report generator
├── app.py                 # Flask web API and dashboard server
├── index.html             # Browser dashboard UI
├── OSINT.PY               # Phase 1: passive OSINT and subdomain discovery
├── NET.py                 # Phase 2: Nmap-based network-service scanning
├── VULN.py                # Phase 3: Nuclei and CORStest vulnerability scanning
├── SECURITY.py            # Phase 4: HTTP, TLS, and clickjacking checks
├── LAST.py                # Phase 5: FFUF, Katana, Waybackurls, and Gau discovery
├── requirements.txt       # Python dependencies
├── install.sh             # Debian/Kali installation helper and 0xghost wrapper
├── Dockerfile             # Kali Linux container image definition
├── docker-compose.yml     # Container build, port, and volume configuration
└── run_scan.yml           # Manual GitHub Actions pipeline definition
```

### `main.py`

The central orchestrator. It:

- Checks whether expected external tools are available.
- Runs `OSINT.PY`, `NET.py`, `VULN.py`, `SECURITY.py`, and `LAST.py` in order.
- Captures each script's stdout, stderr, and return code.
- Records missing tools without immediately stopping the complete pipeline.
- Collects JSON files from `scan_results/`.
- Writes `results.json` with timestamps, tool availability, execution logs, and phase results.

Run it with a target argument or use its interactive prompt.

### `app.py`

The Flask service. It maintains an in-memory `JOBS` dictionary, starts scans in daemon threads, and exposes status/result endpoints. Job state is not persisted, so restarting the Flask process removes active jobs from memory.

### `index.html`

A self-contained dark-themed dashboard. It submits targets to `/api/scan`, polls `/api/status/<job_id>` every three seconds, and renders the returned report as a summary table plus formatted JSON.

### `OSINT.PY`

Implements the passive reconnaissance phase. Its main public entry point is `run_osint_scan(target, output_dir="scan_results")`. It saves a subdomain text file and an OSINT JSON report.

### `NET.py`

Defines `NmapScanner`, `ScanManager`, `ScanResult`, and the `SCAN_PROFILES` configuration. It supports multiple targets and profiles concurrently using `ThreadPoolExecutor`.

### `VULN.py`

Defines `NucleiScanner`, `VulnerabilityScanManager`, `ScanResult`, and `VULN_PROFILES`. It parses JSON output from Nuclei and detects CORS issues using CORStest.

### `SECURITY.py`

Defines `HTTPHeaderScanner`, `SSLScanner`, `ClickjackingScanner`, and `SecurityScanManager`. It produces findings with statuses, severities, evidence, and error messages.

### `LAST.py`

Defines discovery scanners for FFUF, Katana, Waybackurls, and Gau. It runs selected profiles concurrently and stores phase-five results per target.

### `requirements.txt`

Python packages used by the project:

- Flask
- requests
- beautifulsoup4
- urllib3
- python-nmap
- tqdm

Several scanners are external command-line tools and must be installed separately.

### `install.sh`

A Debian/Kali-oriented helper that clones or updates the repository at `~/0xGhost`, installs system and Python dependencies, creates `.venv`, installs a global `/usr/local/bin/0xghost` wrapper, and immediately runs a scan.

The script uses `sudo`, `apt`, and `dpkg`, so it is intended for Debian-based systems rather than Windows or macOS.

### `Dockerfile` and `docker-compose.yml`

The Docker image is based on `kalilinux/kali-rolling`. It installs Python, Nmap, FFUF, Go, and several ProjectDiscovery/archive tools. Docker Compose maps port `8080` and mounts the repository into `/opt/0xGhost` so generated results remain available on the host.

### `run_scan.yml`

A manually triggered GitHub Actions pipeline. It accepts a target, installs Python and several security tools, runs `main.py`, and attempts to commit `results.json` and `scan_results/` back to the repository.

For GitHub Actions to discover it automatically, place it under `.github/workflows/`, for example `.github/workflows/run_scan.yml`.

## Scan pipeline

The master pipeline executes these scripts in order:

| Phase | Script | Main purpose | Typical tools |
|---:|---|---|---|
| 1 | `OSINT.PY` | Passive subdomain discovery and live-host probing | Subfinder, crt.sh, Amass, HTTPX, Subzy |
| 2 | `NET.py` | Port and service enumeration | Nmap, python-nmap |
| 3 | `VULN.py` | Web vulnerability checks | Nuclei, CORStest |
| 4 | `SECURITY.py` | Headers, TLS, and clickjacking audits | Python urllib, testssl.sh, Nuclei |
| 5 | `LAST.py` | Endpoint, directory, JavaScript, and archive discovery | FFUF, Katana, Waybackurls, Gau |

Missing tools are reported by `main.py`, but individual phases may produce incomplete or failed results when their required binaries are unavailable.

## Requirements

### Recommended operating system

- Kali Linux, or
- Debian/Ubuntu with the required security tools installed.

Docker is recommended when you want a repeatable environment.

### Python

Use Python 3.10 or newer when possible. The included GitHub Actions workflow explicitly uses Python 3.10.

### External tools

The pipeline expects these commands to be available on `PATH`:

```text
subfinder
amass
httpx
katana
nuclei
gau
waybackurls
ffuf
nmap
testssl.sh
corstest
subzy
sqlmap
```

Not every tool is installed by every setup path. The Dockerfile and GitHub Actions workflow install only a subset, so install the remaining tools required by the phases you plan to run.

## Installation

### Option 1: Clone and use a virtual environment

```bash
git clone https://github.com/omieee-11/0xGhost.git
cd 0xGhost

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install the external security tools separately and verify them:

```bash
for tool in subfinder amass httpx katana nuclei gau waybackurls ffuf nmap testssl.sh corstest subzy sqlmap; do
  command -v "$tool" || echo "Missing: $tool"
done
```

### Option 2: Use the installation script on Debian/Kali

```bash
curl -fsSL https://raw.githubusercontent.com/omieee-11/0xGhost/main/install.sh -o install.sh
chmod +x install.sh
./install.sh example.com
```

The script installs packages with `apt`, creates a virtual environment, and adds the `0xghost` command. Review scripts downloaded from the internet before executing them in a privileged environment.

## Running the command-line pipeline

Run a complete scan with a target argument:

```bash
source .venv/bin/activate
python3 main.py example.com
```

Or run interactively:

```bash
python3 main.py
```

The command exits with status `0` when all phases complete without reported errors. It exits with status `2` when a phase fails or is skipped. Partial reports may still be available when the exit status is non-zero.

The master report is written to:

```text
results.json
```

Per-phase files are written to:

```text
scan_results/
```

## Running individual phases

### OSINT and subdomain discovery

`OSINT.PY` accepts the target interactively:

```bash
python3 OSINT.PY
```

It asks for a domain or IP and writes files such as:

```text
scan_results/example.com_subdomains.txt
scan_results/example.com_osint_results.json
```

### Network scanning

Fast scan of the top common ports:

```bash
python3 NET.py -t example.com -p FAST_TOP_100
```

Scan common web and database services:

```bash
python3 NET.py -t example.com -p WEB_DB_SERVICE
```

Run the Nmap vulnerability-script profile with controlled concurrency:

```bash
python3 NET.py \
  --targets example.com,192.0.2.10 \
  --profiles DEEP_VULN \
  --concurrency 4
```

### Vulnerability scanning

Run default admin-panel and exposed-secret checks:

```bash
python3 VULN.py -t https://example.com
```

Run selected profiles:

```bash
python3 VULN.py \
  --targets https://example.com \
  --profiles ADMIN_PANELS EXPOSED_SECRETS XSS_PROBING CORS_AUDIT \
  --concurrency 5
```

Available profiles are `ADMIN_PANELS`, `EXPOSED_SECRETS`, `XSS_PROBING`, `SQLI_DETECTION`, `SSRF_DETECTION`, and `CORS_AUDIT`.

### Web-security checks

Run the HTTP header audit:

```bash
python3 SECURITY.py -t https://example.com
```

Run multiple security profiles:

```bash
python3 SECURITY.py \
  --targets https://example.com \
  --profiles HTTP_HEADERS SSL_TLS_AUDIT CLICKJACKING_TEST \
  --concurrency 5
```

### Content and historical discovery

Run directory discovery:

```bash
python3 LAST.py -t https://example.com -p DIRECTORY_BRUTE
```

Run all discovery profiles:

```bash
python3 LAST.py \
  --targets https://example.com \
  --profiles DIRECTORY_BRUTE JS_ASSET_EXTRACTION URL_SCRAPING HISTORICAL_ARCHIVES \
  --concurrency 5
```

FFUF requires a wordlist. The code first checks `/usr/share/wordlists/dirb/common.txt` and then `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`.

## Running the web dashboard

Install the Python dependencies, then start Flask:

```bash
source .venv/bin/activate
python3 app.py
```

Open the dashboard at:

```text
http://127.0.0.1:8080
```

To start a scan through the API:

```bash
curl -X POST http://127.0.0.1:8080/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'
```

The response contains a `job_id`. Poll the status endpoint:

```bash
curl http://127.0.0.1:8080/api/status/JOB_ID
```

When the status becomes `done`, retrieve the report:

```bash
curl http://127.0.0.1:8080/api/result/JOB_ID
```

### Dashboard limitations

- Job state is held in memory and disappears when the process restarts.
- There is no authentication or authorization layer in the Flask app. Do not expose it directly to the public internet.
- The dashboard is intended for trusted local or private-network use.
- Review and test the dashboard integration before production use; the current `app.py` calls `run_pipeline` with a `results_dir` keyword while the current `main.py` defines `timeout_per_script` as its second parameter.

## Running with Docker

Build and start the dashboard using Docker Compose:

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8080
```

Run the container in the background:

```bash
docker compose up --build -d
```

View logs:

```bash
docker compose logs -f 0xghost
```

Stop the service:

```bash
docker compose down
```

The Compose configuration mounts the current repository into `/opt/0xGhost`, so reports created in the container are available in the working directory on the host.

## Using GitHub Actions

`run_scan.yml` is designed for a manually requested scan. Move it to `.github/workflows/run_scan.yml`, commit it, and then use the **Run workflow** action from GitHub Actions.

The workflow:

1. Checks out the repository.
2. Installs Python 3.10.
3. Installs selected Debian and Go security tools.
4. Runs `python3 main.py` with the supplied target.
5. Commits `results.json` and `scan_results/` back to the repository.

Before enabling it, review repository permissions and consider whether scan results may contain sensitive information. The workflow requests `contents: write`, which allows it to push generated results.

## Output files

### Master report: `results.json`

The master report contains fields similar to:

```json
{
  "target": "example.com",
  "started_at": "2026-01-01T00:00:00Z",
  "finished_at": "2026-01-01T00:30:00Z",
  "missing_tools": [],
  "tool_check_details": {
    "nmap": true,
    "nuclei": true
  },
  "run_log": [],
  "scans": {}
}
```

The `run_log` records each phase's command result, return code, stdout, stderr, and whether it was skipped. The `scans` object contains JSON documents collected from `scan_results/`.

### Phase reports

Depending on the target and phase, files can include:

```text
scan_results/<target>_subdomains.txt
scan_results/<target>_osint_results.json
scan_results/<target>_net_results.json
scan_results/<target>_vuln_results.json
scan_results/<target>_phase4_results.json
scan_results/<target>_phase5_results.json
```

Target names that contain URL prefixes or paths may be normalized differently by individual phase scripts.

## Configuration and tuning

Most settings are constants near the top of each phase file. Examples include:

- `main.py`: per-script timeout and expected external tools.
- `NET.py`: Nmap timeouts, concurrency, and scan profiles.
- `VULN.py`: Nuclei, SQLMap, and CORStest timeouts plus concurrency.
- `SECURITY.py`: HTTP/TLS timeouts, request delays, and security headers.
- `LAST.py`: discovery-tool timeouts, delays, and worker count.

When scanning multiple targets, reduce concurrency if the target environment or local system cannot safely handle parallel requests. Increasing concurrency can increase speed but also increases load and may trigger defensive controls.

## Troubleshooting

### `command not found`

A required external binary is not installed or is not on `PATH`:

```bash
command -v nmap
command -v nuclei
command -v subfinder
```

Install the missing tool and rerun the relevant phase.

### Partial results

`main.py` intentionally reports missing tools and continues. Check both the terminal output and `results.json`, especially `missing_tools`, `tool_check_details`, and `run_log`.

### Nmap permission or execution errors

Confirm that Nmap is installed and usable directly:

```bash
nmap -F example.com
```

Some scan modes may require additional privileges depending on the operating system and Nmap arguments.

### FFUF cannot find a wordlist

Install a suitable wordlist package or edit the wordlist paths in `LAST.py`. The default paths are:

```text
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### Dashboard scan errors

Check the Flask terminal output and verify that the dashboard and orchestrator interfaces match. In the current code, `app.py` passes `results_dir=RESULTS_DIR` to `run_pipeline`, while `main.py` currently accepts `target` and `timeout_per_script`. Align those function signatures before relying on dashboard-triggered scans.

### GitHub Actions cannot find the workflow

GitHub only loads workflow files from `.github/workflows/`. Move `run_scan.yml` into that directory and commit the change.

## Security and responsible use

0xGhost can send requests to remote systems and run active security tests. Use it only when:

- You own the target, or
- You have clear written authorization to test it.

Recommended operational safeguards:

- Start with passive reconnaissance.
- Use test environments whenever possible.
- Confirm scope, rate limits, and testing windows before scanning.
- Avoid scanning third-party infrastructure without permission.
- Treat generated reports as sensitive because they may contain hostnames, IP addresses, URLs, technology details, and vulnerability evidence.
- Do not commit private findings to a public repository.
- Add authentication, access control, and network restrictions before deploying the dashboard beyond a trusted environment.

## Development notes

The codebase is organized as independent phase modules with dataclasses and JSON-oriented exports. A practical extension pattern is:

1. Add a scanner class and profile configuration to the relevant phase module.
2. Return a phase-specific `ScanResult` object.
3. Add the profile to the CLI choices.
4. Export results into `scan_results/`.
5. Verify that `main.py` can collect the generated JSON.
6. Update this README with the new tool, profile, output file, and installation requirement.

Before opening a pull request, test the changed phase directly and then run a controlled end-to-end scan against an authorized target.

## License

No license file is currently included in the repository. Until a license is added, all rights remain with the copyright holder, and reuse or redistribution should be confirmed with the repository owner.
