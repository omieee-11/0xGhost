import subprocess
import sys
import time
import json
import urllib.request
from pathlib import Path

def run_command(args, timeout=600):
    """Executes a CLI tool and captures stdout/stderr cleanly."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout expired for command: {' '.join(args)}")
        return ""
    except Exception as e:
        print(f"[!] Error running {' '.join(args)}: {str(e)}")
        return ""

def query_crt_sh(target):
    """Fetch subdomains passively from crt.sh API."""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(target) and '*' not in sub:
                            subdomains.add(sub)
    except Exception as e:
        print(f"[!] crt.sh query failed: {e}")
    return list(subdomains)

def phase_1_osint(target, output_dir):
    """Phase 1: Passive Recon & Subdomain Enumeration."""
    print(f"[START] Phase 1: OSINT & Subdomain Discovery for {target}")
    discovered_subdomains = set()

    # 1. Subfinder
    print("[*] Running Subfinder...")
    subfinder_raw = run_command(['subfinder', '-d', target, '-silent'])
    for line in subfinder_raw.splitlines():
        if line.strip():
            discovered_subdomains.add(line.strip().lower())

    # 2. crt.sh API
    print("[*] Fetching from crt.sh...")
    crt_subs = query_crt_sh(target)
    discovered_subdomains.update(crt_subs)

    # 3. Amass (Passive mode for speed & reliability)
    print("[*] Running Amass...")
    amass_raw = run_command(['amass', 'enum', '-passive', '-d', target, '-silent'])
    for line in amass_raw.splitlines():
        if line.strip():
            discovered_subdomains.add(line.strip().lower())

    # Always ensure root target is in the list
    discovered_subdomains.add(target.lower())

    subs_list = sorted(list(discovered_subdomains))
    
    # Save raw subdomains to text file for pipe-compatible tools
    subs_file = Path(output_dir) / f"{target}_subdomains.txt"
    with open(subs_file, 'w') as f:
        f.write('\n'.join(subs_list))

    print(f"[+] Found {len(subs_list)} unique subdomains.")
    return subs_list, subs_file

def phase_2_probing(target, subs_file):
    """Phase 2: Live Web Host Probing via HTTPX."""
    print(f"[START] Phase 2: Live Web Host & Service Probing for {target}")
    live_hosts = []

    # Run httpx with JSON output
    httpx_raw = run_command([
        'httpx', '-l', str(subs_file),
        '-silent', '-json',
        '-title', '-tech-detect', '-status-code', '-ip'
    ])

    for line in httpx_raw.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            live_hosts.append({
                "subdomain": entry.get("input", entry.get("url", "")),
                "url": entry.get("url", ""),
                "title": entry.get("title", "N/A"),
                "status_code": entry.get("status_code", 0),
                "ip": entry.get("host", entry.get("ip", "N/A")),
                "tech": entry.get("technologies", [])
            })
        except json.JSONDecodeError:
            continue

    print(f"[+] Probed {len(live_hosts)} active HTTP services.")
    return live_hosts

def phase_3_takeover(target, subs_file):
    """Phase 3: Subdomain Takeover Check via Subzy."""
    print(f"[START] Phase 3: Subdomain Takeover Check for {target}")
    takeovers = []

    subzy_raw = run_command(['subzy', 'run', '--targets', str(subs_file), '--hide_fails'])
    for line in subzy_raw.splitlines():
        if "VULNERABLE" in line.upper():
            takeovers.append({"log": line.strip(), "status": "vulnerable"})

    print(f"[+] Subdomain takeover check completed. ({len(takeovers)} issues detected)")
    return takeovers

def run_osint_scan(target, output_dir="scan_results"):
    """Main execution function designed to be imported or run standalone."""
    start_time = time.time()
    out_path = Path(output_dir)
    out_path.mkdir(exist_ok=True)

    # Execute phases
    subdomains, subs_file = phase_1_osint(target, out_path)
    live_hosts = phase_2_probing(target, subs_file)
    takeovers = phase_3_takeover(target, subs_file)

    elapsed = time.time() - start_time

    # Construct unified JSON payload for Dashboard/API consumption
    results = {
        "target": target,
        "scan_type": "OSINT & Subdomain Discovery",
        "elapsed_seconds": round(elapsed, 2),
        "total_subdomains": len(subdomains),
        "total_live_hosts": len(live_hosts),
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "takeover_findings": takeovers
    }

    # Save structured JSON
    json_output_path = out_path / f"{target}_osint_results.json"
    with open(json_output_path, 'w') as f:
        json.dump(results, f, indent=4)

    print(f"\n[+] OSINT Scan finished in {elapsed:.2f}s. Results saved to {json_output_path}")
    return results

if __name__ == "__main__":
    target_input = input("Enter Target IP/Domain: ").strip()
    if target_input:
        run_osint_scan(target_input)
    else:
        print("[-] No target specified.")
