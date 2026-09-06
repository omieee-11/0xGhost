import argparse
import json
import logging
import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Logging setup
LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(name)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("Phase3_VulnScanner")

NUCLEI_TIMEOUT = 300.0  # Host scan timeout in seconds
NUCLEI_CONCURRENCY = 25
SQLMAP_TIMEOUT = 60.0
CORSTEST_TIMEOUT = 15.0

REQUEST_DELAY_MIN = 0.2
REQUEST_DELAY_MAX = 1.0

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "curl/7.68.0"
]

VULN_PROFILES: Dict[str, Dict[str, Any]] = {
    "ADMIN_PANELS": {
        "name": "Technology Stack & Admin Panel Detection",
        "tags": "exposure-panels,panel",
        "description": "Exposed admin panels (WordPress, Grafana, Jenkins, phpMyAdmin)."
    },
    "EXPOSED_SECRETS": {
        "name": "Exposed Secrets, Git, & Config Files",
        "tags": "exposure,tokens,config",
        "description": "Publicly accessible .git/, .env, AWS keys, API secrets, and backup files."
    },
    "XSS_PROBING": {
        "name": "Cross-Site Scripting / XSS Probing",
        "tags": "xss",
        "description": "Reflected and stored XSS opportunities in input parameters."
    },
    "SQLI_DETECTION": {
        "name": "SQL Injection / SQLi Detection",
        "tags": "sqli",
        "description": "Database injection flaws on dynamic GET/POST endpoints."
    },
    "SSRF_DETECTION": {
        "name": "Server-Side Request Forgery / SSRF",
        "tags": "ssrf",
        "description": "Unvalidated URL parameters vulnerable to internal network pivoting."
    },
    "CORS_AUDIT": {
        "name": "CORS Misconfiguration Audit",
        "tool": "CORStest",
        "description": "Overly permissive Access-Control-Allow-Origin headers with credentials."
    }
}


@dataclass
class ScanResult:
    target: str
    profile_name: str
    timestamp: str
    vulnerabilities_found: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    success: bool = False


class NucleiScanner:
    """Wrapper for Nuclei CLI vulnerability scanning engine."""

    def __init__(self, concurrency: int = NUCLEI_CONCURRENCY):
        self.concurrency = concurrency

    def scan_target(self, target: str, profile_name: str, timeout: float = NUCLEI_TIMEOUT) -> ScanResult:
        profile = VULN_PROFILES.get(profile_name, {})
        timestamp = datetime.now().isoformat()
        
        # Format target URL
        url_target = target if target.startswith(("http://", "https://")) else f"https://{target}"
        
        # Handle special non-nuclei tools
        if profile.get("tool") == "CORStest":
            return self._run_corstest(url_target, profile_name, timestamp)

        tags = profile.get("tags", "")
        ua = random.choice(USER_AGENTS)

        cmd = [
            "nuclei",
            "-u", url_target,
            "-tags", tags,
            "-json-export", "-",
            "-silent",
            "-header", f"User-Agent: {ua}"
        ]

        vulnerabilities = []
        try:
            logger.info(f"Executing Nuclei scan [{profile_name}] against {url_target}...")
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    vulnerabilities.append({
                        "id": entry.get("template-id", "N/A"),
                        "title": entry.get("info", {}).get("name", "Unknown Vuln"),
                        "severity": entry.get("info", {}).get("severity", "info").upper(),
                        "description": entry.get("info", {}).get("description", ""),
                        "url": entry.get("matched-at", url_target),
                        "evidence": entry.get("extracted-results", entry.get("curl-command", ""))
                    })
                except json.JSONDecodeError:
                    continue

            time.sleep(random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX))
            return ScanResult(
                target=target,
                profile_name=profile_name,
                timestamp=timestamp,
                vulnerabilities_found=vulnerabilities,
                success=True
            )

        except subprocess.TimeoutExpired:
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, error_message="Scan Timed Out", success=False)
        except Exception as e:
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, error_message=str(e), success=False)

    def _run_corstest(self, target: str, profile_name: str, timestamp: str) -> ScanResult:
        cmd = ["corstest", "-u", target, "-t", str(int(CORSTEST_TIMEOUT))]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CORSTEST_TIMEOUT)
            found = []
            if "VULNERABLE" in proc.stdout.upper():
                found.append({
                    "id": "CORS-MISCONFIG",
                    "title": "Permissive CORS Policy",
                    "severity": "MEDIUM",
                    "description": "Target allows arbitrary origin requests with credentials.",
                    "url": target,
                    "evidence": proc.stdout[:300]
                })
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, vulnerabilities_found=found, success=True)
        except Exception as e:
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, error_message=str(e), success=False)


class VulnerabilityScanManager:
    """Orchestrates vulnerability scan jobs and exports results."""

    def __init__(self, concurrency: int = NUCLEI_CONCURRENCY):
        self.scanner = NucleiScanner(concurrency=concurrency)

    def run_vuln_scan(self, targets: List[str], profiles: List[str], output_dir: str = "scan_results") -> Dict[str, Any]:
        out_path = Path(output_dir)
        out_path.mkdir(exist_ok=True)
        results = []

        with ThreadPoolExecutor(max_workers=self.scanner.concurrency) as executor:
            futures = []
            for target in targets:
                for profile in profiles:
                    futures.append(executor.submit(self.scanner.scan_target, target, profile))

            for future in as_completed(futures):
                res = future.result()
                results.append(asdict(res))

        summary = {
            "timestamp": datetime.now().isoformat(),
            "targets": targets,
            "profiles_executed": profiles,
            "total_scans": len(results),
            "results": results
        }

        for target in targets:
            clean_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
            file_path = out_path / f"{clean_target}_vuln_results.json"
            with open(file_path, "w") as f:
                json.dump(summary, f, indent=4)

        return summary


def main():
    parser = argparse.ArgumentParser(description="Phase 3 OWASP & Vulnerability Scanner")
    parser.add_argument("--targets", "-t", type=str, required=True, help="Comma-separated target host list")
    parser.add_argument("--profiles", "-p", nargs="+", choices=list(VULN_PROFILES.keys()), default=["ADMIN_PANELS", "EXPOSED_SECRETS"])
    parser.add_argument("--concurrency", "-c", type=int, default=NUCLEI_CONCURRENCY)
    parser.add_argument("--timeout", "-T", type=float, default=NUCLEI_TIMEOUT)

    args = parser.parse_args()
    target_list = [t.strip() for t in args.targets.split(",") if t.strip()]

    manager = VulnerabilityScanManager(concurrency=args.concurrency)
    output = manager.run_vuln_scan(target_list, args.profiles)

    print(f"\n[+] Vulnerability Scan Completed. Processed {len(target_list)} targets.")
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
