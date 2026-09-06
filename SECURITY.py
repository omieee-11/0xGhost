import argparse
import json
import logging
import os
import random
import subprocess
import sys
import time
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Logging Configuration
LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(name)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("Phase4_SecurityScanner")

# Constants
HTTP_TIMEOUT = 10.0
SSL_TIMEOUT = 30.0
NUCLEI_TIMEOUT = 25.0
DEFAULT_CONCURRENCY = 25

REQUEST_DELAY_MIN = 0.2
REQUEST_DELAY_MAX = 1.0

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "curl/7.68.0"
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

SECURITY_PROFILES: Dict[str, Dict[str, Any]] = {
    "HTTP_HEADERS": {
        "name": "HTTP Security Header Audit",
        "description": "Evaluation of missing or weak HTTP security headers."
    },
    "SSL_TLS_AUDIT": {
        "name": "SSL/TLS Certificate & Cipher Suite Audit",
        "description": "Weak SSL protocols, expired certificates, and insecure ciphers."
    },
    "CLICKJACKING_TEST": {
        "name": "Clickjacking & Frame Injection Test",
        "description": "Missing framing protection headers or misconfigured rules."
    }
}


@dataclass
class ScanResult:
    target: str
    profile_name: str
    timestamp: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    success: bool = False


class HTTPHeaderScanner:
    """Audits HTTP security headers directly using Python urllib."""

    def scan_target(self, target: str, profile_name: str = "HTTP_HEADERS", timeout: float = HTTP_TIMEOUT) -> ScanResult:
        timestamp = datetime.now().isoformat()
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        findings = []

        try:
            req = urllib.request.Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                headers = response.info()
                
                for h_name in SECURITY_HEADERS:
                    val = headers.get(h_name)
                    if val:
                        findings.append({
                            "header": h_name,
                            "status": "PRESENT",
                            "value": val,
                            "severity": "INFO"
                        })
                    else:
                        findings.append({
                            "header": h_name,
                            "status": "MISSING",
                            "value": None,
                            "severity": "LOW" if h_name != "Strict-Transport-Security" else "MEDIUM"
                        })

            time.sleep(random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX))
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, findings=findings, success=True)

        except Exception as e:
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, error_message=str(e), success=False)


class SSLScanner:
    """Performs basic SSL certificate verification and tls audits via testssl.sh CLI."""

    def scan_target(self, target: str, profile_name: str = "SSL_TLS_AUDIT", timeout: float = SSL_TIMEOUT) -> ScanResult:
        timestamp = datetime.now().isoformat()
        clean_host = target.replace("https://", "").replace("http://", "").split("/")[0]
        cmd = ["testssl.sh", "--fast", "--jsonfile", "-", clean_host]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            findings = []
            if proc.returncode == 0:
                findings.append({"output": proc.stdout[:500], "status": "COMPLETED"})
                return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, findings=findings, success=True)
            else:
                return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, error_message="testssl execution failed", success=False)
        except Exception as e:
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, error_message=str(e), success=False)


class ClickjackingScanner:
    """Executes clickjacking evaluation via nuclei engine."""

    def scan_target(self, target: str, profile_name: str = "CLICKJACKING_TEST", timeout: float = NUCLEI_TIMEOUT) -> ScanResult:
        timestamp = datetime.now().isoformat()
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = ["nuclei", "-u", url, "-tags", "clickjacking", "-json-export", "-", "-silent"]

        findings = []
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        entry = json.loads(line)
                        findings.append({
                            "title": entry.get("info", {}).get("name", "Clickjacking Vulnerability"),
                            "severity": entry.get("info", {}).get("severity", "medium").upper(),
                            "matched": entry.get("matched-at", url)
                        })
                    except json.JSONDecodeError:
                        continue
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, findings=findings, success=True)
        except Exception as e:
            return ScanResult(target=target, profile_name=profile_name, timestamp=timestamp, error_message=str(e), success=False)


class SecurityScanManager:
    """Orchestrates Phase 4 security jobs across workers."""

    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY):
        self.concurrency = concurrency
        self.http_scanner = HTTPHeaderScanner()
        self.ssl_scanner = SSLScanner()
        self.clickjacking_scanner = ClickjackingScanner()

    def _execute_task(self, target: str, profile_name: str) -> ScanResult:
        if profile_name == "HTTP_HEADERS":
            return self.http_scanner.scan_target(target, profile_name)
        elif profile_name == "SSL_TLS_AUDIT":
            return self.ssl_scanner.scan_target(target, profile_name)
        elif profile_name == "CLICKJACKING_TEST":
            return self.clickjacking_scanner.scan_target(target, profile_name)
        else:
            return ScanResult(target=target, profile_name=profile_name, timestamp=datetime.now().isoformat(), error_message=f"Unknown profile: {profile_name}")

    def run_batch_scan(self, targets: List[str], profiles: List[str], output_dir: str = "scan_results") -> Dict[str, Any]:
        out_path = Path(output_dir)
        out_path.mkdir(exist_ok=True)
        results = []

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [
                executor.submit(self._execute_task, target, profile)
                for target in targets
                for profile in profiles
            ]

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
            file_path = out_path / f"{clean_target}_phase4_results.json"
            with open(file_path, "w") as f:
                json.dump(summary, f, indent=4)

        return summary


def main():
    parser = argparse.ArgumentParser(description="Phase 4 Web Application & Security Header Scanner")
    parser.add_argument("--targets", "-t", type=str, required=True, help="Comma-separated target list")
    parser.add_argument("--profiles", "-p", nargs="+", choices=list(SECURITY_PROFILES.keys()), default=["HTTP_HEADERS"])
    parser.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--timeout", "-T", type=float, default=HTTP_TIMEOUT)

    args = parser.parse_args()
    target_list = [t.strip() for t in args.targets.split(",") if t.strip()]

    manager = SecurityScanManager(concurrency=args.concurrency)
    output = manager.run_batch_scan(target_list, args.profiles)

    print(f"\n[+] Phase 4 Scan Complete. Handled {len(target_list)} targets.")
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
