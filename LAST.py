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
from typing import Any, Callable, Dict, List, Optional

# Optional External Dependencies
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# Logging Configuration
LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(name)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("Phase5_DiscoveryScanner")

# Constants & Settings
FFUF_TIMEOUT = 30.0
KATANA_TIMEOUT = 30.0
WAYBACK_TIMEOUT = 60.0
DEFAULT_CONCURRENCY = 25

REQUEST_DELAY_MIN = 0.5
REQUEST_DELAY_MAX = 1.5

DISCOVERY_PROFILES: Dict[str, Dict[str, Any]] = {
    "DIRECTORY_BRUTE": {
        "name": "Directory & File Brute-Forcing (ffuf)",
        "description": "Discovers hidden endpoints and backup files."
    },
    "JS_ASSET_EXTRACTION": {
        "name": "JavaScript Asset & API Endpoint Extraction (katana)",
        "description": "Crawls and extracts routes from static JS files."
    },
    "URL_SCRAPING": {
        "name": "URL Scraping (waybackurls)",
        "description": "Fetches archived URLs from Wayback Machine."
    },
    "HISTORICAL_ARCHIVES": {
        "name": "Historical Archives (gau)",
        "description": "Fetches indexed endpoints via AlienVault, Wayback, and CommonCrawl."
    }
}


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


@dataclass
class ScanResult:
    target: str
    profile_name: str
    timestamp: datetime
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    success: bool = False


class FFUFScanner:
    """Directory brute-forcing scanner module using ffuf."""

    def scan_target(self, target: str, profile_name: str = "DIRECTORY_BRUTE", timeout: Optional[float] = None) -> ScanResult:
        timestamp = datetime.now()
        result = ScanResult(target=target, profile_name=profile_name, timestamp=timestamp)
        clean_target = target.replace("http://", "").replace("https://", "").strip("/")
        
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

        cmd = [
            "ffuf", "-u", f"https://{clean_target}/FUZZ",
            "-w", wordlist,
            "-t", "50", "-mc", "200,204,301,302,307,401,403",
            "-o", "-", "-of", "json", "-s"
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or FFUF_TIMEOUT)
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    data = json.loads(proc.stdout)
                    findings = []
                    for res in data.get("results", []):
                        findings.append({
                            "url": res.get("url"),
                            "status": res.get("status"),
                            "length": res.get("length")
                        })
                    result.findings = findings
                    result.success = True
                except json.JSONDecodeError:
                    result.error_message = "Failed to parse ffuf JSON output"
            else:
                result.error_message = f"ffuf returncode {proc.returncode}"
        except subprocess.TimeoutExpired:
            result.error_message = "ffuf scan timed out"
        except Exception as e:
            result.error_message = str(e)

        time.sleep(random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX))
        return result


class KatanaScanner:
    """JS asset & API endpoint extraction scanner using katana."""

    def scan_target(self, target: str, profile_name: str = "JS_ASSET_EXTRACTION", timeout: Optional[float] = None) -> ScanResult:
        timestamp = datetime.now()
        result = ScanResult(target=target, profile_name=profile_name, timestamp=timestamp)
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        cmd = ["katana", "-u", url, "-js-finder", "-silent", "-jc"]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or KATANA_TIMEOUT)
            if proc.returncode == 0:
                findings = [{"url": line.strip(), "status": "Discovered"} for line in proc.stdout.splitlines() if line.strip()]
                result.findings = findings
                result.success = True
            else:
                result.error_message = f"katana returncode {proc.returncode}"
        except subprocess.TimeoutExpired:
            result.error_message = "katana scan timed out"
        except Exception as e:
            result.error_message = str(e)

        time.sleep(random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX))
        return result


class WaybackScanner:
    """URL scraping scanner using waybackurls."""

    def scan_target(self, target: str, profile_name: str = "URL_SCRAPING", timeout: Optional[float] = None) -> ScanResult:
        timestamp = datetime.now()
        result = ScanResult(target=target, profile_name=profile_name, timestamp=timestamp)
        clean_target = target.replace("http://", "").replace("https://", "").strip("/")

        cmd = ["waybackurls", clean_target]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or WAYBACK_TIMEOUT)
            if proc.returncode == 0:
                findings = [{"url": line.strip(), "status": "Archived"} for line in proc.stdout.splitlines() if line.strip()]
                result.findings = findings
                result.success = True
            else:
                result.error_message = f"waybackurls returncode {proc.returncode}"
        except subprocess.TimeoutExpired:
            result.error_message = "waybackurls scan timed out"
        except Exception as e:
            result.error_message = str(e)

        time.sleep(random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX))
        return result


class GAUScanner:
    """Historical archive endpoint scanner using gau."""

    def scan_target(self, target: str, profile_name: str = "HISTORICAL_ARCHIVES", timeout: Optional[float] = None) -> ScanResult:
        timestamp = datetime.now()
        result = ScanResult(target=target, profile_name=profile_name, timestamp=timestamp)
        clean_target = target.replace("http://", "").replace("https://", "").strip("/")

        cmd = ["gau", clean_target]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or WAYBACK_TIMEOUT)
            if proc.returncode == 0:
                findings = [{"url": line.strip(), "status": "Indexed"} for line in proc.stdout.splitlines() if line.strip()]
                result.findings = findings
                result.success = True
            else:
                result.error_message = f"gau returncode {proc.returncode}"
        except subprocess.TimeoutExpired:
            result.error_message = "gau scan timed out"
        except Exception as e:
            result.error_message = str(e)

        time.sleep(random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX))
        return result


class DiscoveryScanManager:
    """Orchestrates parallel discovery scans across worker threads."""

    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY):
        self.concurrency = concurrency
        self.ffuf_scanner = FFUFScanner()
        self.katana_scanner = KatanaScanner()
        self.wayback_scanner = WaybackScanner()
        self.gau_scanner = GAUScanner()

    def _get_scan_task(self, target: str, profile_name: str, timeout: Optional[float]) -> Callable[[], ScanResult]:
        """Returns non-blocking callable scan function."""
        if profile_name == "DIRECTORY_BRUTE":
            return lambda: self.ffuf_scanner.scan_target(target, profile_name, timeout)
        elif profile_name == "JS_ASSET_EXTRACTION":
            return lambda: self.katana_scanner.scan_target(target, profile_name, timeout)
        elif profile_name == "URL_SCRAPING":
            return lambda: self.wayback_scanner.scan_target(target, profile_name, timeout)
        elif profile_name == "HISTORICAL_ARCHIVES":
            return lambda: self.gau_scanner.scan_target(target, profile_name, timeout)
        else:
            return lambda: ScanResult(
                target=target,
                profile_name=profile_name,
                timestamp=datetime.now(),
                error_message=f"Unknown profile: {profile_name}"
            )

    def run_batch_scan(self, targets: List[str], profiles: List[str], timeout: Optional[float] = None, output_dir: str = "scan_results") -> List[ScanResult]:
        out_path = Path(output_dir)
        out_path.mkdir(exist_ok=True)
        results = []

        tasks = []
        for target in targets:
            for profile_name in profiles:
                task = self._get_scan_task(target, profile_name, timeout)
                tasks.append(task)

        logger.info(f"Executing {len(tasks)} tasks across {self.concurrency} worker threads...")

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [executor.submit(task) for task in tasks]

            iterator = as_completed(futures)
            if tqdm:
                iterator = tqdm(iterator, total=len(tasks), desc="Phase 5 Scanning")

            for future in iterator:
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    logger.error(f"Task execution failed: {e}")

        # Export results to JSON
        for target in targets:
            clean_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
            target_results = [asdict(r) for r in results if r.target == target]
            
            summary = {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "total_scans": len(target_results),
                "results": target_results
            }

            file_path = out_path / f"{clean_target}_phase5_results.json"
            with open(file_path, "w") as f:
                json.dump(summary, f, cls=DateTimeEncoder, indent=4)

        return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 5 Content & Parameter Discovery Scanner")
    parser.add_argument("--targets", "-t", type=str, required=True, help="Comma-separated target hostnames/IPs")
    parser.add_argument("--profiles", "-p", nargs="+", choices=list(DISCOVERY_PROFILES.keys()), default=["DIRECTORY_BRUTE"])
    parser.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY, help="Parallel thread execution workers")
    parser.add_argument("--timeout", "-T", type=float, default=None, help="Scan task timeout override in seconds")

    args = parser.parse_args()
    target_list = [t.strip() for t in args.targets.split(",") if t.strip()]

    if not target_list:
        logger.error("No valid targets provided.")
        return 1

    manager = DiscoveryScanManager(concurrency=args.concurrency)
    results = manager.run_batch_scan(target_list, args.profiles, timeout=args.timeout)

    print("\n" + "=" * 50)
    print("PHASE 5 DISCOVERY SCAN SUMMARY")
    print("=" * 50)
    
    successful_scans = sum(1 for r in results if r.success)
    print(f"Total Tasks Executed: {len(results)} | Successful: {successful_scans} | Failed: {len(results) - successful_scans}")

    for result in results:
        status = "SUCCESS" if result.success else "FAILED"
        print(f"\n[{status}] Target: {result.target} | Profile: {result.profile_name}")
        if result.findings:
            print(f"    Findings Discovered: {len(result.findings)}")
            for finding in result.findings[:3]:
                print(f"      - {finding.get('url', 'N/A')} [{finding.get('status', 'N/A')}]")
        if result.error_message:
            print(f"    Error: {result.error_message}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
