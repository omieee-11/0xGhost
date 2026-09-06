import argparse
import json
import logging
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# External dependencies check
try:
    import nmap
except ImportError:
    nmap = None

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(name)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("Phase2_Network")

NMAP_TIMEOUT = 5.0  # Seconds per port timeout
NMAP_HOST_TIMEOUT = 300.0  # Seconds per host timeout
NMAP_MIN_DELAY = 0.1  # Minimum delay between requests
NMAP_MAX_CONCURRENCY = 10

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "FAST_TOP_100": {
        "name": "Fast Top-100 Port Scan",
        "args": "-F -sV",
        "description": "Rapid discovery of standard open services."
    },
    "WEB_DB_SERVICE": {
        "name": "Common Web & DB Service Scan",
        "args": "-p 80,443,21,22,3306,5432,8080,8443 -sC -sV",
        "description": "Service versions and default scripts for web/database ports."
    },
    "DEEP_VULN": {
        "name": "Deep Script / Vulnerability Scan",
        "args": "--script vuln",
        "description": "Known CVEs and service misconfigurations on open ports."
    }
}


# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

@dataclass
class ScanResult:
    target: str
    profile_name: str
    timestamp: str
    ports_opened: List[int] = field(default_factory=list)
    services_detected: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    success: bool = False


# ==============================================================================
# CORE SCANNER
# ==============================================================================

class NmapScanner:
    """Production-grade network scanner with python-nmap and CLI fallback."""

    def __init__(self, concurrency: int = None):
        self.concurrency = concurrency or NMAP_MAX_CONCURRENCY
        self.has_nmap_lib = nmap is not None

    def _run_python_nmap(self, target: str, profile_name: str, args: str) -> ScanResult:
        """Executes scan using python-nmap bindings."""
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=args, timeout=int(NMAP_HOST_TIMEOUT))
        
        ports = []
        services = {}

        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                lport = nm[target][proto].keys()
                for port in lport:
                    state = nm[target][proto][port]['state']
                    if state == 'open':
                        ports.append(port)
                        services[str(port)] = {
                            'name': nm[target][proto][port].get('name', 'unknown'),
                            'product': nm[target][proto][port].get('product', ''),
                            'version': nm[target][proto][port].get('version', ''),
                            'protocol': proto
                        }

        return ScanResult(
            target=target,
            profile_name=profile_name,
            timestamp=datetime.now().isoformat(),
            ports_opened=ports,
            services_detected=services,
            success=True
        )

    def _run_cli_fallback(self, target: str, profile_name: str, args: str) -> ScanResult:
        """Fallback method executing nmap via subprocess directly."""
        cmd = ["nmap"] + args.split() + [target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_HOST_TIMEOUT)
        
        ports = []
        services = {}

        for line in proc.stdout.splitlines():
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3 and "open" in parts[1]:
                    try:
                        port_num = int(parts[0].split("/")[0])
                        ports.append(port_num)
                        services[str(port_num)] = {
                            "name": parts[2],
                            "product": " ".join(parts[3:]) if len(parts) > 3 else "",
                            "protocol": parts[0].split("/")[1]
                        }
                    except ValueError:
                        continue

        return ScanResult(
            target=target,
            profile_name=profile_name,
            timestamp=datetime.now().isoformat(),
            ports_opened=ports,
            services_detected=services,
            success=True
        )

    def scan_target(self, target: str, profile_name: str) -> ScanResult:
        """Initiate scan with error handling and fallback mechanism."""
        args = SCAN_PROFILES[profile_name]["args"]
        logger.info(f"Starting {profile_name} scan on {target}...")

        try:
            if self.has_nmap_lib:
                try:
                    return self._run_python_nmap(target, profile_name, args)
                except Exception as e:
                    logger.warning(f"python-nmap failed ({e}), switching to CLI fallback.")
                    return self._run_cli_fallback(target, profile_name, args)
            else:
                return self._run_cli_fallback(target, profile_name, args)

        except Exception as e:
            logger.error(f"Scan failed for {target} ({profile_name}): {e}")
            return ScanResult(
                target=target,
                profile_name=profile_name,
                timestamp=datetime.now().isoformat(),
                error_message=str(e),
                success=False
            )


# ==============================================================================
# MANAGER & INTEGRATION EXPORTS
# ==============================================================================

class ScanManager:
    """Orchestrates multithreaded network scanning and formats JSON exports."""

    def __init__(self, concurrency: int = NMAP_MAX_CONCURRENCY):
        self.scanner = NmapScanner(concurrency=concurrency)

    def run_network_scan(self, targets: List[str], profiles: List[str], output_dir: str = "scan_results") -> Dict[str, Any]:
        """Main execution interface for external scripts (main.py)."""
        out_path = Path(output_dir)
        out_path.mkdir(exist_ok=True)
        results = []

        with ThreadPoolExecutor(max_workers=self.scanner.concurrency) as executor:
            futures = []
            for target in targets:
                for profile in profiles:
                    futures.append(
                        executor.submit(self.scanner.scan_target, target, profile)
                    )

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

        # Save structured JSON
        for target in targets:
            file_path = out_path / f"{target}_net_results.json"
            with open(file_path, "w") as f:
                json.dump(summary, f, indent=4)

        return summary


# ==============================================================================
# CLI HANDLER
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Phase 2 Network Scanner (Nmap Engine)")
    parser.add_argument("--targets", "-t", type=str, required=True, help="Comma-separated IP/domain list")
    parser.add_argument("--profiles", "-p", nargs="+", choices=list(SCAN_PROFILES.keys()), default=["FAST_TOP_100"])
    parser.add_argument("--concurrency", "-c", type=int, default=NMAP_MAX_CONCURRENCY)
    
    args = parser.parse_args()
    target_list = [t.strip() for t in args.targets.split(",") if t.strip()]

    manager = ScanManager(concurrency=args.concurrency)
    output = manager.run_network_scan(target_list, args.profiles)
    
    print(f"\n[+] Network Scan Completed. Scanned {len(target_list)} targets.")
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
