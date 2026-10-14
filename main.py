#!/usr/bin/env python3
"""
Orchestrator for 0xGhost: run each phase script in sequence, collect per-phase JSON outputs,
and produce a master results.json. Designed to be run interactively from a Kali terminal.

Behavior changes made to satisfy: missing tools do NOT stop the scan; they are reported
in the master report and printed to the terminal. The orchestrator captures stdout/stderr
for each phase and records them in the run_log inside results.json.

Usage:
  python3 main.py example.com
or (interactive)
  python3 main.py
  (you will be prompted for target)

"""

import os
import sys
import json
import shutil
import subprocess
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

# Config
REPO_ROOT = Path(__file__).parent.resolve()
SCAN_RESULTS_DIR = REPO_ROOT / "scan_results"
SCAN_RESULTS_DIR.mkdir(exist_ok=True)
DEFAULT_TIMEOUT = 1800  # seconds per script (30 minutes)

# Tools we expect (best-effort list). Missing tools are non-fatal but reported.
EXPECTED_TOOLS = [
    "subfinder",
    "amass",
    "httpx",
    "katana",
    "nuclei",
    "gau",
    "waybackurls",
    "ffuf",
    "nmap",
    "testssl.sh",
    "corstest",
    "subzy",
    "sqlmap",
]

PHASE_SCRIPTS = ["OSINT.PY", "NET.py", "VULN.py", "SECURITY.py", "LAST.py"]
PHASE_LABELS = {
    "OSINT.PY": "OSINT / subdomains",
    "NET.py": "Network enumeration",
    "VULN.py": "Vulnerability checks",
    "SECURITY.py": "Web/TLS security",
    "LAST.py": "Content/archive discovery",
}


def is_tool_installed(tool: str) -> bool:
    """Return True if `tool` is available on PATH (or known location)."""
    # Handle testssl.sh which may be installed in ~/testssl.sh/testssl.sh
    if tool == "testssl.sh":
        if shutil.which("testssl.sh"):
            return True
        alt = Path.home() / "testssl.sh" / "testssl.sh"
        return alt.exists() and os.access(str(alt), os.X_OK)

    return shutil.which(tool) is not None


def check_expected_tools() -> Dict[str, bool]:
    """Return a mapping of expected tools to their availability (True/False)."""
    mapping = {}
    for t in EXPECTED_TOOLS:
        mapping[t] = is_tool_installed(t)
    return mapping


def run_subprocess(
    cmd: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    input_text: Optional[str] = None,
    cancel_event: Optional[threading.Event] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run a subprocess and capture rc/stdout/stderr; never raises on missing binary.
    Returns a dict with rc, stdout, stderr, cmd.
    """
    start_time = time.time()
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_text is not None else None,
            text=True,
            env=env,
        )
        if input_text is not None and proc.stdin is not None:
            proc.stdin.write(input_text)
            proc.stdin.close()

        while True:
            if cancel_event and cancel_event.is_set():
                proc.terminate()
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                return {"cmd": cmd, "rc": None, "stdout": stdout or "", "stderr": "ABORTED"}

            if timeout and (time.time() - start_time) > timeout:
                proc.kill()
                stdout, stderr = proc.communicate()
                return {"cmd": cmd, "rc": None, "stdout": stdout or "", "stderr": "TIMEOUT"}

            try:
                stdout, stderr = proc.communicate(timeout=1)
                return {"cmd": cmd, "rc": proc.returncode, "stdout": stdout or "", "stderr": stderr or ""}
            except subprocess.TimeoutExpired:
                continue
    except FileNotFoundError as e:
        msg = str(e)
        return {"cmd": cmd, "rc": None, "stdout": "", "stderr": msg}
    except Exception as e:
        if proc is not None:
            proc.kill()
            proc.communicate()
        return {"cmd": cmd, "rc": None, "stdout": "", "stderr": str(e)}


def run_script(
    script_name: str,
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    cancel_event: Optional[threading.Event] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute a phase script and return an execution record.

    For OSINT.PY we pass target via stdin (legacy behavior in repo). For others we pass -t <target>.
    """
    print(f"\n==> Running {script_name} against {target}")

    if not (REPO_ROOT / script_name).exists():
        msg = f"Script {script_name} not found in repository root ({REPO_ROOT}). Skipping."
        print("[!]", msg)
        return {"script": script_name, "skipped": True, "reason": msg}

    if script_name.upper().endswith(".PY"):
        python_bin = shutil.which("python3") or shutil.which("python") or sys.executable
        env = os.environ.copy()
        if output_dir:
            env["GHOST_SCAN_RESULTS_DIR"] = str(output_dir)
        if script_name == "OSINT.PY":
            cmd = [python_bin, script_name]
            # OSINT.PY expects interactive input; feed target via stdin
            result = run_subprocess(cmd, timeout=timeout, input_text=f"{target}\n", cancel_event=cancel_event, env=env)
        else:
            cmd = [python_bin, script_name, "-t", target]
            result = run_subprocess(cmd, timeout=timeout, cancel_event=cancel_event, env=env)
    else:
        # Generic executables (should not occur for this repo)
        cmd = ["./" + script_name, target]
        result = run_subprocess(cmd, timeout=timeout, cancel_event=cancel_event)

    # Print brief output to terminal for step-by-step UX
    if result.get("rc") is None:
        print(f"[!] {script_name} did not run successfully (rc=None). Stderr: {result.get('stderr')}")
    elif result.get("rc") != 0:
        print(f"[!] {script_name} exited with rc={result.get('rc')}")
        if result.get("stderr"):
            print("    stderr:", result.get("stderr").strip()[:1000])
    else:
        print(f"[+] {script_name} completed (rc=0).")

    # Small preview of stdout if present
    if result.get("stdout"):
        preview = result.get("stdout").strip().splitlines()[:10]
        print("    stdout preview:")
        for line in preview:
            print("     ", line)

    return {"script": script_name, "skipped": False, "rc": result.get("rc"), "stdout": result.get("stdout"), "stderr": result.get("stderr")}


def collect_scan_results(scan_results_dir: Path) -> Dict[str, Any]:
    """Collect per-phase JSON outputs from scan_results/ into a dict keyed by filename stem."""
    collected = {}
    if not scan_results_dir.exists():
        return collected

    for json_file in scan_results_dir.glob("*.json"):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
            collected[json_file.stem] = data
        except Exception as e:
            collected[json_file.stem] = {"error": f"Failed to parse JSON: {e}"}
    return collected


def run_pipeline(
    target: str,
    timeout_per_script: int = DEFAULT_TIMEOUT,
    phase_scripts: Optional[List[str]] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    cancel_event: Optional[threading.Event] = None,
    results_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Main pipeline entrypoint. Returns master report dict."""
    target = target.strip()
    started_at = datetime.utcnow().isoformat() + "Z"
    missing_tools_map = check_expected_tools()
    missing_tools = [t for t, ok in missing_tools_map.items() if not ok]
    scripts_to_run = phase_scripts or PHASE_SCRIPTS
    scan_results_dir = Path(results_dir) if results_dir else SCAN_RESULTS_DIR
    scan_results_dir.mkdir(parents=True, exist_ok=True)

    print("\n=== 0xGhost pipeline starting ===")
    print(f"Target: {target}")
    print(f"Started at: {started_at}")
    if missing_tools:
        print("\n[!] Some expected tools are missing (scan will continue, but results may be partial):")
        for t in missing_tools:
            print("   -", t)
    else:
        print("All expected tools detected (best-effort).")

    run_log: List[Dict[str, Any]] = []

    # Run each phase script sequentially
    for index, script in enumerate(scripts_to_run, start=1):
        if cancel_event and cancel_event.is_set():
            run_log.append({"script": script, "skipped": True, "reason": "Aborted by user"})
            continue

        if progress_callback:
            progress_callback(
                {
                    "event": "phase_started",
                    "phase_script": script,
                    "phase_label": PHASE_LABELS.get(script, script),
                    "phase_index": index,
                    "phase_total": len(scripts_to_run),
                }
            )

        rec = run_script(
            script,
            target,
            timeout=timeout_per_script,
            cancel_event=cancel_event,
            output_dir=scan_results_dir,
        )
        run_log.append(rec)
        if progress_callback:
            progress_callback(
                {
                    "event": "phase_finished",
                    "phase_script": script,
                    "phase_label": PHASE_LABELS.get(script, script),
                    "phase_index": index,
                    "phase_total": len(scripts_to_run),
                    "rc": rec.get("rc"),
                    "skipped": rec.get("skipped", False),
                    "stderr": rec.get("stderr", ""),
                }
            )
        if rec.get("stderr") == "ABORTED":
            break

    # Give scripts a moment to write their JSONs
    time.sleep(1)

    collected = collect_scan_results(scan_results_dir)

    finished_at = datetime.utcnow().isoformat() + "Z"

    master_report = {
        "target": target,
        "started_at": started_at,
        "finished_at": finished_at,
        "missing_tools": missing_tools,
        "tool_check_details": missing_tools_map,
        "run_log": run_log,
        "phase_scripts": scripts_to_run,
        "aborted": any(r.get("stderr") == "ABORTED" for r in run_log),
        "scans": collected,
    }

    # Save master results to results.json
    try:
        with open(REPO_ROOT / "results.json", "w") as f:
            json.dump(master_report, f, indent=2)
        print(f"\n[+] Master results written to {REPO_ROOT / 'results.json'}")
    except Exception as e:
        print(f"[!] Failed to write results.json: {e}")

    # Also print a concise terminal summary
    print("\n=== Summary ===")
    print(f"Target: {target}")
    print(f"Phases run: {len(run_log)}")
    if missing_tools:
        print(f"Missing tools (partial results expected): {', '.join(missing_tools)}")
    print(f"Per-phase status:")
    for r in run_log:
        if r.get("skipped"):
            print(f" - {r.get('script')}: SKIPPED ({r.get('reason')})")
        else:
            rc = r.get("rc")
            if r.get("stderr") == "ABORTED":
                status = "ABORTED"
            else:
                status = "OK" if rc == 0 else ("WARN" if rc and rc != 0 else "ERROR")
            print(f" - {r.get('script')}: {status} (rc={rc})")

    return master_report


def main():
    if len(sys.argv) > 1 and sys.argv[1].strip():
        target = sys.argv[1].strip()
    else:
        # Interactive prompt
        try:
            target = input("Enter target domain or IP (e.g. example.com): ").strip()
        except EOFError:
            target = ""

        if not target:
            print("No target provided. Exiting.")
            sys.exit(1)

    report = run_pipeline(target)
    # Exit code: 0 if all phases rc==0, else 2
    any_errors = any((r.get("rc") not in (0, None) and r.get("rc") != 0) or r.get("skipped") for r in report.get("run_log", []))
    sys.exit(0 if not any_errors else 2)


if __name__ == "__main__":
    main()
