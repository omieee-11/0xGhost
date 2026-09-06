import os
import sys
import subprocess
import json
import time
from pathlib import Path


def run_script(script_name, target, timeout=600):
    """Run a phase script safely and return returncode and stdout/stderr."""
    print(f"\n[+] Running {script_name} against target: {target}")
    if not os.path.exists(script_name):
        print(f"[-] File {script_name} not found. Skipping.")
        return {"rc": None, "stdout": "", "stderr": f"{script_name} not found"}

    try:
        if script_name.upper().startswith("OSINT"):
            # OSINT.PY accepts target via stdin (legacy behavior)
            cmd = [sys.executable, script_name]
            proc = subprocess.run(cmd, input=f"{target}\n", text=True, capture_output=True, timeout=timeout)
        else:
            cmd = [sys.executable, script_name, "-t", target]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)

        print(f"[+] {script_name} finished with rc={proc.returncode}")
        return {"rc": proc.returncode, "stdout": proc.stdout or "", "stderr": proc.stderr or ""}

    except subprocess.TimeoutExpired:
        print(f"[-] Execution timed out for {script_name}")
        return {"rc": None, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        print(f"[-] Execution error on {script_name}: {e}")
        return {"rc": None, "stdout": "", "stderr": str(e)}


def collect_results(results_dir: Path, target: str):
    master_report = {
        "target": target,
        "scans": {},
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    if not results_dir.exists():
        return master_report

    for json_file in results_dir.glob("*.json"):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
            master_report["scans"][json_file.stem] = data
        except Exception as e:
            master_report["scans"][json_file.stem] = {"error": str(e)}

    return master_report


def run_pipeline(target, scripts=None, results_dir=Path("scan_results")):
    results_dir.mkdir(exist_ok=True)
    scripts = scripts or ["OSINT.PY", "NET.py", "VULN.py", "SECURITY.py", "LAST.py"]
    run_log = {"target": target, "runs": [], "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    for s in scripts:
        res = run_script(s, target)
        run_log["runs"].append({"script": s, "rc": res.get("rc"), "stderr": res.get("stderr")})

    # Allow some time for phase scripts to write their JSONs
    time.sleep(1)
    master = collect_results(results_dir, target)
    master["run_log"] = run_log

    # Save results.json at repo root
    try:
        with open("results.json", "w") as f:
            json.dump(master, f, indent=2)
    except Exception as e:
        print(f"[-] Failed to write results.json: {e}")

    print("\n[✔] Scan pipeline finished. Master report saved to results.json.")
    return master


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    run_pipeline(target)
