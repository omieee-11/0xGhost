import os
import sys
import subprocess
import json
from pathlib import Path

def run_script(script_name, target):
    print(f"\n[+] Running {script_name} against target: {target}")
    if not os.path.exists(script_name):
        print(f"[-] File {script_name} not found. Skipping.")
        return

    try:
        if script_name == "OSINT.PY":
            # OSINT.PY accepts target via stdin
            cmd = ["python3", script_name]
            subprocess.run(cmd, input=f"{target}\n", text=True, timeout=600)
        else:
            # Other scripts accept the -t/--targets flag
            cmd = ["python3", script_name, "-t", target]
            subprocess.run(cmd, text=True, timeout=600)
    except Exception as e:
        print(f"[-] Execution error on {script_name}: {e}")

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"==================================================")
    print(f" STARTING 0XGHOST SCAN PIPELINE FOR: {target}")
    print(f"==================================================")

    # 1. Run all 5 phase scripts
    run_script("OSINT.PY", target)
    run_script("NET.py", target)
    run_script("VULN.py", target)
    run_script("SECURITY.py", target)
    run_script("LAST.py", target)

    # 2. Compile generated scan_results/*.json into master results.json
    results_dir = Path("scan_results")
    master_report = {
        "target": target,
        "scans": {}
    }

    if results_dir.exists():
        for json_file in results_dir.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    master_report["scans"][json_file.stem] = json.load(f)
            except Exception as e:
                print(f"[-] Error parsing {json_file}: {e}")

    with open("results.json", "w") as f:
        json.dump(master_report, f, indent=4)

    print("\n[✔] Scan pipeline finished. Master report saved to results.json.")

if __name__ == "__main__":
    main()
