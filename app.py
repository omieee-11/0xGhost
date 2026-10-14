from flask import Flask, request, jsonify, send_from_directory
import threading
import time
import uuid
import json
import os
import re
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional

from main import run_pipeline, PHASE_LABELS, PHASE_SCRIPTS

app = Flask(__name__, static_folder='.', static_url_path='')

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()

RESULTS_DIR = Path(os.getenv("GHOST_RESULTS_DIR", "scan_results")).resolve()
RESULTS_DIR.mkdir(exist_ok=True)

SCAN_TIMEOUT_SECONDS = int(os.getenv("GHOST_SCAN_TIMEOUT", "1800"))
MAX_TERMINAL_LINES = int(os.getenv("GHOST_MAX_TERMINAL_LINES", "300"))

PHASE_TOOL_MAPPING = {
    "OSINT.PY": ["subfinder", "amass", "httpx", "subzy"],
    "NET.py": ["nmap"],
    "VULN.py": ["nuclei", "corstest"],
    "SECURITY.py": ["testssl.sh", "nuclei"],
    "LAST.py": ["ffuf", "katana", "waybackurls", "gau"],
}

PROFILE_PHASES = {
    "full": PHASE_SCRIPTS,
    "recon": ["OSINT.PY", "NET.py"],
    "vuln": ["VULN.py", "SECURITY.py"],
    "discovery": ["LAST.py"],
}
PHASE_RESULT_KEYS = {
    "OSINT.PY": ("_osint_results",),
    "NET.py": ("_net_results",),
    "VULN.py": ("_vuln_results",),
    "SECURITY.py": ("_phase4_results",),
    "LAST.py": ("_phase5_results",),
}

TARGET_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")


def _terminal_line(job_id: str, line: str) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        terminal = job.setdefault("terminal", [])
        terminal.append(line)
        if len(terminal) > MAX_TERMINAL_LINES:
            del terminal[:-MAX_TERMINAL_LINES]


def _now() -> float:
    return time.time()


def _validate_target(target: str) -> Optional[str]:
    if not isinstance(target, str):
        return "target must be a string"
    target = target.strip()
    if not target:
        return "target is required"
    if len(target) > 255:
        return "target is too long"
    if any(ch in target for ch in ["/", "\\", " ", "\n", "\r", "\t", "?", "#", "&"]):
        return "target must be a hostname or IP without path/query"
    if not TARGET_PATTERN.match(target):
        return "target contains invalid characters"

    host = target
    if host.startswith("http://") or host.startswith("https://"):
        host = host.split("://", 1)[1]
    host = host.split(":", 1)[0]

    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    if host.startswith(".") or host.endswith("."):
        return "invalid hostname"

    labels = host.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return "invalid hostname"
    if any(not re.match(r"^[A-Za-z0-9-]+$", label) or label.startswith("-") or label.endswith("-") for label in labels):
        return "invalid hostname"
    return None


def _resolve_phase_scripts(profile: Optional[str]) -> List[str]:
    profile = (profile or "full").strip().lower()
    if profile in PROFILE_PHASES:
        return PROFILE_PHASES[profile]

    selected = []
    for part in profile.split(","):
        part = part.strip().upper()
        if not part:
            continue
        script_name = f"{part}.py" if not part.endswith(".PY") else part
        script_name = script_name.replace(".PY", ".PY")
        matched = None
        for script in PHASE_SCRIPTS:
            if script.upper() == script_name.upper():
                matched = script
                break
        if matched:
            selected.append(matched)
    return selected or PHASE_SCRIPTS


def _phase_status_from_log(script: str, run_log_item: Optional[Dict[str, Any]], tool_check: Dict[str, bool]) -> str:
    required_tools = PHASE_TOOL_MAPPING.get(script, [])
    missing_for_phase = [t for t in required_tools if not tool_check.get(t, True)]

    if run_log_item is None:
        return "queued"
    if run_log_item.get("skipped"):
        return "skipped"
    if run_log_item.get("stderr") == "ABORTED":
        return "aborted"
    if missing_for_phase:
        return "missing_tools"
    rc = run_log_item.get("rc")
    if rc == 0:
        return "done"
    return "error"


def _build_dashboard_report(job_id: str, profile: str, pipeline_report: Dict[str, Any]) -> Dict[str, Any]:
    run_log = pipeline_report.get("run_log", [])
    scans = pipeline_report.get("scans", {})
    tool_check = pipeline_report.get("tool_check_details", {})
    scripts = pipeline_report.get("phase_scripts", PHASE_SCRIPTS)

    run_log_by_script = {item.get("script"): item for item in run_log if item.get("script")}
    phases = []
    for index, script in enumerate(scripts, start=1):
        rec = run_log_by_script.get(script)
        phase_status = _phase_status_from_log(script, rec, tool_check)
        required_tools = PHASE_TOOL_MAPPING.get(script, [])
        missing_for_phase = [t for t in required_tools if not tool_check.get(t, True)]
        phase_result = {}
        key_suffixes = PHASE_RESULT_KEYS.get(script, ())
        for scan_key, scan_val in scans.items():
            if any(scan_key.endswith(suffix) for suffix in key_suffixes):
                phase_result[scan_key] = scan_val

        phase_payload: Dict[str, Any] = {
            "id": script.replace(".py", "").replace(".PY", "").lower(),
            "name": PHASE_LABELS.get(script, script),
            "script": script,
            "status": phase_status,
            "phase_index": index,
            "required_tools": required_tools,
            "missing_tools": missing_for_phase,
            "result": phase_result,
        }

        if rec:
            phase_payload["rc"] = rec.get("rc")
            if rec.get("stderr"):
                phase_payload["stderr"] = rec.get("stderr")[:4000]
            if rec.get("stdout"):
                phase_payload["stdout_preview"] = "\n".join(rec.get("stdout", "").splitlines()[:8])
            if rec.get("reason"):
                phase_payload["reason"] = rec.get("reason")
        phases.append(phase_payload)

    phase_counts = {
        "done": sum(1 for p in phases if p["status"] == "done"),
        "error": sum(1 for p in phases if p["status"] == "error"),
        "missing_tools": sum(1 for p in phases if p["status"] == "missing_tools"),
        "skipped": sum(1 for p in phases if p["status"] == "skipped"),
        "aborted": sum(1 for p in phases if p["status"] == "aborted"),
    }

    summary = {
        "phase_total": len(phases),
        "phase_done": phase_counts["done"],
        "phase_error": phase_counts["error"],
        "phase_missing_tools": phase_counts["missing_tools"],
        "phase_skipped": phase_counts["skipped"],
        "phase_aborted": phase_counts["aborted"],
        "missing_tools_count": len(pipeline_report.get("missing_tools", [])),
        "target": pipeline_report.get("target"),
    }

    status = "aborted" if pipeline_report.get("aborted") else "done"

    return {
        "job_id": job_id,
        "target": pipeline_report.get("target"),
        "profile": profile,
        "status": status,
        "started_at": pipeline_report.get("started_at"),
        "finished_at": pipeline_report.get("finished_at"),
        "summary": summary,
        "phases": phases,
        "missing_tools": pipeline_report.get("missing_tools", []),
        "tool_check_details": tool_check,
        "run_log": run_log,
        "scans": scans,
    }


def _run_job(job_id: str, target: str, profile: str, phase_scripts: List[str], job_output_dir: Path, cancel_event: threading.Event) -> None:
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["started_at"] = _now()

    _terminal_line(job_id, f"[+] Job {job_id} started for target {target}")

    def _progress(event: Dict[str, Any]) -> None:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            job["phase"] = {
                "index": event.get("phase_index"),
                "total": event.get("phase_total"),
                "script": event.get("phase_script"),
                "name": event.get("phase_label"),
                "event": event.get("event"),
            }
        if event.get("event") == "phase_started":
            _terminal_line(job_id, f"[>] Phase {event.get('phase_index')}/{event.get('phase_total')} started: {event.get('phase_label')}")
        elif event.get("event") == "phase_finished":
            rc = event.get("rc")
            _terminal_line(job_id, f"[<] Phase {event.get('phase_index')}/{event.get('phase_total')} finished: {event.get('phase_label')} (rc={rc})")

    try:
        report = run_pipeline(
            target,
            timeout_per_script=SCAN_TIMEOUT_SECONDS,
            phase_scripts=phase_scripts,
            progress_callback=_progress,
            cancel_event=cancel_event,
            results_dir=job_output_dir,
        )
        dashboard_report = _build_dashboard_report(job_id, profile, report)
        final_status = dashboard_report.get("status", "done")

        with JOBS_LOCK:
            JOBS[job_id]["status"] = final_status
            JOBS[job_id]["result"] = dashboard_report
            JOBS[job_id]["finished_at"] = _now()

        _terminal_line(job_id, f"[+] Job {job_id} finished with status={final_status}")
    except Exception as e:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "aborted" if cancel_event.is_set() else "error"
            JOBS[job_id]["error"] = str(e)
            JOBS[job_id]["finished_at"] = _now()
        _terminal_line(job_id, f"[!] Job {job_id} failed: {str(e)}")


@app.route('/')
def root():
    return send_from_directory('.', 'index.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(silent=True) or request.form or {}
    target = data.get('target')
    profile = (data.get('profile') or 'full').strip()

    validation_error = _validate_target(target)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    phase_scripts = _resolve_phase_scripts(profile)
    if not phase_scripts:
        return jsonify({"error": "invalid profile"}), 400

    job_id = uuid.uuid4().hex
    cancel_event = threading.Event()
    job_output_dir = RESULTS_DIR / "jobs" / job_id
    job_output_dir.mkdir(parents=True, exist_ok=True)

    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "queued",
            "target": target,
            "profile": profile,
            "created_at": _now(),
            "phase": {"index": 0, "total": len(phase_scripts), "script": None, "name": None, "event": "queued"},
            "terminal": ["[.] Job queued"],
            "cancel_event": cancel_event,
            "output_dir": str(job_output_dir),
            "phase_scripts": phase_scripts,
        }

    thread = threading.Thread(
        target=_run_job,
        args=(job_id, target, profile, phase_scripts, job_output_dir, cancel_event),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "job_id": job_id,
        "status": "queued",
        "status_url": f"/api/status/{job_id}",
        "result_url": f"/api/result/{job_id}",
        "abort_url": f"/api/abort/{job_id}",
    }), 202


@app.route('/api/status/<job_id>')
def api_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404

        payload = {
            "job_id": job_id,
            "status": job.get('status'),
            "target": job.get('target'),
            "profile": job.get('profile'),
            "created_at": job.get('created_at'),
            "started_at": job.get('started_at'),
            "finished_at": job.get('finished_at'),
            "phase": job.get('phase'),
            "phase_scripts": job.get('phase_scripts', []),
            "terminal": job.get('terminal', []),
        }
        if job.get("error"):
            payload["error"] = job.get("error")
        return jsonify(payload)


@app.route('/api/result/<job_id>')
def api_result(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        status = job.get('status')
        if status in ('queued', 'running'):
            return jsonify({"error": "result not ready", "status": status}), 202
        if status == 'error':
            return jsonify({"error": job.get('error', 'scan failed'), "status": status}), 500
        if status == 'aborted' and not job.get('result'):
            return jsonify({"error": "scan aborted", "status": status}), 409
        return jsonify(job.get('result') or {"status": status})


@app.route('/api/abort/<job_id>', methods=['POST'])
def api_abort(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        if job.get("status") in {"done", "error", "aborted"}:
            return jsonify({"job_id": job_id, "status": job.get("status"), "message": "job already finished"}), 200

        cancel_event = job.get("cancel_event")
        if cancel_event:
            cancel_event.set()
        job["status"] = "aborted"
        job["finished_at"] = _now()
        job.setdefault("terminal", []).append("[!] Abort requested by operator")

    return jsonify({"job_id": job_id, "status": "aborted", "message": "abort requested"}), 202


@app.route('/api/latest')
def api_latest():
    results_path = Path('results.json')
    if results_path.exists():
        with open(results_path, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    return jsonify({"error": "no results.json found"}), 404


if __name__ == '__main__':
    host = os.getenv("GHOST_HOST", "0.0.0.0")
    port = int(os.getenv("GHOST_PORT", "8080"))
    app.run(host=host, port=port)
