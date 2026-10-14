from flask import Flask, request, jsonify, send_from_directory
import ipaddress
import json
import re
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from main import run_pipeline

app = Flask(__name__, static_folder='.', static_url_path='')

JOBS = {}
JOBS_LOCK = threading.Lock()
RESULTS_DIR = Path("scan_results")
RESULTS_DIR.mkdir(exist_ok=True)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def normalize_target(raw_target: str) -> str:
    if not isinstance(raw_target, str):
        raise ValueError("target must be a string")

    candidate = raw_target.strip()
    if not candidate:
        raise ValueError("target is empty")

    if "://" in candidate:
        parsed = urlparse(candidate)
        if not parsed.netloc:
            raise ValueError("invalid URL target")
        candidate = parsed.netloc

    candidate = candidate.split("/")[0].split(":")[0].strip().lower().rstrip(".")
    if not candidate:
        raise ValueError("target is empty")

    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass

    if not DOMAIN_PATTERN.match(candidate):
        raise ValueError("target must be a valid domain or IP")

    return candidate


def _run_job(job_id: str, target: str):
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["started_at"] = time.time()

    try:
        report = run_pipeline(target, timeout_per_script=1800)
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["result"] = report
            JOBS[job_id]["finished_at"] = time.time()
    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = str(exc)
            JOBS[job_id]["finished_at"] = time.time()


@app.route('/')
def root():
    return send_from_directory('.', 'index.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(silent=True) or request.form or {}
    raw_target = data.get('target') if isinstance(data, dict) else None

    if not raw_target:
        return jsonify({"error": "missing target"}), 400

    try:
        target = normalize_target(raw_target)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "queued",
            "target": target,
            "created_at": time.time(),
        }

    thread = threading.Thread(target=_run_job, args=(job_id, target), daemon=True)
    thread.start()

    return jsonify(
        {
            "job_id": job_id,
            "target": target,
            "status": "queued",
            "status_url": f"/api/status/{job_id}",
            "result_url": f"/api/result/{job_id}",
        }
    ), 202


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
        "created_at": job.get('created_at'),
        "started_at": job.get('started_at'),
        "finished_at": job.get('finished_at'),
    }

    if job.get('status') == 'error':
        payload["error"] = job.get("error", "unknown error")

    return jsonify(payload)


@app.route('/api/result/<job_id>')
def api_result(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)

    if not job:
        return jsonify({"error": "job not found"}), 404

    status = job.get('status')
    if status in {'queued', 'running'}:
        return jsonify({"error": "result not ready", "status": status}), 202

    if status == 'error':
        return jsonify({
            "status": "error",
            "target": job.get("target"),
            "error": job.get("error", "scan failed")
        }), 200

    return jsonify(job.get('result', {}))


@app.route('/api/latest')
def api_latest():
    latest_path = Path('results.json')
    if latest_path.exists():
        with latest_path.open('r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    return jsonify({"error": "no results.json found"}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
