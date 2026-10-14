from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

from main import run_pipeline

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "scan_results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


def _set_job(job_id: str, **updates: Any) -> None:
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(updates)


def _run_job(job_id: str, target: str, profile: str) -> None:
    _set_job(job_id, status="running", started_at=time.time(), profile=profile)
    try:
        # The current pipeline runs all five phases. Keep the profile in job
        # metadata so the UI remains forward-compatible without pretending that
        # profiles change execution until the orchestrator supports that option.
        report = run_pipeline(target)
        _set_job(job_id, status="done", result=report, finished_at=time.time())
    except Exception as exc:  # pragma: no cover - exercised by integration use
        _set_job(job_id, status="error", error=str(exc), finished_at=time.time())


@app.get("/")
def root():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/health")
def api_health():
    return jsonify({"status": "ok", "service": "0xghost", "jobs": len(JOBS)})


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or request.form.to_dict()
    target = str(data.get("target", "")).strip()
    profile = str(data.get("profile", "FULL_ATTACK_PIPELINE")).strip()
    if not target:
        return jsonify({"error": "missing target"}), 400
    if len(target) > 255:
        return jsonify({"error": "target is too long"}), 400

    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "target": target,
            "profile": profile,
            "created_at": time.time(),
        }
    threading.Thread(target=_run_job, args=(job_id, target, profile), daemon=True).start()
    return jsonify({
        "job_id": job_id,
        "status_url": f"/api/status/{job_id}",
        "result_url": f"/api/result/{job_id}",
    }), 202


@app.get("/api/status/<job_id>")
def api_status(job_id: str):
    with JOBS_LOCK:
        job = dict(JOBS.get(job_id, {}))
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify({
        "job_id": job_id,
        "status": job.get("status"),
        "target": job.get("target"),
        "profile": job.get("profile"),
        "error": job.get("error"),
    })


@app.get("/api/result/<job_id>")
def api_result(job_id: str):
    with JOBS_LOCK:
        job = dict(JOBS.get(job_id, {}))
    if not job:
        return jsonify({"error": "job not found"}), 404
    if job.get("status") == "error":
        return jsonify({"error": job.get("error", "scan failed")}), 500
    if job.get("status") != "done":
        return jsonify({"error": "result not ready", "status": job.get("status")}), 202
    return jsonify(job.get("result", {}))


@app.delete("/api/scan/<job_id>")
def api_abort(job_id: str):
    # The phase subprocesses are not cancellable by the current orchestrator.
    # Marking queued jobs cancelled is safe; running jobs receive a clear status.
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        if job.get("status") == "queued":
            job["status"] = "cancelled"
        else:
            return jsonify({"error": "running scans cannot be cancelled yet", "status": job.get("status")}), 409
    return jsonify({"job_id": job_id, "status": "cancelled"})


@app.get("/api/latest")
def api_latest():
    results_file = BASE_DIR / "results.json"
    if not results_file.exists():
        return jsonify({"error": "no results.json found"}), 404
    try:
        return jsonify(json.loads(results_file.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        return jsonify({"error": f"invalid results.json: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
