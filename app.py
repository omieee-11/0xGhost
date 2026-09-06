from flask import Flask, request, jsonify, send_from_directory
import threading
import time
import uuid
import json
from pathlib import Path

# Import run_pipeline from main.py
from main import run_pipeline

app = Flask(__name__, static_folder='.', static_url_path='')

JOBS = {}

RESULTS_DIR = Path("scan_results")
RESULTS_DIR.mkdir(exist_ok=True)


def _run_job(job_id, target):
    JOBS[job_id]["status"] = "running"
    JOBS[job_id]["started_at"] = time.time()
    try:
        report = run_pipeline(target, results_dir=RESULTS_DIR)
        JOBS[job_id]["status"] = "done"
        JOBS[job_id]["result"] = report
        JOBS[job_id]["finished_at"] = time.time()
    except Exception as e:
        JOBS[job_id]["status"] = "error"
        JOBS[job_id]["error"] = str(e)
        JOBS[job_id]["finished_at"] = time.time()


@app.route('/')
def root():
    return send_from_directory('.', 'index.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json() or request.form
    target = data.get('target') if isinstance(data, dict) else None
    if not target:
        return jsonify({"error": "missing target"}), 400

    job_id = uuid.uuid4().hex
    JOBS[job_id] = {"status": "queued", "target": target, "created_at": time.time()}
    thread = threading.Thread(target=_run_job, args=(job_id, target), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status_url": f"/api/status/{job_id}", "result_url": f"/api/result/{job_id}"}), 202


@app.route('/api/status/<job_id>')
def api_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify({"job_id": job_id, "status": job.get('status'), "target": job.get('target')})


@app.route('/api/result/<job_id>')
def api_result(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    if job.get('status') != 'done':
        return jsonify({"error": "result not ready", "status": job.get('status')}), 202
    return jsonify(job.get('result'))


@app.route('/api/latest')
def api_latest():
    if Path('results.json').exists():
        with open('results.json', 'r') as f:
            return jsonify(json.load(f))
    return jsonify({"error": "no results.json found"}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
