import time
import unittest
from unittest.mock import patch

import app as ghost_app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = ghost_app.app.test_client()
        with ghost_app.JOBS_LOCK:
            ghost_app.JOBS.clear()

    def test_rejects_invalid_target(self):
        resp = self.client.post('/api/scan', json={'target': 'https://example.com/path'})
        self.assertEqual(resp.status_code, 400)
        self.assertIn('error', resp.get_json())

    def test_scan_lifecycle_and_result(self):
        def fake_pipeline(target, timeout_per_script, phase_scripts, progress_callback, cancel_event, results_dir):
            for idx, script in enumerate(phase_scripts, start=1):
                progress_callback({
                    'event': 'phase_started',
                    'phase_script': script,
                    'phase_label': script,
                    'phase_index': idx,
                    'phase_total': len(phase_scripts),
                })
                progress_callback({
                    'event': 'phase_finished',
                    'phase_script': script,
                    'phase_label': script,
                    'phase_index': idx,
                    'phase_total': len(phase_scripts),
                    'rc': 0,
                    'skipped': False,
                    'stderr': '',
                })
            return {
                'target': target,
                'started_at': '2026-01-01T00:00:00Z',
                'finished_at': '2026-01-01T00:00:05Z',
                'missing_tools': [],
                'tool_check_details': {},
                'run_log': [{'script': s, 'rc': 0, 'stdout': '', 'stderr': '', 'skipped': False} for s in phase_scripts],
                'phase_scripts': phase_scripts,
                'aborted': False,
                'scans': {'example_osint_results': {'total_subdomains': 1}},
            }

        with patch('app.run_pipeline', side_effect=fake_pipeline):
            res = self.client.post('/api/scan', json={'target': 'example.com', 'profile': 'recon'})
            self.assertEqual(res.status_code, 202)
            job_id = res.get_json()['job_id']

            for _ in range(30):
                status = self.client.get(f'/api/status/{job_id}').get_json()
                if status['status'] == 'done':
                    break
                time.sleep(0.05)

            result = self.client.get(f'/api/result/{job_id}')
            self.assertEqual(result.status_code, 200)
            payload = result.get_json()
            self.assertEqual(payload['status'], 'done')
            self.assertEqual(payload['summary']['phase_total'], 2)

    def test_missing_tool_phase_status(self):
        report = ghost_app._build_dashboard_report(
            'job1',
            'full',
            {
                'target': 'example.com',
                'started_at': 's',
                'finished_at': 'f',
                'missing_tools': ['nmap'],
                'tool_check_details': {'nmap': False},
                'run_log': [{'script': 'NET.py', 'rc': 0, 'stdout': '', 'stderr': '', 'skipped': False}],
                'phase_scripts': ['NET.py'],
                'aborted': False,
                'scans': {},
            },
        )
        self.assertEqual(report['phases'][0]['status'], 'missing_tools')

    def test_abort_endpoint(self):
        def fake_pipeline(target, timeout_per_script, phase_scripts, progress_callback, cancel_event, results_dir):
            for _ in range(20):
                if cancel_event.is_set():
                    return {
                        'target': target,
                        'started_at': 's',
                        'finished_at': 'f',
                        'missing_tools': [],
                        'tool_check_details': {},
                        'run_log': [{'script': phase_scripts[0], 'rc': None, 'stdout': '', 'stderr': 'ABORTED', 'skipped': False}],
                        'phase_scripts': phase_scripts,
                        'aborted': True,
                        'scans': {},
                    }
                time.sleep(0.05)
            return {
                'target': target,
                'started_at': 's',
                'finished_at': 'f',
                'missing_tools': [],
                'tool_check_details': {},
                'run_log': [{'script': phase_scripts[0], 'rc': 0, 'stdout': '', 'stderr': '', 'skipped': False}],
                'phase_scripts': phase_scripts,
                'aborted': False,
                'scans': {},
            }

        with patch('app.run_pipeline', side_effect=fake_pipeline):
            res = self.client.post('/api/scan', json={'target': 'example.com'})
            job_id = res.get_json()['job_id']
            abort = self.client.post(f'/api/abort/{job_id}')
            self.assertEqual(abort.status_code, 202)

            final_status = None
            for _ in range(40):
                status = self.client.get(f'/api/status/{job_id}').get_json()['status']
                final_status = status
                if status in ('aborted', 'done'):
                    break
                time.sleep(0.05)
            self.assertIn(final_status, ('aborted', 'done'))


if __name__ == '__main__':
    unittest.main()
