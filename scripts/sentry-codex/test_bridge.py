import concurrent.futures
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.request
from unittest.mock import patch

import bridge


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = json.loads(Path(__file__).with_name('config.example.json').read_text())
        self.config.update(state_dir=self.tmp.name, installation_uuid='test-installation')
        self.config['codex_command'] = 'codex'
        bridge.database(self.config).close()

    def payload(self, project='atomic-browser', issue='123', **changes):
        data = {'action': 'created', 'installation': {'uuid': 'test-installation'},
                'data': {'issue': {'id': issue, 'project': {'slug': project},
                                   'issueCategory': 'error', 'title': 'private title'}}}
        data.update(changes)
        return json.dumps(data).encode()

    def send(self, body, signature=None, resource='issue'):
        signature = signature or hmac.new(b'secret', body, hashlib.sha256).hexdigest()
        return bridge.enqueue(self.config, 'secret', body, signature, resource)

    def test_routes_all_projects_without_storing_telemetry(self):
        for project in self.config['projects']:
            self.assertEqual(self.send(self.payload(project))[0], 202)
        with bridge.database(self.config) as db:
            jobs = [dict(r) for r in db.execute('SELECT * FROM jobs')]
        self.assertEqual(len(jobs), 3)
        self.assertNotIn('private title', json.dumps(jobs))
        self.assertEqual(self.config['projects']['atomic-browser'], 'atomic-server')
        self.assertEqual(self.config['repositories']['atomic-saas']['base'], 'main')

    def test_actual_http_delivery_and_duplicate(self):
        with patch.dict('os.environ', {'SENTRY_WEBHOOK_SECRET': 'secret'}):
            server = bridge.make_server(self.config, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            body = self.payload()
            signature = hmac.new(b'secret', body, hashlib.sha256).hexdigest()
            for expected in (b'queued', b'duplicate'):
                request = urllib.request.Request(
                    f'http://127.0.0.1:{server.server_port}/sentry', data=body,
                    headers={'Sentry-Hook-Signature': signature, 'Sentry-Hook-Resource': 'issue'})
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 202)
                    self.assertEqual(response.read(), expected)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_signature_installation_and_unknown_project_rejected(self):
        self.assertEqual(self.send(self.payload(), '0' * 64)[0], 401)
        self.assertEqual(self.send(self.payload(installation={'uuid': 'other'}))[0], 403)
        self.assertEqual(self.send(self.payload('untrusted'))[0], 400)
        self.assertEqual(self.send(self.payload(issue='../../injection'))[0], 400)
        self.assertEqual(self.send(b'null')[0], 400)
        self.assertEqual(self.send(b'{')[0], 400)

    def test_non_error_and_non_trigger_ignored(self):
        self.assertEqual(self.send(self.payload(action='resolved'))[0], 204)
        self.assertEqual(self.send(self.payload(), resource='event_alert')[0], 204)
        data = json.loads(self.payload())
        data['data']['issue']['issueCategory'] = 'feedback'
        self.assertEqual(self.send(json.dumps(data).encode())[0], 204)

    def test_concurrent_delivery_and_claim_and_terminal_dedup(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.send(self.payload()), range(8)))
        self.assertEqual(sum(r[1] == 'queued' for r in results), 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            claims = list(pool.map(lambda _: bridge.claim(self.config), range(4)))
        job = next(j for j in claims if j)
        self.assertEqual(sum(j is not None for j in claims), 1)
        bridge.finish(self.config, job['key'], 'draft', 'https://github.com/example/pr/1')
        self.assertEqual(self.send(self.payload(action='unresolved'))[1], 'duplicate')

    def test_failure_remains_blocked_not_automatically_retried(self):
        self.send(self.payload())
        with patch.object(bridge, 'investigate', side_effect=RuntimeError('secret must not leak')):
            self.assertTrue(bridge.work_once(self.config))
        with bridge.database(self.config) as db:
            row = dict(db.execute('SELECT * FROM jobs').fetchone())
        self.assertEqual(row['status'], 'blocked')
        self.assertNotIn('secret', row['detail'])
        self.assertFalse(bridge.work_once(self.config))
        self.assertEqual(self.send(self.payload())[1], 'duplicate')

    def test_existing_closed_pr_prevents_new_run(self):
        job = {'project': 'atomic-saas', 'issue': '42', 'key': 'ontola:atomic-saas:42'}
        with patch.object(bridge, 'run', return_value='[{"url":"https://github.com/ontola/atomic-saas/pull/1"}]') as run:
            status, _ = bridge.investigate(self.config, job)
        self.assertEqual(status, 'existing')
        self.assertIn('all', run.call_args.args[0])
        self.assertEqual(run.call_count, 1)

    def test_remote_branch_without_pr_blocks(self):
        job = {'project': 'atomic-server', 'issue': '42', 'key': 'ontola:atomic-server:42'}
        with patch.object(bridge, 'run', side_effect=['[]', 'hash refs/heads/existing']):
            status, _ = bridge.investigate(self.config, job)
        self.assertEqual(status, 'blocked')

    def test_publication_is_draft_on_correct_base(self):
        job = {'project': 'atomic-saas', 'issue': '42', 'key': 'ontola:atomic-saas:42'}
        commands = []
        outcome = 'passed'

        def fake_run(args, cwd=None, **kwargs):
            commands.append(args)
            if args[:3] == ['gh', 'pr', 'list']:
                return '[]'
            if args[:3] == ['git', 'rev-parse', 'HEAD']:
                return 'basehash'
            if args[:2] == ['codex', 'exec']:
                report = Path(args[args.index('--output-last-message') + 1])
                report.write_text(json.dumps({'status': 'fixed', 'summary': 'test',
                    'tests': [{'command': 'cargo test regression', 'outcome': outcome}]}))
            if args[:4] == ['git', 'diff', '--cached', '--name-only']:
                return 'src/fix.rs'
            if args[:3] == ['gh', 'pr', 'create']:
                return 'https://github.com/ontola/atomic-saas/pull/2'
            return ''

        with patch.object(bridge, 'run', side_effect=fake_run):
            self.assertEqual(bridge.investigate(self.config, job)[0], 'draft')
        publish = next(c for c in commands if c[:3] == ['gh', 'pr', 'create'])
        self.assertIn('--draft', publish)
        self.assertEqual(publish[publish.index('--base') + 1], 'main')
        self.assertFalse(any('merge' in c for c in commands))
        codex = next(c for c in commands if c[:2] == ['codex', 'exec'])
        self.assertIn('workspace-write', codex)
        self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', codex)
        outcome = 'failed'
        commands.clear()
        job.update(issue='43', key='ontola:atomic-saas:43')
        with patch.object(bridge, 'run', side_effect=fake_run):
            self.assertEqual(bridge.investigate(self.config, job)[0], 'blocked')
        self.assertFalse(any(c[:2] == ['git', 'push'] or c[:3] == ['gh', 'pr', 'create']
                             for c in commands))


if __name__ == '__main__':
    unittest.main()
