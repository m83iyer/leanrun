import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = str(Path(__file__).with_name('leanrun.py').resolve())

class LeanrunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / 'state'
        (self.root/'inputs.json').write_text('{"case":1}')
        (self.root/'environment.json').write_text('{"runtime":"test"}')
        self.code("print('OK')")

    def code(self, value):
        (self.root/'check.py').write_text(value)

    def argv(self, *extra):
        return [sys.executable, SCRIPT, 'run', '--task', 'demo', '--state', str(self.state),
                '--root', str(self.root), '--scope', 'unit', '--input', 'inputs.json',
                '--env', 'environment.json', '--file', 'check.py', *extra,
                '--', sys.executable, 'check.py']

    def runit(self, *extra):
        p = subprocess.run(self.argv(*extra), capture_output=True, text=True)
        return p, json.loads(p.stdout or p.stderr)

    def test_reuse_and_invalidate_every_declared_dimension(self):
        self.assertFalse(self.runit()[1]['reused'])
        self.assertTrue(self.runit()[1]['reused'])
        for file, text in [('check.py', "print('changed')"), ('inputs.json','{"case":2}'),
                           ('environment.json','{"runtime":"changed"}')]:
            (self.root/file).write_text(text)
            self.assertFalse(self.runit()[1]['reused'])
            self.assertTrue(self.runit()[1]['reused'])
        self.assertFalse(self.runit('--scope','integration')[1]['reused'])

    def test_failure_is_not_reused(self):
        self.code('raise SystemExit(9)')
        for _ in range(2):
            p, r = self.runit()
            self.assertEqual(p.returncode, 1)
            self.assertEqual(r['state'], 'failed')
            self.assertFalse(r['reused'])

    def test_changed_during_run_fails_closed(self):
        self.code("from pathlib import Path\nPath('inputs.json').write_text('{}')")
        self.assertEqual(self.runit()[1]['state'], 'failed')

    def test_symlink_and_traversal_block(self):
        (self.root/'link').symlink_to(self.root/'check.py')
        for name in ['link', '../check.py', '/etc/hosts']:
            p, r = self.runit('--file',name)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(r['state'], 'blocked')
        self.assertEqual(self.runit('--task','../escape')[0].returncode, 2)

    def test_bad_json_and_corrupt_record_block(self):
        (self.root/'inputs.json').write_text('broken')
        self.assertEqual(self.runit()[0].returncode, 2)
        (self.root/'inputs.json').write_text('{}')
        self.runit()
        (self.state/'demo'/'evidence.json').write_text('broken')
        self.assertEqual(self.runit()[0].returncode, 2)

    def test_semantically_corrupt_evidence_blocks(self):
        self.runit()
        path = self.state/'demo'/'evidence.json'
        original = json.loads(path.read_text())
        invalid = [{}, dict(original, exit_code=99), dict(original, exit_code=False),
                   dict(original, inputs_unchanged=False), dict(original, log_sha256='bad')]
        for record in invalid:
            path.write_text(json.dumps(record))
            self.assertEqual(self.runit()[0].returncode, 2)

    def test_invalid_utf8_tail_is_source_byte_bounded(self):
        self.code("import os; os.write(1, bytes([255])*5000)")
        _, r = self.runit()
        self.assertEqual(r['tail_source_max_bytes'], 4096)
        self.assertEqual(len(r['tail']), 4096)
        self.assertEqual(r['log_bytes'], 5000)

    def test_log_integrity(self):
        _, r = self.runit()
        Path(r['log']).write_text('tampered')
        self.assertEqual(self.runit()[0].returncode, 2)

    def test_log_tail_bounded_full_log_kept(self):
        self.code("print('x'*100000)")
        _, r = self.runit()
        self.assertEqual(len(r['tail']), 4096)
        self.assertEqual(Path(r['log']).stat().st_size, 100001)
        self.assertEqual(Path(r['log']).stat().st_mode & 0o777, 0o600)

    def test_atomic_single_owner_and_no_release_while_running(self):
        self.code("import time\nfrom pathlib import Path\nPath('ready').write_text('yes')\ntime.sleep(0.6)")
        first = subprocess.Popen(self.argv(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: first.poll() is None and first.kill())
        deadline = time.monotonic()+5
        while not (self.root/'ready').exists() and time.monotonic()<deadline:
            time.sleep(.01)
        self.assertTrue((self.root/'ready').exists())
        self.assertEqual(self.runit()[0].returncode, 2)
        r = subprocess.run([sys.executable,SCRIPT,'release','--state',str(self.state),'--task','demo'],capture_output=True)
        self.assertEqual(r.returncode, 2)
        first.communicate(timeout=5)
        self.assertEqual(first.returncode, 0)

    def test_interrupted_record_requires_explicit_release(self):
        self.runit()
        path = self.state/'demo'/'evidence.json'
        r = json.loads(path.read_text()); r['state']='running'; path.write_text(json.dumps(r))
        self.assertEqual(self.runit()[0].returncode, 2)
        p = subprocess.run([sys.executable,SCRIPT,'release','--state',str(self.state),'--task','demo'],capture_output=True)
        self.assertEqual(p.returncode, 0)
        self.assertFalse(self.runit()[1]['reused'])
        self.assertTrue(list(path.parent.glob('history-*.json')))

    def test_timeout_is_failed(self):
        self.code('import time; time.sleep(2)')
        self.assertEqual(self.runit('--timeout','.05')[1]['state'], 'failed')

    def test_world_readable_state_is_rejected(self):
        self.state.mkdir(mode=0o755)
        self.assertEqual(self.runit()[0].returncode, 2)

    def test_command_not_shell_expanded(self):
        self.code('import sys; print(sys.argv[1:])')
        p = subprocess.run(self.argv()+['; touch PWNED'],capture_output=True,text=True)
        self.assertEqual(p.returncode, 0)
        self.assertFalse((self.root/'PWNED').exists())

if __name__ == '__main__':
    unittest.main(verbosity=2)
