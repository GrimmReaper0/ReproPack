import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile
from repropack.cli import capture, collect, inspect, replay, safe_name, canonical_command
from repropack._runtime import sha

ROOT = Path(__file__).parents[1]


class ReproPackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.archive = self.base/'bug.repro'

    def make(self):
        return capture(ROOT/'examples/bug', ['*.py', 'input.txt'], ['python', 'bug.py'], self.archive)

    def rewrite(self, change):
        with zipfile.ZipFile(self.archive) as z:
            data = {n: z.read(n) for n in z.namelist()}
        change(data)
        with zipfile.ZipFile(self.archive, 'w') as z:
            for name, value in data.items(): z.writestr(name, value)

    def test_capture_replay_real_bug(self):
        self.make(); r = replay(self.archive)
        self.assertTrue(r['reproduced']); self.assertEqual(r['actual']['exit_code'], 7)

    def test_integrity(self):
        self.make(); manifest, payloads = inspect(self.archive)
        self.assertEqual(len(payloads), 4); self.assertEqual(manifest['schema'], 1)

    def test_tampering(self):
        self.make(); self.rewrite(lambda d: d.update({'files/input.txt': b'different'}))
        with self.assertRaises(ValueError): inspect(self.archive)

    def test_extra_member(self):
        self.make(); self.rewrite(lambda d: d.update({'unexpected.txt': b'hello'}))
        with self.assertRaises(ValueError): inspect(self.archive)

    def test_path_traversal(self):
        for name in ('../oops', '/absolute', 'C:/file', 'a/../b', 'a\\b', './file'):
            with self.subTest(name=name), self.assertRaises(ValueError): safe_name(name)

    def test_archive_symlink(self):
        self.make()
        with zipfile.ZipFile(self.archive, 'a') as z:
            info = zipfile.ZipInfo('files/link'); info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, '/etc/passwd')
        with self.assertRaises(ValueError): inspect(self.archive)

    def test_duplicate_member(self):
        self.make()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(self.archive, 'a') as z: z.writestr('stdout.txt', 'again')
        with self.assertRaises(ValueError): inspect(self.archive)

    def test_no_overwrite(self):
        self.make()
        with self.assertRaises(ValueError): self.make()

    def test_secret_refused(self):
        (self.base/'secret.py').write_text('api_key = "this-is-a-secret-value"')
        with self.assertRaises(ValueError): collect(self.base, ['secret.py'])

    def test_dotfile_refused(self):
        (self.base/'.env').write_text('SAFE=1')
        with self.assertRaises(ValueError): collect(self.base, ['.env'])

    def test_missing_include(self):
        with self.assertRaises(ValueError): collect(self.base, ['nothing.py'])

    def test_command_secret(self):
        with self.assertRaises(ValueError): canonical_command(['cmd', '--token', 'supersecret'])

    def test_inline_token(self):
        with self.assertRaises(ValueError): canonical_command(['cmd', '--token=secret-value'])

    def test_python_placeholder(self):
        self.assertEqual(canonical_command(['python', 'a.py'])[0], '{python}')

    def test_prerun_inputs(self):
        source = self.base/'source'; source.mkdir()
        (source/'bug.py').write_text('open("new.txt", "w").write("new")')
        capture(source, ['bug.py'], ['python', 'bug.py'], self.archive)
        self.assertFalse((source/'new.txt').exists())
        self.assertNotIn('files/new.txt', inspect(self.archive)[1])

    def test_unsupported_schema(self):
        self.make()
        def mutate(data):
            m = json.loads(data['manifest.json']); m['schema'] = 999
            data['manifest.json'] = json.dumps(m).encode()
        self.rewrite(mutate)
        with self.assertRaises(ValueError): inspect(self.archive)

    def test_changed_exit_not_reproduced(self):
        self.make()
        def mutate(data):
            m = json.loads(data['manifest.json']); m['capture']['exit_code'] = 9
            data['manifest.json'] = json.dumps(m).encode()
        self.rewrite(mutate)
        self.assertFalse(replay(self.archive)['reproduced'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX executable permissions')
    def test_executable_mode(self):
        root = self.base/'src'; root.mkdir(); script = root/'bug.sh'
        script.write_text('#!/bin/sh\necho expected >&2\nexit 7\n'); script.chmod(0o755)
        capture(root, ['bug.sh'], ['./bug.sh'], self.archive)
        self.assertTrue(replay(self.archive)['reproduced'])
        self.assertEqual(inspect(self.archive)[0]['members']['files/bug.sh']['mode'], 0o755)

    def test_stdout_compared(self):
        self.make()
        def mutate(data):
            data['stdout.txt'] = b'changed output\n'
            m = json.loads(data['manifest.json'])
            m['members']['stdout.txt'].update(sha256=sha(data['stdout.txt']), bytes=len(data['stdout.txt']))
            data['manifest.json'] = json.dumps(m).encode()
        self.rewrite(mutate)
        self.assertFalse(replay(self.archive)['reproduced'])


if __name__ == '__main__':
    unittest.main()
