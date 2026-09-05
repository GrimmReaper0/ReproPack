import tempfile, unittest, sys
from pathlib import Path
from repropack.cli import capture, inspect, replay
ROOT=Path(__file__).parents[1]
class Tests(unittest.TestCase):
 def test_capture_inspect_replay(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'bug.repro'; capture(ROOT/'examples/bug',['bug.py','input.txt'],[sys.executable,'bug.py'],out); manifest,payloads=inspect(out); self.assertEqual(manifest['tool'],'repropack'); self.assertIn('files/bug.py',payloads); self.assertTrue(replay(out)['reproduced'])
 def test_no_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'x.repro'; out.write_bytes(b'x')
   with self.assertRaises(ValueError): capture(ROOT/'examples/bug',['bug.py'],[sys.executable,'bug.py'],out)
if __name__=='__main__': unittest.main()
