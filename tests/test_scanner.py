import tempfile
import unittest
from pathlib import Path
from siteguard.scanner import scan, main

class ScannerTests(unittest.TestCase):
    def test_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test.py").write_text('import subprocess\nsubprocess.run("echo hi", shell=True)\napp.run(debug=True)\neval("1")\n', encoding="utf-8")
            self.assertEqual({f["rule"] for f in scan(tmp)["findings"]}, {"PY002", "PY003", "PY004"})
            self.assertEqual(main([tmp, "--fail-on-high"]), 1)

    def test_syntax(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "broken.py").write_text("def f(:\n", encoding="utf-8")
            self.assertEqual(scan(tmp)["findings"][0]["rule"], "PY001")

    def test_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "ok.py").write_text("print('ok')\n", encoding="utf-8")
            self.assertFalse(scan(tmp)["findings"])
            self.assertEqual(main([tmp, "--fail-on-high"]), 0)

    def test_pickle(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pickle_test.py").write_text("import pickle\npickle.loads(data)\n", encoding="utf-8")
            self.assertEqual(scan(tmp)["findings"][0]["rule"], "PY005")

if __name__ == "__main__":
    unittest.main()
