import json
import tempfile
import unittest
from pathlib import Path

from core.hasher import sha256_file
from core.detector import static_checks
from core.risk_engine import calculate_risk

class AntivirusTests(unittest.TestCase):
    def test_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "hello.txt"
            p.write_text("hello", encoding="utf-8")
            self.assertEqual(
                sha256_file(str(p)),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            )

    def test_double_extension(self):
        reasons = static_checks("invoice.pdf.exe")
        self.assertTrue(any("Double file extension" in r for r in reasons))

    def test_risk(self):
        risk, score = calculate_risk(True, [])
        self.assertEqual(risk, "CRITICAL")
        self.assertEqual(score, 100)

if __name__ == "__main__":
    unittest.main()
