import unittest
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.prepare_test_parameters import build_parameters

class PrepareTestParametersTests(unittest.TestCase):
    def test_builds_isolated_test_parameters(self):
        parameters, sensitive = build_parameters({})
        self.assertEqual(parameters["EnvironmentName"], "test")
        self.assertEqual(parameters["ConfigTableName"], "zoolanding-config-registry-test")
        self.assertEqual(sensitive, set())
        template = (Path(__file__).resolve().parents[1] / "template.yaml").read_text(encoding="utf-8")
        declared = set(re.findall(r"(?m)^  ([A-Za-z][A-Za-z0-9]+):$", template.split("\nConditions:", 1)[0].split("\nRules:", 1)[0]))
        self.assertEqual(set(parameters), declared)

if __name__ == "__main__":
    unittest.main()
