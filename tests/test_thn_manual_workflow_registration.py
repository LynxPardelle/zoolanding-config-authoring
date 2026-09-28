"""Register the existing rollback path without making recovery automatic."""
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ManualWorkflowRegistrationTests(unittest.TestCase):
    def test_registration_tests_import_without_site_packages(self):
        result = subprocess.run(
            [sys.executable, "-S", "-B", "-c",
             "import runpy; runpy.run_path('tests/test_thn_manual_workflow_registration.py')"],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/rollback-test.yml").read_text(encoding="utf-8")
        # Match this workflow's closed block layout; YAML syntax is checked by Actionlint.
        parts = re.split(r"^  (\S[^\n]*):[ \t]*\n", self.workflow.split("\njobs:\n", 1)[1], flags=re.MULTILINE)
        self.assertEqual(parts[0], "")
        self.assertEqual(len(parts[1::2]), len(set(parts[1::2])))
        self.jobs = dict(zip(parts[1::2], parts[2::2]))

    def test_registration_push_is_limited_to_existing_delivery_branch(self):
        events = self.workflow.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
        self.assertEqual(re.findall(r"^  (\S[^\n]*):[ \t]*$", events, re.MULTILINE), ["push", "workflow_dispatch"])
        self.assertEqual(events.split("  push:\n", 1)[1].split("  workflow_dispatch:\n", 1)[0],
                         "    branches: [codex/thn-task029-config-authoring]\n")

    def test_registration_has_no_credentials_checkout_environment_or_artifact(self):
        self.assertIn("register", self.jobs)
        self.assertEqual(self.jobs["register"].rstrip(), "\n".join([
            "    if: github.event_name == 'push'",
            "    runs-on: ubuntu-24.04",
            "    permissions:",
            "      contents: read",
            "    steps:",
            "      - run: echo 'TEST manual workflow registered. No checkout, environment, artifact or AWS credentials.'",
        ]))

    def test_both_recovery_modes_and_source_validation_remain_manual_only(self):
        expected = {
            "verify-source": "github.event_name == 'workflow_dispatch'",
            "rollback": "github.event_name == 'workflow_dispatch' && inputs.recovery_mode == 'GitHub-release'",
            "recover-aws": "github.event_name == 'workflow_dispatch' && inputs.recovery_mode == 'AWS-live-snapshot/v1'",
        }
        self.assertEqual(set(self.jobs) - {"register"}, set(expected))
        for name, condition in expected.items():
            with self.subTest(job=name):
                self.assertEqual(re.findall(r"^    if: ([^\n]*)$", self.jobs[name], re.MULTILINE), [condition])


if __name__ == "__main__":
    unittest.main()
