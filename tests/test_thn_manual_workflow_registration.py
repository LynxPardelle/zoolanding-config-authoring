"""Register the existing rollback path without making recovery automatic."""
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class ManualWorkflowRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load((ROOT / ".github/workflows/rollback-test.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    def test_registration_push_is_limited_to_existing_delivery_branch(self):
        self.assertEqual(set(self.workflow["on"]), {"push", "workflow_dispatch"})
        self.assertEqual(self.workflow["on"]["push"], {"branches": ["codex/thn-task029-config-authoring"]})

    def test_registration_has_no_credentials_checkout_environment_or_artifact(self):
        self.assertIn("register", self.workflow["jobs"])
        self.assertEqual(self.workflow["jobs"]["register"], {
            "if": "github.event_name == 'push'",
            "runs-on": "ubuntu-24.04",
            "permissions": {"contents": "read"},
            "steps": [{"run": "echo 'TEST manual workflow registered. No checkout, environment, artifact or AWS credentials.'"}],
        })

    def test_both_recovery_modes_and_source_validation_remain_manual_only(self):
        expected = {
            "verify-source": "github.event_name == 'workflow_dispatch'",
            "rollback": "github.event_name == 'workflow_dispatch' && inputs.recovery_mode == 'GitHub-release'",
            "recover-aws": "github.event_name == 'workflow_dispatch' && inputs.recovery_mode == 'AWS-live-snapshot/v1'",
        }
        self.assertEqual(set(self.workflow["jobs"]) - {"register"}, set(expected))
        for name, condition in expected.items():
            with self.subTest(job=name):
                self.assertEqual(self.workflow["jobs"][name].get("if"), condition)


if __name__ == "__main__":
    unittest.main()
