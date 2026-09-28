"""The current verifier reads historical source as data, never as executable tooling."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import build_lambda_artifact as artifact
try:
    from tools import verify_recorded_release as recorded
except ImportError:
    recorded = None


class RecordedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(recorded, "current-tooling historical data verifier is missing")
        self.source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.build = Path(self.temporary.name)
        self.files = []
        for path in artifact.RUNTIME_FILES:
            body = subprocess.check_output(["git", "show", self.source + ":" + path.as_posix()], cwd=ROOT)
            target = self.build / "ConfigAuthoringFunction" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            self.files.append({"path": path.as_posix(), "size": len(body), "sha256": hashlib.sha256(body).hexdigest()})
        (self.build / "template.yaml").write_text("synthetic reviewed template")
        self.manifest = {"version": 1, "sourceCommit": self.source, "files": sorted(self.files, key=lambda row: row["path"])}
        (self.build / artifact.SAM_MANIFEST_NAME).write_bytes(artifact._canonical_json_bytes(self.manifest))

    def test_current_eight_file_contract_uses_exact_git_data_without_checkout(self):
        before = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
        recorded.verify_recorded_release(self.build, self.source)
        self.assertEqual(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT), before)
        self.assertEqual(artifact.PROJECT_ROOT, ROOT)

    def test_old_seven_file_source_is_not_a_github_release_fallback(self):
        with self.assertRaises(recorded.RecordedReleaseError):
            recorded.verify_recorded_release(self.build, "34e9e0ad9512b9882381e245f2cc67606f5b075e")

    def test_manifest_or_payload_substitution_fails(self):
        (self.build / "ConfigAuthoringFunction/lambda_function.py").write_text("substituted")
        with self.assertRaises(recorded.RecordedReleaseError):
            recorded.verify_recorded_release(self.build, self.source)

    def test_full_source_sha_is_required(self):
        with self.assertRaises(recorded.RecordedReleaseError):
            recorded.verify_recorded_release(self.build, "test")


if __name__ == "__main__":
    unittest.main()
