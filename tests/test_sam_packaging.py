import ast
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build_lambda_artifact.py"
STAGED_ARTIFACT = ROOT / ".build" / "config-authoring"
EXPECTED_RUNTIME_FILES = {
    "lambda_function.py",
    "zoolanding_lambda_common.py",
}


def artifact_inventory(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }


def artifact_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for relative_path in sorted(artifact_inventory(root)):
        path = root / relative_path
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
        digest.update(str(int(path.stat().st_mtime)).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


class SamPackagingTest(unittest.TestCase):
    def run_builder(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(BUILDER), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_template_uses_generated_allowlisted_codeuri(self):
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertIn("CodeUri: .build/config-authoring", template)
        self.assertNotIn("CodeUri: .\n", template)

    def test_allowlist_covers_local_python_imports(self):
        local_dependencies: set[str] = set()
        for relative_path in EXPECTED_RUNTIME_FILES:
            if not relative_path.endswith(".py"):
                continue
            tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = [alias.name.split(".", 1)[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    modules = [node.module.split(".", 1)[0]]
                else:
                    continue
                for module in modules:
                    candidate = ROOT / f"{module}.py"
                    if candidate.is_file():
                        local_dependencies.add(candidate.relative_to(ROOT).as_posix())

        self.assertLessEqual(local_dependencies, EXPECTED_RUNTIME_FILES)

    def test_builder_stages_only_runtime_allowlist(self):
        result = self.run_builder()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(EXPECTED_RUNTIME_FILES, artifact_inventory(STAGED_ARTIFACT))
        for relative_path in EXPECTED_RUNTIME_FILES:
            self.assertEqual(
                (ROOT / relative_path).read_bytes(),
                (STAGED_ARTIFACT / relative_path).read_bytes(),
            )

    def test_builder_output_is_reproducible(self):
        first = self.run_builder()
        self.assertEqual(0, first.returncode, first.stderr)
        first_digest = artifact_digest(STAGED_ARTIFACT)

        second = self.run_builder()
        self.assertEqual(0, second.returncode, second.stderr)

        self.assertEqual(first_digest, artifact_digest(STAGED_ARTIFACT))

    def test_verifier_fails_closed_on_unexpected_file(self):
        build = self.run_builder()
        self.assertEqual(0, build.returncode, build.stderr)
        unexpected = STAGED_ARTIFACT / "README.md"
        self.addCleanup(unexpected.unlink, missing_ok=True)
        unexpected.write_text("must not be deployed", encoding="utf-8")

        result = self.run_builder("--verify-artifact", str(STAGED_ARTIFACT))

        self.assertNotEqual(0, result.returncode)
        self.assertIn("unexpected artifact files: README.md", result.stderr)


if __name__ == "__main__":
    unittest.main()
