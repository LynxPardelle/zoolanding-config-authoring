import ast
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build_lambda_artifact.py"
STAGED_ARTIFACT = ROOT / ".build" / "config-authoring"
EXPECTED_RUNTIME_FILES = {
    "lambda_function.py",
    "server_policy_validation.py",
    "schemas/server-features/commerce.schema.json",
    "schemas/server-features/data-spaces.schema.json",
    "schemas/server-features/integration-bindings.schema.json",
    "schemas/server-features/notification-policies.schema.json",
    "zoolanding_lambda_common.py",
}
sys.path.insert(0, str(ROOT))
from tools import bootstrap_server_scopes
from tools import build_lambda_artifact


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
        self.assertEqual(EXPECTED_RUNTIME_FILES, set(bootstrap_server_scopes.RUNTIME_ARTIFACT_FILES))
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

    def test_builder_rejects_a_junction_like_build_root_before_cleanup(self):
        with mock.patch.object(
            Path,
            "is_junction",
            autospec=True,
            side_effect=lambda path: path == build_lambda_artifact.BUILD_ROOT,
        ):
            with self.assertRaisesRegex(build_lambda_artifact.ArtifactError, "junction"):
                build_lambda_artifact._assert_safe_build_location()

    @unittest.skipUnless(sys.platform == "win32", "Windows junction test")
    def test_builder_rejects_a_real_windows_build_root_junction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_root = root / "repository"
            external = root / "external"
            build_root = project_root / ".build"
            artifact_root = build_root / "config-authoring"
            project_root.mkdir()
            external.mkdir()
            sentinel = external / "must-survive.txt"
            sentinel.write_text("do not delete\n", encoding="utf-8")
            junction = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(build_root), str(external)],
                capture_output=True,
                text=True,
                check=False,
            )
            if junction.returncode != 0:
                self.skipTest(f"mklink /J unavailable: {junction.stderr.strip()}")

            try:
                with (
                    mock.patch.object(build_lambda_artifact, "PROJECT_ROOT", project_root),
                    mock.patch.object(build_lambda_artifact, "BUILD_ROOT", build_root),
                    mock.patch.object(build_lambda_artifact, "DEFAULT_ARTIFACT", artifact_root),
                ):
                    with self.assertRaisesRegex(build_lambda_artifact.ArtifactError, "junction"):
                        build_lambda_artifact._assert_safe_build_location()
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "do not delete\n")
            finally:
                build_root.rmdir()

    def test_builder_rejects_a_nested_junction_like_build_entry_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            build_root = project_root / ".build"
            artifact_root = build_root / "config-authoring"
            trap = artifact_root / "trap"
            trap.mkdir(parents=True)

            with (
                mock.patch.object(build_lambda_artifact, "PROJECT_ROOT", project_root),
                mock.patch.object(build_lambda_artifact, "BUILD_ROOT", build_root),
                mock.patch.object(build_lambda_artifact, "DEFAULT_ARTIFACT", artifact_root),
                mock.patch.object(
                    build_lambda_artifact,
                    "_is_unsafe_link",
                    side_effect=lambda path: path == trap,
                ),
            ):
                with self.assertRaisesRegex(build_lambda_artifact.ArtifactError, "junction"):
                    build_lambda_artifact._assert_safe_build_location()

    def test_builder_rejects_a_junction_like_runtime_source_parent(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            build_root = Path(directory) / ".build"
            artifact_root = build_root / "config-authoring"
            with (
                mock.patch.object(build_lambda_artifact, "BUILD_ROOT", build_root),
                mock.patch.object(build_lambda_artifact, "DEFAULT_ARTIFACT", artifact_root),
                mock.patch.object(
                    build_lambda_artifact,
                    "_is_unsafe_link",
                    side_effect=lambda path: path.name == "schemas",
                ),
                mock.patch.object(shutil, "copyfile", wraps=shutil.copyfile) as copyfile,
            ):
                with self.assertRaisesRegex(build_lambda_artifact.ArtifactError, "junction"):
                    build_lambda_artifact.build_artifact()
                copyfile.assert_not_called()

    def test_verifier_fails_closed_on_unexpected_file(self):
        build = self.run_builder()
        self.assertEqual(0, build.returncode, build.stderr)
        unexpected = STAGED_ARTIFACT / "README.md"
        self.addCleanup(unexpected.unlink, missing_ok=True)
        unexpected.write_text("must not be deployed", encoding="utf-8")

        result = self.run_builder("--verify-artifact", str(STAGED_ARTIFACT))

        self.assertNotEqual(0, result.returncode)
        self.assertIn("unexpected artifact files: README.md", result.stderr)

    def test_inventory_rejects_a_junction_like_entry_before_traversal(self):
        build = self.run_builder()
        self.assertEqual(0, build.returncode, build.stderr)

        with mock.patch.object(
            build_lambda_artifact,
            "_is_unsafe_link",
            side_effect=lambda path: path.name == "schemas",
        ):
            with self.assertRaisesRegex(build_lambda_artifact.ArtifactError, "junction"):
                build_lambda_artifact.verify_artifact(STAGED_ARTIFACT)

    def test_inventory_rejects_a_non_regular_file_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "not-regular"
            candidate.write_text("placeholder", encoding="utf-8")
            real_is_file = Path.is_file
            with mock.patch.object(
                Path,
                "is_file",
                autospec=True,
                side_effect=lambda path: False if path == candidate else real_is_file(path),
            ):
                with self.assertRaisesRegex(build_lambda_artifact.ArtifactError, "non-regular"):
                    build_lambda_artifact._relative_inventory(root)

    def test_normalizer_restores_reproducible_timestamps_after_artifact_transport(self):
        build = self.run_builder()
        self.assertEqual(0, build.returncode, build.stderr)
        transported = STAGED_ARTIFACT / "lambda_function.py"
        transported.touch()
        self.assertNotEqual(315532800, int(transported.stat().st_mtime))

        result = self.run_builder("--normalize-artifact", str(STAGED_ARTIFACT))

        self.assertEqual(0, result.returncode, result.stderr)
        for path in [STAGED_ARTIFACT, *STAGED_ARTIFACT.rglob("*")]:
            self.assertEqual(315532800, int(path.stat().st_mtime), path)
        self.assertEqual(EXPECTED_RUNTIME_FILES, artifact_inventory(STAGED_ARTIFACT))

    def test_sam_manifest_binds_exact_source_commit_and_seven_file_bytes(self):
        build = self.run_builder()
        self.assertEqual(0, build.returncode, build.stderr)
        source_commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            sam_root = Path(directory)
            function_root = sam_root / "ConfigAuthoringFunction"
            function_root.mkdir()
            for relative_path in EXPECTED_RUNTIME_FILES:
                destination = function_root / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative_path).read_bytes())
            (sam_root / "template.yaml").write_text("Resources: {}\n", encoding="utf-8")

            build_lambda_artifact.write_sam_manifest(sam_root, source_commit)
            build_lambda_artifact.verify_sam_build(sam_root, source_commit)
            manifest = json.loads((sam_root / "config-authoring-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(source_commit, manifest["sourceCommit"])
            self.assertEqual(EXPECTED_RUNTIME_FILES, {entry["path"] for entry in manifest["files"]})

            (function_root / "lambda_function.py").write_bytes(b"tampered")
            with self.assertRaises(build_lambda_artifact.ArtifactError):
                build_lambda_artifact.verify_sam_build(sam_root, source_commit)

    def test_deployed_zip_must_equal_manifest_bound_artifact_and_live_code_hash(self):
        build = self.run_builder()
        self.assertEqual(0, build.returncode, build.stderr)
        with tempfile.TemporaryDirectory() as directory:
            zip_path = Path(directory) / "deployed.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for relative_path in sorted(EXPECTED_RUNTIME_FILES):
                    archive.writestr(relative_path, (STAGED_ARTIFACT / relative_path).read_bytes())
            code_sha = base64.b64encode(hashlib.sha256(zip_path.read_bytes()).digest()).decode("ascii")

            build_lambda_artifact.verify_deployed_zip(STAGED_ARTIFACT, zip_path, code_sha)
            with self.assertRaises(build_lambda_artifact.ArtifactError):
                build_lambda_artifact.verify_deployed_zip(STAGED_ARTIFACT, zip_path, "wrong")

            tampered_path = Path(directory) / "tampered.zip"
            with zipfile.ZipFile(tampered_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for relative_path in sorted(EXPECTED_RUNTIME_FILES):
                    body = (STAGED_ARTIFACT / relative_path).read_bytes()
                    if relative_path == "lambda_function.py":
                        body += b"tamper"
                    archive.writestr(relative_path, body)
            tampered_sha = base64.b64encode(hashlib.sha256(tampered_path.read_bytes()).digest()).decode("ascii")
            with self.assertRaises(build_lambda_artifact.ArtifactError):
                build_lambda_artifact.verify_deployed_zip(STAGED_ARTIFACT, tampered_path, tampered_sha)

    def test_packaged_template_code_uri_is_exactly_scoped_to_the_current_run_prefix(self):
        sha = "a" * 40
        bucket = "zoolanding-config-payloads"
        prefix = f"system/deploy-artifacts/{sha}/123/1"
        with tempfile.TemporaryDirectory() as directory:
            template_path = Path(directory) / "packaged-template.json"

            def write(code_uri):
                template_path.write_text(json.dumps({
                    "Resources": {
                        "ConfigAuthoringFunction": {
                            "Properties": {"CodeUri": code_uri},
                        },
                    },
                }), encoding="utf-8")

            expected_key = f"{prefix}/{'b' * 32}"
            write(f"s3://{bucket}/{expected_key}")
            self.assertEqual(
                expected_key,
                build_lambda_artifact.packaged_lambda_s3_key(
                    template_path,
                    bucket,
                    prefix,
                ),
            )

            for unsafe_uri in (
                f"s3://other-bucket/{expected_key}",
                f"s3://{bucket}/system/deploy-artifacts/{sha}/other/1/{'b' * 32}",
                f"s3://{bucket}/{expected_key}?signed=value",
                {"Bucket": bucket, "Key": expected_key},
            ):
                with self.subTest(unsafe_uri=unsafe_uri):
                    write(unsafe_uri)
                    with self.assertRaises(build_lambda_artifact.ArtifactError):
                        build_lambda_artifact.packaged_lambda_s3_key(
                            template_path,
                            bucket,
                            prefix,
                        )


if __name__ == "__main__":
    unittest.main()
