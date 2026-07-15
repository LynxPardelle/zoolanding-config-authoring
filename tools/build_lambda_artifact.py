"""Build and verify the allowlisted Config Authoring Lambda artifact."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import stat
import sys
from urllib.parse import urlsplit
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = PROJECT_ROOT / ".build"
DEFAULT_ARTIFACT = BUILD_ROOT / "config-authoring"
SOURCE_DATE_EPOCH = 315532800  # 1980-01-01T00:00:00Z, valid for ZIP metadata.
SAM_MANIFEST_NAME = "config-authoring-manifest.json"
SOURCE_COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
MAX_DEPLOYED_ZIP_BYTES = 10 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 2 * 1024 * 1024
RUNTIME_FILES = (
    Path("lambda_function.py"),
    Path("server_policy_validation.py"),
    Path("schemas/server-features/commerce.schema.json"),
    Path("schemas/server-features/data-spaces.schema.json"),
    Path("schemas/server-features/integration-bindings.schema.json"),
    Path("schemas/server-features/notification-policies.schema.json"),
    Path("zoolanding_lambda_common.py"),
)


class ArtifactError(RuntimeError):
    """Raised when an artifact cannot be built or verified safely."""


def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _source_commit(value: str) -> str:
    if not isinstance(value, str) or not SOURCE_COMMIT_PATTERN.fullmatch(value):
        raise ArtifactError("source commit is not an exact SHA")
    return value


def _relative_inventory(root: Path) -> set[str]:
    if not root.is_dir() or root.is_symlink():
        raise ArtifactError(f"artifact directory is missing or unsafe: {root}")

    inventory: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ArtifactError(f"artifact contains a symlink: {path.relative_to(root).as_posix()}")
        if path.is_file():
            inventory.add(path.relative_to(root).as_posix())
    return inventory


def verify_artifact(artifact_root: Path) -> None:
    artifact_root = artifact_root.absolute()
    expected = {path.as_posix() for path in RUNTIME_FILES}
    actual = _relative_inventory(artifact_root)
    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unexpected:
        raise ArtifactError(f"unexpected artifact files: {', '.join(unexpected)}")
    if missing:
        raise ArtifactError(f"missing artifact files: {', '.join(missing)}")

    for relative_path in RUNTIME_FILES:
        source = PROJECT_ROOT / relative_path
        deployed = artifact_root / relative_path
        if not source.is_file() or source.is_symlink():
            raise ArtifactError(f"runtime source is missing or unsafe: {relative_path.as_posix()}")
        if deployed.read_bytes() != source.read_bytes():
            raise ArtifactError(f"artifact content differs from source: {relative_path.as_posix()}")


def artifact_manifest(artifact_root: Path, source_commit: str) -> dict[str, object]:
    verify_artifact(artifact_root)
    source_commit = _source_commit(source_commit)
    return {
        "version": 1,
        "sourceCommit": source_commit,
        "files": [
            {
                "path": relative_path.as_posix(),
                "size": (artifact_root / relative_path).stat().st_size,
                "sha256": hashlib.sha256((artifact_root / relative_path).read_bytes()).hexdigest(),
            }
            for relative_path in sorted(RUNTIME_FILES, key=lambda path: path.as_posix())
        ],
    }


def _strict_json_object(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise ArtifactError(f"manifest is missing or unsafe: {path}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ArtifactError("manifest contains duplicate keys")
            result[key] = value
        return result

    try:
        parsed = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError("manifest is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ArtifactError("manifest must be an object")
    return parsed


def _sam_build_inventory(build_root: Path) -> set[str]:
    inventory = _relative_inventory(build_root)
    expected = {"template.yaml", SAM_MANIFEST_NAME}
    expected.update(f"ConfigAuthoringFunction/{path.as_posix()}" for path in RUNTIME_FILES)
    if inventory != expected:
        raise ArtifactError("SAM build inventory is not exact")
    return inventory


def write_sam_manifest(build_root: Path, source_commit: str) -> Path:
    build_root = build_root.absolute()
    if not build_root.is_dir() or build_root.is_symlink():
        raise ArtifactError(f"SAM build directory is missing or unsafe: {build_root}")
    template = build_root / "template.yaml"
    if not template.is_file() or template.is_symlink():
        raise ArtifactError("SAM build template is missing or unsafe")
    function_root = build_root / "ConfigAuthoringFunction"
    manifest = artifact_manifest(function_root, source_commit)
    pre_manifest_inventory = _relative_inventory(build_root)
    expected = {"template.yaml"}
    expected.update(f"ConfigAuthoringFunction/{path.as_posix()}" for path in RUNTIME_FILES)
    if pre_manifest_inventory != expected:
        raise ArtifactError("SAM build inventory is not exact before manifest creation")
    manifest_path = build_root / SAM_MANIFEST_NAME
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _sam_build_inventory(build_root)
    return manifest_path


def verify_sam_build(build_root: Path, expected_source_commit: str) -> None:
    build_root = build_root.absolute()
    expected_source_commit = _source_commit(expected_source_commit)
    _sam_build_inventory(build_root)
    manifest_path = build_root / SAM_MANIFEST_NAME
    parsed = _strict_json_object(manifest_path)
    expected = artifact_manifest(build_root / "ConfigAuthoringFunction", expected_source_commit)
    if parsed != expected or manifest_path.read_bytes() != _canonical_json_bytes(expected):
        raise ArtifactError("SAM build manifest differs from the exact seven-file artifact")


def verify_deployed_zip(artifact_root: Path, deployed_zip_path: Path, expected_code_sha256: str) -> None:
    artifact_root = artifact_root.absolute()
    deployed_zip_path = deployed_zip_path.absolute()
    verify_artifact(artifact_root)
    if (
        not deployed_zip_path.is_file()
        or deployed_zip_path.is_symlink()
        or deployed_zip_path.stat().st_size < 1
        or deployed_zip_path.stat().st_size > MAX_DEPLOYED_ZIP_BYTES
    ):
        raise ArtifactError("deployed Lambda ZIP is missing or unsafe")
    deployed_zip = deployed_zip_path.read_bytes()
    actual_code_sha256 = base64.b64encode(hashlib.sha256(deployed_zip).digest()).decode("ascii")
    if not isinstance(expected_code_sha256, str) or actual_code_sha256 != expected_code_sha256:
        raise ArtifactError("downloaded Lambda ZIP differs from the live CodeSha256")

    expected_files = {path.as_posix() for path in RUNTIME_FILES}
    deployed_files: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(deployed_zip), "r") as archive:
            for info in archive.infolist():
                path = PurePosixPath(info.filename)
                if (
                    info.filename != path.as_posix()
                    or path.is_absolute()
                    or ".." in path.parts
                    or "\\" in info.filename
                    or stat.S_ISLNK(info.external_attr >> 16)
                    or info.flag_bits & 0x1
                ):
                    raise ArtifactError("deployed Lambda ZIP contains an unsafe path")
                if info.is_dir():
                    continue
                if (
                    info.filename in deployed_files
                    or info.filename not in expected_files
                    or info.file_size > MAX_RUNTIME_FILE_BYTES
                ):
                    raise ArtifactError("deployed Lambda ZIP inventory is not exact")
                deployed_files[info.filename] = archive.read(info)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise ArtifactError("deployed Lambda ZIP is invalid") from exc

    expected_bodies = {
        relative_path.as_posix(): (artifact_root / relative_path).read_bytes()
        for relative_path in RUNTIME_FILES
    }
    if deployed_files != expected_bodies:
        raise ArtifactError("live test Lambda differs from the manifest-bound artifact")


def packaged_lambda_s3_key(
    packaged_template_path: Path,
    expected_bucket: str,
    expected_prefix: str,
) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", expected_bucket):
        raise ArtifactError("expected package bucket is invalid")
    if not re.fullmatch(
        r"system/deploy-artifacts/[a-f0-9]{40}/[1-9][0-9]*/[1-9][0-9]*",
        expected_prefix,
    ):
        raise ArtifactError("expected package prefix is invalid")
    template = _strict_json_object(packaged_template_path.absolute())
    resources = template.get("Resources")
    function = resources.get("ConfigAuthoringFunction") if isinstance(resources, dict) else None
    properties = function.get("Properties") if isinstance(function, dict) else None
    code_uri = properties.get("CodeUri") if isinstance(properties, dict) else None
    if not isinstance(code_uri, str):
        raise ArtifactError("packaged Lambda CodeUri is unavailable")
    parsed = urlsplit(code_uri)
    if (
        parsed.scheme != "s3"
        or parsed.netloc != expected_bucket
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or not parsed.path.startswith("/")
    ):
        raise ArtifactError("packaged Lambda CodeUri is not exact")
    key = parsed.path[1:]
    if not re.fullmatch(
        re.escape(expected_prefix) + r"/[A-Za-z0-9._-]{16,128}",
        key,
    ):
        raise ArtifactError("packaged Lambda object key is outside the exact run prefix")
    return key


def normalize_artifact(artifact_root: Path) -> None:
    """Verify transported bytes, then restore deterministic ZIP timestamps."""
    artifact_root = artifact_root.absolute()
    verify_artifact(artifact_root)
    for path in artifact_root.rglob("*"):
        if path.is_file():
            os.utime(path, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))
    for directory in sorted(
        (path for path in artifact_root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        os.utime(directory, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))
    os.utime(artifact_root, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))
    verify_artifact(artifact_root)


def _assert_safe_build_location() -> None:
    if BUILD_ROOT.exists() and BUILD_ROOT.is_symlink():
        raise ArtifactError(f"build root must not be a symlink: {BUILD_ROOT}")
    if DEFAULT_ARTIFACT.exists():
        if DEFAULT_ARTIFACT.is_symlink():
            raise ArtifactError(f"artifact path must not be a symlink: {DEFAULT_ARTIFACT}")
        for path in DEFAULT_ARTIFACT.rglob("*"):
            if path.is_symlink():
                raise ArtifactError(
                    f"existing artifact contains a symlink: {path.relative_to(DEFAULT_ARTIFACT).as_posix()}"
                )


def build_artifact() -> Path:
    _assert_safe_build_location()
    if DEFAULT_ARTIFACT.exists():
        shutil.rmtree(DEFAULT_ARTIFACT)
    DEFAULT_ARTIFACT.mkdir(parents=True)

    for relative_path in RUNTIME_FILES:
        source = PROJECT_ROOT / relative_path
        if not source.is_file() or source.is_symlink():
            raise ArtifactError(f"runtime source is missing or unsafe: {relative_path.as_posix()}")
        if not source.resolve().is_relative_to(PROJECT_ROOT.resolve()):
            raise ArtifactError(f"runtime source escapes project root: {relative_path.as_posix()}")

        destination = DEFAULT_ARTIFACT / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        os.utime(destination, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))

    for directory in sorted(
        (path for path in DEFAULT_ARTIFACT.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        os.utime(directory, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))
    os.utime(DEFAULT_ARTIFACT, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))

    verify_artifact(DEFAULT_ARTIFACT)
    return DEFAULT_ARTIFACT


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--verify-artifact",
        type=Path,
        help="Verify an existing SAM artifact instead of rebuilding the staging directory.",
    )
    mode.add_argument(
        "--normalize-artifact",
        type=Path,
        help="Verify transported bytes and restore deterministic ZIP timestamps.",
    )
    mode.add_argument(
        "--write-sam-manifest",
        type=Path,
        help="Write the exact seven-file manifest into a completed SAM build directory.",
    )
    mode.add_argument(
        "--verify-sam-build",
        type=Path,
        help="Verify a SAM build, its exact inventory, and its source-bound manifest.",
    )
    mode.add_argument(
        "--verify-deployed-zip",
        type=Path,
        help="Verify a downloaded live Lambda ZIP against an exact artifact.",
    )
    mode.add_argument(
        "--extract-packaged-code-key",
        type=Path,
        help="Validate a packaged JSON template and print its exact Lambda S3 object key.",
    )
    parser.add_argument("--source-commit")
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--against-artifact", type=Path)
    parser.add_argument("--expected-code-sha256")
    parser.add_argument("--expected-bucket")
    parser.add_argument("--expected-prefix")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify_artifact is not None:
            verify_artifact(args.verify_artifact)
            print(f"verified allowlisted Lambda artifact: {args.verify_artifact}")
        elif args.normalize_artifact is not None:
            normalize_artifact(args.normalize_artifact)
            print(f"normalized allowlisted Lambda artifact: {args.normalize_artifact}")
        elif args.write_sam_manifest is not None:
            if args.source_commit is None:
                raise ArtifactError("--source-commit is required")
            write_sam_manifest(args.write_sam_manifest, args.source_commit)
            print("wrote exact source-bound SAM artifact manifest")
        elif args.verify_sam_build is not None:
            if args.expected_source_commit is None:
                raise ArtifactError("--expected-source-commit is required")
            verify_sam_build(args.verify_sam_build, args.expected_source_commit)
            print("verified exact source-bound SAM build")
        elif args.verify_deployed_zip is not None:
            if args.against_artifact is None or args.expected_code_sha256 is None:
                raise ArtifactError("--against-artifact and --expected-code-sha256 are required")
            verify_deployed_zip(
                args.against_artifact,
                args.verify_deployed_zip,
                args.expected_code_sha256,
            )
            print("verified live Lambda ZIP against the exact manifest-bound artifact")
        elif args.extract_packaged_code_key is not None:
            if args.expected_bucket is None or args.expected_prefix is None:
                raise ArtifactError("--expected-bucket and --expected-prefix are required")
            print(packaged_lambda_s3_key(
                args.extract_packaged_code_key,
                args.expected_bucket,
                args.expected_prefix,
            ))
        else:
            artifact = build_artifact()
            print(f"staged {len(RUNTIME_FILES)} allowlisted runtime files: {artifact}")
    except (ArtifactError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
