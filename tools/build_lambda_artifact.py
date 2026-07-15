"""Build and verify the allowlisted Config Authoring Lambda artifact."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = PROJECT_ROOT / ".build"
DEFAULT_ARTIFACT = BUILD_ROOT / "config-authoring"
SOURCE_DATE_EPOCH = 315532800  # 1980-01-01T00:00:00Z, valid for ZIP metadata.
RUNTIME_FILES = (
    Path("lambda_function.py"),
    Path("zoolanding_lambda_common.py"),
)


class ArtifactError(RuntimeError):
    """Raised when an artifact cannot be built or verified safely."""


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
    parser.add_argument(
        "--verify-artifact",
        type=Path,
        help="Verify an existing SAM artifact instead of rebuilding the staging directory.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify_artifact is not None:
            verify_artifact(args.verify_artifact)
            print(f"verified allowlisted Lambda artifact: {args.verify_artifact}")
        else:
            artifact = build_artifact()
            print(f"staged {len(RUNTIME_FILES)} allowlisted runtime files: {artifact}")
    except (ArtifactError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
