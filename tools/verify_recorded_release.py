#!/usr/bin/env python3
"""Run the unchanged current eight-file verifier against data-only historical Git blobs."""

import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build_lambda_artifact as artifact

ROOT = Path(__file__).resolve().parents[1]


class RecordedReleaseError(ValueError):
    pass


def verify_recorded_release(build, source):
    if not isinstance(source, str) or re.fullmatch(r"[a-f0-9]{40}", source) is None:
        raise RecordedReleaseError("recorded_source_invalid")
    original_root = artifact.PROJECT_ROOT
    try:
        with tempfile.TemporaryDirectory(prefix="config-source-data-") as directory:
            source_root = Path(directory)
            for relative in artifact.RUNTIME_FILES:
                name = relative.as_posix()
                entry = subprocess.check_output(["git", "ls-tree", source, "--", name], cwd=ROOT,
                                                stderr=subprocess.DEVNULL).decode().strip()
                if re.fullmatch(r"100(?:644|755) blob [a-f0-9]{40}\t" + re.escape(name), entry) is None:
                    raise RecordedReleaseError("recorded_source_inventory_invalid")
                body = subprocess.check_output(["git", "show", source + ":" + name], cwd=ROOT,
                                               stderr=subprocess.DEVNULL)
                target = source_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            # Only the source data root changes. No historical Python is imported or executed.
            artifact.PROJECT_ROOT = source_root
            artifact.verify_sam_build(Path(build), source)
    except (OSError, UnicodeError, subprocess.SubprocessError, artifact.ArtifactError):
        raise RecordedReleaseError("recorded_release_verification_failed") from None
    finally:
        artifact.PROJECT_ROOT = original_root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        verify_recorded_release(args.build, args.source_sha)
    except RecordedReleaseError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("recorded_eight_file_release_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
