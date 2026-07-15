"""Fail closed unless a deployment commit is the exact reviewed branch promotion."""

from __future__ import annotations

import argparse
import re
from typing import Optional


SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")


class PromotionProvenanceError(RuntimeError):
    """Raised when a promotion commit does not have exact expected provenance."""


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA_PATTERN.fullmatch(value):
        raise PromotionProvenanceError(f"{label} is not an exact commit SHA")
    return value


def verify_promotion_provenance(
    *,
    commit: str,
    parents: list[str],
    before_sha: str,
    source_tip: str,
    commit_tree: str,
    source_tree: str,
) -> str:
    _sha(commit, "promotion commit")
    before_sha = _sha(before_sha, "previous target tip")
    source_tip = _sha(source_tip, "current source tip")
    commit_tree = _sha(commit_tree, "promotion tree")
    source_tree = _sha(source_tree, "source tree")
    if not isinstance(parents, list) or len(parents) != 2:
        raise PromotionProvenanceError("promotion commit must have exactly two parents")
    first_parent = _sha(parents[0], "first parent")
    second_parent = _sha(parents[1], "second parent")
    if first_parent != before_sha:
        raise PromotionProvenanceError("first parent is not the exact previous target tip")
    if second_parent != source_tip:
        raise PromotionProvenanceError("second parent is not the current source branch tip")
    if commit_tree != source_tree:
        raise PromotionProvenanceError("promotion tree differs from the exact source tree")
    return second_parent


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--before-sha", required=True)
    parser.add_argument("--source-tip", required=True)
    parser.add_argument("--commit-tree", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--parents-line", required=True)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    words = args.parents_line.split()
    if not words or words[0] != args.commit:
        raise PromotionProvenanceError("git parent record does not match the promotion commit")
    verify_promotion_provenance(
        commit=args.commit,
        parents=words[1:],
        before_sha=args.before_sha,
        source_tip=args.source_tip,
        commit_tree=args.commit_tree,
        source_tree=args.source_tree,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
