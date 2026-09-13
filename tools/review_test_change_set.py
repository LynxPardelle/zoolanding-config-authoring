#!/usr/bin/env python3
"""Fail-closed review of one TEST CloudFormation change set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping, Set


class ChangeSetReviewError(ValueError):
    """Raised when a change set is not exact and safe to execute."""


_NO_CHANGE_REASON = (
    "The submitted information didn't contain changes. "
    "Submit different information to create a change set."
)


def _parameter_map(payload: Any) -> dict[str, str]:
    if not isinstance(payload, list):
        raise ChangeSetReviewError("change_set_parameters_invalid")
    values: dict[str, str] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ChangeSetReviewError("change_set_parameters_invalid")
        key = item.get("ParameterKey")
        value = item.get("ParameterValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in values:
            raise ChangeSetReviewError("change_set_parameters_invalid")
        values[key] = value
    return values


def _require_change_set_arn(arn: str, name: str) -> None:
    pattern = (
        r"^arn:(?:aws|aws-us-gov|aws-cn):cloudformation:[a-z0-9-]+:[0-9]{12}:"
        rf"changeSet/{re.escape(name)}/[A-Za-z0-9-]+$"
    )
    if re.fullmatch(pattern, arn) is None:
        raise ChangeSetReviewError("change_set_arn_invalid")


def review_change_set(
    change_set: Any,
    *,
    expected_stack_name: str,
    expected_change_set_name: str,
    expected_change_set_arn: str,
    expected_change_set_type: str,
    expected_parameters: Mapping[str, str],
    required_parameters: Set[str],
) -> str:
    """Return execute/noop, rejecting identity, parameter, deletion, or replacement drift."""
    if not isinstance(change_set, dict):
        raise ChangeSetReviewError("change_set_description_invalid")
    if expected_change_set_type not in {"CREATE", "UPDATE"}:
        raise ChangeSetReviewError("change_set_type_invalid")
    _require_change_set_arn(expected_change_set_arn, expected_change_set_name)
    if (
        change_set.get("StackName") != expected_stack_name
        or change_set.get("ChangeSetName") != expected_change_set_name
        or change_set.get("ChangeSetId") != expected_change_set_arn
        # DescribeChangeSet omits the type; the create request pins it.
        # Reject an explicit conflicting field without requiring AWS to return it.
        or ("ChangeSetType" in change_set and change_set["ChangeSetType"] != expected_change_set_type)
    ):
        raise ChangeSetReviewError("change_set_identity_invalid")

    actual_parameters = _parameter_map(change_set.get("Parameters"))
    for key, value in expected_parameters.items():
        if actual_parameters.get(key) != value:
            raise ChangeSetReviewError("change_set_parameter_drift")
    for key in required_parameters:
        if not actual_parameters.get(key):
            raise ChangeSetReviewError("change_set_required_parameter_missing")

    status = change_set.get("Status")
    execution_status = change_set.get("ExecutionStatus")
    changes = change_set.get("Changes")
    if (
        status == "FAILED"
        and execution_status == "UNAVAILABLE"
        and change_set.get("StatusReason") == _NO_CHANGE_REASON
        and changes in (None, [])
    ):
        return "noop"
    if status != "CREATE_COMPLETE" or execution_status != "AVAILABLE":
        raise ChangeSetReviewError("change_set_not_available")
    if not isinstance(changes, list) or not changes:
        raise ChangeSetReviewError("change_set_changes_invalid")

    for change in changes:
        if not isinstance(change, dict) or change.get("Type") != "Resource":
            raise ChangeSetReviewError("change_set_entry_invalid")
        resource = change.get("ResourceChange")
        if not isinstance(resource, dict):
            raise ChangeSetReviewError("change_set_resource_invalid")
        if resource.get("Action") not in {"Add", "Modify"}:
            raise ChangeSetReviewError("stateful_resource_change_forbidden")
        if resource.get("Replacement") not in (None, "False"):
            raise ChangeSetReviewError("stateful_resource_change_forbidden")
    return "execute"


def _key_values(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or not key or key in parsed:
            raise ChangeSetReviewError("expected_parameters_invalid")
        parsed[key] = value
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("description", type=Path)
    parser.add_argument("--expected-stack-name", required=True)
    parser.add_argument("--expected-change-set-name", required=True)
    parser.add_argument("--expected-change-set-arn", required=True)
    parser.add_argument("--expected-change-set-type", choices=("CREATE", "UPDATE"), required=True)
    parser.add_argument("--expected-parameter", action="append", default=[])
    parser.add_argument("--required-parameter", action="append", default=[])
    args = parser.parse_args()
    try:
        payload = json.loads(args.description.read_text(encoding="utf-8"))
        decision = review_change_set(
            payload,
            expected_stack_name=args.expected_stack_name,
            expected_change_set_name=args.expected_change_set_name,
            expected_change_set_arn=args.expected_change_set_arn,
            expected_change_set_type=args.expected_change_set_type,
            expected_parameters=_key_values(args.expected_parameter),
            required_parameters=set(args.required_parameter),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ChangeSetReviewError) as exc:
        raise SystemExit(str(exc)) from exc
    print(decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
