#!/usr/bin/env python3
"""Fail-closed review for one explicitly named CloudFormation change set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping


class ChangeSetReviewError(ValueError):
    """Raised when a change set is not exact and safe to execute."""


_NO_CHANGE_REASON = (
    "The submitted information didn't contain changes. "
    "Submit different information to create a change set."
)


def _parameters(payload: Any) -> dict[str, str]:
    if not isinstance(payload, list):
        raise ChangeSetReviewError("change set parameters are unavailable")
    values: dict[str, str] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ChangeSetReviewError("change set parameter entry is invalid")
        key = item.get("ParameterKey")
        value = item.get("ParameterValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in values:
            raise ChangeSetReviewError("change set parameters are unavailable or ambiguous")
        values[key] = value
    return values


def _require_change_set_arn(arn: str, name: str) -> None:
    pattern = (
        r"^arn:(?:aws|aws-us-gov|aws-cn):cloudformation:[a-z0-9-]+:[0-9]{12}:"
        rf"changeSet/{re.escape(name)}/[A-Za-z0-9-]+$"
    )
    if re.fullmatch(pattern, arn) is None:
        raise ChangeSetReviewError("change set ARN is invalid")


def review_change_set(
    change_set: Any,
    *,
    expected_stack_name: str,
    expected_change_set_name: str,
    expected_change_set_arn: str,
    expected_parameters: Mapping[str, str],
) -> str:
    """Return ``execute`` or ``noop``; reject every ambiguous state."""
    if not isinstance(change_set, dict):
        raise ChangeSetReviewError("change set description is invalid")
    _require_change_set_arn(expected_change_set_arn, expected_change_set_name)
    if (
        change_set.get("StackName") != expected_stack_name
        or change_set.get("ChangeSetName") != expected_change_set_name
        or change_set.get("ChangeSetId") != expected_change_set_arn
        or change_set.get("ChangeSetType") != "UPDATE"
        or _parameters(change_set.get("Parameters")) != dict(expected_parameters)
    ):
        raise ChangeSetReviewError("change set identity or parameters are not exact")

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
        raise ChangeSetReviewError("change set is not complete and available")
    if not isinstance(changes, list) or not changes:
        raise ChangeSetReviewError("reviewed change set has no resource changes")

    for change in changes:
        if not isinstance(change, dict) or change.get("Type") != "Resource":
            raise ChangeSetReviewError("change set entry is invalid")
        resource = change.get("ResourceChange")
        if not isinstance(resource, dict) or resource.get("Action") not in {"Add", "Modify"}:
            raise ChangeSetReviewError("change set resource entry is invalid")
        if resource.get("Replacement") not in (None, "False"):
            raise ChangeSetReviewError("change set contains a possible replacement")
    return "execute"


def _parse_expected_parameters(values: list[str]) -> dict[str, str]:
    parameters: dict[str, str] = {}
    for value in values:
        key, separator, parameter_value = value.partition("=")
        if not separator or not key or key in parameters:
            raise ChangeSetReviewError("expected parameters are invalid")
        parameters[key] = parameter_value
    if not parameters:
        raise ChangeSetReviewError("expected parameters are required")
    return parameters


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("description", type=Path)
    parser.add_argument("--expected-stack-name", required=True)
    parser.add_argument("--expected-change-set-name", required=True)
    parser.add_argument("--expected-change-set-arn", required=True)
    parser.add_argument("--expected-parameter", action="append", default=[])
    args = parser.parse_args()
    try:
        payload = json.loads(args.description.read_text(encoding="utf-8"))
        decision = review_change_set(
            payload,
            expected_stack_name=args.expected_stack_name,
            expected_change_set_name=args.expected_change_set_name,
            expected_change_set_arn=args.expected_change_set_arn,
            expected_parameters=_parse_expected_parameters(args.expected_parameter),
        )
    except (OSError, json.JSONDecodeError, ChangeSetReviewError) as exc:
        raise SystemExit(str(exc)) from exc
    print(decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
