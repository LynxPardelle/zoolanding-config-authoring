#!/usr/bin/env python3
"""Materialize exact non-secret TEST parameters for CloudFormation."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping


class ParameterPreparationError(ValueError):
    pass


def build_parameters(env: Mapping[str, str]) -> tuple[dict[str, str], set[str]]:
    del env
    return {
        "EnvironmentName": "test",
        "ManageStorageResources": "true",
        "ConfigTableName": "zoolanding-config-registry-test",
        "ConfigPayloadsBucketName": "zoolanding-config-payloads-test",
        "LogLevel": "INFO",
        "DeployAuthzConfigS3Key": "system/deploy-authz-v2.json",
    }, set()


def write_parameter_files(output: Path, parameters: Mapping[str, str], sensitive: set[str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if any(not key or not isinstance(value, str) or "\n" in value or "\r" in value for key, value in parameters.items()):
        raise ParameterPreparationError("test_parameter_invalid")
    payload = [{"ParameterKey": key, "ParameterValue": value} for key, value in parameters.items()]
    (output / "parameters.json").write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    expected = "".join(f"{key}={parameters[key]}\n" for key in sorted(parameters) if key not in sensitive)
    required = "".join(f"{key}\n" for key in sorted(sensitive) if parameters.get(key))
    (output / "expected-parameters.txt").write_text(expected, encoding="utf-8")
    (output / "required-parameters.txt").write_text(required, encoding="utf-8")


def main() -> int:
    parameters, sensitive = build_parameters(os.environ)
    write_parameter_files(Path(os.environ["RUNNER_TEMP"]) / "test-release-parameters", parameters, sensitive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

