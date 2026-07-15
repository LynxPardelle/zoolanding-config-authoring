"""Plan, apply, and roll back private per-draft authoring scope registries.

The tool derives the reviewed draft set from the Zoolanding hub registry, reads
environment-scoped AWS_ROLE_ARN values from GitHub, verifies each IAM role and
its exact GitHub OIDC trust, and writes only private S3 objects. It never reads
secret values and never accepts legacy roleName authorization.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request
import zipfile
from zoneinfo import ZoneInfo


LEGACY_AUTHZ_KEY = "system/deploy-authz.json"
AUTHZ_KEY = "system/deploy-authz-v2.json"
SCOPE_KEY = "system/server-scopes.json"
ENVIRONMENTS = ("test", "production")
ENVIRONMENT_BUCKETS = {
    "test": "zoolanding-config-payloads-test",
    "production": "zoolanding-config-payloads",
}
CANONICAL_ACTIONS = ("createSite", "upsertDraft", "publishDraft", "getSite")
SAFE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REPO_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
GITHUB_OWNER_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ROLE_ARN_PATTERN = re.compile(r"^arn:(?P<partition>[^:]+):iam::(?P<account>\d{12}):role/(?P<name>[A-Za-z0-9+=,.@_/-]+)$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
CENTRAL_TIME = ZoneInfo("America/Mexico_City")
AUTHORING_REPOSITORY = "zoolanding-config-authoring"
TEST_STACK_NAME = "zoolanding-config-authoring-test"
TEST_FUNCTION_LOGICAL_ID = "ConfigAuthoringFunction"
RUNTIME_ARTIFACT_FILES = (
    "lambda_function.py",
    "server_policy_validation.py",
    "schemas/server-features/commerce.schema.json",
    "schemas/server-features/data-spaces.schema.json",
    "schemas/server-features/integration-bindings.schema.json",
    "schemas/server-features/notification-policies.schema.json",
    "zoolanding_lambda_common.py",
)
MAX_DEPLOYED_ZIP_BYTES = 10 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 2 * 1024 * 1024


class BootstrapError(RuntimeError):
    """Raised when the bootstrap cannot prove a required invariant."""


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def verify_deployed_artifact(
    *,
    artifact_root: Path,
    deployed_zip: bytes,
    function_configuration: dict[str, Any],
    source_commit: str,
) -> dict[str, str]:
    if not re.fullmatch(r"[a-f0-9]{40}", source_commit):
        raise BootstrapError("test artifact source commit is invalid")
    if (
        not isinstance(deployed_zip, bytes)
        or not deployed_zip
        or len(deployed_zip) > MAX_DEPLOYED_ZIP_BYTES
        or not artifact_root.is_dir()
        or artifact_root.is_symlink()
    ):
        raise BootstrapError("test Lambda artifact is unavailable or unsafe")
    deployed_code_sha = base64.b64encode(hashlib.sha256(deployed_zip).digest()).decode("ascii")
    if function_configuration.get("CodeSha256") != deployed_code_sha:
        raise BootstrapError("deployed Lambda code hash differs from its downloaded package")

    expected_files = set(RUNTIME_ARTIFACT_FILES)
    artifact_files: dict[str, bytes] = {}
    for path in artifact_root.rglob("*"):
        if path.is_symlink():
            raise BootstrapError("test workflow artifact contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(artifact_root).as_posix()
        if relative not in expected_files or path.stat().st_size > MAX_RUNTIME_FILE_BYTES:
            raise BootstrapError("test workflow artifact inventory is not exact")
        artifact_files[relative] = path.read_bytes()
    if set(artifact_files) != expected_files:
        raise BootstrapError("test workflow artifact inventory is not exact")

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
                ):
                    raise BootstrapError("deployed Lambda package path is unsafe")
                if info.is_dir():
                    continue
                if (
                    info.filename in deployed_files
                    or info.filename not in expected_files
                    or info.file_size > MAX_RUNTIME_FILE_BYTES
                ):
                    raise BootstrapError("deployed Lambda package inventory is not exact")
                deployed_files[info.filename] = archive.read(info)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise BootstrapError("deployed Lambda package is invalid") from exc
    if set(deployed_files) != expected_files or deployed_files != artifact_files:
        raise BootstrapError("deployed Lambda package differs from the exact test workflow artifact")

    manifest = {
        "version": 1,
        "sourceCommit": source_commit,
        "files": [
            {
                "path": path,
                "size": len(artifact_files[path]),
                "sha256": sha256_hex(artifact_files[path]),
            }
            for path in sorted(artifact_files)
        ],
    }
    return {
        "sourceCommit": source_commit,
        "manifestSha256": sha256_hex(canonical_json_bytes(manifest)),
        "lambdaCodeSha256": deployed_code_sha,
    }


def _strict_domain(value: Any) -> str:
    if not isinstance(value, str):
        raise BootstrapError("canonical draft domain is missing")
    domain = value.strip().lower().rstrip(".")
    if domain != value or len(domain) > 253 or "." not in domain:
        raise BootstrapError("canonical draft domain is invalid")
    if any(not DOMAIN_LABEL_PATTERN.fullmatch(label) for label in domain.split(".")):
        raise BootstrapError("canonical draft domain is invalid")
    return domain


def _strict_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_PATTERN.fullmatch(value):
        raise BootstrapError(f"{label} is invalid")
    return value


def _strict_repo(value: Any) -> str:
    if not isinstance(value, str) or not REPO_PATTERN.fullmatch(value):
        raise BootstrapError("canonical draft repository is invalid")
    return value


def _strict_owner(value: Any) -> str:
    if not isinstance(value, str) or not GITHUB_OWNER_PATTERN.fullmatch(value):
        raise BootstrapError("canonical registry owner is invalid")
    return value


def _load_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise BootstrapError("JSON input is unavailable or invalid") from exc


def build_scope_registry(
    registry: Any,
    *,
    expected_draft_count: int,
    tenant_overrides: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(registry, dict) or registry.get("version") != 1:
        raise BootstrapError("unsupported canonical draft registry")
    owner = _strict_owner(registry.get("owner"))
    drafts = registry.get("drafts")
    if not isinstance(drafts, list) or len(drafts) != expected_draft_count or expected_draft_count < 1:
        raise BootstrapError("canonical draft count does not match explicit review")

    scopes: list[dict[str, str]] = []
    domains: set[str] = set()
    repos: set[str] = set()
    for entry in drafts:
        if not isinstance(entry, dict):
            raise BootstrapError("canonical draft entry is invalid")
        domain = _strict_domain(entry.get("domain"))
        repo = _strict_repo(entry.get("repo"))
        expected_url = f"https://github.com/{owner}/{repo}.git"
        if entry.get("githubUrl") != expected_url or entry.get("localPath") != f"drafts/{domain}":
            raise BootstrapError("canonical draft ownership fields disagree")
        if domain in domains or repo in repos:
            raise BootstrapError("canonical draft domain or repository is duplicated")
        domains.add(domain)
        repos.add(repo)
        tenant_id = _strict_id(tenant_overrides.get(domain, repo), "tenantId")
        scopes.append({
            "domain": domain,
            "repo": repo,
            "tenantId": tenant_id,
            "draftId": _strict_id(repo, "draftId"),
        })

    unknown_overrides = set(tenant_overrides) - domains
    if unknown_overrides:
        raise BootstrapError("tenant override targets an unregistered draft")
    scopes.sort(key=lambda entry: entry["domain"])
    return {"version": 1, "scopes": scopes}


def build_authz_rules(
    scope_registry: dict[str, Any],
    bindings: list[dict[str, str]],
    environment: str,
) -> list[dict[str, Any]]:
    if environment not in ENVIRONMENTS:
        raise BootstrapError("environment must be test or production")
    scopes = scope_registry.get("scopes")
    if scope_registry.get("version") != 1 or not isinstance(scopes, list) or not scopes:
        raise BootstrapError("scope registry is invalid")
    if len(bindings) != len(scopes):
        raise BootstrapError("role binding count does not match canonical scopes")

    bindings_by_domain: dict[str, dict[str, str]] = {}
    role_arns: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"domain", "repo", "environment", "roleArn"}:
            raise BootstrapError("role binding shape is invalid")
        domain = _strict_domain(binding.get("domain"))
        if domain in bindings_by_domain:
            raise BootstrapError("role binding is duplicated")
        if binding.get("environment") != environment:
            raise BootstrapError("role binding environment mismatch")
        role_arn = binding.get("roleArn")
        if not isinstance(role_arn, str) or not ROLE_ARN_PATTERN.fullmatch(role_arn):
            raise BootstrapError("role binding ARN is invalid")
        if role_arn in role_arns:
            raise BootstrapError("one IAM role cannot bind multiple draft scopes")
        role_arns.add(role_arn)
        bindings_by_domain[domain] = binding

    canonical_domains = {entry.get("domain") for entry in scopes}
    if set(bindings_by_domain) != canonical_domains:
        raise BootstrapError("role bindings include missing or unregistered drafts")

    rules: list[dict[str, Any]] = []
    for scope in scopes:
        domain = _strict_domain(scope.get("domain"))
        repo = _strict_repo(scope.get("repo"))
        binding = bindings_by_domain[domain]
        if binding.get("repo") != repo:
            raise BootstrapError("role binding repository mismatch")
        rules.append({
            "roleArn": binding["roleArn"],
            "tenantId": _strict_id(scope.get("tenantId"), "tenantId"),
            "draftId": _strict_id(scope.get("draftId"), "draftId"),
            "domains": [domain],
            "environments": [environment],
            "actions": list(CANONICAL_ACTIONS),
        })
    return rules


def _one_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BootstrapError(f"{label} is missing")
    return value


def require_environment_bucket(environment: str, bucket: str) -> None:
    if environment not in ENVIRONMENT_BUCKETS or bucket != ENVIRONMENT_BUCKETS[environment]:
        raise BootstrapError("environment and private config bucket do not match")


def require_stable_scope_bytes(test_scope_bytes: bytes, production_scope_bytes: bytes) -> None:
    if test_scope_bytes != production_scope_bytes:
        raise BootstrapError("scope registry bytes differ across test and production")


def _exact_parameter_map(stack: dict[str, Any]) -> dict[str, str]:
    parameters = stack.get("Parameters")
    if not isinstance(parameters, list):
        raise BootstrapError("test stack parameters are unavailable")
    result: dict[str, str] = {}
    for parameter in parameters:
        if (
            not isinstance(parameter, dict)
            or not isinstance(parameter.get("ParameterKey"), str)
            or not isinstance(parameter.get("ParameterValue"), str)
            or parameter["ParameterKey"] in result
        ):
            raise BootstrapError("test stack parameters are ambiguous")
        result[parameter["ParameterKey"]] = parameter["ParameterValue"]
    return result


def _stack_authoring_endpoint(stack: dict[str, Any]) -> str:
    outputs = stack.get("Outputs")
    if not isinstance(outputs, list):
        raise BootstrapError("test stack authoring endpoint output is unavailable")
    urls = [
        output.get("OutputValue")
        for output in outputs
        if isinstance(output, dict) and output.get("OutputKey") == "FunctionUrl"
    ]
    if (
        len(urls) != 1
        or not isinstance(urls[0], str)
        or not re.fullmatch(r"https://[a-z0-9]+\.lambda-url\.us-east-1\.on\.aws/", urls[0])
    ):
        raise BootstrapError("test stack authoring endpoint output is invalid")
    return urls[0]


def _normalize_authoring_endpoint(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise BootstrapError("test authoring endpoint is invalid")
    normalized = value.rstrip("/")
    if (
        not normalized
        or not re.fullmatch(
            r"https://[a-z0-9]+\.lambda-url\.us-east-1\.on\.aws",
            normalized,
        )
    ):
        raise BootstrapError("test authoring endpoint is invalid")
    return normalized


def _workflow_metadata(
    value: Any,
    *,
    expected_name: str,
    expected_path: str,
) -> int:
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("id"), int)
        or value["id"] < 1
        or value.get("name") != expected_name
        or value.get("path") != expected_path
        or value.get("state") != "active"
    ):
        raise BootstrapError("GitHub workflow identity is not exact and active")
    return value["id"]


def _aware_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise BootstrapError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BootstrapError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BootstrapError(f"{label} has no timezone")
    return parsed


def _git_sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value) is not None


def _commit_tree(value: Any, expected_sha: str, label: str) -> str:
    tree = value.get("tree") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("sha") != expected_sha
        or not isinstance(tree, dict)
        or not _git_sha(tree.get("sha"))
    ):
        raise BootstrapError(f"{label} is invalid")
    return tree["sha"]


def _validate_canary_dispatch_provenance(
    snapshot: dict[str, Any],
    *,
    owner: str,
    canary_repo: str,
    canary_commit_sha: str,
    canary_started: datetime,
) -> dict[str, Any]:
    expected_repo = f"{_strict_owner(owner)}/{_strict_repo(canary_repo)}"
    canary_commit = snapshot.get("canaryCommit")
    canary_tree = _commit_tree(canary_commit, canary_commit_sha, "test canary merge commit")
    parents = canary_commit.get("parents") if isinstance(canary_commit, dict) else None
    if (
        not isinstance(parents, list)
        or len(parents) != 2
        or any(not isinstance(parent, dict) or not _git_sha(parent.get("sha")) for parent in parents)
    ):
        raise BootstrapError("test canary merge commit must have exactly two parents")
    base_sha = parents[0]["sha"]
    dev_sha = parents[1]["sha"]

    dev_ref = snapshot.get("canaryDevRef")
    dev_object = dev_ref.get("object") if isinstance(dev_ref, dict) else None
    if (
        not isinstance(dev_object, dict)
        or dev_object.get("type") != "commit"
        or dev_object.get("sha") != dev_sha
    ):
        raise BootstrapError("test canary source is not the current dev tip")
    dev_tree = _commit_tree(snapshot.get("canaryDevCommit"), dev_sha, "test canary dev commit")
    if canary_tree != dev_tree:
        raise BootstrapError("test canary merge tree differs from its dev source tree")

    pulls = snapshot.get("canaryPulls")
    if not isinstance(pulls, list) or len(pulls) != 1 or not isinstance(pulls[0], dict):
        raise BootstrapError("test canary merge must have exactly one associated pull request")
    pull = pulls[0]
    base = pull.get("base")
    head = pull.get("head")
    base_repo = base.get("repo") if isinstance(base, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    merged_at = _aware_timestamp(pull.get("merged_at"), "test canary pull request merge time")
    if (
        not isinstance(pull.get("number"), int)
        or pull["number"] < 1
        or pull.get("state") != "closed"
        or pull.get("merge_commit_sha") != canary_commit_sha
        or not isinstance(base, dict)
        or base.get("ref") != "test"
        or base.get("sha") != base_sha
        or not isinstance(base_repo, dict)
        or base_repo.get("full_name") != expected_repo
        or not isinstance(head, dict)
        or head.get("ref") != "dev"
        or head.get("sha") != dev_sha
        or not isinstance(head_repo, dict)
        or head_repo.get("full_name") != expected_repo
        or merged_at >= canary_started
    ):
        raise BootstrapError("test canary pull request provenance is not exact")
    return {
        "pullRequest": pull["number"],
        "mergeCommit": canary_commit_sha,
        "baseCommit": base_sha,
        "devCommit": dev_sha,
        "tree": canary_tree,
    }


def validate_test_green_snapshot(
    snapshot: dict[str, Any],
    *,
    owner: str,
    test_commit: str,
    test_run_id: int,
    canary_repo: str,
    canary_run_id: int,
    expected_scope_bytes: bytes,
    expected_authz_bytes: bytes,
) -> dict[str, Any]:
    if not isinstance(snapshot, dict) or not re.fullmatch(r"[a-f0-9]{40}", test_commit):
        raise BootstrapError("test deployment evidence context is invalid")
    owner = _strict_owner(owner)
    canary_repo = _strict_repo(canary_repo)
    if (
        not isinstance(test_run_id, int)
        or test_run_id < 1
        or not isinstance(canary_run_id, int)
        or canary_run_id < 1
    ):
        raise BootstrapError("test deployment run id is invalid")

    try:
        scope_contract = json.loads(expected_scope_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("test scope contract is invalid") from exc
    scopes = scope_contract.get("scopes") if isinstance(scope_contract, dict) else None
    matching_canary_scopes = [
        scope for scope in scopes or []
        if isinstance(scope, dict) and scope.get("repo") == canary_repo
    ]
    if len(matching_canary_scopes) != 1:
        raise BootstrapError("test canary repository is not one canonical draft scope")

    remote_ref = snapshot.get("remoteRef")
    run = snapshot.get("run")
    remote_object = remote_ref.get("object") if isinstance(remote_ref, dict) else None
    authoring_workflow_id = _workflow_metadata(
        snapshot.get("authoringWorkflow"),
        expected_name="Deploy Test",
        expected_path=".github/workflows/deploy-test.yml",
    )
    if (
        not isinstance(remote_ref, dict)
        or not isinstance(remote_object, dict)
        or remote_object.get("sha") != test_commit
        or remote_object.get("type") != "commit"
        or not isinstance(run, dict)
        or run.get("databaseId") != test_run_id
        or run.get("runAttempt") != 1
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("headSha") != test_commit
        or run.get("headBranch") != "test"
        or run.get("event") != "push"
        or run.get("workflowName") != "Deploy Test"
        or run.get("workflowId") != authoring_workflow_id
        or run.get("path") != ".github/workflows/deploy-test.yml"
    ):
        raise BootstrapError("GitHub test deployment evidence is not green and exact")

    canary_ref = snapshot.get("canaryRef")
    canary_object = canary_ref.get("object") if isinstance(canary_ref, dict) else None
    canary_run = snapshot.get("canaryRun")
    canary_workflow_id = _workflow_metadata(
        snapshot.get("canaryWorkflow"),
        expected_name="Deploy test draft",
        expected_path=".github/workflows/deploy-test.yml",
    )
    authoring_finished = _aware_timestamp(run.get("updatedAt"), "test workflow completion time")
    canary_started = _aware_timestamp(
        canary_run.get("createdAt") if isinstance(canary_run, dict) else None,
        "test canary start time",
    )
    endpoint_evidence = snapshot.get("canaryAuthoringEndpoint")
    if (
        not isinstance(endpoint_evidence, dict)
        or set(endpoint_evidence) != {"name", "value", "updatedAt"}
        or endpoint_evidence.get("name") != "AUTHORING_ENDPOINT"
    ):
        raise BootstrapError("test canary authoring endpoint evidence is invalid")
    endpoint_updated = _aware_timestamp(
        endpoint_evidence.get("updatedAt"),
        "test canary authoring endpoint update time",
    )
    if (
        not isinstance(canary_object, dict)
        or canary_object.get("type") != "commit"
        or not isinstance(canary_run, dict)
        or canary_run.get("databaseId") != canary_run_id
        or canary_run.get("runAttempt") != 1
        or canary_run.get("status") != "completed"
        or canary_run.get("conclusion") != "success"
        or canary_run.get("headSha") != canary_object.get("sha")
        or canary_run.get("headBranch") != "test"
        or canary_run.get("event") != "workflow_dispatch"
        or canary_run.get("workflowName") != "Deploy test draft"
        or canary_run.get("workflowId") != canary_workflow_id
        or canary_run.get("path") != ".github/workflows/deploy-test.yml"
        or authoring_finished >= canary_started
        or endpoint_updated >= canary_started
    ):
        raise BootstrapError("signed canonical draft test canary is not green and ordered")
    canary_provenance = _validate_canary_dispatch_provenance(
        snapshot,
        owner=owner,
        canary_repo=canary_repo,
        canary_commit_sha=canary_run["headSha"],
        canary_started=canary_started,
    )

    stack_result = snapshot.get("stack")
    stacks = stack_result.get("Stacks") if isinstance(stack_result, dict) else None
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise BootstrapError("test stack evidence is unavailable")
    stack = stacks[0]
    if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise BootstrapError("test stack is not complete")
    expected_parameters = {
        "EnvironmentName": "test",
        "ManageStorageResources": "true",
        "ConfigTableName": "zoolanding-config-registry-test",
        "ConfigPayloadsBucketName": ENVIRONMENT_BUCKETS["test"],
        "LogLevel": "INFO",
        "DeployAuthzConfigS3Key": AUTHZ_KEY,
    }
    if _exact_parameter_map(stack) != expected_parameters:
        raise BootstrapError("test stack parameters do not match the reviewed environment")
    authoring_endpoint = _stack_authoring_endpoint(stack)
    if (
        _normalize_authoring_endpoint(endpoint_evidence.get("value"))
        != _normalize_authoring_endpoint(authoring_endpoint)
    ):
        raise BootstrapError("test canary authoring endpoint does not match the reviewed stack")

    resource_result = snapshot.get("stackResource")
    resource = resource_result.get("StackResourceDetail") if isinstance(resource_result, dict) else None
    function = snapshot.get("function")
    if (
        not isinstance(resource, dict)
        or resource.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
        or not isinstance(resource.get("PhysicalResourceId"), str)
        or not isinstance(function, dict)
        or function.get("FunctionName") != resource.get("PhysicalResourceId")
        or not isinstance(function.get("FunctionArn"), str)
        or not function.get("FunctionArn")
        or function.get("Runtime") != "python3.13"
        or function.get("State") != "Active"
        or function.get("LastUpdateStatus") != "Successful"
        or not isinstance(function.get("CodeSha256"), str)
        or not function.get("CodeSha256")
        or not isinstance(function.get("RevisionId"), str)
        or not function.get("RevisionId")
    ):
        raise BootstrapError("test Lambda deployment is not active and exact")
    function_url_config = snapshot.get("functionUrlConfig")
    if (
        not isinstance(function_url_config, dict)
        or function_url_config.get("FunctionArn") != function.get("FunctionArn")
        or function_url_config.get("FunctionUrl") != authoring_endpoint
        or function_url_config.get("AuthType") != "AWS_IAM"
        or function_url_config.get("InvokeMode") != "BUFFERED"
    ):
        raise BootstrapError("test Lambda Function URL is not exact and IAM-protected")
    expected_variables = {
        "CONFIG_TABLE_NAME": "zoolanding-config-registry-test",
        "CONFIG_PAYLOADS_BUCKET_NAME": ENVIRONMENT_BUCKETS["test"],
        "ENVIRONMENT_NAME": "test",
        "LOG_LEVEL": "INFO",
        "DEPLOY_AUTHZ_CONFIG_S3_KEY": AUTHZ_KEY,
    }
    function_environment = function.get("Environment")
    if (
        not isinstance(function_environment, dict)
        or function_environment.get("Variables") != expected_variables
    ):
        raise BootstrapError("test Lambda environment does not match the reviewed stack")
    artifact_evidence = snapshot.get("artifactEvidence")
    if (
        not isinstance(artifact_evidence, dict)
        or set(artifact_evidence) != {
            "sourceCommit", "manifestSha256", "lambdaCodeSha256"
        }
        or artifact_evidence.get("sourceCommit") != test_commit
        or not isinstance(artifact_evidence.get("manifestSha256"), str)
        or not SHA256_PATTERN.fullmatch(artifact_evidence["manifestSha256"])
        or artifact_evidence.get("lambdaCodeSha256") != function.get("CodeSha256")
    ):
        raise BootstrapError("test Lambda is not bound to the exact workflow artifact")

    state = snapshot.get("bucketState")
    if state != {
        "versioning": "Enabled",
        "ownership": "BucketOwnerEnforced",
        "publicAccessBlock": True,
    }:
        raise BootstrapError("test private bucket controls are not exact")
    scope_head = snapshot.get("scopeHead")
    authz_head = snapshot.get("authzHead")
    if not isinstance(scope_head, dict) or not isinstance(authz_head, dict):
        raise BootstrapError("test private object metadata is unavailable")
    _require_exact_object_metadata(scope_head, expected_scope_bytes)
    _require_exact_object_metadata(authz_head, expected_authz_bytes)
    expected_canary_binding = {
        "scopeVersionId": scope_head.get("versionId"),
        "scopeSha256": sha256_hex(expected_scope_bytes),
        "authzVersionId": authz_head.get("versionId"),
        "authzSha256": sha256_hex(expected_authz_bytes),
    }
    if snapshot.get("canaryBinding") != expected_canary_binding:
        raise BootstrapError("test canary is not bound to the current private bundle")
    if (
        _aware_timestamp(scope_head.get("lastModified"), "test scope last-modified time") >= canary_started
        or _aware_timestamp(authz_head.get("lastModified"), "test authorization last-modified time") >= canary_started
    ):
        raise BootstrapError("test canary predates the current private bundle")
    if (
        snapshot.get("scopeCurrent") != expected_scope_bytes
        or snapshot.get("scopeVersioned") != expected_scope_bytes
        or snapshot.get("authzCurrent") != expected_authz_bytes
        or snapshot.get("authzVersioned") != expected_authz_bytes
        or snapshot.get("unsignedApiStatus") != 403
    ):
        raise BootstrapError("test private readback or unsigned API probe is not exact")

    final_state = snapshot.get("finalState")
    stable_keys = {
        "remoteRef",
        "authoringWorkflow",
        "run",
        "canaryRef",
        "canaryWorkflow",
        "canaryRun",
        "canaryCommit",
        "canaryDevRef",
        "canaryDevCommit",
        "canaryPulls",
        "canaryAuthoringEndpoint",
        "stack",
        "stackResource",
        "function",
        "functionUrlConfig",
        "bucketState",
        "scopeHead",
        "authzHead",
        "scopeCurrent",
        "authzCurrent",
        "unsignedApiStatus",
    }
    if not isinstance(final_state, dict) or set(final_state) != stable_keys:
        raise BootstrapError("final test evidence revalidation is unavailable")
    if any(final_state.get(key) != snapshot.get(key) for key in stable_keys):
        raise BootstrapError("test evidence changed during final revalidation")

    return {
        "version": 1,
        "testCommit": test_commit,
        "testRunId": test_run_id,
        "workflow": {"status": "completed", "conclusion": "success"},
        "signedCanary": {
            "repo": canary_repo,
            "runId": canary_run_id,
            "headSha": canary_run["headSha"],
            "status": "completed",
            "conclusion": "success",
            "authoringEndpointSha256": sha256_hex(
                _normalize_authoring_endpoint(authoring_endpoint).encode("utf-8")
            ),
            "authoringEndpointVariableUpdatedAt": endpoint_evidence["updatedAt"],
            "provenance": canary_provenance,
            "testBundle": expected_canary_binding,
        },
        "stack": {"name": TEST_STACK_NAME, "status": stack["StackStatus"]},
        "lambda": {
            "codeSha256": function["CodeSha256"],
            "revisionId": function["RevisionId"],
            "artifactManifestSha256": artifact_evidence["manifestSha256"],
            "sourceCommit": artifact_evidence["sourceCommit"],
        },
        "scope": {
            "etag": scope_head.get("etag"),
            "versionId": scope_head.get("versionId"),
            "sha256": sha256_hex(expected_scope_bytes),
        },
        "authz": {
            "etag": authz_head.get("etag"),
            "versionId": authz_head.get("versionId"),
            "sha256": sha256_hex(expected_authz_bytes),
        },
        "authoringEndpointSha256": sha256_hex(authoring_endpoint.encode("utf-8")),
        "unsignedApiStatus": 403,
    }


def require_approved_test_evidence(evidence: dict[str, Any], approved_sha256: str) -> None:
    _require_approved_hash(
        approved_sha256,
        canonical_json_bytes(evidence),
        "test green evidence",
    )


def _unsigned_api_status(api_url: str) -> int:
    request = urllib_request.Request(
        api_url,
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(request, timeout=15) as response:
            return int(response.status)
    except urllib_error.HTTPError as exc:
        return int(exc.code)
    except (urllib_error.URLError, TimeoutError, OSError) as exc:
        raise BootstrapError("unsigned test API probe failed") from exc


def _rest_run_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BootstrapError("GitHub workflow run evidence is unavailable")
    return {
        "databaseId": value.get("id"),
        "runAttempt": value.get("run_attempt"),
        "status": value.get("status"),
        "conclusion": value.get("conclusion"),
        "headSha": value.get("head_sha"),
        "headBranch": value.get("head_branch"),
        "event": value.get("event"),
        "workflowName": value.get("name"),
        "workflowId": value.get("workflow_id"),
        "path": value.get("path"),
        "createdAt": value.get("created_at"),
        "updatedAt": value.get("updated_at"),
    }


def _download_deployed_zip(location: Any) -> bytes:
    if not isinstance(location, str) or not location.startswith("https://"):
        raise BootstrapError("deployed Lambda package location is unavailable")
    try:
        with urllib_request.urlopen(location, timeout=30) as response:
            payload = response.read(MAX_DEPLOYED_ZIP_BYTES + 1)
    except (urllib_error.URLError, TimeoutError, OSError) as exc:
        raise BootstrapError("deployed Lambda package could not be downloaded") from exc
    if not payload or len(payload) > MAX_DEPLOYED_ZIP_BYTES:
        raise BootstrapError("deployed Lambda package exceeds the review limit")
    return payload


def collect_artifact_evidence(
    *,
    runner: "CommandRunner",
    owner: str,
    profile: str,
    region: str,
    test_commit: str,
    test_run_id: int,
    function_name: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    artifact_name = f"config-authoring-test-{test_commit}"
    artifact_result = runner.run_json([
        "gh", "api",
        f"repos/{owner}/{AUTHORING_REPOSITORY}/actions/runs/{test_run_id}/artifacts",
        "--method", "GET",
        "-f", "per_page=100",
    ])
    artifacts = artifact_result.get("artifacts") if isinstance(artifact_result, dict) else None
    matches = [
        artifact for artifact in artifacts or []
        if isinstance(artifact, dict) and artifact.get("name") == artifact_name
    ]
    if (
        not isinstance(artifacts, list)
        or len(matches) != 1
        or matches[0].get("expired") is not False
        or not isinstance(matches[0].get("size_in_bytes"), int)
        or matches[0]["size_in_bytes"] < 1
        or matches[0]["size_in_bytes"] > MAX_DEPLOYED_ZIP_BYTES
    ):
        raise BootstrapError("exact test workflow artifact metadata is unavailable")
    function_result = runner.run_json([
        "aws", "lambda", "get-function", "--profile", profile,
        "--region", region, "--function-name", function_name,
        "--output", "json", "--no-cli-pager",
    ])
    configuration = (
        function_result.get("Configuration") if isinstance(function_result, dict) else None
    )
    code = function_result.get("Code") if isinstance(function_result, dict) else None
    if not isinstance(configuration, dict) or not isinstance(code, dict):
        raise BootstrapError("deployed Lambda function evidence is unavailable")
    deployed_zip = _download_deployed_zip(code.get("Location"))

    with tempfile.TemporaryDirectory(prefix="zoolanding-test-artifact-") as directory:
        download_root = Path(directory)
        runner.run([
            "gh", "run", "download", str(test_run_id),
            "--repo", f"{owner}/{AUTHORING_REPOSITORY}",
            "--name", artifact_name,
            "--dir", str(download_root),
        ], timeout=120)
        candidates = [
            path for path in download_root.rglob(TEST_FUNCTION_LOGICAL_ID)
            if path.is_dir() and not path.is_symlink()
        ]
        if len(candidates) != 1:
            raise BootstrapError("exact test workflow Lambda artifact is unavailable")
        artifact_evidence = verify_deployed_artifact(
            artifact_root=candidates[0],
            deployed_zip=deployed_zip,
            function_configuration=configuration,
            source_commit=test_commit,
        )
    return configuration, artifact_evidence


def collect_test_green_evidence(
    *,
    runner: "CommandRunner",
    s3: Any,
    owner: str,
    account_id: str,
    profile: str,
    region: str,
    test_commit: str,
    test_run_id: int,
    canary_repo: str,
    canary_run_id: int,
    expected_scope_bytes: bytes,
    expected_authz_bytes: bytes,
) -> dict[str, Any]:
    owner = _strict_owner(owner)
    remote_ref = runner.run_json([
        "gh", "api", f"repos/{owner}/{AUTHORING_REPOSITORY}/git/ref/heads/test",
    ])
    authoring_workflow = runner.run_json([
        "gh", "api",
        f"repos/{owner}/{AUTHORING_REPOSITORY}/actions/workflows/deploy-test.yml",
    ])
    run = _rest_run_evidence(runner.run_json([
        "gh", "api", f"repos/{owner}/{AUTHORING_REPOSITORY}/actions/runs/{test_run_id}",
    ]))
    canary_repo = _strict_repo(canary_repo)
    canary_ref = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/ref/heads/test",
    ])
    canary_workflow = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/actions/workflows/deploy-test.yml",
    ])
    canary_run = _rest_run_evidence(runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/actions/runs/{canary_run_id}",
    ]))
    canary_commit_sha = canary_run.get("headSha") if isinstance(canary_run, dict) else None
    if not _git_sha(canary_commit_sha):
        raise BootstrapError("test canary run commit is invalid")
    canary_commit = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/commits/{canary_commit_sha}",
    ])
    canary_dev_ref = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/ref/heads/dev",
    ])
    canary_dev_object = (
        canary_dev_ref.get("object") if isinstance(canary_dev_ref, dict) else None
    )
    canary_dev_sha = (
        canary_dev_object.get("sha") if isinstance(canary_dev_object, dict) else None
    )
    if not _git_sha(canary_dev_sha):
        raise BootstrapError("test canary dev ref is invalid")
    canary_dev_commit = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/commits/{canary_dev_sha}",
    ])
    canary_pulls = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/commits/{canary_commit_sha}/pulls",
    ])
    canary_authoring_endpoint = _github_environment_variable_evidence(
        runner,
        owner,
        canary_repo,
        "test",
        "AUTHORING_ENDPOINT",
    )
    stack = runner.run_json([
        "aws", "cloudformation", "describe-stacks", "--profile", profile,
        "--region", region, "--stack-name", TEST_STACK_NAME,
        "--output", "json", "--no-cli-pager",
    ])
    stacks = stack.get("Stacks") if isinstance(stack, dict) else None
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise BootstrapError("test stack evidence is unavailable")
    authoring_endpoint = _stack_authoring_endpoint(stacks[0])
    stack_resource = runner.run_json([
        "aws", "cloudformation", "describe-stack-resource", "--profile", profile,
        "--region", region, "--stack-name", TEST_STACK_NAME,
        "--logical-resource-id", TEST_FUNCTION_LOGICAL_ID,
        "--output", "json", "--no-cli-pager",
    ])
    resource = (
        stack_resource.get("StackResourceDetail")
        if isinstance(stack_resource, dict)
        else None
    )
    function_name = resource.get("PhysicalResourceId") if isinstance(resource, dict) else None
    if not isinstance(function_name, str) or not function_name:
        raise BootstrapError("test Lambda resource evidence is unavailable")
    function_url_config = runner.run_json([
        "aws", "lambda", "get-function-url-config", "--profile", profile,
        "--region", region, "--function-name", function_name,
        "--output", "json", "--no-cli-pager",
    ])
    function, artifact_evidence = collect_artifact_evidence(
        runner=runner,
        owner=owner,
        profile=profile,
        region=region,
        test_commit=test_commit,
        test_run_id=test_run_id,
        function_name=function_name,
    )

    bucket = ENVIRONMENT_BUCKETS["test"]
    scope_head = s3.head_object(bucket, SCOPE_KEY, account_id)
    authz_head = s3.head_object(bucket, AUTHZ_KEY, account_id)
    if scope_head is None or authz_head is None:
        raise BootstrapError("test private scope or authorization object is missing")
    snapshot = {
        "remoteRef": remote_ref,
        "authoringWorkflow": authoring_workflow,
        "run": run,
        "canaryRef": canary_ref,
        "canaryWorkflow": canary_workflow,
        "canaryRun": canary_run,
        "canaryCommit": canary_commit,
        "canaryDevRef": canary_dev_ref,
        "canaryDevCommit": canary_dev_commit,
        "canaryPulls": canary_pulls,
        "canaryAuthoringEndpoint": canary_authoring_endpoint,
        "stack": stack,
        "stackResource": stack_resource,
        "function": function,
        "functionUrlConfig": function_url_config,
        "artifactEvidence": artifact_evidence,
        "bucketState": s3.bucket_state(bucket, account_id),
        "scopeHead": scope_head,
        "authzHead": authz_head,
        "canaryBinding": {
            "scopeVersionId": scope_head.get("versionId"),
            "scopeSha256": sha256_hex(expected_scope_bytes),
            "authzVersionId": authz_head.get("versionId"),
            "authzSha256": sha256_hex(expected_authz_bytes),
        },
        "scopeCurrent": s3.get_object(bucket, SCOPE_KEY, account_id),
        "scopeVersioned": s3.get_object(bucket, SCOPE_KEY, account_id, scope_head["versionId"]),
        "authzCurrent": s3.get_object(bucket, AUTHZ_KEY, account_id),
        "authzVersioned": s3.get_object(bucket, AUTHZ_KEY, account_id, authz_head["versionId"]),
        "unsignedApiStatus": _unsigned_api_status(authoring_endpoint),
    }

    final_remote_ref = runner.run_json([
        "gh", "api", f"repos/{owner}/{AUTHORING_REPOSITORY}/git/ref/heads/test",
    ])
    final_authoring_workflow = runner.run_json([
        "gh", "api",
        f"repos/{owner}/{AUTHORING_REPOSITORY}/actions/workflows/deploy-test.yml",
    ])
    final_run = _rest_run_evidence(runner.run_json([
        "gh", "api", f"repos/{owner}/{AUTHORING_REPOSITORY}/actions/runs/{test_run_id}",
    ]))
    final_canary_ref = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/ref/heads/test",
    ])
    final_canary_workflow = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/actions/workflows/deploy-test.yml",
    ])
    final_canary_run = _rest_run_evidence(runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/actions/runs/{canary_run_id}",
    ]))
    final_canary_object = (
        final_canary_ref.get("object") if isinstance(final_canary_ref, dict) else None
    )
    final_canary_sha = (
        final_canary_object.get("sha") if isinstance(final_canary_object, dict) else None
    )
    if not _git_sha(final_canary_sha):
        raise BootstrapError("final test canary ref is invalid")
    final_canary_commit = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/commits/{final_canary_sha}",
    ])
    final_canary_dev_ref = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/ref/heads/dev",
    ])
    final_canary_dev_object = (
        final_canary_dev_ref.get("object")
        if isinstance(final_canary_dev_ref, dict)
        else None
    )
    final_canary_dev_sha = (
        final_canary_dev_object.get("sha")
        if isinstance(final_canary_dev_object, dict)
        else None
    )
    if not _git_sha(final_canary_dev_sha):
        raise BootstrapError("final test canary dev ref is invalid")
    final_canary_dev_commit = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/git/commits/{final_canary_dev_sha}",
    ])
    final_canary_pulls = runner.run_json([
        "gh", "api", f"repos/{owner}/{canary_repo}/commits/{final_canary_sha}/pulls",
    ])
    final_canary_authoring_endpoint = _github_environment_variable_evidence(
        runner,
        owner,
        canary_repo,
        "test",
        "AUTHORING_ENDPOINT",
    )
    final_stack = runner.run_json([
        "aws", "cloudformation", "describe-stacks", "--profile", profile,
        "--region", region, "--stack-name", TEST_STACK_NAME,
        "--output", "json", "--no-cli-pager",
    ])
    final_stacks = final_stack.get("Stacks") if isinstance(final_stack, dict) else None
    if (
        not isinstance(final_stacks, list)
        or len(final_stacks) != 1
        or not isinstance(final_stacks[0], dict)
    ):
        raise BootstrapError("final test stack evidence is unavailable")
    final_authoring_endpoint = _stack_authoring_endpoint(final_stacks[0])
    final_stack_resource = runner.run_json([
        "aws", "cloudformation", "describe-stack-resource", "--profile", profile,
        "--region", region, "--stack-name", TEST_STACK_NAME,
        "--logical-resource-id", TEST_FUNCTION_LOGICAL_ID,
        "--output", "json", "--no-cli-pager",
    ])
    final_resource = (
        final_stack_resource.get("StackResourceDetail")
        if isinstance(final_stack_resource, dict)
        else None
    )
    final_function_name = (
        final_resource.get("PhysicalResourceId") if isinstance(final_resource, dict) else None
    )
    if not isinstance(final_function_name, str) or not final_function_name:
        raise BootstrapError("final test Lambda resource evidence is unavailable")
    final_function_result = runner.run_json([
        "aws", "lambda", "get-function", "--profile", profile,
        "--region", region, "--function-name", final_function_name,
        "--output", "json", "--no-cli-pager",
    ])
    final_function = (
        final_function_result.get("Configuration")
        if isinstance(final_function_result, dict)
        else None
    )
    if not isinstance(final_function, dict):
        raise BootstrapError("final test Lambda configuration is unavailable")
    final_function_url_config = runner.run_json([
        "aws", "lambda", "get-function-url-config", "--profile", profile,
        "--region", region, "--function-name", final_function_name,
        "--output", "json", "--no-cli-pager",
    ])
    final_scope_head = s3.head_object(bucket, SCOPE_KEY, account_id)
    final_authz_head = s3.head_object(bucket, AUTHZ_KEY, account_id)
    if final_scope_head is None or final_authz_head is None:
        raise BootstrapError("final test private scope or authorization object is missing")
    snapshot["finalState"] = {
        "remoteRef": final_remote_ref,
        "authoringWorkflow": final_authoring_workflow,
        "run": final_run,
        "canaryRef": final_canary_ref,
        "canaryWorkflow": final_canary_workflow,
        "canaryRun": final_canary_run,
        "canaryCommit": final_canary_commit,
        "canaryDevRef": final_canary_dev_ref,
        "canaryDevCommit": final_canary_dev_commit,
        "canaryPulls": final_canary_pulls,
        "canaryAuthoringEndpoint": final_canary_authoring_endpoint,
        "stack": final_stack,
        "stackResource": final_stack_resource,
        "function": final_function,
        "functionUrlConfig": final_function_url_config,
        "bucketState": s3.bucket_state(bucket, account_id),
        "scopeHead": final_scope_head,
        "authzHead": final_authz_head,
        "scopeCurrent": s3.get_object(bucket, SCOPE_KEY, account_id),
        "authzCurrent": s3.get_object(bucket, AUTHZ_KEY, account_id),
        "unsignedApiStatus": _unsigned_api_status(final_authoring_endpoint),
    }
    return validate_test_green_snapshot(
        snapshot,
        owner=owner,
        test_commit=test_commit,
        test_run_id=test_run_id,
        canary_repo=canary_repo,
        canary_run_id=canary_run_id,
        expected_scope_bytes=expected_scope_bytes,
        expected_authz_bytes=expected_authz_bytes,
    )


def verify_role_evidence(
    *,
    owner: str,
    domain: str,
    repo: str,
    environment: str,
    account_id: str,
    evidence: dict[str, Any],
) -> dict[str, str]:
    owner = _strict_owner(owner)
    domain = _strict_domain(domain)
    repo = _strict_repo(repo)
    if environment not in ENVIRONMENTS or not re.fullmatch(r"\d{12}", account_id):
        raise BootstrapError("role verification context is invalid")
    github = evidence.get("github")
    iam = evidence.get("iam")
    if not isinstance(github, dict) or not isinstance(iam, dict):
        raise BootstrapError("role evidence is incomplete")
    role_arn = _one_string(github.get("AWS_ROLE_ARN"), "GitHub AWS_ROLE_ARN")
    match = ROLE_ARN_PATTERN.fullmatch(role_arn)
    suffix = "test" if environment == "test" else "production"
    expected_role_name = f"{repo}-{suffix}-deploy"
    if (
        github.get("DRAFT_DOMAIN") != domain
        or match is None
        or match.group("partition") != "aws"
        or match.group("account") != account_id
        or match.group("name") != expected_role_name
        or iam.get("Arn") != role_arn
        or iam.get("RoleName") != expected_role_name
    ):
        raise BootstrapError("GitHub and IAM role evidence disagree")

    trust = iam.get("AssumeRolePolicyDocument")
    statements = trust.get("Statement") if isinstance(trust, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or len(statements) != 1 or not isinstance(statements[0], dict):
        raise BootstrapError("IAM role trust must contain one exact statement")
    statement = statements[0]
    principal = statement.get("Principal")
    condition = statement.get("Condition")
    equals = condition.get("StringEquals") if isinstance(condition, dict) else None
    expected_branch = "test" if environment == "test" else "main"
    expected_equals = {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:ref": f"refs/heads/{expected_branch}",
        "token.actions.githubusercontent.com:sub": f"repo:{owner}/{repo}:environment:{environment}",
    }
    if (
        set(statement) != {"Effect", "Principal", "Action", "Condition"}
        or statement.get("Effect") != "Allow"
        or statement.get("Action") != "sts:AssumeRoleWithWebIdentity"
        or not isinstance(principal, dict)
        or set(principal) != {"Federated"}
        or principal.get("Federated") != f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
        or not isinstance(condition, dict)
        or set(condition) != {"StringEquals"}
        or not isinstance(equals, dict)
        or equals != expected_equals
    ):
        raise BootstrapError("IAM role GitHub OIDC trust is not exact")
    return {"domain": domain, "repo": repo, "environment": environment, "roleArn": role_arn}


class CommandRunner:
    def run(self, arguments: list[str], *, timeout: int = 60) -> None:
        environment = os.environ.copy()
        environment["AWS_PAGER"] = ""
        environment["GH_PAGER"] = ""
        try:
            completed = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise BootstrapError(f"required command is unavailable: {arguments[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise BootstrapError(f"{arguments[0]} operation timed out") from exc
        if completed.returncode != 0:
            raise BootstrapError(f"{arguments[0]} operation failed")

    def run_json(self, arguments: list[str], *, allow_not_found: bool = False) -> Optional[Any]:
        environment = os.environ.copy()
        environment["AWS_PAGER"] = ""
        environment["GH_PAGER"] = ""
        try:
            completed = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=60,
            )
        except FileNotFoundError as exc:
            raise BootstrapError(f"required command is unavailable: {arguments[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise BootstrapError(f"{arguments[0]} operation timed out") from exc
        if completed.returncode != 0:
            error_text = completed.stderr or ""
            if allow_not_found and any(marker in error_text for marker in ("404", "Not Found", "NoSuchKey")):
                return None
            raise BootstrapError(f"{arguments[0]} operation failed")
        try:
            return json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise BootstrapError(f"{arguments[0]} returned invalid JSON") from exc


def _github_variables(runner: CommandRunner, owner: str, repo: str, environment: str) -> dict[str, str]:
    result = runner.run_json([
        "gh", "variable", "list", "--repo", f"{owner}/{repo}", "--env", environment,
        "--json", "name,value",
    ])
    if not isinstance(result, list):
        raise BootstrapError("GitHub environment variables are unavailable")
    variables: dict[str, str] = {}
    for entry in result:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or not isinstance(entry.get("value"), str)
        ):
            raise BootstrapError("GitHub environment variable response is invalid")
        if entry["name"] in variables:
            raise BootstrapError("GitHub environment variable response is ambiguous")
        variables[entry["name"]] = entry.get("value")
    return variables


def _github_environment_variable_evidence(
    runner: CommandRunner,
    owner: str,
    repo: str,
    environment: str,
    variable_name: str,
) -> dict[str, str]:
    owner = _strict_owner(owner)
    repo = _strict_repo(repo)
    if environment not in {"test", "production"}:
        raise BootstrapError("GitHub environment is invalid")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", variable_name):
        raise BootstrapError("GitHub environment variable name is invalid")
    result = runner.run_json([
        "gh", "api",
        f"repos/{owner}/{repo}/environments/{environment}/variables/{variable_name}",
    ])
    if (
        not isinstance(result, dict)
        or result.get("name") != variable_name
        or not isinstance(result.get("value"), str)
        or not isinstance(result.get("updated_at"), str)
    ):
        raise BootstrapError("GitHub environment variable evidence is unavailable")
    return {
        "name": variable_name,
        "value": result["value"],
        "updatedAt": result["updated_at"],
    }


def collect_verified_bindings(
    registry: dict[str, Any],
    *,
    environment: str,
    profile: str,
    account_id: str,
    runner: CommandRunner,
) -> list[dict[str, str]]:
    owner = _strict_owner(registry.get("owner"))
    drafts = registry.get("drafts")
    if not isinstance(drafts, list):
        raise BootstrapError("canonical draft registry is invalid")
    bindings: list[dict[str, str]] = []
    for entry in drafts:
        if not isinstance(entry, dict):
            raise BootstrapError("canonical draft entry is invalid")
        domain = _strict_domain(entry.get("domain"))
        repo = _strict_repo(entry.get("repo"))
        github = _github_variables(runner, owner, repo, environment)
        role_arn = github.get("AWS_ROLE_ARN")
        match = ROLE_ARN_PATTERN.fullmatch(role_arn or "")
        if match is None:
            raise BootstrapError("GitHub AWS_ROLE_ARN is invalid")
        iam_result = runner.run_json([
            "aws", "iam", "get-role", "--profile", profile,
            "--role-name", match.group("name"), "--output", "json", "--no-cli-pager",
        ])
        if not isinstance(iam_result, dict) or not isinstance(iam_result.get("Role"), dict):
            raise BootstrapError("IAM role evidence is unavailable")
        bindings.append(verify_role_evidence(
            owner=owner,
            domain=domain,
            repo=repo,
            environment=environment,
            account_id=account_id,
            evidence={"github": github, "iam": iam_result["Role"]},
        ))
    return bindings


class AwsCliS3:
    def __init__(self, *, profile: str, region: str, runner: Optional[CommandRunner] = None):
        self.profile = profile
        self.region = region
        self.runner = runner or CommandRunner()

    def _command(self, operation: str, bucket: str, expected_owner: str) -> list[str]:
        return [
            "aws", "s3api", operation, "--profile", self.profile, "--region", self.region,
            "--bucket", bucket, "--expected-bucket-owner", expected_owner,
        ]

    def bucket_state(self, bucket: str, expected_owner: str) -> dict[str, Any]:
        versioning = self.runner.run_json(self._command("get-bucket-versioning", bucket, expected_owner) + [
            "--output", "json", "--no-cli-pager",
        ])
        ownership = self.runner.run_json(self._command("get-bucket-ownership-controls", bucket, expected_owner) + [
            "--output", "json", "--no-cli-pager",
        ])
        public_access = self.runner.run_json(self._command("get-public-access-block", bucket, expected_owner) + [
            "--output", "json", "--no-cli-pager",
        ])
        rules = ownership.get("OwnershipControls", {}).get("Rules", []) if isinstance(ownership, dict) else []
        block = (
            public_access.get("PublicAccessBlockConfiguration", {})
            if isinstance(public_access, dict)
            else {}
        )
        return {
            "versioning": versioning.get("Status") if isinstance(versioning, dict) and versioning.get("Status") else "null",
            "ownership": rules[0].get("ObjectOwnership") if len(rules) == 1 and isinstance(rules[0], dict) else "unknown",
            "publicAccessBlock": (
                isinstance(block, dict)
                and set(block) == {
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                }
                and all(value is True for value in block.values())
            ),
        }

    def head_object(self, bucket: str, key: str, expected_owner: str) -> Optional[dict[str, Any]]:
        result = self.runner.run_json(self._command("head-object", bucket, expected_owner) + [
            "--key", key, "--checksum-mode", "ENABLED", "--output", "json", "--no-cli-pager",
        ], allow_not_found=True)
        if result is None:
            return None
        if not isinstance(result, dict) or not isinstance(result.get("ETag"), str):
            raise BootstrapError("S3 object metadata is invalid")
        return {
            "etag": result["ETag"],
            "versionId": result.get("VersionId") or "null",
            "contentLength": result.get("ContentLength"),
            "contentType": result.get("ContentType"),
            "serverSideEncryption": result.get("ServerSideEncryption"),
            "checksumSHA256": result.get("ChecksumSHA256"),
            "lastModified": result.get("LastModified"),
        }

    def get_object(
        self,
        bucket: str,
        key: str,
        expected_owner: str,
        version_id: Optional[str] = None,
    ) -> bytes:
        handle = tempfile.NamedTemporaryFile(prefix="zoolanding-s3-read-", suffix=".json", delete=False)
        path = Path(handle.name)
        handle.close()
        try:
            command = self._command("get-object", bucket, expected_owner) + ["--key", key]
            if version_id is not None:
                command.extend(["--version-id", version_id])
            command.extend([str(path), "--output", "json", "--no-cli-pager"])
            self.runner.run_json(command)
            return path.read_bytes()
        except OSError as exc:
            raise BootstrapError("S3 object could not be read") from exc
        finally:
            path.unlink(missing_ok=True)

    def put_object(
        self,
        bucket: str,
        key: str,
        body: bytes,
        expected_owner: str,
        *,
        if_match: Optional[str] = None,
        if_none_match: Optional[str] = None,
    ) -> dict[str, str]:
        handle = tempfile.NamedTemporaryFile(prefix="zoolanding-s3-write-", suffix=".json", delete=False)
        path = Path(handle.name)
        try:
            handle.write(body)
            handle.close()
            checksum = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
            command = self._command("put-object", bucket, expected_owner) + [
                "--key", key,
                "--body", str(path),
                "--content-type", "application/json",
                "--server-side-encryption", "AES256",
                "--checksum-algorithm", "SHA256",
                "--checksum-sha256", checksum,
                "--output", "json",
                "--no-cli-pager",
            ]
            if if_match is not None:
                command.extend(["--if-match", if_match])
            if if_none_match is not None:
                command.extend(["--if-none-match", if_none_match])
            result = self.runner.run_json(command)
            if not isinstance(result, dict) or not isinstance(result.get("ETag"), str) or not result.get("VersionId"):
                raise BootstrapError("versioned S3 write did not return ETag and VersionId")
            return {"etag": result["ETag"], "versionId": result["VersionId"]}
        finally:
            try:
                handle.close()
            finally:
                path.unlink(missing_ok=True)


def _require_approved_hash(value: str, body: bytes, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value) or value != sha256_hex(body):
        raise BootstrapError(f"{label} approval hash does not match generated bytes")
    return value


def _verify_readback(
    s3: Any,
    *,
    bucket: str,
    key: str,
    expected_owner: str,
    expected_body: bytes,
    result: dict[str, str],
) -> None:
    if s3.get_object(bucket, key, expected_owner) != expected_body:
        raise BootstrapError("current S3 readback does not match generated bytes")
    if s3.get_object(bucket, key, expected_owner, result["versionId"]) != expected_body:
        raise BootstrapError("versioned S3 readback does not match generated bytes")
    head = s3.head_object(bucket, key, expected_owner)
    if not head or head.get("etag") != result["etag"] or head.get("versionId") != result["versionId"]:
        raise BootstrapError("S3 metadata readback does not match the new version")
    _require_exact_object_metadata(head, expected_body)


def _require_exact_object_metadata(head: dict[str, Any], expected_body: bytes) -> None:
    expected_checksum = base64.b64encode(hashlib.sha256(expected_body).digest()).decode("ascii")
    if (
        head.get("contentLength") != len(expected_body)
        or head.get("contentType") != "application/json"
        or head.get("serverSideEncryption") != "AES256"
        or head.get("checksumSHA256") != expected_checksum
    ):
        raise BootstrapError("S3 object encryption, content type, length, or checksum is not exact")


def _read_stable_versioned_object(
    s3: Any,
    *,
    bucket: str,
    key: str,
    expected_owner: str,
    head: dict[str, Any],
) -> bytes:
    current_body = s3.get_object(bucket, key, expected_owner)
    version_body = s3.get_object(bucket, key, expected_owner, head["versionId"])
    if current_body != version_body or s3.head_object(bucket, key, expected_owner) != head:
        raise BootstrapError("S3 object changed during reviewed readback")
    return current_body


def apply_private_bundle(
    s3: Any,
    *,
    bucket: str,
    expected_owner: str,
    scope_bytes: bytes,
    authz_bytes: bytes,
    approved_scope_sha256: str,
    approved_authz_sha256: str,
    expected_current_authz_etag: str,
    expected_current_authz_version_id: str,
    expected_current_scope_etag: str,
    expected_current_scope_version_id: str,
    expected_current_scope_sha256: str,
) -> dict[str, Any]:
    _require_approved_hash(approved_scope_sha256, scope_bytes, "scope registry")
    _require_approved_hash(approved_authz_sha256, authz_bytes, "authorization")
    state = s3.bucket_state(bucket, expected_owner)
    if state.get("versioning") != "Enabled":
        raise BootstrapError("S3 versioning must be enabled before bootstrap")
    if state.get("ownership") != "BucketOwnerEnforced":
        raise BootstrapError("S3 bucket ownership must be BucketOwnerEnforced")
    if state.get("publicAccessBlock") is not True:
        raise BootstrapError("all S3 public access block controls must be enabled")

    current_authz = s3.head_object(bucket, AUTHZ_KEY, expected_owner)
    previous_authz: Optional[dict[str, str]] = None
    if current_authz is None:
        if (
            expected_current_authz_etag != "MISSING"
            or expected_current_authz_version_id != "MISSING"
        ):
            raise BootstrapError("authorization object presence changed after review")
    else:
        if (
            current_authz.get("etag") != expected_current_authz_etag
            or current_authz.get("versionId") != expected_current_authz_version_id
        ):
            raise BootstrapError("authorization object changed after review")
    scope_head = s3.head_object(bucket, SCOPE_KEY, expected_owner)
    scope_result: dict[str, str]
    scope_written = False
    previous_scope: Optional[dict[str, str]] = None
    if scope_head is None:
        if (
            expected_current_scope_etag != "MISSING"
            or expected_current_scope_version_id != "MISSING"
            or expected_current_scope_sha256 != "MISSING"
        ):
            raise BootstrapError("scope registry presence changed after review")
        scope_result = s3.put_object(
            bucket, SCOPE_KEY, scope_bytes, expected_owner, if_none_match="*"
        )
        scope_written = True
        _verify_readback(
            s3,
            bucket=bucket,
            key=SCOPE_KEY,
            expected_owner=expected_owner,
            expected_body=scope_bytes,
            result=scope_result,
        )
    else:
        if (
            scope_head.get("etag") != expected_current_scope_etag
            or scope_head.get("versionId") != expected_current_scope_version_id
        ):
            raise BootstrapError("scope registry metadata changed after review")
        current_scope_body = _read_stable_versioned_object(
            s3,
            bucket=bucket,
            key=SCOPE_KEY,
            expected_owner=expected_owner,
            head=scope_head,
        )
        _require_approved_hash(
            expected_current_scope_sha256,
            current_scope_body,
            "current scope registry",
        )
        _require_exact_object_metadata(scope_head, current_scope_body)
        previous_scope = {
            "etag": scope_head["etag"],
            "versionId": scope_head["versionId"],
            "sha256": sha256_hex(current_scope_body),
        }
        if current_scope_body == scope_bytes:
            scope_result = {
                "etag": scope_head["etag"],
                "versionId": scope_head["versionId"],
            }
        else:
            validate_append_only_scope_update(current_scope_body, scope_bytes)
            scope_result = s3.put_object(
                bucket,
                SCOPE_KEY,
                scope_bytes,
                expected_owner,
                if_match=expected_current_scope_etag,
            )
            scope_written = True
            _verify_readback(
                s3,
                bucket=bucket,
                key=SCOPE_KEY,
                expected_owner=expected_owner,
                expected_body=scope_bytes,
                result=scope_result,
            )

    if current_authz is not None:
        previous_authz_body = _read_stable_versioned_object(
            s3,
            bucket=bucket,
            key=AUTHZ_KEY,
            expected_owner=expected_owner,
            head=current_authz,
        )
        previous_authz = {
            "etag": expected_current_authz_etag,
            "versionId": expected_current_authz_version_id,
            "sha256": sha256_hex(previous_authz_body),
        }
    authz_result = s3.put_object(
        bucket,
        AUTHZ_KEY,
        authz_bytes,
        expected_owner,
        if_match=(expected_current_authz_etag if current_authz is not None else None),
        if_none_match=("*" if current_authz is None else None),
    )
    _verify_readback(
        s3,
        bucket=bucket,
        key=AUTHZ_KEY,
        expected_owner=expected_owner,
        expected_body=authz_bytes,
        result=authz_result,
    )
    _verify_readback(
        s3,
        bucket=bucket,
        key=SCOPE_KEY,
        expected_owner=expected_owner,
        expected_body=scope_bytes,
        result=scope_result,
    )
    return {
        "bucket": bucket,
        "scope": {**scope_result, "sha256": sha256_hex(scope_bytes), "written": scope_written},
        "authz": {**authz_result, "sha256": sha256_hex(authz_bytes), "written": True},
        "previousScope": previous_scope,
        "previousAuthz": previous_authz,
    }


def rollback_object(
    s3: Any,
    *,
    bucket: str,
    key: str,
    expected_owner: str,
    restore_version_id: str,
    approved_restore_sha256: str,
    expected_current_etag: str,
    canonical_scope_bytes: bytes,
    environment: str,
) -> dict[str, str]:
    if key not in {AUTHZ_KEY, SCOPE_KEY}:
        raise BootstrapError("rollback key is not allowlisted")
    state = s3.bucket_state(bucket, expected_owner)
    if (
        state.get("versioning") != "Enabled"
        or state.get("ownership") != "BucketOwnerEnforced"
        or state.get("publicAccessBlock") is not True
    ):
        raise BootstrapError("rollback requires versioning, private access, and enforced bucket ownership")
    current = s3.head_object(bucket, key, expected_owner)
    if not current or current.get("etag") != expected_current_etag:
        raise BootstrapError("rollback target changed after review")
    restore_body = s3.get_object(bucket, key, expected_owner, restore_version_id)
    _require_approved_hash(approved_restore_sha256, restore_body, "rollback version")
    validate_restore_contract(
        key=key,
        restore_body=restore_body,
        canonical_scope_bytes=canonical_scope_bytes,
        environment=environment,
        expected_owner=expected_owner,
    )
    result = s3.put_object(
        bucket, key, restore_body, expected_owner, if_match=expected_current_etag
    )
    _verify_readback(
        s3,
        bucket=bucket,
        key=key,
        expected_owner=expected_owner,
        expected_body=restore_body,
        result=result,
    )
    return {**result, "sha256": sha256_hex(restore_body)}


def _parse_canonical_json_bytes(body: bytes, label: str) -> Any:
    if not isinstance(body, bytes) or not body:
        raise BootstrapError(f"{label} is unavailable")
    try:
        value = json.loads(
            body.decode("utf-8"),
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BootstrapError(f"{label} is invalid JSON") from exc
    if canonical_json_bytes(value) != body:
        raise BootstrapError(f"{label} is not canonical JSON")
    return value


def _validated_scope_contract(canonical_scope_bytes: bytes) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    contract = _parse_canonical_json_bytes(canonical_scope_bytes, "canonical scope contract")
    if (
        not isinstance(contract, dict)
        or set(contract) != {"version", "scopes"}
        or type(contract.get("version")) is not int
        or contract["version"] != 1
        or not isinstance(contract.get("scopes"), list)
        or not contract["scopes"]
    ):
        raise BootstrapError("canonical scope contract shape is invalid")

    scopes_by_domain: dict[str, dict[str, str]] = {}
    repos: set[str] = set()
    draft_ids: set[str] = set()
    for scope in contract["scopes"]:
        if not isinstance(scope, dict) or set(scope) != {"domain", "repo", "tenantId", "draftId"}:
            raise BootstrapError("canonical scope entry shape is invalid")
        domain = _strict_domain(scope.get("domain"))
        repo = _strict_repo(scope.get("repo"))
        tenant_id = _strict_id(scope.get("tenantId"), "tenantId")
        draft_id = _strict_id(scope.get("draftId"), "draftId")
        if domain in scopes_by_domain or repo in repos or draft_id in draft_ids:
            raise BootstrapError("canonical scope entry is duplicated")
        scopes_by_domain[domain] = {
            "domain": domain,
            "repo": repo,
            "tenantId": tenant_id,
            "draftId": draft_id,
        }
        repos.add(repo)
        draft_ids.add(draft_id)
    if list(scopes_by_domain) != sorted(scopes_by_domain):
        raise BootstrapError("canonical scope entries are not sorted")
    return contract, scopes_by_domain


def validate_append_only_scope_update(current_scope_bytes: bytes, proposed_scope_bytes: bytes) -> None:
    _, current_by_domain = _validated_scope_contract(current_scope_bytes)
    _, proposed_by_domain = _validated_scope_contract(proposed_scope_bytes)
    if not set(current_by_domain) < set(proposed_by_domain):
        raise BootstrapError("scope registry update must append at least one new canonical draft")
    if any(
        proposed_by_domain.get(domain) != scope
        for domain, scope in current_by_domain.items()
    ):
        raise BootstrapError("existing scope mappings are immutable during append")


def validate_restore_contract(
    *,
    key: str,
    restore_body: bytes,
    canonical_scope_bytes: bytes,
    environment: str,
    expected_owner: str,
) -> None:
    if key not in {AUTHZ_KEY, SCOPE_KEY}:
        raise BootstrapError("rollback key is not allowlisted")
    if environment not in ENVIRONMENTS or not re.fullmatch(r"\d{12}", expected_owner):
        raise BootstrapError("rollback environment or AWS account is invalid")
    _, scopes_by_domain = _validated_scope_contract(canonical_scope_bytes)
    if key == SCOPE_KEY:
        if restore_body != canonical_scope_bytes:
            raise BootstrapError("scope rollback would change the stable canonical registry")
        return

    rules = _parse_canonical_json_bytes(restore_body, "authorization rollback version")
    if not isinstance(rules, list) or len(rules) != len(scopes_by_domain):
        raise BootstrapError("authorization rollback rule count is invalid")
    seen_domains: set[str] = set()
    seen_role_arns: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
            "roleArn", "tenantId", "draftId", "domains", "environments", "actions"
        }:
            raise BootstrapError("authorization rollback rule shape is invalid")
        domains = rule.get("domains")
        if not isinstance(domains, list) or len(domains) != 1:
            raise BootstrapError("authorization rollback domain scope is invalid")
        domain = _strict_domain(domains[0])
        scope = scopes_by_domain.get(domain)
        if scope is None or domain in seen_domains:
            raise BootstrapError("authorization rollback domain is unregistered or duplicated")
        role_arn = rule.get("roleArn")
        match = ROLE_ARN_PATTERN.fullmatch(role_arn) if isinstance(role_arn, str) else None
        if (
            match is None
            or match.group("partition") != "aws"
            or match.group("account") != expected_owner
            or match.group("name") != f"{scope['repo']}-{environment}-deploy"
            or role_arn in seen_role_arns
            or rule.get("tenantId") != scope["tenantId"]
            or rule.get("draftId") != scope["draftId"]
            or rule.get("environments") != [environment]
            or rule.get("actions") != list(CANONICAL_ACTIONS)
        ):
            raise BootstrapError("authorization rollback binding is not exact")
        seen_domains.add(domain)
        seen_role_arns.add(role_arn)
    if seen_domains != set(scopes_by_domain):
        raise BootstrapError("authorization rollback is missing canonical scopes")


def _parse_overrides(values: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise BootstrapError("tenant override must use domain=tenantId")
        domain, tenant_id = value.split("=", 1)
        domain = _strict_domain(domain)
        if domain in overrides:
            raise BootstrapError("tenant override is duplicated")
        overrides[domain] = _strict_id(tenant_id, "tenantId")
    return overrides


def _account_id(runner: CommandRunner, profile: str) -> str:
    result = runner.run_json([
        "aws", "sts", "get-caller-identity", "--profile", profile,
        "--output", "json", "--no-cli-pager",
    ])
    account_id = result.get("Account") if isinstance(result, dict) else None
    if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
        raise BootstrapError("AWS account identity is unavailable")
    return account_id


def _generated_bundle(args: argparse.Namespace, environment: str, runner: CommandRunner) -> tuple[bytes, bytes, str]:
    registry = _load_json_file(args.registry)
    overrides = _parse_overrides(args.tenant_override)
    scopes = build_scope_registry(
        registry,
        expected_draft_count=args.expected_draft_count,
        tenant_overrides=overrides,
    )
    account_id = _account_id(runner, args.profile)
    bindings = collect_verified_bindings(
        registry,
        environment=environment,
        profile=args.profile,
        account_id=account_id,
        runner=runner,
    )
    rules = build_authz_rules(scopes, bindings, environment)
    return canonical_json_bytes(scopes), canonical_json_bytes(rules), account_id


def _central_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BootstrapError("S3 object timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BootstrapError("S3 object timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise BootstrapError("S3 object timestamp has no timezone")
    return parsed.astimezone(CENTRAL_TIME).isoformat()


def _safe_head(head: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if head is None:
        return None
    return {
        "etag": head.get("etag"),
        "versionId": head.get("versionId"),
        "contentLength": head.get("contentLength"),
        "lastModifiedCentral": _central_timestamp(head.get("lastModified")),
    }


def _plan(args: argparse.Namespace) -> dict[str, Any]:
    require_environment_bucket("test", args.test_bucket)
    require_environment_bucket("production", args.production_bucket)
    runner = CommandRunner()
    bundles: dict[str, tuple[bytes, bytes, str]] = {}
    environments: dict[str, Any] = {}
    for environment in ENVIRONMENTS:
        scope_bytes, authz_bytes, account_id = _generated_bundle(args, environment, runner)
        bundles[environment] = (scope_bytes, authz_bytes, account_id)
        bucket = args.test_bucket if environment == "test" else args.production_bucket
        s3 = AwsCliS3(profile=args.profile, region=args.region, runner=runner)
        current_authz = s3.head_object(bucket, AUTHZ_KEY, account_id)
        current_scope = s3.head_object(bucket, SCOPE_KEY, account_id)
        current_authz_sha256: Optional[str] = None
        if current_authz is not None:
            current_authz_body = _read_stable_versioned_object(
                s3,
                bucket=bucket,
                key=AUTHZ_KEY,
                expected_owner=account_id,
                head=current_authz,
            )
            _require_exact_object_metadata(current_authz, current_authz_body)
            current_authz_sha256 = sha256_hex(current_authz_body)
        current_scope_sha256: Optional[str] = None
        scope_update_mode = "create"
        if current_scope is not None:
            current_scope_body = _read_stable_versioned_object(
                s3,
                bucket=bucket,
                key=SCOPE_KEY,
                expected_owner=account_id,
                head=current_scope,
            )
            _require_exact_object_metadata(current_scope, current_scope_body)
            current_scope_sha256 = sha256_hex(current_scope_body)
            if current_scope_body == scope_bytes:
                scope_update_mode = "idempotent"
            else:
                validate_append_only_scope_update(current_scope_body, scope_bytes)
                scope_update_mode = "append"
        environments[environment] = {
            "bucket": bucket,
            "bucketState": s3.bucket_state(bucket, account_id),
            "scopeCount": len(json.loads(scope_bytes)["scopes"]),
            "ruleCount": len(json.loads(authz_bytes)),
            "scopeSha256": sha256_hex(scope_bytes),
            "authzSha256": sha256_hex(authz_bytes),
            "currentScope": _safe_head(current_scope),
            "currentScopeSha256": current_scope_sha256,
            "scopeUpdateMode": scope_update_mode,
            "currentAuthz": _safe_head(current_authz),
            "currentAuthzSha256": current_authz_sha256,
        }
    require_stable_scope_bytes(bundles["test"][0], bundles["production"][0])
    return {
        "mode": "plan",
        "scopeBytesStableAcrossEnvironments": True,
        "environments": environments,
    }


def _apply(args: argparse.Namespace) -> dict[str, Any]:
    require_environment_bucket(args.environment, args.bucket)
    runner = CommandRunner()
    scope_bytes, authz_bytes, account_id = _generated_bundle(args, args.environment, runner)
    test_evidence_sha256: Optional[str] = None
    if args.environment == "production":
        if (
            args.test_commit is None
            or args.test_run_id is None
            or args.canary_repo is None
            or args.canary_run_id is None
            or args.approve_test_evidence_sha256 is None
        ):
            raise BootstrapError("production apply requires approved machine-readable test evidence")
        test_scope_bytes, test_authz_bytes, test_account_id = _generated_bundle(args, "test", runner)
        if test_account_id != account_id:
            raise BootstrapError("test and production AWS accounts differ")
        require_stable_scope_bytes(test_scope_bytes, scope_bytes)
        registry = _load_json_file(args.registry)
        owner = _strict_owner(registry.get("owner") if isinstance(registry, dict) else None)
        test_s3 = AwsCliS3(profile=args.profile, region=args.region, runner=runner)
        evidence = collect_test_green_evidence(
            runner=runner,
            s3=test_s3,
            owner=owner,
            account_id=account_id,
            profile=args.profile,
            region=args.region,
            test_commit=args.test_commit,
            test_run_id=args.test_run_id,
            canary_repo=args.canary_repo,
            canary_run_id=args.canary_run_id,
            expected_scope_bytes=test_scope_bytes,
            expected_authz_bytes=test_authz_bytes,
        )
        require_approved_test_evidence(evidence, args.approve_test_evidence_sha256)
        test_evidence_sha256 = sha256_hex(canonical_json_bytes(evidence))
    s3 = AwsCliS3(profile=args.profile, region=args.region, runner=runner)
    result = apply_private_bundle(
        s3,
        bucket=args.bucket,
        expected_owner=account_id,
        scope_bytes=scope_bytes,
        authz_bytes=authz_bytes,
        approved_scope_sha256=args.approve_scope_sha256,
        approved_authz_sha256=args.approve_authz_sha256,
        expected_current_authz_etag=args.expected_current_authz_etag,
        expected_current_authz_version_id=args.expected_current_authz_version_id,
        expected_current_scope_etag=args.expected_current_scope_etag,
        expected_current_scope_version_id=args.expected_current_scope_version_id,
        expected_current_scope_sha256=args.expected_current_scope_sha256,
    )
    response = {"mode": "apply", "environment": args.environment, **result}
    if test_evidence_sha256 is not None:
        response["testEvidenceSha256"] = test_evidence_sha256
    return response


def _verify_test(args: argparse.Namespace) -> dict[str, Any]:
    runner = CommandRunner()
    scope_bytes, authz_bytes, account_id = _generated_bundle(args, "test", runner)
    registry = _load_json_file(args.registry)
    owner = _strict_owner(registry.get("owner") if isinstance(registry, dict) else None)
    s3 = AwsCliS3(profile=args.profile, region=args.region, runner=runner)
    evidence = collect_test_green_evidence(
        runner=runner,
        s3=s3,
        owner=owner,
        account_id=account_id,
        profile=args.profile,
        region=args.region,
        test_commit=args.test_commit,
        test_run_id=args.test_run_id,
        canary_repo=args.canary_repo,
        canary_run_id=args.canary_run_id,
        expected_scope_bytes=scope_bytes,
        expected_authz_bytes=authz_bytes,
    )
    return {
        "mode": "verify-test",
        "evidence": evidence,
        "evidenceSha256": sha256_hex(canonical_json_bytes(evidence)),
    }


def _rollback(args: argparse.Namespace) -> dict[str, Any]:
    require_environment_bucket(args.environment, args.bucket)
    runner = CommandRunner()
    registry = _load_json_file(args.registry)
    scopes = build_scope_registry(
        registry,
        expected_draft_count=args.expected_draft_count,
        tenant_overrides=_parse_overrides(args.tenant_override),
    )
    scope_bytes = canonical_json_bytes(scopes)
    account_id = _account_id(runner, args.profile)
    s3 = AwsCliS3(profile=args.profile, region=args.region, runner=runner)
    result = rollback_object(
        s3,
        bucket=args.bucket,
        key=args.key,
        expected_owner=account_id,
        restore_version_id=args.restore_version_id,
        approved_restore_sha256=args.approve_restore_sha256,
        expected_current_etag=args.expected_current_etag,
        canonical_scope_bytes=scope_bytes,
        environment=args.environment,
    )
    return {
        "mode": "rollback",
        "environment": args.environment,
        "bucket": args.bucket,
        "key": args.key,
        **result,
    }


def _add_generation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--expected-draft-count", required=True, type=int)
    parser.add_argument("--tenant-override", action="append", default=[])
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", default="us-east-1")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="Verify sources and print hashes/metadata without writing.")
    _add_generation_arguments(plan)
    plan.add_argument("--test-bucket", required=True)
    plan.add_argument("--production-bucket", required=True)

    apply = commands.add_parser("apply", help="Conditionally write and read back one reviewed environment.")
    _add_generation_arguments(apply)
    apply.add_argument("--environment", required=True, choices=ENVIRONMENTS)
    apply.add_argument("--bucket", required=True)
    apply.add_argument("--approve-scope-sha256", required=True)
    apply.add_argument("--approve-authz-sha256", required=True)
    apply.add_argument("--expected-current-authz-etag", required=True)
    apply.add_argument("--expected-current-authz-version-id", required=True)
    apply.add_argument("--expected-current-scope-etag", required=True)
    apply.add_argument("--expected-current-scope-version-id", required=True)
    apply.add_argument("--expected-current-scope-sha256", required=True)
    apply.add_argument("--test-commit")
    apply.add_argument("--test-run-id", type=int)
    apply.add_argument("--canary-repo")
    apply.add_argument("--canary-run-id", type=int)
    apply.add_argument("--approve-test-evidence-sha256")

    verify_test = commands.add_parser(
        "verify-test",
        help="Prove a successful test workflow, stack, private bundle, Lambda, and IAM denial probe.",
    )
    _add_generation_arguments(verify_test)
    verify_test.add_argument("--test-commit", required=True)
    verify_test.add_argument("--test-run-id", required=True, type=int)
    verify_test.add_argument("--canary-repo", required=True)
    verify_test.add_argument("--canary-run-id", required=True, type=int)

    rollback = commands.add_parser("rollback", help="Restore one prior version as a new conditional version.")
    _add_generation_arguments(rollback)
    rollback.add_argument("--environment", required=True, choices=ENVIRONMENTS)
    rollback.add_argument("--bucket", required=True)
    rollback.add_argument("--key", required=True, choices=(AUTHZ_KEY, SCOPE_KEY))
    rollback.add_argument("--restore-version-id", required=True)
    rollback.add_argument("--approve-restore-sha256", required=True)
    rollback.add_argument("--expected-current-etag", required=True)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    try:
        args = parse_args(argv)
        if args.command == "plan":
            result = _plan(args)
        elif args.command == "apply":
            result = _apply(args)
        elif args.command == "verify-test":
            result = _verify_test(args)
        else:
            result = _rollback(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except BootstrapError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
