#!/usr/bin/env python3
"""Explicit TEST-only AWS-observed recovery. Private values never reach stdout or disk."""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit
import zipfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.prepare_test_parameters import build_parameters
from tools.review_test_change_set import ChangeSetReviewError, review_change_set

SCHEMA = "AWS-live-snapshot/v1"
SERVICE = "zoolanding-config-authoring"
REGION = "us-east-1"
STACK_NAME = "zoolanding-config-authoring-test"
FUNCTION = "ConfigAuthoringFunction"
BUCKET = build_parameters({})[0]["ConfigPayloadsBucketName"]
ACCOUNT_SHA256 = "3e19eeb25ac142d015c5a4d347dc58784b0a79a124f1353b5e92d90673810a8f"
LEGACY_SOURCE = "34e9e0ad9512b9882381e245f2cc67606f5b075e"
LEGACY_ZIP_SHA256 = "aaca4c9f5f3d9148438399e5979d3f073ecb83f5856fa15066c10948fcdcb713"
LEGACY_ZIP_SIZE = 29360
LEGACY_SELECTOR_SHA256 = "f4cb00cadf1f687b7c5296411ebcd26047bc914fa07eb0c94fef1c16331d1050"
LEGACY_VERSION_SHA256 = "6984afadd24127cc007a9cdcc387984f50305189ac4e88ff101d81b76a696ea3"
LEGACY_FILES = {
    "lambda_function.py": "7b46b8cc06db36d01b880363da5388aa7858cbba54d03948a8f24dd35b3907e7",
    "server_policy_validation.py": "3520f225659189b67c79090cb69b7c4d6bc6bf52af69d2b705d492bde8039ed8",
    "schemas/server-features/commerce.schema.json": "1f1b2934fbbf025abc3c1cb7d70faf2eab4d856dfc7cca6461e53037a4e3b6ce",
    "schemas/server-features/data-spaces.schema.json": "90616c08d80a26694bff836c568d3e46ef3c6ce29dffe21e4d50056929a9b02a",
    "schemas/server-features/integration-bindings.schema.json": "b095c29702d33d7fa87e98685e204c1f99512685b83d3288df6b621982ab23c4",
    "schemas/server-features/notification-policies.schema.json": "6c7bbcabb4ef506fccde9750f822254f93ffdb325c095f9534755d7d058937e8",
    "zoolanding_lambda_common.py": "354a6e400548b043cc0d6976cd2c5b02e1babf681c79ffd6068f0d37cc1ea92a",
}
NEW_SCHEMA = "schemas/server-features/protected-feature-bindings-v2.schema.json"
MAX_ZIP = 10 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_RECORD = 1024 * 1024
WORKFLOW = ".github/workflows/rollback-test.yml"
STABLE = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}


class RecoveryBlocked(ValueError):
    """Only fixed, non-sensitive error codes may leave this boundary."""


def require(condition, code):
    if not condition:
        raise RecoveryBlocked(code)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        raise RecoveryBlocked("record_shape_invalid") from None


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(isinstance(key, str) and key not in result, "duplicate_or_invalid_key")
        result[key] = value
    return result


def parse_json(body):
    try:
        result = json.loads(body, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(RecoveryBlocked("json_invalid")))
        require(isinstance(result, dict), "json_object_required")
        canonical(result)
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise RecoveryBlocked("json_invalid") from None


def _template(value):
    if isinstance(value, str):
        require(len(value.encode()) <= MAX_RECORD, "template_too_large")
        try:
            value = parse_json(value)
        except RecoveryBlocked as exc:
            if str(exc) != "json_invalid":
                raise
            import yaml
            class UniqueLoader(yaml.SafeLoader):
                pass
            UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                lambda loader, node: _pairs(loader.construct_pairs(node, deep=True)))
            try:
                value = yaml.load(value, Loader=UniqueLoader)
            except yaml.YAMLError:
                raise RecoveryBlocked("template_invalid") from None
    require(isinstance(value, dict) and isinstance(value.get("Resources"), dict), "template_invalid")
    canonical(value)
    return value


def _version(value):
    require(isinstance(value, str) and 0 < len(value) <= 1024 and value != "null"
            and not any(ord(c) < 32 for c in value), "version_invalid")
    return value


def _tooling(tooling):
    require(isinstance(tooling, dict) and set(tooling) == {"sha", "workflowSha256"}, "tooling_invalid")
    require(re.fullmatch(r"[a-f0-9]{40}", str(tooling["sha"])) is not None
            and re.fullmatch(r"[a-f0-9]{64}", str(tooling["workflowSha256"])) is not None, "tooling_invalid")
    return deepcopy(tooling)


class AwsSession:
    """Lazy, one-attempt AWS transport; offline tests inject only this boundary."""

    region_name = REGION

    def __init__(self, profile=None):
        import boto3
        from botocore.config import Config
        self.session = boto3.Session(profile_name=profile, region_name=REGION)
        self.config = Config(connect_timeout=8, read_timeout=20, retries={"total_max_attempts": 1})

    def client(self, service):
        return self.session.client(service, config=self.config)


def _client(session, service):
    return session.client(service)


def _call(client, operation, **kwargs):
    try:
        return getattr(client, operation)(**kwargs)
    except Exception:
        raise RecoveryBlocked("aws_" + operation + "_failed") from None


def _inspect_zip(payload):
    require(isinstance(payload, bytes) and 0 < len(payload) <= MAX_ZIP, "zip_size_invalid")
    result = []
    seen = set()
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for member in archive.infolist():
                name = member.filename
                path = PurePosixPath(name)
                mode = stat.S_IFMT(member.external_attr >> 16)
                require(name and name == path.as_posix() and not path.is_absolute()
                        and ".." not in path.parts and "\\" not in name and ":" not in name
                        and not any(ord(c) < 32 for c in name)
                        and not member.is_dir() and mode in (0, stat.S_IFREG)
                        and not member.flag_bits & 1 and name not in seen,
                        "zip_member_unsafe")
                require(name in set(LEGACY_FILES) | {NEW_SCHEMA} and 0 <= member.file_size <= MAX_FILE,
                        "zip_inventory_invalid")
                seen.add(name)
                body = archive.read(member)
                require(len(body) == member.file_size, "zip_member_size_invalid")
                result.append({"path": name, "size": len(body), "sha256": sha(body)})
    except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError):
        raise RecoveryBlocked("zip_invalid") from None
    require(seen in (set(LEGACY_FILES), set(LEGACY_FILES) | {NEW_SCHEMA}), "zip_inventory_invalid")
    return sorted(result, key=lambda row: row["path"])


def verify_legacy_package(payload, source):
    require(source == LEGACY_SOURCE, "legacy_source_invalid")
    require(len(payload) == LEGACY_ZIP_SIZE and sha(payload) == LEGACY_ZIP_SHA256, "legacy_zip_mismatch")
    files = _inspect_zip(payload)
    require({row["path"]: row["sha256"] for row in files} == LEGACY_FILES, "legacy_files_mismatch")
    return files


def _code(template, processed=False):
    resource = template.get("Resources", {}).get(FUNCTION, {})
    require(resource.get("Type") == ("AWS::Lambda::Function" if processed else "AWS::Serverless::Function"),
            "function_template_invalid")
    value = resource.get("Properties", {}).get("Code" if processed else "CodeUri")
    if isinstance(value, str) and not processed:
        uri = urlsplit(value)
        require(uri.scheme == "s3" and not uri.query and not uri.fragment, "code_uri_invalid")
        value = {"Bucket": uri.netloc, "Key": uri.path.removeprefix("/")}
    elif processed and isinstance(value, dict):
        require(set(value).issubset({"S3Bucket", "S3Key", "S3ObjectVersion"}), "processed_code_invalid")
        value = {"Bucket": value.get("S3Bucket"), "Key": value.get("S3Key"),
                 **({"Version": value["S3ObjectVersion"]} if "S3ObjectVersion" in value else {})}
    require(isinstance(value, dict) and set(value) in ({"Bucket", "Key"}, {"Bucket", "Key", "Version"}),
            "code_selector_invalid")
    require(value["Bucket"] == BUCKET and isinstance(value["Key"], str)
            and re.fullmatch(r"system/deploy-artifacts/[a-f0-9]{40}/[1-9][0-9]*/[1-9][0-9]*/(?:artifacts/)?[A-Za-z0-9._-]{16,128}", value["Key"])
            is not None, "code_selector_invalid")
    if "Version" in value:
        _version(value["Version"])
    return value


def _read_object(s3, account, key, version, limit):
    response = _call(s3, "get_object", Bucket=BUCKET, Key=key, VersionId=_version(version),
                     ExpectedBucketOwner=account)
    require(response.get("VersionId") == version and response.get("DeleteMarker") is not True,
            "object_version_mismatch")
    stream = response.get("Body")
    require(stream is not None, "object_body_missing")
    try:
        body = stream.read(limit + 1)
    except Exception:
        raise RecoveryBlocked("object_read_failed") from None
    finally:
        stream.close()
    require(isinstance(body, bytes) and 0 < len(body) <= limit
            and len(body) == response.get("ContentLength"), "object_size_invalid")
    return body


def _account(session):
    require(session.region_name == REGION, "region_invalid")
    account = _call(_client(session, "sts"), "get_caller_identity").get("Account")
    require(isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account) is not None
            and sha(account.encode()) == ACCOUNT_SHA256, "account_invalid")
    return account


def _parameters(rows):
    require(isinstance(rows, list), "parameters_invalid")
    result = _pairs([(row.get("ParameterKey"), row.get("ParameterValue")) for row in rows if isinstance(row, dict)])
    require(len(result) == len(rows) and result == build_parameters({})[0], "parameters_not_exact_test")
    return result


def _observe_once(session, tooling, legacy):
    account = _account(session)
    cfn, lambdas, s3 = (_client(session, name) for name in ("cloudformation", "lambda", "s3"))
    rows = _call(cfn, "describe_stacks", StackName=STACK_NAME).get("Stacks", [])
    require(len(rows) == 1 and isinstance(rows[0], dict), "stack_missing_or_ambiguous")
    live = rows[0]
    stack_id = live.get("StackId", "")
    require(live.get("StackName") == STACK_NAME and re.fullmatch(
        rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK_NAME}/[A-Za-z0-9-]+", stack_id)
        is not None and live.get("StackStatus") in STABLE, "stack_identity_or_state_invalid")
    parameters = _parameters(live.get("Parameters"))
    stack = {key: deepcopy(live[key]) for key in ("StackName", "StackId", "StackStatus",
             "EnableTerminationProtection", "RoleARN", "Tags", "Capabilities", "DisableRollback",
             "NotificationARNs", "RollbackConfiguration") if key in live}
    inventory, tokens, token = {}, set(), None
    while True:
        page = _call(cfn, "list_stack_resources", StackName=stack_id, **({"NextToken": token} if token else {}))
        require(isinstance(page.get("StackResourceSummaries"), list), "inventory_invalid")
        for row in page["StackResourceSummaries"]:
            logical = row.get("LogicalResourceId")
            require(isinstance(logical, str) and logical not in inventory and row.get("ResourceStatus") in STABLE
                    and isinstance(row.get("PhysicalResourceId"), str) and row["PhysicalResourceId"]
                    and isinstance(row.get("ResourceType"), str), "inventory_invalid")
            inventory[logical] = {key: row[key] for key in ("PhysicalResourceId", "ResourceType")}
        token = page.get("NextToken")
        if not token:
            break
        require(isinstance(token, str) and token not in tokens and len(tokens) < 20, "inventory_pagination_invalid")
        tokens.add(token)
    require({key for key, row in inventory.items() if row["ResourceType"] == "AWS::Lambda::Function"}
            == {FUNCTION}, "function_inventory_invalid")
    original = _template(_call(cfn, "get_template", StackName=stack_id, TemplateStage="Original").get("TemplateBody"))
    processed = _template(_call(cfn, "get_template", StackName=stack_id, TemplateStage="Processed").get("TemplateBody"))
    selector = _code(original)
    require(_code(processed, True) == selector, "processed_code_mismatch")
    function_id = inventory[FUNCTION]["PhysicalResourceId"]
    configuration = _call(lambdas, "get_function_configuration", FunctionName=function_id)
    function = {key: value for key, value in configuration.items() if key != "ResponseMetadata"}
    require(function.get("FunctionName") == function_id
            and function.get("FunctionArn") == f"arn:aws:lambda:{REGION}:{account}:function:{function_id}"
            and function.get("Version") == "$LATEST" and function.get("State") == "Active"
            and function.get("LastUpdateStatus") == "Successful"
            and isinstance(function.get("RevisionId"), str) and function["RevisionId"], "function_identity_or_state_invalid")
    request = {"Bucket": BUCKET, "Key": selector["Key"], "ExpectedBucketOwner": account}
    if "Version" in selector:
        request["VersionId"] = selector["Version"]
    head = _call(s3, "head_object", **request)
    version = _version(head.get("VersionId"))
    require("Version" not in selector or selector["Version"] == version, "object_version_mismatch")
    payload = _read_object(s3, account, selector["Key"], version, MAX_ZIP)
    code_sha = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
    require(len(payload) == head.get("ContentLength") == function.get("CodeSize")
            and code_sha == function.get("CodeSha256"), "lambda_package_mismatch")
    if legacy:
        require(digest({"Bucket": BUCKET, "Key": selector["Key"]}) == LEGACY_SELECTOR_SHA256
                and sha(version.encode()) == LEGACY_VERSION_SHA256, "legacy_selector_mismatch")
        files = verify_legacy_package(payload, LEGACY_SOURCE)
    else:
        files = _inspect_zip(payload)
    return {"schema": SCHEMA, "service": SERVICE, "environment": "test", "account": account, "region": REGION,
            "sourceSha": LEGACY_SOURCE if legacy else None, "tooling": _tooling(tooling), "stack": stack,
            "original": original, "processed": processed, "parameters": parameters, "inventory": inventory,
            "function": function, "package": {"Bucket": BUCKET, "Key": selector["Key"], "VersionId": version,
                "size": len(payload), "sha256": sha(payload), "files": files}}


def observe(session, tooling, *, legacy=True):
    """Two complete version-specific reads; no writes, selector output or wire logging."""
    first = _observe_once(session, _tooling(tooling), legacy)
    require(first == _observe_once(session, tooling, legacy), "baseline_drift")
    return first


def _validate_snapshot(snapshot):
    fields = {"schema", "service", "environment", "account", "region", "sourceSha", "tooling", "stack",
              "original", "processed", "parameters", "inventory", "function", "package"}
    require(isinstance(snapshot, dict) and set(snapshot) == fields and snapshot["schema"] == SCHEMA
            and snapshot["service"] == SERVICE and snapshot["environment"] == "test"
            and snapshot["sourceSha"] == LEGACY_SOURCE and snapshot["region"] == REGION, "snapshot_contract_invalid")
    _tooling(snapshot["tooling"])
    require(sha(str(snapshot["account"]).encode()) == ACCOUNT_SHA256, "snapshot_account_invalid")
    package = snapshot["package"]
    require(isinstance(package, dict) and set(package) == {"Bucket", "Key", "VersionId", "size", "sha256", "files"}
            and package["Bucket"] == BUCKET and package["size"] == LEGACY_ZIP_SIZE
            and package["sha256"] == LEGACY_ZIP_SHA256, "snapshot_package_invalid")
    require(digest({"Bucket": BUCKET, "Key": package["Key"]}) == LEGACY_SELECTOR_SHA256
            and sha(_version(package["VersionId"]).encode()) == LEGACY_VERSION_SHA256, "snapshot_selector_invalid")
    require({row["path"]: row["sha256"] for row in package["files"]} == LEGACY_FILES
            and len(package["files"]) == len(LEGACY_FILES), "snapshot_inventory_invalid")
    selector = _code(snapshot["original"])
    require(selector["Bucket"] == package["Bucket"] and selector["Key"] == package["Key"]
            and selector.get("Version", package["VersionId"]) == package["VersionId"]
            and selector == _code(snapshot["processed"], True), "snapshot_template_invalid")
    expected_code = base64.b64encode(bytes.fromhex(LEGACY_ZIP_SHA256)).decode("ascii")
    require(snapshot["function"].get("CodeSha256") == expected_code
            and snapshot["function"].get("CodeSize") == LEGACY_ZIP_SIZE, "snapshot_lambda_invalid")
    canonical(snapshot)


def safe_summary(snapshot):
    """Only fixed labels, counts and digests; never echo operational selectors."""
    return {"schema": SCHEMA, "service": SERVICE, "environment": "test", "snapshotSha256": digest(snapshot),
            "sourceSha": snapshot["sourceSha"], "tooling": _tooling(snapshot["tooling"]),
            "originalSha256": digest(snapshot["original"]), "processedSha256": digest(snapshot["processed"]),
            "parametersSha256": digest(snapshot["parameters"]), "inventorySha256": digest(snapshot["inventory"]),
            "stackSha256": digest(snapshot["stack"]), "functionSha256": digest(snapshot["function"]),
            "zipSha256": snapshot["package"]["sha256"], "zipBytes": snapshot["package"]["size"],
            "versionIdSha256": sha(snapshot["package"]["VersionId"].encode()),
            "fileCount": len(snapshot["package"]["files"]), "resourceCount": len(snapshot["inventory"])}


def _snapshot_key(key, tooling=None):
    prefix = re.escape(_tooling(tooling)["sha"]) if tooling else r"[a-f0-9]{40}"
    require(isinstance(key, str) and re.fullmatch(
        rf"system/deploy-artifacts/{prefix}/[1-9][0-9]*/[1-9][0-9]*/aws-live-snapshot\.json", key)
        is not None, "snapshot_channel_invalid")
    return key


def capture(session, tooling, key, expected_snapshot):
    """Opt-in immutable metadata capture to the already owned private release prefix."""
    _snapshot_key(key, tooling)
    snapshot = observe(session, tooling)
    require(digest(snapshot) == expected_snapshot, "snapshot_approval_mismatch")
    body = canonical(snapshot)
    require(len(body) <= MAX_RECORD, "snapshot_too_large")
    s3 = _client(session, "s3")
    response = _call(s3, "put_object", Bucket=BUCKET, Key=key, Body=body,
                     IfNoneMatch="*", ServerSideEncryption="AES256", ContentType="application/json",
                     ExpectedBucketOwner=snapshot["account"])
    version = _version(response.get("VersionId"))
    require(_read_object(s3, snapshot["account"], key, version, MAX_RECORD) == body, "capture_readback_mismatch")
    require(observe(session, tooling) == snapshot, "capture_baseline_drift")
    return {**safe_summary(snapshot), "status": "captured", "recordVersionSha256": sha(version.encode()),
            "recordKeySha256": sha(key.encode())}


def _without_code(template, processed=False):
    result = deepcopy(template)
    result["Resources"][FUNCTION]["Properties"].pop("Code" if processed else "CodeUri", None)
    return result


def _configuration(function):
    return {key: value for key, value in function.items()
            if key not in {"CodeSha256", "CodeSize", "RevisionId", "LastModified"}}


def _runtime_management(session, current):
    function = current["function"]
    response = _call(_client(session, "lambda"), "get_runtime_management_config",
                     FunctionName=function["FunctionName"])
    require(isinstance(response, dict)
            and set(response).issubset({"FunctionArn", "UpdateRuntimeOn", "RuntimeVersionArn", "ResponseMetadata"})
            and response.get("FunctionArn") == function["FunctionArn"], "runtime_management_identity_invalid")
    mode, arn = response.get("UpdateRuntimeOn"), response.get("RuntimeVersionArn")
    require(mode in {"Auto", "FunctionUpdate", "Manual"}, "runtime_management_mode_invalid")
    if mode == "Manual":
        require(isinstance(arn, str) and re.fullmatch(rf"arn:aws:lambda:{REGION}::runtime:[a-f0-9]{{64}}", arn)
                and function.get("RuntimeVersionConfig") == {"RuntimeVersionArn": arn}, "runtime_manual_pin_invalid")
    else:
        require(arn is None, "runtime_automatic_pin_invalid")
    result = {"UpdateRuntimeOn": mode, **({"RuntimeVersionArn": arn} if mode == "Manual" else {})}
    expected = current["processed"]["Resources"][FUNCTION]["Properties"].get(
        "RuntimeManagementConfig", {"UpdateRuntimeOn": "Auto"})
    require(result == expected, "runtime_management_template_drift")
    return result


def _same_configuration(left, right, runtime_management):
    left, right = _configuration(left), _configuration(right)
    if left == right:
        return True
    if runtime_management["UpdateRuntimeOn"] not in {"Auto", "FunctionUpdate"}:
        return False
    normalized = []
    for function in (left, right):
        patch = function.get("RuntimeVersionConfig")
        if (not isinstance(patch, dict) or set(patch) != {"RuntimeVersionArn"}
                or not isinstance(patch["RuntimeVersionArn"], str)
                or not re.fullmatch(rf"arn:aws:lambda:{REGION}::runtime:[a-f0-9]{{64}}", patch["RuntimeVersionArn"])
                or function.get("Runtime") != "python3.13" or function.get("PackageType") != "Zip"
                or function.get("Architectures") not in (["x86_64"], ["arm64"])):
            return False
        # Compare only across deployments; the full ARN remains in every live
        # observation and plan digest, so concurrent patch changes still deny.
        normalized.append({**function, "RuntimeVersionConfig": {"RuntimeVersionArn": "aws-managed-patch"}})
    return normalized[0] == normalized[1]


def plan_recovery(session, tooling, snapshot):
    _validate_snapshot(snapshot)
    current = observe(session, tooling, legacy=False)
    runtime_management = _runtime_management(session, current)
    require(current["account"] == snapshot["account"] and current["stack"] == snapshot["stack"]
            and current["parameters"] == snapshot["parameters"] and current["inventory"] == snapshot["inventory"]
            and _same_configuration(current["function"], snapshot["function"], runtime_management)
            and _without_code(current["original"]) == _without_code(snapshot["original"])
            and _without_code(current["processed"], True) == _without_code(snapshot["processed"], True),
            "non_code_baseline_drift")
    package = snapshot["package"]
    for _ in range(2):
        payload = _read_object(_client(session, "s3"), current["account"], package["Key"], package["VersionId"], MAX_ZIP)
        require(verify_legacy_package(payload, snapshot["sourceSha"]) == package["files"], "snapshot_file_drift")
    template = deepcopy(current["original"])
    template["Resources"][FUNCTION]["Properties"]["CodeUri"] = {
        "Bucket": package["Bucket"], "Key": package["Key"], "Version": package["VersionId"]}
    require(len(canonical(template)) <= 51200, "recovery_template_too_large")
    require(current == observe(session, tooling, legacy=False), "plan_baseline_drift")
    require(runtime_management == _runtime_management(session, current), "plan_runtime_management_drift")
    return {"schema": SCHEMA, "tooling": _tooling(tooling), "snapshotSha256": digest(snapshot), "baseline": current,
            "template": template, "runtimeManagement": runtime_management,
            "parameters": [{"ParameterKey": key, "UsePreviousValue": True} for key in sorted(current["parameters"])]}


def plan_digest(plan):
    return digest(plan)


def review_recovery_change_set(description, change_id, name, snapshot):
    try:
        decision = review_change_set(description, expected_stack_name=STACK_NAME,
            expected_change_set_name=name, expected_change_set_arn=change_id, expected_change_set_type="UPDATE",
            expected_parameters=snapshot["parameters"], required_parameters=set(snapshot["parameters"]))
    except ChangeSetReviewError:
        raise RecoveryBlocked("recovery_change_set_rejected") from None
    require(description.get("StackId") == snapshot["stack"]["StackId"]
            and change_id.startswith(f"arn:aws:cloudformation:{REGION}:{snapshot['account']}:changeSet/")
            and not description.get("NextToken")
            and _parameters(description.get("Parameters")) == snapshot["parameters"], "change_set_identity_or_parameter_drift")
    for change in description.get("Changes") or []:
        resource = change["ResourceChange"]
        require(resource.get("Action") == "Modify" and resource.get("LogicalResourceId") == FUNCTION
                and resource.get("ResourceType") == "AWS::Lambda::Function"
                and resource.get("Scope") == ["Properties"], "recovery_non_code_change")
        details = resource.get("Details")
        require(isinstance(details, list) and details, "recovery_change_detail_missing")
        for detail in details:
            target = detail.get("Target", {})
            require(target.get("Attribute") == "Properties" and target.get("Name") == "Code"
                    and target.get("RequiresRecreation") in (None, "Never"), "recovery_non_code_change")
    return decision


def _wait(client, waiter, **kwargs):
    try:
        client.get_waiter(waiter).wait(**kwargs, WaiterConfig={"Delay": 5, "MaxAttempts": 120})
        return True
    except Exception:
        return False


def recover(session, tooling, snapshot, expected_plan, change_set_name):
    require(isinstance(change_set_name, str) and re.fullmatch(r"recovery-[1-9][0-9]*-[1-9][0-9]*", change_set_name)
            is not None, "change_set_name_invalid")
    plan = plan_recovery(session, tooling, snapshot)
    require(plan_digest(plan) == expected_plan, "plan_approval_mismatch")
    cfn = _client(session, "cloudformation")
    stack_id = plan["baseline"]["stack"]["StackId"]
    capability_arguments = {"Capabilities": deepcopy(plan["baseline"]["stack"]["Capabilities"])} \
        if "Capabilities" in plan["baseline"]["stack"] else {}
    created = _call(cfn, "create_change_set", StackName=stack_id, ChangeSetName=change_set_name,
        ChangeSetType="UPDATE", TemplateBody=canonical(plan["template"]).decode(), Parameters=plan["parameters"],
        **capability_arguments,
        ClientToken=change_set_name + "-" + expected_plan[:32], Description="Reviewed TEST AWS-observed code recovery")
    change_id = created.get("Id", "")
    require(created.get("StackId") == stack_id, "created_stack_mismatch")
    require(re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{snapshot['account']}:changeSet/{change_set_name}/[A-Za-z0-9-]+", change_id)
            is not None, "created_change_set_invalid")
    ready = _wait(cfn, "change_set_create_complete", StackName=stack_id, ChangeSetName=change_id)
    description = _call(cfn, "describe_change_set", StackName=stack_id, ChangeSetName=change_id, IncludePropertyValues=True)
    decision = review_recovery_change_set(description, change_id, change_set_name, plan["baseline"])
    require(plan_recovery(session, tooling, snapshot) == plan, "pre_execute_baseline_drift")
    final = _call(cfn, "describe_change_set", StackName=stack_id, ChangeSetName=change_id, IncludePropertyValues=True)
    require(review_recovery_change_set(final, change_id, change_set_name, plan["baseline"]) == decision
            and {k: v for k, v in description.items() if k != "ResponseMetadata"}
            == {k: v for k, v in final.items() if k != "ResponseMetadata"}, "change_set_drift")
    require(observe(session, tooling, legacy=False) == plan["baseline"], "final_baseline_drift")
    require(_runtime_management(session, plan["baseline"]) == plan["runtimeManagement"], "final_runtime_management_drift")
    if decision == "noop":
        require(plan["baseline"]["package"] == snapshot["package"], "noop_target_not_live")
        _call(cfn, "delete_change_set", StackName=stack_id, ChangeSetName=change_id)
        return {"schema": SCHEMA, "status": "noop", "planSha256": expected_plan}
    require(ready, "change_set_wait_failed")
    _call(cfn, "execute_change_set", StackName=stack_id, ChangeSetName=change_id,
          ClientRequestToken=change_set_name + "-execute-" + expected_plan[:24])
    require(_wait(cfn, "stack_update_complete", StackName=stack_id), "recovery_stack_wait_failed")
    post = observe(session, tooling)
    require(_runtime_management(session, post) == plan["runtimeManagement"], "recovery_runtime_management_drift")
    require(post["original"] == plan["template"] and post["parameters"] == snapshot["parameters"]
            and post["inventory"] == snapshot["inventory"] and post["stack"] == snapshot["stack"]
            and _same_configuration(post["function"], snapshot["function"], plan["runtimeManagement"])
            and _without_code(post["processed"], True) == _without_code(snapshot["processed"], True)
            and post["package"] == snapshot["package"], "recovery_postcheck_failed")
    return {**safe_summary(post), "status": "recovered", "planSha256": expected_plan, "smoke": "stack_and_lambda_ready"}


def run(operation, session, tooling, selection=None, *, expected_snapshot=None, expected_plan=None, change_set_name=None):
    """Shared operator/workflow boundary; all returned values are safe to print."""
    _tooling(tooling)
    if operation == "observe":
        require(not selection, "observe_selection_forbidden")
        return {**safe_summary(observe(session, tooling)), "status": "observed", "awsWrites": 0}
    require(isinstance(selection, dict), "private_selection_required")
    require(isinstance(expected_snapshot, str) and re.fullmatch(r"[a-f0-9]{64}", expected_snapshot),
            "snapshot_approval_required")
    if operation == "capture":
        require(set(selection) == {"snapshotKey"}, "capture_selection_invalid")
        return capture(session, tooling, selection["snapshotKey"], expected_snapshot)
    require(operation in {"plan", "recover"} and set(selection) == {"snapshotKey", "snapshotVersionId"},
            "recovery_selection_invalid")
    key, version = _snapshot_key(selection["snapshotKey"]), _version(selection["snapshotVersionId"])
    account, s3 = _account(session), _client(session, "s3")
    body = _read_object(s3, account, key, version, MAX_RECORD)
    snapshot = parse_json(body)
    require(canonical(snapshot) == body and digest(snapshot) == expected_snapshot, "snapshot_approval_mismatch")
    _validate_snapshot(snapshot)
    require(_snapshot_key(key, snapshot["tooling"]) == key, "snapshot_tooling_channel_mismatch")
    require(_read_object(s3, account, key, version, MAX_RECORD) == body, "snapshot_record_drift")
    if operation == "plan":
        plan = plan_recovery(session, tooling, snapshot)
        return {"schema": SCHEMA, "status": "planned", "snapshotSha256": expected_snapshot,
                "planSha256": plan_digest(plan), "templateSha256": digest(plan["template"]), "awsWrites": 0}
    return recover(session, tooling, snapshot, expected_plan, change_set_name)


def verify_tooling(expected_sha, expected_workflow_sha256):
    tooling = _tooling({"sha": expected_sha, "workflowSha256": expected_workflow_sha256})
    root = Path(__file__).resolve().parents[1]
    paths = ("tools/aws_live_snapshot.py", "tools/review_test_change_set.py", "tools/prepare_test_parameters.py", WORKFLOW)
    try:
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
        require(actual == expected_sha, "tooling_commit_mismatch")
        for path in paths:
            source = subprocess.check_output(["git", "show", expected_sha + ":" + path], cwd=root, stderr=subprocess.DEVNULL)
            require(source.replace(b"\r\n", b"\n") == (root / path).read_bytes().replace(b"\r\n", b"\n"), "tooling_source_mismatch")
        require(sha((root / WORKFLOW).read_bytes().replace(b"\r\n", b"\n")) == expected_workflow_sha256, "tooling_workflow_mismatch")
    except (subprocess.SubprocessError, OSError, UnicodeError):
        raise RecoveryBlocked("tooling_unavailable") from None
    return tooling


def main(argv=None):
    class SafeParser(argparse.ArgumentParser):
        def error(self, message):
            raise RecoveryBlocked("arguments_invalid")
    parser = SafeParser(description=__doc__)
    parser.add_argument("operation", choices=("observe", "capture", "plan", "recover"))
    parser.add_argument("--expected-tooling-sha", required=True)
    parser.add_argument("--expected-workflow-sha256", required=True)
    parser.add_argument("--expected-snapshot-sha256")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--change-set-name")
    parser.add_argument("--profile")
    try:
        args = parser.parse_args(argv)
        tooling = verify_tooling(args.expected_tooling_sha, args.expected_workflow_sha256)
        raw = os.environ.get("CONFIG_TEST_RECOVERY_SELECTION_JSON")
        require(raw is None or len(raw.encode()) <= 8192, "selection_too_large")
        selection = parse_json(raw) if raw else None
        session = AwsSession(args.profile)
        result = run(args.operation, session, tooling, selection, expected_snapshot=args.expected_snapshot_sha256,
                     expected_plan=args.expected_plan_sha256, change_set_name=args.change_set_name)
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "status": "blocked",
                          "code": str(exc) if isinstance(exc, RecoveryBlocked) else "recovery_failed"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
