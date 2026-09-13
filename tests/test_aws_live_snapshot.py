"""Real recovery logic with synthetic AWS responses; no credentials or network."""
import base64
import builtins
import contextlib
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
import warnings
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import build_lambda_artifact as current_artifact
from tools.prepare_test_parameters import build_parameters

try:
    from tools import aws_live_snapshot as recovery
except ImportError:
    recovery = None

ACCOUNT = "123456789012"
SOURCE = "34e9e0ad9512b9882381e245f2cc67606f5b075e"
TOOLING = {"sha": "b" * 40, "workflowSha256": "c" * 64}
STACK = "zoolanding-config-authoring-test"
BUCKET = build_parameters({})[0]["ConfigPayloadsBucketName"]
KEY = f"system/deploy-artifacts/{SOURCE}/32919856177/1/" + "d" * 32
SNAPSHOT_KEY = f"system/deploy-artifacts/{TOOLING['sha']}/42/1/aws-live-snapshot.json"
FILES = tuple(str(path).replace("\\", "/") for path in current_artifact.RUNTIME_FILES
              if path.name != "protected-feature-bindings-v2.schema.json")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def package(files=None, *, member=None, symlink=False):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in FILES if files is None else files:
            archive.writestr(name, ("synthetic fixture: " + name).encode())
        if member:
            item = zipfile.ZipInfo(member)
            if symlink:
                item.external_attr = (stat.S_IFLNK | 0o777) << 16
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(item, b"synthetic")
    return result.getvalue()


class FakeAws:
    """Only external AWS boundaries are substituted; production orchestration runs."""
    region_name = "us-east-1"

    def __init__(self):
        self.account = ACCOUNT
        self.payload = package()
        self.version = "legacy-version-1"
        self.objects = {(KEY, self.version): self.payload}
        self.latest = {KEY: self.version}
        self.writes = []
        self.calls = []
        self.read_hook = None
        self.function_reads = 0
        self.capabilities = ["CAPABILITY_IAM"]
        self.params = build_parameters({})[0]
        self.stack_id = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{STACK}/synthetic-stack"
        self.function_id = "synthetic-config-test-function"
        self.function_arn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{self.function_id}"
        self.original = {"Transform": "AWS::Serverless-2016-10-31", "Resources": {
            "ConfigAuthoringFunction": {"Type": "AWS::Serverless::Function", "Properties": {
                "CodeUri": f"s3://{BUCKET}/{KEY}", "Handler": "lambda_function.lambda_handler",
                "Environment": {"Variables": {"SYNTHETIC_PRIVATE": "not-for-output"}}}},
            "ConfigRegistryTable": {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Retain"}}}
        self.processed = deepcopy(self.original)
        function = self.processed["Resources"]["ConfigAuthoringFunction"]
        function["Type"] = "AWS::Lambda::Function"
        function["Properties"].pop("CodeUri")
        function["Properties"]["Code"] = {"S3Bucket": BUCKET, "S3Key": KEY}
        self.inventory = {
            "ConfigAuthoringFunction": {"PhysicalResourceId": self.function_id, "ResourceType": "AWS::Lambda::Function"},
            "ConfigRegistryTable": {"PhysicalResourceId": "synthetic-table", "ResourceType": "AWS::DynamoDB::Table"}}
        self.configuration = {"FunctionName": self.function_id, "FunctionArn": self.function_arn,
            "Version": "$LATEST", "RevisionId": "synthetic-revision", "State": "Active",
            "LastUpdateStatus": "Successful", "CodeSize": len(self.payload),
            "CodeSha256": base64.b64encode(hashlib.sha256(self.payload).digest()).decode()}
        self.description = None

    def client(self, name, **kwargs):
        return self

    def get_caller_identity(self):
        return {"Account": self.account, "ResponseMetadata": {"RequestId": "ignored"}}

    def describe_stacks(self, **kwargs):
        return {"Stacks": [{"StackName": STACK, "StackId": self.stack_id, "StackStatus": "UPDATE_COMPLETE",
            "EnableTerminationProtection": False,
            **({"Capabilities": deepcopy(self.capabilities)} if self.capabilities is not None else {}),
            "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in self.params.items()]}]}

    def list_stack_resources(self, **kwargs):
        return {"StackResourceSummaries": [{"LogicalResourceId": key, "ResourceStatus": "UPDATE_COMPLETE", **value}
                                          for key, value in self.inventory.items()]}

    def get_template(self, **kwargs):
        return {"TemplateBody": deepcopy(self.original if kwargs["TemplateStage"] == "Original" else self.processed)}

    def get_function_configuration(self, **kwargs):
        self.function_reads += 1
        if self.read_hook:
            self.read_hook(self)
        return {**deepcopy(self.configuration), "ResponseMetadata": {"RequestId": str(self.function_reads)}}

    def head_object(self, **kwargs):
        self.calls.append(("head", kwargs))
        key = kwargs["Key"]
        version = kwargs.get("VersionId", self.latest[key])
        return {"VersionId": version, "ContentLength": len(self.objects[(key, version)])}

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        version = kwargs["VersionId"]
        body = self.objects[(kwargs["Key"], version)]
        return {"VersionId": version, "ContentLength": len(body), "Body": io.BytesIO(body),
                "ResponseMetadata": {"RequestId": str(len(self.calls))}}

    def put_object(self, **kwargs):
        self.writes.append(("put_object", kwargs))
        if kwargs.get("IfNoneMatch") != "*" or kwargs["Key"] in self.latest:
            raise RuntimeError("synthetic conditional-write denial")
        version = "snapshot-version-1"
        self.objects[(kwargs["Key"], version)] = kwargs["Body"]
        self.latest[kwargs["Key"]] = version
        return {"VersionId": version}

    def create_change_set(self, **kwargs):
        self.writes.append(("create_change_set", kwargs))
        change_id = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:changeSet/{kwargs['ChangeSetName']}/synthetic-change"
        self.description = {"StackName": STACK, "StackId": self.stack_id, "ChangeSetName": kwargs["ChangeSetName"],
            "ChangeSetId": change_id, "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
            "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in self.params.items()],
            "Changes": [{"Type": "Resource", "ResourceChange": {"LogicalResourceId": "ConfigAuthoringFunction",
                "ResourceType": "AWS::Lambda::Function", "Action": "Modify", "Replacement": "False",
                "Scope": ["Properties"], "Details": [{"Target": {"Attribute": "Properties", "Name": "Code"}}]}}]}
        return {"Id": change_id, "StackId": self.stack_id}

    def describe_change_set(self, **kwargs):
        result = deepcopy(self.description)
        result["ResponseMetadata"] = {"RequestId": str(len(self.calls))}
        self.calls.append(("describe_change_set", kwargs))
        return result

    def execute_change_set(self, **kwargs):
        self.writes.append(("execute_change_set", kwargs))
        request = next(value for name, value in self.writes if name == "create_change_set")
        self.capabilities = deepcopy(request.get("Capabilities"))
        self.original = json.loads(request["TemplateBody"])
        self.processed["Resources"]["ConfigAuthoringFunction"]["Properties"]["Code"] = {
            "S3Bucket": BUCKET, "S3Key": KEY, "S3ObjectVersion": self.version}
        self.configuration["CodeSha256"] = base64.b64encode(hashlib.sha256(self.payload).digest()).decode()
        self.configuration["CodeSize"] = len(self.payload)
        self.configuration["RevisionId"] = "recovered-revision"

    def get_waiter(self, name):
        return SimpleNamespace(wait=lambda **kwargs: None)

    def delete_change_set(self, **kwargs):
        self.writes.append(("delete_change_set", kwargs))


class AwsObservedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(recovery, "explicit AWS-live-snapshot/v1 driver is missing")
        self.aws = FakeAws()
        self.pins = patch.multiple(recovery,
            ACCOUNT_SHA256=sha(ACCOUNT.encode()), LEGACY_ZIP_SHA256=sha(self.aws.payload),
            LEGACY_ZIP_SIZE=len(self.aws.payload),
            LEGACY_SELECTOR_SHA256=recovery.digest({"Bucket": BUCKET, "Key": KEY}),
            LEGACY_VERSION_SHA256=sha(self.aws.version.encode()),
            LEGACY_FILES={name: sha(("synthetic fixture: " + name).encode()) for name in FILES})
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def snapshot(self):
        return recovery.observe(self.aws, TOOLING, legacy=True)

    def test_old_seven_file_payload_has_separate_verifier_and_current_eight_stays_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(("synthetic fixture: " + name).encode())
            with self.assertRaises(current_artifact.ArtifactError):
                current_artifact.verify_artifact(root)
        result = recovery.verify_legacy_package(self.aws.payload, SOURCE)
        self.assertEqual({item["path"] for item in result}, set(FILES))

    def test_wrong_prior_source_or_zip_is_denied(self):
        for payload, source in ((self.aws.payload, "e" * 40), (self.aws.payload + b"changed", SOURCE)):
            with self.subTest(source=source), self.assertRaises(recovery.RecoveryBlocked):
                recovery.verify_legacy_package(payload, source)

    def test_offline_driver_needs_no_operator_sdk_when_aws_boundary_is_injected(self):
        original = builtins.__import__
        def without_sdk(name, *args, **kwargs):
            if name.startswith(("boto3", "botocore")):
                raise ImportError("operator SDK intentionally absent")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", without_sdk):
            try:
                result = self.snapshot()
            except ImportError:
                self.fail("Offline driver imports the operator-only SDK")
            self.assertEqual(result["sourceSha"], SOURCE)

    def test_real_cli_entrypoint_prints_only_safe_fields(self):
        output = io.StringIO()
        with patch.object(recovery, "verify_tooling", return_value=TOOLING), \
             patch.object(recovery, "AwsSession", return_value=self.aws, create=True), \
             patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(output):
            code = recovery.main(["observe", "--expected-tooling-sha", TOOLING["sha"],
                                  "--expected-workflow-sha256", TOOLING["workflowSha256"]])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "observed")
        for private in (ACCOUNT, self.aws.stack_id, BUCKET, KEY, self.aws.version, "not-for-output", "synthetic-revision"):
            self.assertNotIn(private, output.getvalue())

    def test_cli_invalid_arguments_do_not_echo_values_or_tracebacks(self):
        canary = "SYNTHETIC-PRIVATE-ARGUMENT-DO-NOT-EMIT"
        for arguments in ([canary], ["observe", "--expected-tooling-sha", TOOLING["sha"],
                                    "--expected-workflow-sha256", TOOLING["workflowSha256"], "--unexpected", canary]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, str(ROOT / "tools/aws_live_snapshot.py"), *arguments],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(canary, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_new_eight_file_live_code_can_recover_only_to_exact_original_seven(self):
        snapshot = self.snapshot()
        candidate = package(files=(*FILES, "schemas/server-features/protected-feature-bindings-v2.schema.json"))
        key = "system/deploy-artifacts/" + "e" * 40 + "/99/1/" + "f" * 32
        self.aws.objects[(key, "candidate-version")] = candidate
        self.aws.latest[key] = "candidate-version"
        self.aws.original["Resources"]["ConfigAuthoringFunction"]["Properties"]["CodeUri"] = f"s3://{BUCKET}/{key}"
        self.aws.processed["Resources"]["ConfigAuthoringFunction"]["Properties"]["Code"] = {"S3Bucket": BUCKET, "S3Key": key}
        self.aws.configuration.update(CodeSize=len(candidate), RevisionId="candidate-revision",
            CodeSha256=base64.b64encode(hashlib.sha256(candidate).digest()).decode())
        plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
        result = recovery.recover(self.aws, TOOLING, snapshot, recovery.plan_digest(plan), "recovery-42-1")
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["zipSha256"], sha(self.aws.payload))
        self.assertEqual(result["fileCount"], 7)

    def test_capture_binds_all_private_fields_and_reads_exact_versions_twice(self):
        snapshot = self.snapshot()
        self.assertEqual(snapshot["schema"], "AWS-live-snapshot/v1")
        self.assertEqual(snapshot["sourceSha"], SOURCE)
        self.assertEqual(snapshot["tooling"], TOOLING)
        for field in ("stack", "original", "processed", "parameters", "inventory", "function", "package"):
            self.assertIn(field, snapshot)
        self.assertGreaterEqual(len([call for call in self.aws.calls if call[0] == "get"]), 2)
        self.assertTrue(all(call[1]["VersionId"] == self.aws.version for call in self.aws.calls if call[0] == "get"))
        self.assertEqual(self.aws.writes, [])

    def test_wrong_account_region_function_or_lambda_hash_is_denied(self):
        for mutate in (lambda: setattr(self.aws, "account", "999999999999"),
                       lambda: setattr(self.aws, "region_name", "us-west-2"),
                       lambda: self.aws.inventory.update(UnexpectedFunction={"PhysicalResourceId": "other", "ResourceType": "AWS::Lambda::Function"}),
                       lambda: self.aws.configuration.update(CodeSha256="wrong")):
            with self.subTest(mutation=mutate):
                self.aws = FakeAws()
                mutate()
                with self.assertRaises(recovery.RecoveryBlocked):
                    self.snapshot()
                self.assertEqual(self.aws.writes, [])

    def test_second_read_revision_drift_is_denied(self):
        self.aws.read_hook = lambda aws: aws.configuration.update(RevisionId="drift") if aws.function_reads >= 2 else None
        with self.assertRaisesRegex(recovery.RecoveryBlocked, "drift"):
            self.snapshot()

    def test_transport_metadata_is_ignored_but_unknown_nested_business_drift_denies(self):
        self.assertEqual(self.snapshot(), self.snapshot())
        self.aws = FakeAws()
        self.aws.read_hook = lambda aws: aws.configuration.update(UnexpectedBusiness={"nested": "changed"}) if aws.function_reads >= 2 else None
        with self.assertRaisesRegex(recovery.RecoveryBlocked, "drift"):
            self.snapshot()

    def test_null_or_substituted_s3_version_is_denied(self):
        self.aws.latest[KEY] = "null"
        self.aws.objects[(KEY, "null")] = self.aws.payload
        with self.assertRaises(recovery.RecoveryBlocked):
            self.snapshot()

    def test_same_bytes_under_an_unapproved_version_or_key_are_denied(self):
        for substituted in ("version", "key"):
            self.aws = FakeAws()
            if substituted == "version":
                self.aws.latest[KEY] = "substituted-version"
                self.aws.objects[(KEY, "substituted-version")] = self.aws.payload
            else:
                key = KEY + "extra"
                self.aws.latest[key] = self.aws.version
                self.aws.objects[(key, self.aws.version)] = self.aws.payload
                self.aws.original["Resources"]["ConfigAuthoringFunction"]["Properties"]["CodeUri"] = f"s3://{BUCKET}/{key}"
                self.aws.processed["Resources"]["ConfigAuthoringFunction"]["Properties"]["Code"]["S3Key"] = key
            with self.subTest(substituted=substituted), self.assertRaises(recovery.RecoveryBlocked):
                self.snapshot()

    def test_stack_identity_processed_pointer_and_function_binding_are_verified(self):
        for mutation in (lambda: setattr(self.aws, "stack_id", self.aws.stack_id.replace(STACK, "other-test")),
                         lambda: self.aws.configuration.update(FunctionArn=self.aws.function_arn + ":1"),
                         lambda: self.aws.processed["Resources"]["ConfigAuthoringFunction"]["Properties"]["Code"].update(S3Key="other")):
            self.aws = FakeAws()
            mutation()
            with self.assertRaises(recovery.RecoveryBlocked):
                self.snapshot()

    def test_duplicate_stack_parameters_and_inventory_are_denied(self):
        for method, key in (("describe_stacks", "Parameters"), ("list_stack_resources", "StackResourceSummaries")):
            original = getattr(self.aws, method)
            def duplicate(**kwargs):
                result = original(**kwargs)
                rows = result["Stacks"][0][key] if key == "Parameters" else result[key]
                rows.append(deepcopy(rows[0]))
                return result
            with patch.object(self.aws, method, duplicate), self.assertRaises(recovery.RecoveryBlocked):
                self.snapshot()

    def test_unsafe_duplicate_traversal_symlink_members_are_denied_even_with_matching_outer_hash(self):
        for member, symlink in (("../outside", False), (FILES[0], False), ("linked", True), ("C:/outside", False)):
            with self.subTest(member=member):
                payload = package(member=member, symlink=symlink)
                with patch.object(recovery, "LEGACY_ZIP_SHA256", sha(payload)), patch.object(recovery, "LEGACY_ZIP_SIZE", len(payload)):
                    with self.assertRaises(recovery.RecoveryBlocked):
                        recovery.verify_legacy_package(payload, SOURCE)

    def test_safe_summary_has_no_raw_selectors_configuration_or_revision(self):
        snapshot = self.snapshot()
        summary = recovery.safe_summary(snapshot)
        text = json.dumps(summary)
        for private in (ACCOUNT, self.aws.stack_id, BUCKET, KEY, self.aws.version, "not-for-output", "synthetic-revision"):
            self.assertNotIn(private, text)
        self.assertEqual(summary["snapshotSha256"], recovery.digest(snapshot))

    def test_capture_uses_existing_private_prefix_conditional_write_and_exact_readback(self):
        snapshot = self.snapshot()
        summary = recovery.capture(self.aws, TOOLING, SNAPSHOT_KEY, recovery.digest(snapshot))
        put = next(value for name, value in self.aws.writes if name == "put_object")
        self.assertEqual(put["Bucket"], BUCKET)
        self.assertEqual(put["IfNoneMatch"], "*")
        self.assertEqual(put["ServerSideEncryption"], "AES256")
        self.assertEqual(json.loads(put["Body"]), snapshot)
        self.assertNotIn("snapshot-version-1", json.dumps(summary))

    def test_unapproved_capture_hash_or_outside_prefix_never_writes(self):
        for key, expected in (("sites/unrelated/snapshot.json", recovery.digest(self.snapshot())), (SNAPSHOT_KEY, "0" * 64)):
            with self.subTest(key=key), self.assertRaises(recovery.RecoveryBlocked):
                recovery.capture(self.aws, TOOLING, key, expected)
        self.assertEqual(self.aws.writes, [])

    def test_plan_changes_only_original_code_pointer_and_preserves_all_parameters(self):
        snapshot = self.snapshot()
        plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
        expected = deepcopy(self.aws.original)
        expected["Resources"]["ConfigAuthoringFunction"]["Properties"]["CodeUri"] = {
            "Bucket": BUCKET, "Key": KEY, "Version": self.aws.version}
        self.assertEqual(plan["template"], expected)
        self.assertEqual(plan["parameters"], [{"ParameterKey": key, "UsePreviousValue": True} for key in sorted(self.aws.params)])
        self.assertEqual(self.aws.writes, [])

    def test_recovery_refuses_non_code_template_or_parameter_or_inventory_drift(self):
        snapshot = self.snapshot()
        for mutation in (lambda: self.aws.original["Resources"]["ConfigRegistryTable"].update(DeletionPolicy="Delete"),
                         lambda: self.aws.params.update(LogLevel="DEBUG"),
                         lambda: self.aws.inventory["ConfigRegistryTable"].update(PhysicalResourceId="different")):
            self.aws = FakeAws()
            mutation()
            with self.assertRaises(recovery.RecoveryBlocked):
                recovery.plan_recovery(self.aws, TOOLING, snapshot)
            self.assertEqual(self.aws.writes, [])

    def test_execute_uses_real_change_set_reviewer_exact_id_and_no_rebuilt_zip(self):
        snapshot = self.snapshot()
        plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
        result = recovery.recover(self.aws, TOOLING, snapshot, recovery.plan_digest(plan), "recovery-42-1")
        self.assertEqual(result["status"], "recovered")
        self.assertEqual([name for name, _ in self.aws.writes], ["create_change_set", "execute_change_set"])
        create = self.aws.writes[0][1]
        execute = self.aws.writes[1][1]
        self.assertEqual(create["ChangeSetType"], "UPDATE")
        self.assertEqual(execute["ChangeSetName"], self.aws.description["ChangeSetId"])
        self.assertTrue(all(row.get("UsePreviousValue") for row in create["Parameters"]))

    def test_wrong_plan_never_creates_a_change_set(self):
        with self.assertRaises(recovery.RecoveryBlocked):
            recovery.recover(self.aws, TOOLING, self.snapshot(), "0" * 64, "recovery-42-1")
        self.assertEqual(self.aws.writes, [])

    def test_execute_preserves_reviewed_capabilities_in_request_and_postcheck(self):
        for capabilities in (["CAPABILITY_IAM"], None):
            with self.subTest(capabilities=capabilities):
                self.aws.capabilities = capabilities
                self.aws.writes.clear()
                snapshot = self.snapshot()
                plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
                result = recovery.recover(self.aws, TOOLING, snapshot, recovery.plan_digest(plan), "recovery-42-1")
                self.assertEqual(result["status"], "recovered")
                create = self.aws.writes[0][1]
                self.assertEqual(create.get("Capabilities"), capabilities)
                self.assertEqual("Capabilities" in create, capabilities is not None)
                self.assertEqual(self.aws.capabilities, snapshot["stack"].get("Capabilities"))

    def test_private_entrypoint_loads_exact_snapshot_and_runs_real_recovery(self):
        snapshot = self.snapshot()
        payload = recovery.canonical(snapshot)
        self.aws.objects[(SNAPSHOT_KEY, "snapshot-version-1")] = payload
        self.aws.latest[SNAPSHOT_KEY] = "snapshot-version-1"
        selection = {"snapshotKey": SNAPSHOT_KEY, "snapshotVersionId": "snapshot-version-1"}
        expected = recovery.digest(snapshot)
        preview = recovery.run("plan", self.aws, TOOLING, selection, expected_snapshot=expected)
        self.assertEqual(self.aws.writes, [])
        result = recovery.run("recover", self.aws, TOOLING, selection, expected_snapshot=expected,
                              expected_plan=preview["planSha256"], change_set_name="recovery-42-1")
        self.assertEqual(result["status"], "recovered")
        self.assertNotIn("not-for-output", json.dumps(result))

    def test_private_entrypoint_rejects_substitution_and_unknown_selection_fields(self):
        for selection in ({"snapshotKey": SNAPSHOT_KEY, "snapshotVersionId": "null"},
                          {"snapshotKey": SNAPSHOT_KEY, "snapshotVersionId": "version", "stack": "other"}):
            with self.assertRaises(recovery.RecoveryBlocked):
                recovery.run("plan", self.aws, TOOLING, selection, expected_snapshot="a" * 64)
        self.assertEqual(self.aws.writes, [])

    def test_non_code_function_configuration_drift_cannot_execute(self):
        snapshot = self.snapshot()
        self.aws.configuration["Environment"] = {"Variables": {"changed": "private-value"}}
        with self.assertRaises(recovery.RecoveryBlocked):
            recovery.plan_recovery(self.aws, TOOLING, snapshot)
        self.assertEqual(self.aws.writes, [])

    def test_drift_after_change_set_review_never_executes(self):
        snapshot = self.snapshot()
        plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
        original = self.aws.describe_change_set
        def drift(**kwargs):
            result = original(**kwargs)
            self.aws.configuration["RevisionId"] = "changed-during-review"
            return result
        with patch.object(self.aws, "describe_change_set", drift), self.assertRaises(recovery.RecoveryBlocked):
            recovery.recover(self.aws, TOOLING, snapshot, recovery.plan_digest(plan), "recovery-42-1")
        self.assertEqual([name for name, _ in self.aws.writes], ["create_change_set"])

    def test_drift_during_final_description_never_executes(self):
        snapshot = self.snapshot()
        plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
        original = self.aws.describe_change_set
        def drift(**kwargs):
            result = original(**kwargs)
            count = sum(name == "describe_change_set" for name, _ in self.aws.calls)
            if count == 2:
                self.aws.configuration["RevisionId"] = "final-describe-drift"
            return result
        with patch.object(self.aws, "describe_change_set", drift), self.assertRaises(recovery.RecoveryBlocked):
            recovery.recover(self.aws, TOOLING, snapshot, recovery.plan_digest(plan), "recovery-42-1")
        self.assertEqual([name for name, _ in self.aws.writes], ["create_change_set"])

    def test_changed_business_detail_in_second_change_set_description_is_rejected(self):
        snapshot = self.snapshot()
        plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
        original = self.aws.describe_change_set
        def drift(**kwargs):
            result = original(**kwargs)
            if sum(name == "describe_change_set" for name, _ in self.aws.calls) == 2:
                result["UnexpectedBusiness"] = {"nested": "changed"}
            return result
        with patch.object(self.aws, "describe_change_set", drift), self.assertRaises(recovery.RecoveryBlocked):
            recovery.recover(self.aws, TOOLING, snapshot, recovery.plan_digest(plan), "recovery-42-1")
        self.assertEqual([name for name, _ in self.aws.writes], ["create_change_set"])

    def test_exact_nochange_deletes_only_the_reviewed_changeset(self):
        snapshot = self.snapshot()
        plan = recovery.plan_recovery(self.aws, TOOLING, snapshot)
        original = self.aws.create_change_set
        def noop(**kwargs):
            result = original(**kwargs)
            self.aws.description.update(Status="FAILED", ExecutionStatus="UNAVAILABLE", Changes=[],
                StatusReason="The submitted information didn't contain changes. Submit different information to create a change set.")
            return result
        with patch.object(self.aws, "create_change_set", noop):
            result = recovery.recover(self.aws, TOOLING, snapshot, recovery.plan_digest(plan), "recovery-42-1")
        self.assertEqual(result["status"], "noop")
        self.assertEqual([name for name, _ in self.aws.writes], ["create_change_set", "delete_change_set"])
        self.assertEqual(self.aws.writes[-1][1]["ChangeSetName"], self.aws.description["ChangeSetId"])

    def test_existing_reviewer_rejects_removal_replacement_and_non_code_change(self):
        self.aws.create_change_set(ChangeSetName="recovery-42-1")
        for patch_value in ({"Action": "Remove"}, {"Replacement": "True"}, {"LogicalResourceId": "ConfigRegistryTable"},
                            {"Details": [{"Target": {"Attribute": "Properties", "Name": "Role"}}]}):
            description = deepcopy(self.aws.description)
            description["Changes"][0]["ResourceChange"].update(patch_value)
            with self.subTest(value=patch_value), self.assertRaises(recovery.RecoveryBlocked):
                recovery.review_recovery_change_set(description, self.aws.description["ChangeSetId"], "recovery-42-1", self.snapshot())


class RecoveryWorkflowTests(unittest.TestCase):
    def coordinate_guard(self, **overrides):
        workflow = (ROOT / ".github/workflows/rollback-test.yml").read_text()
        start = workflow.index("        run: |") + len("        run: |")
        end = workflow.index("      - name: Verify source Deploy Test run", start)
        code = textwrap.dedent(workflow[start:end])
        env = {**os.environ, "GITHUB_REF": "refs/heads/test", "GITHUB_SHA": TOOLING["sha"],
               "TOOLING_SHA": TOOLING["sha"], "WORKFLOW_SHA256": TOOLING["workflowSha256"],
               "SNAPSHOT_SHA256": "d" * 64, "PLAN_SHA256": "e" * 64,
               "RECOVERY_MODE": "AWS-live-snapshot/v1", "SOURCE_RUN_ID": "", "SOURCE_ARTIFACT_ID": "",
               "SOURCE_SHA": "", "manifest_digest": "", **overrides}
        bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
        return subprocess.run([bash, "-c", code], env=env, capture_output=True, text=True)

    def test_actual_workflow_coordinate_gate_accepts_only_exact_mode_coordinates(self):
        self.assertEqual(self.coordinate_guard().returncode, 0)
        for invalid in ({"TOOLING_SHA": "bad"}, {"SNAPSHOT_SHA256": "bad"}, {"PLAN_SHA256": ""},
                        {"SOURCE_SHA": SOURCE}, {"GITHUB_REF": "refs/heads/main"}, {"RECOVERY_MODE": "other"}):
            with self.subTest(invalid=invalid):
                self.assertNotEqual(self.coordinate_guard(**invalid).returncode, 0)

    def test_actual_github_provenance_gate_denies_missing_or_expired_artifact(self):
        workflow = (ROOT / ".github/workflows/rollback-test.yml").read_text()
        start = workflow.index("          script: |") + len("          script: |")
        end = workflow.index("\n  rollback:", start)
        code = textwrap.dedent(workflow[start:end])
        env = {**os.environ, "GITHUB_REF": "refs/heads/test", "SOURCE_RUN_ID": "42", "SOURCE_ARTIFACT_ID": "17", "SOURCE_SHA": SOURCE}
        run = {"path": ".github/workflows/deploy-test.yml", "event": "push", "head_branch": "test",
               "head_sha": SOURCE, "status": "completed", "conclusion": "success"}
        valid = {"expired": False, "workflow_run": {"id": 42, "head_sha": SOURCE, "head_branch": "test"},
                 "name": f"config-authoring-test-42-1-{SOURCE}"}
        for artifact in (valid, {**valid, "expired": True}, {**valid, "workflow_run": {"id": 99}}, None):
            wrapper = "const context={repo:{owner:'synthetic',repo:'synthetic'}};" + \
                "const github={rest:{actions:{getWorkflowRun:async()=>({data:" + json.dumps(run) + "})," + \
                "getArtifact:async()=>{const data=" + json.dumps(artifact) + ";if(!data)throw Error('missing');return {data};}}}};" + \
                "(async()=>{" + code + "})().catch(()=>process.exit(1));"
            result = subprocess.run([shutil.which("node"), "-e", wrapper], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, artifact == valid)

    def test_current_tooling_checkout_is_not_the_historical_payload_checkout(self):
        workflow = (ROOT / ".github/workflows/rollback-test.yml").read_text()
        self.assertNotIn("ref: ${{ inputs.source_sha }}", workflow,
                         "historical source lacks the four release helpers invoked after checkout")
        self.assertIn("ref: ${{ github.sha }}", workflow)

    def test_aws_mode_is_explicit_and_private_with_a_distinct_current_tooling_pin(self):
        workflow = (ROOT / ".github/workflows/rollback-test.yml").read_text()
        for token in ("AWS-live-snapshot/v1", "expected_tooling_sha:", "expected_snapshot_sha256:",
                      "expected_plan_sha256:", "secrets.CONFIG_TEST_RECOVERY_SELECTION_JSON", "tools/aws_live_snapshot.py"):
            self.assertIn(token, workflow)


if __name__ == "__main__":
    unittest.main()
