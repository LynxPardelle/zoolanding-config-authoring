"""Execute the real TEST baseline collector with a strictly read-only AWS fake."""

import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
STACK = "zoolanding-config-authoring-test"
ACCOUNT = "765932874577"
FUNCTION = STACK + "-ConfigAuthoringFunction-synthetic"


class TestNativeRollbackBaselineTests(unittest.TestCase):
    def setUp(self):
        self.stack = {
            "StackName": STACK,
            "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{STACK}/stable-id",
            "StackStatus": "UPDATE_COMPLETE",
            "Parameters": [{"ParameterKey": "EnvironmentName", "ParameterValue": "test"}],
            "Outputs": [],
        }
        self.resources = [
            {"LogicalResourceId": "ConfigAuthoringFunction", "PhysicalResourceId": FUNCTION,
             "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "UPDATE_COMPLETE"},
            {"LogicalResourceId": "AuthoringApi", "PhysicalResourceId": "synthetic-api",
             "ResourceType": "AWS::ApiGateway::RestApi", "ResourceStatus": "CREATE_COMPLETE"},
        ]
        self.function = {
            "FunctionName": FUNCTION,
            "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FUNCTION}",
            "Version": "$LATEST", "State": "Active", "LastUpdateStatus": "Successful",
            "CodeSha256": base64.b64encode(b"s" * 32).decode("ascii"),
            "RevisionId": "verified-revision",
            "Environment": {"Variables": {"SYNTHETIC_SETTING": "unprinted-value"}},
        }
        self.account = ACCOUNT
        self.extra_resource_response = {}

    def collector(self, workflow="deploy-test.yml"):
        source = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
        marker = "          collect_native_baseline() {\n            python3 - \"$STACK_NAME\" \"$1\" <<'PY'\n"
        self.assertEqual(source.count(marker), 1)
        return textwrap.dedent(source.split(marker, 1)[1].split("\n          PY\n", 1)[0])

    def collect(self, region="us-east-1"):
        calls = []

        def aws(args, **_kwargs):
            self.assertEqual(args[0], "aws")
            operation = tuple(args[1:3])
            calls.append(operation)
            if operation == ("sts", "get-caller-identity"):
                payload = {"Account": self.account}
            elif operation == ("cloudformation", "describe-stacks"):
                payload = {"Stacks": [copy.deepcopy(self.stack)]}
            elif operation == ("cloudformation", "list-stack-resources"):
                payload = {"StackResourceSummaries": copy.deepcopy(self.resources), **self.extra_resource_response}
            elif operation == ("lambda", "get-function-configuration"):
                payload = copy.deepcopy(self.function)
            elif operation == ("cloudformation", "get-template"):
                payload = {"TemplateBody": {"Resources": {"ConfigAuthoringFunction": {"Type": "AWS::Lambda::Function"}}}}
            else:
                raise AssertionError("Baseline attempted an unexpected or mutating AWS operation")
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "baseline.json"
            error = None
            with patch.object(sys, "argv", ["inline-baseline", STACK, str(target)]), \
                 patch.dict(os.environ, {"AWS_REGION": region}), \
                 patch.object(subprocess, "run", side_effect=aws), \
                 contextlib.redirect_stdout(output):
                try:
                    exec(compile(self.collector(), "inline-test-baseline", "exec"), {})
                except SystemExit as failure:
                    error = str(failure.code)
            baseline = json.loads(target.read_text(encoding="utf-8")) if target.exists() else None
        self.assertEqual(output.getvalue(), "", "Collector must not print configuration values")
        return error, baseline, calls

    def test_verified_rollback_complete_is_a_usable_sealed_baseline(self):
        self.stack["StackStatus"] = "UPDATE_ROLLBACK_COMPLETE"
        error, baseline, calls = self.collect()
        self.assertIsNone(error)
        self.assertEqual(baseline["stackStatus"], "UPDATE_ROLLBACK_COMPLETE")
        self.assertEqual(baseline["functions"][0]["CodeSha256"], self.function["CodeSha256"])
        self.assertEqual(baseline["functions"][0]["RevisionId"], "verified-revision")
        self.assertEqual(calls.count(("lambda", "get-function-configuration")), 1)

    def test_existing_successful_states_remain_usable_and_record_their_state(self):
        for state in ["CREATE_COMPLETE", "UPDATE_COMPLETE"]:
            with self.subTest(state=state):
                self.stack["StackStatus"] = state
                error, baseline, _ = self.collect()
                self.assertIsNone(error)
                self.assertEqual(baseline.get("stackStatus"), state)

    def test_incomplete_failed_deleted_or_initial_rollback_states_are_rejected(self):
        for state in ["UPDATE_IN_PROGRESS", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
                      "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "DELETE_COMPLETE", "CREATE_FAILED"]:
            with self.subTest(state=state):
                self.stack["StackStatus"] = state
                error, baseline, _ = self.collect()
                self.assertEqual(error, "native_stack_unavailable")
                self.assertIsNone(baseline)

    def test_rollback_is_not_verified_when_function_is_unhealthy_or_unbound(self):
        original = copy.deepcopy(self.function)
        cases = [
            {"State": "Pending"}, {"State": "Failed"}, {"LastUpdateStatus": "Failed"},
            {"LastUpdateStatus": "InProgress"}, {"RevisionId": ""}, {"CodeSha256": ""},
            {"CodeSha256": "not-a-sha256"}, {"FunctionArn": "unexpected-function"},
            {"FunctionName": "other-function"}, {"Version": "1"},
        ]
        for state in ["UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"]:
            self.stack["StackStatus"] = state
            for changes in cases:
                with self.subTest(state=state, fields=list(changes)):
                    self.function = {**original, **changes}
                    error, baseline, _ = self.collect()
                    self.assertIsNotNone(error)
                    self.assertIsNone(baseline)

    def test_incomplete_duplicate_failed_or_ambiguous_inventory_is_rejected(self):
        original = copy.deepcopy(self.resources)
        cases = [[], original + [original[0]],
                 [{**original[0], "ResourceStatus": "UPDATE_FAILED"}, original[1]],
                 [original[0], {**original[1], "ResourceStatus": "UPDATE_FAILED"}],
                 [{**original[0], "LogicalResourceId": "OtherFunction"}, original[1]],
                 [original[0], {**original[1], "ResourceType": "AWS::Lambda::Function"}]]
        for resources in cases:
            with self.subTest(resources=resources):
                self.resources = copy.deepcopy(resources)
                error, baseline, _ = self.collect()
                self.assertIsNotNone(error)
                self.assertIsNone(baseline)
        self.resources = original
        self.extra_resource_response = {"NextToken": "unread-page"}
        error, baseline, _ = self.collect()
        self.assertIsNotNone(error)
        self.assertIsNone(baseline)

    def test_stack_and_account_identity_remain_exact(self):
        original = copy.deepcopy(self.stack)
        for change in [{"StackName": "other-stack"}, {"StackId": "unexpected-stack"}]:
            with self.subTest(change=change):
                self.stack = {**original, **change}
                error, baseline, _ = self.collect()
                self.assertIsNotNone(error)
                self.assertIsNone(baseline)
        self.stack = original
        self.account = "000000000000"
        self.assertEqual(self.collect()[0], "native_identity_invalid")
        self.account = ACCOUNT
        self.assertEqual(self.collect(region="us-west-2")[0], "native_identity_invalid")

    def test_recovery_does_not_change_the_execute_or_production_boundaries(self):
        source = (ROOT / ".github/workflows/deploy-test.yml").read_text(encoding="utf-8")
        self.assertIn('test "$REVIEW_DIGEST" = "$review_inventory_digest"', source)
        self.assertIn('cmp -s "$baseline" "$RUNNER_TEMP/native-execute-baseline.json"', source)
        self.assertLess(source.index('cmp -s "$baseline"'), source.index("aws cloudformation execute-change-set"))
        self.assertIn('test "$final_status" = "UPDATE_COMPLETE"', source)
        self.assertNotIn("UPDATE_ROLLBACK_COMPLETE", self.collector("deploy-production.yml"))


if __name__ == "__main__":
    unittest.main()
