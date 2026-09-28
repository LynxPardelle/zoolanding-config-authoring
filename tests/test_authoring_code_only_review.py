import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("deploy-test.yml", "deploy-production.yml")


class AuthoringCodeOnlyReviewTests(unittest.TestCase):
    def review(self, workflow, resource, event="workflow_dispatch", extra=None):
        source = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
        code = textwrap.dedent(source.split("# inline-change-set-review:start", 1)[1]
                              .split("# inline-change-set-review:end", 1)[0]).strip()
        name = "zoolanding-123-1"
        arn = "arn:aws:cloudformation:us-east-1:765932874577:changeSet/" + name + "/native-id"
        parameters = {"EnvironmentName": "test"}
        payload = {"ChangeSetName": name, "ChangeSetId": arn,
                   "StackName": "zoolanding-config-authoring-test", "ChangeSetType": "UPDATE",
                   "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
                   "Parameters": [{"ParameterKey": key, "ParameterValue": value}
                                  for key, value in parameters.items()],
                   "Changes": [{"Type": "Resource", "ResourceChange": resource}]}
        if extra is not None:
            payload["Changes"].append({"Type": "Resource", "ResourceChange": extra})
        with tempfile.TemporaryDirectory() as directory:
            description = Path(directory) / "description.json"
            description.write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.run([sys.executable, "-c", code, str(description),
                                   payload["StackName"], name, arn, json.dumps(parameters)],
                                  cwd=directory, env={**os.environ, "GITHUB_EVENT_NAME": event},
                                  capture_output=True, text=True, check=False)

    def code_change(self):
        return {"Action": "Modify", "Replacement": "False",
                "LogicalResourceId": "ConfigAuthoringFunction", "ResourceType": "AWS::Lambda::Function",
                "Scope": ["Properties"], "Details": [{"Target": {
                    "Attribute": "Properties", "Name": "Code", "RequiresRecreation": "Never"},
                    "Evaluation": "Static", "ChangeSource": "DirectModification"}]}

    def test_manual_review_accepts_actual_native_code_detail_shape(self):
        for workflow in WORKFLOWS:
            for source, evaluation in (("DirectModification", "Static"),
                                       ("ParameterReference", "Dynamic"),
                                       ("ResourceReference", "Dynamic")):
                resource = self.code_change()
                resource["Details"][0].update(ChangeSource=source, Evaluation=evaluation)
                with self.subTest(workflow=workflow, source=source):
                    result = self.review(workflow, resource)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "execute")

    def test_manual_review_rejects_non_code_property_and_metadata_changes(self):
        candidates = []
        for name in ("Tags", "Environment", "Role"):
            resource = self.code_change()
            resource["Details"][0]["Target"]["Name"] = name
            candidates.append((name, resource))
        resource = self.code_change()
        resource["Scope"] = ["Metadata"]
        resource["Details"][0]["Target"] = {"Attribute": "Metadata", "RequiresRecreation": "Never"}
        candidates.append(("Metadata", resource))
        for workflow in WORKFLOWS:
            for name, resource in candidates:
                with self.subTest(workflow=workflow, target=name):
                    self.assertNotEqual(self.review(workflow, resource).returncode, 0)

    def test_manual_review_rejects_other_resources_and_additions(self):
        for workflow in WORKFLOWS:
            for action in ("Add", "Modify"):
                resource = self.code_change()
                resource.update(Action=action, LogicalResourceId="UnexpectedPolicy", ResourceType="AWS::IAM::Policy")
                with self.subTest(workflow=workflow, action=action):
                    self.assertNotEqual(self.review(workflow, resource).returncode, 0)

    def test_manual_review_rejects_a_second_resource_and_duplicate_code_entry(self):
        unexpected = self.code_change()
        unexpected.update(Action="Add", LogicalResourceId="UnexpectedPolicy", ResourceType="AWS::IAM::Policy")
        for workflow in WORKFLOWS:
            for extra in (unexpected, self.code_change()):
                with self.subTest(workflow=workflow, extra=extra["LogicalResourceId"]):
                    self.assertNotEqual(self.review(workflow, self.code_change(), extra=extra).returncode, 0)

    def test_manual_review_rejects_missing_or_mixed_details(self):
        candidates = []
        resource = self.code_change()
        resource["Details"] = []
        candidates.append(resource)
        resource = self.code_change()
        extra = copy.deepcopy(resource["Details"][0])
        extra["Target"]["Name"] = "Tags"
        resource["Details"].append(extra)
        candidates.append(resource)
        for workflow in WORKFLOWS:
            for index, resource in enumerate(candidates):
                with self.subTest(workflow=workflow, candidate=index):
                    self.assertNotEqual(self.review(workflow, resource).returncode, 0)

    def test_existing_replacement_and_removal_checks_remain_closed(self):
        for workflow in WORKFLOWS:
            for action, replacement in (("Remove", "False"), ("Modify", "True"), ("Modify", "Conditional")):
                resource = self.code_change()
                resource.update(Action=action, Replacement=replacement)
                with self.subTest(workflow=workflow, action=action, replacement=replacement):
                    self.assertNotEqual(self.review(workflow, resource).returncode, 0)

    def test_legacy_push_reviewer_preserves_existing_nonreplacement_scope(self):
        resource = self.code_change()
        resource.update(LogicalResourceId="LegacyResource", ResourceType="AWS::IAM::Policy", Action="Add")
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                result = self.review(workflow, resource, event="push")
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
