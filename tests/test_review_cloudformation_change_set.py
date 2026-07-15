import copy
import unittest

from tools.review_cloudformation_change_set import (
    ChangeSetReviewError,
    review_change_set,
)


EXPECTED_PARAMETERS = {
    "EnvironmentName": "test",
    "ManageStorageResources": "true",
    "ConfigTableName": "zoolanding-config-registry-test",
    "ConfigPayloadsBucketName": "zoolanding-config-payloads-test",
    "LogLevel": "INFO",
    "DeployAuthzConfigS3Key": "system/deploy-authz.json",
}
CHANGE_SET_NAME = "zoolanding-123-1"
CHANGE_SET_ARN = (
    "arn:aws:cloudformation:us-east-1:765932874577:"
    "changeSet/zoolanding-123-1/00000000-0000-0000-0000-000000000000"
)


def valid_change_set():
    return {
        "ChangeSetName": CHANGE_SET_NAME,
        "ChangeSetId": CHANGE_SET_ARN,
        "StackName": "zoolanding-config-authoring-test",
        "ChangeSetType": "UPDATE",
        "Status": "CREATE_COMPLETE",
        "ExecutionStatus": "AVAILABLE",
        "Parameters": [
            {"ParameterKey": key, "ParameterValue": value}
            for key, value in EXPECTED_PARAMETERS.items()
        ],
        "Changes": [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "ConfigAuthoringFunction",
                    "ResourceType": "AWS::Lambda::Function",
                    "Replacement": "False",
                },
            }
        ],
    }


class ReviewCloudFormationChangeSetTest(unittest.TestCase):
    def review(self, payload):
        return review_change_set(
            payload,
            expected_stack_name="zoolanding-config-authoring-test",
            expected_change_set_name=CHANGE_SET_NAME,
            expected_change_set_arn=CHANGE_SET_ARN,
            expected_parameters=EXPECTED_PARAMETERS,
        )

    def test_accepts_exact_nonreplacement_update(self):
        self.assertEqual(self.review(valid_change_set()), "execute")

    def test_accepts_only_an_exact_no_change_failure_as_noop(self):
        payload = valid_change_set()
        payload.update({
            "Status": "FAILED",
            "ExecutionStatus": "UNAVAILABLE",
            "StatusReason": (
                "The submitted information didn't contain changes. "
                "Submit different information to create a change set."
            ),
            "Changes": [],
        })
        self.assertEqual(self.review(payload), "noop")

        payload["StatusReason"] = "Template validation failed"
        with self.assertRaises(ChangeSetReviewError):
            self.review(payload)

    def test_rejects_identity_status_parameter_and_shape_drift(self):
        mutations = (
            ("ChangeSetName", "other"),
            ("ChangeSetId", CHANGE_SET_ARN + "-other"),
            ("StackName", "other"),
            ("ChangeSetType", "CREATE"),
            ("Status", "CREATE_PENDING"),
            ("ExecutionStatus", "OBSOLETE"),
            ("Parameters", []),
            ("Changes", []),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                payload = valid_change_set()
                payload[key] = value
                with self.assertRaises(ChangeSetReviewError):
                    self.review(payload)

    def test_rejects_duplicate_or_unknown_parameters(self):
        for parameters in (
            [
                {"ParameterKey": "EnvironmentName", "ParameterValue": "test"},
                {"ParameterKey": "EnvironmentName", "ParameterValue": "test"},
            ],
            valid_change_set()["Parameters"]
            + [{"ParameterKey": "Unknown", "ParameterValue": "value"}],
        ):
            with self.subTest(parameters=parameters):
                payload = valid_change_set()
                payload["Parameters"] = parameters
                with self.assertRaises(ChangeSetReviewError):
                    self.review(payload)

    def test_rejects_removal_or_any_possible_replacement(self):
        for action, replacement in (
            ("Remove", "False"),
            ("Modify", "True"),
            ("Modify", "Conditional"),
        ):
            with self.subTest(action=action, replacement=replacement):
                payload = copy.deepcopy(valid_change_set())
                resource = payload["Changes"][0]["ResourceChange"]
                resource["Action"] = action
                resource["Replacement"] = replacement
                with self.assertRaises(ChangeSetReviewError):
                    self.review(payload)

    def test_rejects_non_resource_or_malformed_changes(self):
        for change in (
            None,
            {},
            {"Type": "Resource"},
            {"Type": "Hook", "ResourceChange": {}},
        ):
            with self.subTest(change=change):
                payload = valid_change_set()
                payload["Changes"] = [change]
                with self.assertRaises(ChangeSetReviewError):
                    self.review(payload)


if __name__ == "__main__":
    unittest.main()
