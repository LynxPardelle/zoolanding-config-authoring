import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.review_test_change_set import ChangeSetReviewError, review_change_set


ARN = "arn:aws:cloudformation:us-east-1:123456789012:changeSet/release-1/abc"


def payload(*, action="Modify", replacement="False"):
    return {
        "StackName": "example-test",
        "ChangeSetName": "release-1",
        "ChangeSetId": ARN,
        "ChangeSetType": "UPDATE",
        "Status": "CREATE_COMPLETE",
        "ExecutionStatus": "AVAILABLE",
        "Parameters": [
            {"ParameterKey": "EnvironmentName", "ParameterValue": "test"},
            {"ParameterKey": "EnableFeature", "ParameterValue": "false"},
        ],
        "Changes": [
            {
                "Type": "Resource",
                "ResourceChange": {"Action": action, "Replacement": replacement},
            }
        ],
    }


class ReviewTestChangeSetTests(unittest.TestCase):
    def test_accepts_exact_nonreplacement_update(self):
        self.assertEqual(
            review_change_set(
                payload(),
                expected_stack_name="example-test",
                expected_change_set_name="release-1",
                expected_change_set_arn=ARN,
                expected_change_set_type="UPDATE",
                expected_parameters={"EnvironmentName": "test", "EnableFeature": "false"},
                required_parameters=set(),
            ),
            "execute",
        )

    def test_rejects_remove_and_replacement(self):
        for candidate in (payload(action="Remove"), payload(replacement="True")):
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                ChangeSetReviewError, "stateful_resource_change_forbidden"
            ):
                review_change_set(
                    candidate,
                    expected_stack_name="example-test",
                    expected_change_set_name="release-1",
                    expected_change_set_arn=ARN,
                    expected_change_set_type="UPDATE",
                    expected_parameters={"EnvironmentName": "test"},
                    required_parameters=set(),
                )

    def test_rejects_parameter_drift(self):
        with self.assertRaises(ChangeSetReviewError):
            review_change_set(
                payload(),
                expected_stack_name="example-test",
                expected_change_set_name="release-1",
                expected_change_set_arn=ARN,
                expected_change_set_type="UPDATE",
                expected_parameters={"EnableFeature": "true"},
                required_parameters=set(),
            )


if __name__ == "__main__":
    unittest.main()
