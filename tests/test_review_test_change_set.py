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
    def review(self, candidate, *, expected_type="UPDATE"):
        return review_change_set(
            candidate,
            expected_stack_name="example-test",
            expected_change_set_name="release-1",
            expected_change_set_arn=ARN,
            expected_change_set_type=expected_type,
            expected_parameters={"EnvironmentName": "test", "EnableFeature": "false"},
            required_parameters=set(),
        )

    def test_accepts_aws_description_without_change_set_type(self):
        for expected_type in ("CREATE", "UPDATE"):
            with self.subTest(expected_type=expected_type):
                self.assertEqual(self.review(payload(action="Add"), expected_type=expected_type), "execute")

    def test_rejects_explicit_type_mismatch_or_invalid_expected_type(self):
        for response_type in (None, "", "CREATE", "IMPORT"):
            with self.subTest(response_type=response_type), self.assertRaisesRegex(
                ChangeSetReviewError, "change_set_identity_invalid"
            ):
                self.review({**payload(), "ChangeSetType": response_type})
        with self.assertRaisesRegex(ChangeSetReviewError, "change_set_type_invalid"):
            self.review(payload(), expected_type="IMPORT")
        self.assertEqual(self.review({**payload(), "ChangeSetType": "UPDATE"}), "execute")

    def test_aws_description_still_requires_exact_identity_and_parameters(self):
        for field in ("StackName", "ChangeSetName", "ChangeSetId"):
            with self.subTest(field=field), self.assertRaisesRegex(
                ChangeSetReviewError, "change_set_identity_invalid"
            ):
                self.review({**payload(), field: "unexpected"})
        with self.assertRaisesRegex(ChangeSetReviewError, "change_set_parameter_drift"):
            self.review({**payload(), "Parameters": []})

    def test_accepts_exact_aws_noop_without_change_set_type(self):
        candidate = {
            **payload(), "Status": "FAILED", "ExecutionStatus": "UNAVAILABLE", "Changes": [],
            "StatusReason": "The submitted information didn't contain changes. Submit different information to create a change set.",
        }
        self.assertEqual(self.review(candidate), "noop")
        with self.assertRaisesRegex(ChangeSetReviewError, "change_set_not_available"):
            self.review({**candidate, "StatusReason": "unexpected failure"})

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
