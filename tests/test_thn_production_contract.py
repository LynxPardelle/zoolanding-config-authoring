import copy
import unittest
from test_server_policy_validation import THN_PROTECTED_FEATURE_BINDING
import server_policy_validation as policy


class ProductionDescriptorTests(unittest.TestCase):
    def test_closed_production_descriptor_is_accepted_only_in_its_server_scope(self):
        descriptor = {**THN_PROTECTED_FEATURE_BINDING, "environment": "production",
                      "serviceBindingId": "thn-journal-production-v2"}
        files = [{"path": "thehairnarrative.com/server/protected-feature-bindings-v2.json", "content": descriptor}]
        try:
            policy.validate_server_policy_files("thehairnarrative.com", "production", files)
        except policy.PolicyValidationError as error:
            self.fail(f"closed production descriptor rejected: {error}")
        for key, value in (("environment", "test"), ("serviceBindingId", "thn-journal-test-v2"),
                           ("domain", "other.example.com"), ("namespace", "browser-controlled")):
            with self.subTest(key=key), self.assertRaises(policy.PolicyValidationError):
                candidate = copy.deepcopy(files)
                candidate[0]["content"][key] = value
                policy.validate_server_policy_files("thehairnarrative.com", "production", candidate)
