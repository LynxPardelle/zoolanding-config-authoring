"""Existing scope bootstrap must not silently erase reviewed catalog options."""

import copy
import hashlib
import unittest

import test_server_scope_bootstrap as scope_fixtures
from tools import bootstrap_server_scopes as bootstrap


class CatalogGrantPreservationTest(unittest.TestCase):
    def rule(self):
        return {
            "roleArn": "arn:aws:iam::123456789012:role/draft-example-test-deploy",
            "tenantId": "tenant-example", "draftId": "draft-example",
            "domains": ["example.com"], "environments": ["test"],
            "actions": ["upsertDraft", "publishDraft", "getSite"],
            "catalog": {"enabled": False},
        }

    def test_scope_bootstrap_blocks_catalog_changes_before_any_write(self):
        original = self.rule()
        for mutate in ["remove", "change", "identity", "type"]:
            with self.subTest(mutate=mutate):
                store = scope_fixtures.FakeS3()
                previous = bootstrap.canonical_json_bytes([original])
                head = store.put_object("bucket", bootstrap.AUTHZ_KEY, previous, "123456789012", if_none_match="*")
                store.puts.clear()
                changed = copy.deepcopy(original)
                if mutate == "remove":
                    del changed["catalog"]
                elif mutate == "change":
                    changed["catalog"] = {"enabled": True, "entryIds": ["guitarra"], "environments": ["test"]}
                elif mutate == "identity":
                    changed["draftId"] = "other-draft"
                else:
                    changed["catalog"] = {"enabled": 0}
                candidate = bootstrap.canonical_json_bytes([changed])
                scope = bootstrap.canonical_json_bytes({"version": 1, "scopes": []})
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.apply_private_bundle(
                        store, bucket="bucket", expected_owner="123456789012",
                        scope_bytes=scope, authz_bytes=candidate,
                        approved_scope_sha256=hashlib.sha256(scope).hexdigest(),
                        approved_authz_sha256=hashlib.sha256(candidate).hexdigest(),
                        expected_current_authz_etag=head["etag"], expected_current_authz_version_id=head["versionId"],
                        expected_current_scope_etag="MISSING", expected_current_scope_version_id="MISSING",
                        expected_current_scope_sha256="MISSING",
                    )
                self.assertEqual(store.puts, [])

    def test_identical_enrollment_and_explicit_opt_out_can_be_preserved(self):
        for options in [
            {"enabled": False},
            {"enabled": True, "entryIds": ["guitarra"], "environments": ["test"]},
        ]:
            rule = self.rule()
            rule["catalog"] = options
            previous = bootstrap.canonical_json_bytes([rule])
            bootstrap._require_catalog_grants_preserved(previous, bootstrap.canonical_json_bytes([copy.deepcopy(rule)]))


if __name__ == "__main__":
    unittest.main()
