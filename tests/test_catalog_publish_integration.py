"""IAM-scoped automatic catalog synchronization without coupling publish errors."""

import copy
import json
import unittest
from unittest.mock import patch

import test_catalog_contract as catalog_fixtures
import test_catalog_projection as projection_fixtures
import test_handler as handler_fixtures


class CatalogPublishIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.fixture = projection_fixtures.CatalogProjectionTest(methodName="runTest")
        self.fixture.setUp()
        self.handler = self.fixture.handler
        self.authoring = self.fixture.fixture
        self.domain = "example.com"
        self.entry_id = "guitarra"
        self.role = "draft-example-test-deploy"

    def opt_in(self):
        self.authoring.test_authz_rule["catalog"] = {
            "enabled": True, "entryIds": [self.entry_id], "environments": ["test"],
        }

    def use_curated_source(self):
        self.domain = "zoositioweb.com.mx"
        self.entry_id = "zoositioweb-com-mx"
        self.authoring.test_authz_rule["domains"] = [self.domain]

    def package(self, entry_id=None):
        package = catalog_fixtures.files({"entries": [catalog_fixtures.entry(
            entryId=entry_id or self.entry_id, path="/",
            imageUrl="https://assets.zoolandingpage.com.mx/public/cover.webp",
        )]})
        for file in package:
            file["path"] = file["path"].replace("example.com/", self.domain + "/", 1)
        package[0]["content"]["domain"] = self.domain
        return package

    def call(self, action, **changes):
        payload = {"action": action, "domain": self.domain, "environment": "test"}
        payload.update(changes)
        return self.handler.lambda_handler(handler_fixtures.event(payload, self.role), handler_fixtures.Context())

    def upsert(self, version="integration-v1", entry_id=None):
        response = self.call("upsertDraft", versionId=version, files=self.package(entry_id))
        self.assertEqual(response["statusCode"], 200, response["body"])

    def test_existing_non_enrolled_grant_preserves_legacy_publish_response(self):
        self.upsert()
        response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 200)
        self.assertNotIn("catalogSync", handler_fixtures.parse(response))
        self.assertEqual(self.fixture.writes, [])

    def test_curated_test_source_uses_its_existing_exact_publish_grant(self):
        self.use_curated_source()
        self.upsert()
        response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response).get("catalogSync", {}).get("status"), "pending")
        self.assertEqual(self.fixture.writes, [])
        response = self.call("reconcileCatalog")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response)["catalogSync"]["status"], "applied")
        document = self.authoring.items[("CATALOG#test", "SOURCE#DRAFT#zoositioweb.com.mx")]
        self.assertEqual(document["entries"][0]["entryId"], self.entry_id)
        self.assertEqual(document["sourceDomain"], self.domain)

    def test_explicit_private_grant_enables_only_its_exact_entry_ids(self):
        self.opt_in()
        self.upsert()
        response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response).get("catalogSync", {}).get("status"), "pending")
        self.assertEqual(self.call("reconcileCatalog")["statusCode"], 200)
        self.assertEqual(self.fixture.writes[0]["sourceId"], "draft:example.com")

    def test_explicit_opt_out_wins_over_curated_test_enrollment(self):
        self.use_curated_source()
        self.authoring.test_authz_rule["catalog"] = {"enabled": False}
        self.upsert()
        response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertNotIn("catalogSync", handler_fixtures.parse(response))
        self.assertEqual(self.fixture.writes, [])
        self.assertEqual(self.call("reconcileCatalog")["statusCode"], 401)

    def test_explicit_opt_in_overrides_the_curated_id_allowlist(self):
        self.use_curated_source()
        self.entry_id = "reviewed-alternate"
        self.opt_in()
        self.upsert()
        response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(self.call("reconcileCatalog")["statusCode"], 200)
        self.assertEqual(self.fixture.writes[0]["entries"][0]["entryId"], "reviewed-alternate")

    def test_invalid_optional_authorization_extension_denies_every_write(self):
        invalid_options = [
            None, {}, {"enabled": 1}, {"enabled": False, "entryIds": []},
            {"enabled": True, "entryIds": ["guitarra"], "environments": ["production"]},
            {"enabled": True, "entryIds": [], "environments": ["test"]},
            {"enabled": True, "entryIds": ["guitarra", "guitarra"], "environments": ["test"]},
            {"enabled": True, "entryIds": ["guitarra"], "environments": ["test"], "sourceDomain": "other.example"},
        ]
        for options in invalid_options:
            with self.subTest(options=options):
                self.authoring.test_authz_rule["catalog"] = options
                response = self.call("upsertDraft", versionId="invalid-options", files=self.package())
                self.assertEqual(response["statusCode"], 401)
        self.assertEqual(self.authoring.items, {})
        self.assertEqual(self.authoring.objects, {})

    def test_unapproved_catalog_id_is_rejected_before_pointer_commit(self):
        self.opt_in()
        self.upsert(entry_id="unapproved")
        before = copy.deepcopy(self.authoring.items)
        response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 400, response["body"])
        self.assertEqual(handler_fixtures.parse(response)["error"], "catalog_source_invalid")
        self.assertEqual(self.authoring.items, before)
        self.assertEqual(self.fixture.writes, [])

    def test_request_cannot_supply_its_own_catalog_registration(self):
        self.upsert()
        response = self.call("publishDraft", versionId="integration-v1", _authorizedCatalogRegistration=self.fixture.registration)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(self.fixture.writes, [])
        self.assertNotIn("catalogSync", handler_fixtures.parse(response))

    def test_publish_never_calls_projection_and_returns_durable_pending_intent(self):
        self.opt_in()
        self.upsert()
        with patch.object(self.handler, "_project_published_catalog", side_effect=RuntimeError("synthetic-sensitive-error")) as projection:
            response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response).get("catalogSync", {}).get("status"), "pending")
        self.assertNotIn("synthetic-sensitive-error", response["body"])
        projection.assert_not_called()
        metadata = self.authoring.items[("SITE#example.com", "METADATA")]
        self.assertEqual(metadata["publishedEnvironments"]["test"]["catalogRevision"]["sequence"], 2)
        self.assertEqual(metadata["revision"], 2)
        self.assertEqual(self.fixture.writes, [])

    def test_pointer_conflict_never_invokes_projection(self):
        self.opt_in()
        self.upsert()
        before = copy.deepcopy(self.authoring.items)
        with patch.object(self.handler, "put_item_if_revision", side_effect=self.handler.RevisionConflictError()), \
             patch.object(self.handler, "_project_published_catalog") as projection:
            response = self.call("publishDraft", versionId="integration-v1")
        self.assertEqual(response["statusCode"], 409)
        projection.assert_not_called()
        self.assertEqual(self.authoring.items, before)

    def test_projection_retry_failure_has_a_safe_retryable_response(self):
        self.opt_in()
        self.upsert()
        self.call("publishDraft", versionId="integration-v1")
        before = copy.deepcopy(self.authoring.items)
        with patch.object(self.handler, "_project_published_catalog", side_effect=RuntimeError("sensitive-synthetic-detail")):
            response = self.call("reconcileCatalog")
        self.assertEqual(response["statusCode"], 500)
        self.assertEqual(handler_fixtures.parse(response)["error"], "catalog_projection_pending")
        self.assertNotIn("sensitive-synthetic-detail", response["body"])
        self.assertEqual(self.authoring.items, before)

    def test_two_draft_grants_cannot_own_the_same_catalog_entry_id(self):
        self.opt_in()
        other = copy.deepcopy(self.authoring.test_authz_rule)
        other.update({"roleArn": handler_fixtures.role_arn("other-draft-test-deploy"),
                      "draftId": "other-draft", "domains": ["other.example"]})
        self.authoring.authz_rules.append(other)
        response = self.call("upsertDraft", versionId="duplicate-owner", files=self.package())
        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(self.authoring.items, {})
        self.assertEqual(self.authoring.objects, {})

    def test_reconcile_retries_current_pointer_without_republishing_and_is_idempotent(self):
        self.opt_in()
        self.upsert()
        with patch.object(self.handler, "_project_published_catalog", side_effect=RuntimeError("offline failure")):
            self.assertEqual(self.call("publishDraft", versionId="integration-v1")["statusCode"], 200)
        before = copy.deepcopy(self.authoring.items[("SITE#example.com", "METADATA")])
        objects_before = copy.deepcopy(self.authoring.objects)
        response = self.call("reconcileCatalog")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response).get("catalogSync", {}).get("status"), "applied")
        response = self.call("reconcileCatalog")
        self.assertEqual(handler_fixtures.parse(response).get("catalogSync", {}).get("status"), "noop")
        self.assertEqual(self.authoring.items[("SITE#example.com", "METADATA")], before)
        self.assertEqual(self.authoring.objects, objects_before)
        self.assertEqual(len(self.fixture.writes), 1)

    def test_reconcile_requires_publish_permission_and_effective_enrollment(self):
        self.opt_in()
        self.authoring.test_authz_rule["actions"] = ["getSite"]
        self.assertEqual(self.call("reconcileCatalog")["statusCode"], 401)
        self.authoring.test_authz_rule["actions"] = ["publishDraft"]
        self.role = "other-draft-test-deploy"
        self.assertEqual(self.call("reconcileCatalog")["statusCode"], 401)
        self.role = "draft-example-test-deploy"
        del self.authoring.test_authz_rule["catalog"]
        self.assertEqual(self.call("reconcileCatalog")["statusCode"], 401)

    def test_reconcile_rejects_request_selected_versions_or_registration(self):
        self.opt_in()
        self.upsert()
        self.call("publishDraft", versionId="integration-v1")
        before = copy.deepcopy(self.authoring.items)
        for extras in [{"versionId": "integration-v1"}, {"entryIds": ["other"]}, {"registration": self.fixture.registration}]:
            with self.subTest(extras=extras):
                self.assertEqual(self.call("reconcileCatalog", **extras)["statusCode"], 400)
        self.assertEqual(self.authoring.items, before)

    def test_curated_test_enrollment_does_not_implicitly_enable_production(self):
        self.use_curated_source()
        self.handler.ENVIRONMENT_NAME = "production"
        grant = copy.deepcopy(self.authoring.test_authz_rule)
        grant["environments"] = ["production"]
        self.authoring.authz_rules = [grant]
        payload = {"action": "reconcileCatalog", "domain": self.domain, "environment": "production"}
        response = self.handler.lambda_handler(handler_fixtures.event(payload, self.role), handler_fixtures.Context())
        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(self.fixture.writes, [])

    def test_production_can_only_enroll_through_its_explicit_exact_private_grant(self):
        self.handler.ENVIRONMENT_NAME = "production"
        grant = copy.deepcopy(self.authoring.production_authz_rule)
        grant["catalog"] = {"enabled": True, "entryIds": [self.entry_id], "environments": ["production"]}
        self.authoring.authz_rules = [grant]
        role = "draft-example-production-deploy"
        for action, changes in [
            ("upsertDraft", {"versionId": "production-v1", "files": self.package()}),
            ("publishDraft", {"versionId": "production-v1"}),
            ("reconcileCatalog", {}),
        ]:
            response = self.handler.lambda_handler(handler_fixtures.event({
                "action": action, "domain": self.domain, "environment": "production", **changes,
            }, role), handler_fixtures.Context())
            self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response)["catalogSync"]["status"], "applied")
        self.assertIn(("CATALOG#production", "SOURCE#DRAFT#example.com"), self.authoring.items)
        self.assertNotIn(("CATALOG#test", "SOURCE#DRAFT#example.com"), self.authoring.items)


if __name__ == "__main__":
    unittest.main()
