"""Isolated storage integration for an explicitly approved catalog source."""

import copy
import unittest
from decimal import Decimal
from unittest.mock import patch

import test_catalog_contract as catalog_fixtures
import test_handler as handler_fixtures


class CatalogProjectionTest(unittest.TestCase):
    def setUp(self):
        self.fixture = handler_fixtures.AuthoringHandlerTest(methodName="runTest")
        self.fixture.setUp()
        self.handler = self.fixture.handler
        self.handler.load_item_consistently = self.handler.load_item
        self.registration = {
            "sourceDomain": "example.com", "tenantId": "tenant-example",
            "draftId": "draft-example", "entryIds": ["guitarra", "gtr-lab"],
        }
        self.projection_key = ("CATALOG#test", "SOURCE#DRAFT#example.com")
        self.writes = []

        def put_if_newer(_table, item):
            key = (item["pk"], item["sk"])
            existing = self.fixture.items.get(key)
            if existing is not None and existing.get("sequence", 0) >= item["sequence"]:
                raise self.handler.RevisionConflictError()
            self.writes.append(copy.deepcopy(item))
            self.fixture.items[key] = copy.deepcopy(item)

        self.handler.put_catalog_projection_if_newer = put_if_newer

    def upsert(self, version, catalog):
        response = self.handler.lambda_handler(handler_fixtures.event({
            "action": "upsertDraft", "domain": "example.com", "environment": "test",
            "versionId": version, "files": catalog_fixtures.files(catalog),
        }, "draft-example-test-deploy"), handler_fixtures.Context())
        self.assertEqual(response["statusCode"], 200, response["body"])

    def publish(self, version):
        response = self.handler.lambda_handler(handler_fixtures.event({
            "action": "publishDraft", "domain": "example.com", "environment": "test", "versionId": version,
        }, "draft-example-test-deploy"), handler_fixtures.Context())
        self.assertEqual(response["statusCode"], 200, response["body"])

    def seed(self, version="catalog-v1", catalog=None):
        self.upsert(version, catalog if catalog is not None else {"entries": [catalog_fixtures.entry()]})
        self.publish(version)

    def project(self, registration=None):
        self.assertTrue(hasattr(self.handler, "_project_published_catalog"), "internal projector is missing")
        return self.handler._project_published_catalog(registration or self.registration, "test")

    def metadata(self):
        return self.fixture.items[("SITE#example.com", "METADATA")]

    def test_resolves_the_effective_published_version_not_the_newer_draft(self):
        self.seed()
        self.upsert("unpublished-v2", {"entries": [catalog_fixtures.entry(title="Unpublished draft")]})
        metadata_before = copy.deepcopy(self.metadata())
        objects_before = copy.deepcopy(self.fixture.objects)
        result = self.project()
        self.assertEqual(result["status"], "applied")
        document = self.fixture.items[self.projection_key]
        self.assertEqual(document["sourceId"], "draft:example.com")
        self.assertEqual(document["sourceDomain"], "example.com")
        self.assertEqual(document["catalogState"], "declared")
        self.assertEqual(document["versionId"], "catalog-v1")
        self.assertEqual(document["sequence"], 2)
        self.assertEqual(document["entries"], [catalog_fixtures.entry()])
        self.assertEqual(document["entriesSha256"], metadata_before["publishedEnvironments"]["test"]["catalogRevision"]["entriesSha256"])
        self.assertEqual(self.metadata(), metadata_before)
        self.assertEqual(self.fixture.objects, objects_before)
        self.assertNotIn("tenantId", document)
        self.assertNotIn("draftId", document)

    def test_identical_replay_does_not_write_or_increment_sequence(self):
        self.seed()
        self.assertEqual(self.project()["status"], "applied")
        before = copy.deepcopy(self.fixture.items)
        self.assertEqual(self.project()["status"], "noop")
        self.assertEqual(len(self.writes), 1)
        self.assertEqual(self.fixture.items, before)

    def test_immutable_rollback_is_a_new_monotonic_publication(self):
        self.seed()
        self.project()
        self.seed("catalog-v2", {"entries": [catalog_fixtures.entry(title="Second publication")]})
        self.project()
        self.publish("catalog-v1")
        self.assertEqual(self.project()["status"], "applied")
        self.assertEqual(self.fixture.items[self.projection_key]["versionId"], "catalog-v1")
        self.assertEqual([document["sequence"] for document in self.writes], [2, 4, 5])

    def test_declared_empty_entries_remain_an_explicit_retirement(self):
        self.seed(catalog={"entries": []})
        self.assertEqual(self.project()["status"], "applied")
        self.assertEqual(self.fixture.items[self.projection_key]["catalogState"], "declared")
        self.assertEqual(self.fixture.items[self.projection_key]["entries"], [])

    def test_legacy_source_does_not_participate_until_it_is_adopted(self):
        self.upsert("legacy-v1", catalog_fixtures.UNSET)
        self.publish("legacy-v1")
        self.assertEqual(self.project()["status"], "legacy")
        self.assertEqual(self.writes, [])
        self.assertNotIn(self.projection_key, self.fixture.items)

    def test_absent_catalog_after_adoption_removes_ghosts_and_allows_manual_fallback(self):
        self.seed()
        self.project()
        self.upsert("legacy-v2", catalog_fixtures.UNSET)
        self.publish("legacy-v2")
        self.assertEqual(self.project()["status"], "applied")
        document = self.fixture.items[self.projection_key]
        self.assertEqual(document["catalogState"], "legacy")
        self.assertEqual(document["entries"], [])
        self.assertEqual(document["sequence"], 4)
        self.assertEqual(document["versionId"], "legacy-v2")

    def test_registration_is_closed_and_does_not_grant_an_unapproved_entry_id(self):
        self.seed()
        self.assertTrue(hasattr(self.handler, "_project_published_catalog"), "internal projector is missing")
        for registration in [
            {**self.registration, "environment": "production"},
            {**self.registration, "entryIds": ["other"]},
            {**self.registration, "draftId": "other-draft"},
            {key: value for key, value in self.registration.items() if key != "tenantId"},
        ]:
            with self.subTest(registration=registration), self.assertRaises(ValueError):
                self.handler._project_published_catalog(registration, "test")
        self.assertEqual(self.writes, [])

    def test_invalid_pointer_snapshot_or_digest_fails_before_projection_write(self):
        self.seed()
        original = copy.deepcopy(self.metadata()["publishedEnvironments"]["test"])
        self.assertTrue(hasattr(self.handler, "_project_published_catalog"), "internal projector is missing")
        for changes in [
            {"entriesSha256": "0" * 64}, {"entryCount": 0}, {"schemaVersion": 2},
            {"sequence": 0}, {"sequence": True}, {"sequence": 999}, {"unexpected": True},
        ]:
            with self.subTest(changes=changes):
                pointer = copy.deepcopy(original)
                pointer["catalogRevision"].update(changes)
                self.metadata()["publishedEnvironments"]["test"] = pointer
                with self.assertRaises(ValueError):
                    self.project()
        self.metadata()["publishedEnvironments"]["test"] = {key: value for key, value in original.items() if key != "catalogRevision"}
        with self.assertRaises(ValueError):
            self.project()
        self.assertEqual(self.writes, [])

    def test_changed_source_at_final_read_keeps_the_projection_pending(self):
        self.seed()
        load = self.handler.load_item_consistently
        source_reads = 0

        def change_before_final_read(table, pk, sk="METADATA"):
            nonlocal source_reads
            if pk == "SITE#example.com":
                source_reads += 1
                if source_reads == 2:
                    self.seed("catalog-v2", {"entries": [catalog_fixtures.entry(title="New publication")]})
            return load(table, pk, sk)

        self.handler.load_item_consistently = change_before_final_read
        self.assertEqual(self.project()["status"], "source_changed")
        self.assertEqual(self.writes, [])
        self.handler.load_item_consistently = load
        self.assertEqual(self.project()["status"], "applied")
        self.assertEqual(self.fixture.items[self.projection_key]["versionId"], "catalog-v2")

    def test_publication_after_final_read_is_eventually_reconciled_without_claiming_atomicity(self):
        self.seed()
        write = self.handler.put_catalog_projection_if_newer

        def publish_at_write_boundary(table, item):
            self.seed("catalog-v2", {"entries": [catalog_fixtures.entry(title="New publication")]})
            write(table, item)

        self.handler.put_catalog_projection_if_newer = publish_at_write_boundary
        self.assertEqual(self.project()["status"], "applied")
        self.assertEqual(self.fixture.items[self.projection_key]["sequence"], 2)
        self.handler.put_catalog_projection_if_newer = write
        self.assertEqual(self.project()["status"], "applied")
        self.assertEqual(self.fixture.items[self.projection_key]["sequence"], 4)

    def test_newer_projection_wins_a_conditional_write_race(self):
        self.seed()
        write = self.handler.put_catalog_projection_if_newer

        def newer_writer_wins(table, item):
            newer = copy.deepcopy(item)
            newer["sequence"] += 2
            self.fixture.items[self.projection_key] = newer
            write(table, item)

        self.handler.put_catalog_projection_if_newer = newer_writer_wins
        self.assertEqual(self.project()["status"], "stale")
        self.assertEqual(self.fixture.items[self.projection_key]["sequence"], 4)
        self.assertEqual(self.writes, [])

    def test_same_sequence_with_different_contents_is_not_an_idempotent_replay(self):
        self.seed()
        self.project()
        self.fixture.items[self.projection_key]["entries"][0]["title"] = "Conflicting projection"
        with self.assertRaises(ValueError):
            self.project()
        self.assertEqual(len(self.writes), 1)

    def test_same_sequence_numeric_boolean_confusion_is_not_an_idempotent_replay(self):
        self.seed()
        self.project()
        original = copy.deepcopy(self.fixture.items[self.projection_key])
        for field in ["enabled", "schemaVersion"]:
            with self.subTest(field=field):
                corrupt = copy.deepcopy(original)
                if field == "enabled":
                    corrupt["entries"][0]["enabled"] = 1
                else:
                    corrupt["schemaVersion"] = True
                self.fixture.items[self.projection_key] = corrupt
                with self.assertRaises(ValueError):
                    self.project()

    def test_integral_dynamodb_decimals_preserve_idempotency(self):
        self.seed()
        self.project()
        document = self.fixture.items[self.projection_key]
        for key in ["schemaVersion", "sequence", "entryCount"]:
            document[key] = Decimal(document[key])
        self.assertEqual(self.project()["status"], "noop")
        self.assertEqual(len(self.writes), 1)

    def test_projection_failure_does_not_undo_a_successful_publish(self):
        self.seed()
        published_before = copy.deepcopy(self.metadata())
        with patch.object(self.handler, "put_catalog_projection_if_newer", side_effect=RuntimeError("isolated storage failure")):
            with self.assertRaises(RuntimeError):
                self.project()
        self.assertEqual(self.metadata(), published_before)
        self.assertNotIn(self.projection_key, self.fixture.items)

    def test_environment_scope_and_missing_test_pointer_cannot_import_production(self):
        self.seed()
        self.metadata()["published"] = copy.deepcopy(self.metadata()["publishedEnvironments"]["test"])
        self.metadata()["publishedEnvironments"] = {"production": copy.deepcopy(self.metadata()["published"])}
        self.assertEqual(self.project()["status"], "unpublished")
        self.assertEqual(self.writes, [])
        self.assertTrue(hasattr(self.handler, "_project_published_catalog"), "internal projector is missing")
        with self.assertRaises(ValueError):
            self.handler._project_published_catalog(self.registration, "production")


if __name__ == "__main__":
    unittest.main()
