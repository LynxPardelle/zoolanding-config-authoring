"""Contract-first coverage for public project listings; all storage is isolated."""

import copy
import hashlib
import importlib
import json
import os
import unicodedata
import unittest
from unittest.mock import patch

import test_handler as handler_fixtures


DOMAIN = "example.com"
UNSET = object()


def entry(**changes):
    value = {
        "entryId": "guitarra",
        "kind": "website",
        "path": "/guitarra",
        "title": "Clases de guitarra eléctrica 🎸",
        "description": "Práctica guiada de guitarra para principiantes e intermedios.",
        "imageUrl": "https://example.com/images/guitarra.jpg",
        "imageAlt": "Guitarra acústica y guitarra eléctrica.",
        "enabled": True,
    }
    value.update(changes)
    return value


def files(catalog=UNSET, routes=None):
    site = {
        "version": 1,
        "domain": DOMAIN,
        "defaultPageId": "default",
        "routes": routes if routes is not None else [
            {"path": "/", "pageId": "default"},
            {"path": "/guitarra", "pageId": "guitar"},
            {"path": "/gtr-lab", "pageId": "gtr"},
            {"path": "/cuenta", "pageId": "account", "auth": {"required": True}},
        ],
        "site": {"seo": {"canonicalOrigin": "https://example.com"}},
    }
    if catalog is not UNSET:
        site["catalog"] = catalog
    return [
        {"path": f"{DOMAIN}/site-config.json", "content": site},
        {"path": f"{DOMAIN}/default/page-config.json", "content": {"rootIds": []}},
    ]


class CatalogContractTest(unittest.TestCase):
    def setUp(self):
        with patch.dict(os.environ, {"ENVIRONMENT_NAME": "test"}):
            self.handler = importlib.reload(importlib.import_module("lambda_function"))

    def normalize(self, package):
        return self.handler._normalize_files(DOMAIN, "test", copy.deepcopy(package))

    def assert_invalid(self, catalog, routes=None):
        with self.assertRaises(ValueError):
            self.normalize(files(catalog, routes=routes))

    def test_existing_packages_without_catalog_remain_unchanged(self):
        package = files()
        normalized = self.normalize(package)
        self.assertEqual(normalized[0]["content"], package[0]["content"])
        self.assertNotIn("catalog", normalized[0]["content"])

    def test_valid_website_app_and_retirement_preserve_declared_public_fields(self):
        for record in [
            entry(),
            entry(entryId="gtr-lab", kind="app", path="/gtr-lab", category="music-apps", builtWith="zoolandingpage"),
            entry(enabled=False),
            entry(imageUrl="https://assets.zoolandingpage.com.mx/example.com/cover.webp"),
            entry(imageUrl="https://EXAMPLE.COM/images/guitarra.jpg", builtWith="zoositioweb"),
        ]:
            with self.subTest(record=record["entryId"], enabled=record["enabled"], image=record["imageUrl"]):
                catalog = {"entries": [record]}
                self.assertEqual(self.normalize(files(catalog))[0]["content"]["catalog"], catalog)
        self.assertEqual(self.normalize(files({"entries": []}))[0]["content"]["catalog"], {"entries": []})

    def test_root_and_literal_safe_ascii_paths_are_valid_when_registered(self):
        for path in ["/", "/Guitar_Lab/v1.0/~practice"]:
            with self.subTest(path=path):
                catalog = {"entries": [entry(path=path)]}
                normalized = self.normalize(files(catalog, routes=[{"path": path, "pageId": "default"}]))
                self.assertEqual(normalized[0]["content"]["catalog"], catalog)

    def test_catalog_validation_does_not_fetch_images_or_other_remote_resources(self):
        with patch("socket.socket.connect", side_effect=AssertionError("Catalog validation must stay offline")):
            self.assertEqual(len(self.normalize(files({"entries": [entry()]}))), 2)

    def test_catalog_is_a_closed_object_with_required_array(self):
        for invalid in [None, False, [], "catalog", {}, {"entries": None}, {"entries": {}},
                        {"entries": [entry()], "version": 1}, {"entries": [], "environment": "production"}]:
            with self.subTest(catalog=invalid):
                self.assert_invalid(invalid)

    def test_entries_are_closed_and_required_fields_cannot_be_omitted(self):
        for required in entry():
            incomplete = entry()
            del incomplete[required]
            with self.subTest(missing=required):
                self.assert_invalid({"entries": [incomplete]})
        for unknown in ["domain", "environment", "roleArn", "versionId", "url", "sourceDraft"]:
            with self.subTest(unknown=unknown):
                self.assert_invalid({"entries": [entry(**{unknown: "synthetic-unapproved-value"})]})
        for invalid in [None, False, [], "entry"]:
            with self.subTest(entry=invalid):
                self.assert_invalid({"entries": [invalid]})

    def test_kind_and_enabled_are_exact_types(self):
        for invalid in [None, "Website", "site", "landingpage", "product", {}, 1]:
            with self.subTest(kind=invalid):
                self.assert_invalid({"entries": [entry(kind=invalid)]})
        for invalid in [None, 0, 1, "true", "false", []]:
            with self.subTest(enabled=invalid):
                self.assert_invalid({"entries": [entry(enabled=invalid)]})

    def test_entry_and_category_use_canonical_slugs(self):
        for field in ["entryId", "category"]:
            for invalid in ["", "UpperCase", "with space", "with_underscore", "with.dot", "-start", "end-", "a--b", 1, None]:
                with self.subTest(field=field, value=invalid):
                    self.assert_invalid({"entries": [entry(**{field: invalid})]})
        for invalid in [None, 1, [], {}, "<b>Platform</b>", "roadmap2u", "ZooLandingPage"]:
            with self.subTest(builtWith=invalid):
                self.assert_invalid({"entries": [entry(builtWith=invalid)]})

    def test_public_field_lengths_accept_the_limit_and_reject_overflow(self):
        for field, limit, character in [
            ("entryId", 64, "g"), ("category", 48, "c"), ("title", 100, "T"),
            ("description", 320, "D"), ("imageAlt", 200, "A"),
        ]:
            with self.subTest(field=field):
                at_limit = entry(**{field: character * limit})
                self.assertEqual(self.normalize(files({"entries": [at_limit]}))[0]["content"]["catalog"]["entries"][0][field], character * limit)
                self.assert_invalid({"entries": [entry(**{field: character * (limit + 1)})]})
        for length in [256, 257]:
            path = "/" + "p" * (length - 1)
            package = files({"entries": [entry(path=path)]}, routes=[{"path": path, "pageId": "default"}])
            if length == 256:
                self.assertEqual(self.normalize(package)[0]["content"]["catalog"]["entries"][0]["path"], path)
            else:
                with self.assertRaises(ValueError):
                    self.normalize(package)
        prefix = "https://example.com/"
        valid_url = prefix + "i" * (1024 - len(prefix))
        self.assertEqual(self.normalize(files({"entries": [entry(imageUrl=valid_url)]}))[0]["content"]["catalog"]["entries"][0]["imageUrl"], valid_url)
        self.assert_invalid({"entries": [entry(imageUrl=valid_url + "i")]})

    def test_entry_count_is_bounded_and_ids_and_paths_are_unique_even_when_disabled(self):
        routes = [{"path": f"/entry-{n}", "pageId": f"entry-{n}"} for n in range(33)]
        records = [entry(entryId=f"entry-{n}", path=f"/entry-{n}") for n in range(33)]
        self.assertEqual(len(self.normalize(files({"entries": records[:32]}, routes=routes))[0]["content"]["catalog"]["entries"]), 32)
        self.assert_invalid({"entries": records}, routes=routes)
        self.assert_invalid({"entries": [entry(), entry(path="/gtr-lab")]})
        self.assert_invalid({"entries": [entry(), entry(entryId="other", enabled=False)]})

    def test_paths_are_exact_canonical_static_paths(self):
        for path in ["", "guitarra", "/guitarra/", "/guitarra//", "//example.com/guitarra", "https://example.com/guitarra",
                     "/./guitarra", "/other/../guitarra", "/%67uitarra", "/guitarra?q=1", "/guitarra#top",
                     "/:slug", "/guitarra/*", "/guitarra\\practice", "/guitarrá", "/guitarra\n"]:
            with self.subTest(path=path):
                self.assert_invalid({"entries": [entry(path=path)]}, routes=[{"path": path, "pageId": "guitar"}])

    def test_unregistered_private_and_redirect_source_routes_cannot_be_listed(self):
        self.assert_invalid({"entries": [entry(path="/missing")]})
        self.assert_invalid({"entries": [entry(path="/cuenta")]})
        package = files({"entries": [entry()]})
        package[0]["content"]["site"]["seo"]["redirects"] = [{"from": "/guitarra", "to": "/gtr-lab"}]
        with self.assertRaises(ValueError):
            self.normalize(package)
        public_routes = [{"path": "/guitarra", "pageId": "guitar", "auth": {"required": False}}]
        self.assertEqual(len(self.normalize(files({"entries": [entry()]}, routes=public_routes))), 2)

    def test_normalized_private_shadows_and_redirect_sources_do_not_make_public_listings(self):
        for private_path in ["/guitarra/", "//guitarra", "/%67uitarra", "\\guitarra"]:
            with self.subTest(private_path=private_path):
                routes = [{"path": private_path, "pageId": "private", "auth": {"required": True}}, {"path": "/guitarra", "pageId": "guitar"}]
                self.assert_invalid({"entries": [entry()]}, routes=routes)
        for path, source in [("/guitarra", "/guitarra/"), ("/", "/")]:
            with self.subTest(path=path, source=source):
                package = files({"entries": [entry(path=path)]})
                package[0]["content"]["site"]["seo"]["redirects"] = [{"from": source, "to": "/gtr-lab"}]
                with self.assertRaises(ValueError):
                    self.normalize(package)

    def test_image_url_is_public_https_on_canonical_or_approved_asset_host(self):
        for image in ["http://example.com/image.jpg", "//example.com/image.jpg", "/image.jpg",
                      "https://other.example/image.jpg", "https://sub.example.com/image.jpg",
                      "https://user@example.com/image.jpg", "https://user:pass@example.com/image.jpg",
                      "https://example.com:443/image.jpg", "https://example.com/image.jpg?q=1",
                      "https://example.com/image.jpg#cover", "https://example.com/image.jpg?",
                      "https://example.com/image.jpg#", "https://example.com./image.jpg",
                      "https://example.com\\@other.example/image.jpg", " https://example.com/image.jpg",
                      "https://example.com/image.jpg\n", "https://example.com/hidden\u202eimage.jpg",
                      "https://example.com/surrogate\ud800image.jpg", "data:image/png;base64,synthetic", None, 1]:
            with self.subTest(image=image):
                self.assert_invalid({"entries": [entry(imageUrl=image)]})

    def test_authored_aliases_and_canonical_origin_cannot_expand_approved_image_hosts(self):
        package = files({"entries": [entry(imageUrl="https://other.example/image.jpg")]})
        site = package[0]["content"]
        site["domain"] = "other.example"
        site["aliases"] = ["other.example"]
        site["site"]["seo"]["canonicalOrigin"] = "https://other.example"
        with self.assertRaises(ValueError):
            self.normalize(package)

    def test_friendly_text_is_trimmed_nfc_without_html_or_control_characters(self):
        for field in ["title", "description", "imageAlt"]:
            for text in ["", " leading", "trailing ", "<b>markup</b>", "line\nbreak", "tab\ttext",
                         "control\x00text", "control\x7ftext", "bidi\u202etext", unicodedata.normalize("NFD", "Práctica"), None, 1]:
                with self.subTest(field=field, text=text):
                    self.assert_invalid({"entries": [entry(**{field: text})]})
        self.assertEqual(self.normalize(files({"entries": [entry(title="🎸" * 100)]}))[0]["content"]["catalog"]["entries"][0]["title"], "🎸" * 100)

    def test_handler_rejects_invalid_catalog_with_a_generic_non_echoing_error_before_writes(self):
        invalid_kind = "synthetic-unapproved-kind"
        payload = {"action": "upsertDraft", "domain": DOMAIN, "environment": "test", "versionId": "catalog-error-test",
                   "files": files({"entries": [entry(kind=invalid_kind)]})}
        with patch.object(self.handler, "_authorize_request", return_value=(True, "synthetic-test-role", {"tenantId": "tenant-example", "draftId": "draft-example"})), \
             patch.object(self.handler, "_store_files") as s3_write, \
             patch.object(self.handler, "_save_registry_conditionally") as registry_write:
            response = self.handler.lambda_handler({"body": json.dumps(payload)}, None)
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(json.loads(response["body"])["error"], "invalid_catalog")
        self.assertNotIn(invalid_kind, response["body"])
        s3_write.assert_not_called()
        registry_write.assert_not_called()

    def test_invalid_catalog_rejects_upsert_before_any_storage_write(self):
        payload = {
            "action": "upsertDraft", "domain": DOMAIN, "environment": "test", "versionId": "catalog-contract-test",
            "_authorizedServerScope": {"tenantId": "tenant-example", "draftId": "draft-example"},
            "files": files({"entries": [entry(kind="unapproved")]}),
        }
        with patch.object(self.handler, "_load_registry", return_value=None), \
             patch.object(self.handler, "_store_files") as s3_write, \
             patch.object(self.handler, "_save_registry_conditionally") as registry_write:
            with self.assertRaises(ValueError):
                self.handler._create_or_replace_draft(payload, "catalog-contract-test")
            s3_write.assert_not_called()
            registry_write.assert_not_called()

    def test_stored_packages_are_revalidated_before_publishing(self):
        invalid_package = files({"entries": [entry(kind="unapproved")]})
        with patch.object(self.handler, "_load_integrity_checked_stored_files", return_value=("synthetic-prefix", invalid_package)):
            with self.assertRaises(self.handler.StoredPackageError):
                self.handler._load_validated_stored_files(DOMAIN, "test", "catalog-contract-test")


class CatalogPublicationTest(unittest.TestCase):
    def setUp(self):
        self.fixture = handler_fixtures.AuthoringHandlerTest(methodName="runTest")
        self.fixture.setUp()
        self.handler = self.fixture.handler
        self.environment = "test"
        self.role = "draft-example-test-deploy"

    def upsert(self, version_id, package):
        response = self.handler.lambda_handler(handler_fixtures.event({
            "action": "upsertDraft", "domain": DOMAIN, "environment": self.environment,
            "versionId": version_id, "files": package,
        }, self.role), handler_fixtures.Context())
        self.assertEqual(response["statusCode"], 200, response["body"])

    def publish(self, version_id, **changes):
        payload = {"action": "publishDraft", "domain": DOMAIN, "environment": self.environment,
                   "versionId": version_id}
        payload.update(changes)
        return self.handler.lambda_handler(handler_fixtures.event(payload, self.role), handler_fixtures.Context())

    def metadata(self):
        return self.fixture.items[(f"SITE#{DOMAIN}", "METADATA")]

    def test_publication_binds_exact_stored_entries_to_the_same_conditional_pointer_write(self):
        stored_entries = [entry(), entry(entryId="gtr-lab", kind="app", path="/gtr-lab", enabled=False)]
        self.upsert("catalog-v1", files({"entries": stored_entries}))
        self.upsert("catalog-v2", files({"entries": [entry(title="A newer unpublished title")]}))
        revision = self.metadata()["revision"]
        objects_before = copy.deepcopy(self.fixture.objects)
        with patch.object(self.handler, "put_item_if_revision", wraps=self.handler.put_item_if_revision) as conditional_write, \
             patch.object(self.handler, "put_item") as unconditional_write:
            response = self.publish("catalog-v1", catalog={"entries": []}, catalogRevision={"sequence": 999})
        self.assertEqual(response["statusCode"], 200, response["body"])
        pointer = handler_fixtures.parse(response)["published"]
        canonical = json.dumps(stored_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(pointer.get("catalogRevision"), {
            "schemaVersion": 1, "sequence": revision + 1,
            "entriesSha256": hashlib.sha256(canonical).hexdigest(), "entryCount": 2,
        })
        self.assertEqual(pointer["versionId"], "catalog-v1")
        self.assertEqual(pointer["prefix"], self.handler.default_version_prefix(DOMAIN, "catalog-v1"))
        self.assertEqual(self.metadata()["publishedEnvironments"]["test"], pointer)
        self.assertEqual(self.metadata()["revision"], revision + 1)
        self.assertNotIn("entries", pointer)
        self.assertNotIn("catalog", pointer)
        conditional_write.assert_called_once()
        self.assertEqual(conditional_write.call_args.args[2], revision)
        self.assertEqual(conditional_write.call_args.args[1]["publishedEnvironments"]["test"], pointer)
        unconditional_write.assert_not_called()
        self.assertEqual(self.fixture.objects, objects_before)

    def test_digest_ignores_object_key_order_but_binds_entries_array_order(self):
        records = [entry(), entry(entryId="gtr-lab", kind="app", path="/gtr-lab")]
        reversed_keys = [dict(reversed(list(record.items()))) for record in records]
        digests = []
        sequences = []
        for version_id, entries in [("ordered-v1", records), ("ordered-v2", reversed_keys), ("ordered-v3", list(reversed(records)))]:
            self.upsert(version_id, files({"entries": entries}))
            response = self.publish(version_id)
            self.assertEqual(response["statusCode"], 200, response["body"])
            snapshot = handler_fixtures.parse(response)["published"].get("catalogRevision")
            self.assertIsNotNone(snapshot)
            digests.append(snapshot["entriesSha256"])
            sequences.append(snapshot["sequence"])
        self.assertEqual(digests[0], digests[1])
        self.assertNotEqual(digests[1], digests[2])
        self.assertEqual(sequences, [2, 4, 6])

    def test_empty_entries_records_an_explicit_retirement_snapshot(self):
        self.upsert("withdrawal-v1", files({"entries": []}))
        response = self.publish("withdrawal-v1")
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response)["published"].get("catalogRevision"), {
            "schemaVersion": 1, "sequence": 2,
            "entriesSha256": hashlib.sha256(b"[]").hexdigest(), "entryCount": 0,
        })

    def test_absent_catalog_preserves_legacy_pointer_shape_and_removes_prior_participation(self):
        self.upsert("catalog-v1", files({"entries": [entry()]}))
        self.assertEqual(self.publish("catalog-v1")["statusCode"], 200)
        self.upsert("legacy-v2", files())
        with patch.object(self.handler, "now_iso", return_value="2026-11-19T10:00:00Z"):
            response = self.publish("legacy-v2")
        expected = {
            "versionId": "legacy-v2", "prefix": self.handler.default_version_prefix(DOMAIN, "legacy-v2"),
            "manifestVersion": 1, "updatedAt": "2026-11-19T10:00:00Z",
            "updatedBy": self.role,
        }
        self.assertEqual(response["statusCode"], 200, response["body"])
        self.assertEqual(handler_fixtures.parse(response)["published"], expected)
        self.assertEqual(self.metadata()["publishedEnvironments"]["test"], expected)
        self.assertNotIn("published", self.metadata())

    def test_revision_conflict_does_not_leave_a_catalog_snapshot_or_move_any_pointer(self):
        self.upsert("catalog-v1", files({"entries": [entry()]}))
        before = copy.deepcopy(self.fixture.items)
        objects_before = copy.deepcopy(self.fixture.objects)
        with patch.object(self.handler, "put_item_if_revision", side_effect=self.handler.RevisionConflictError()) as conditional_write:
            response = self.publish("catalog-v1")
        self.assertEqual(response["statusCode"], 409)
        self.assertEqual(handler_fixtures.parse(response)["error"], "registry_revision_conflict")
        conditional_write.assert_called_once()
        candidate_pointer = conditional_write.call_args.args[1]["publishedEnvironments"]["test"]
        self.assertIsNotNone(candidate_pointer.get("catalogRevision"))
        self.assertEqual(self.fixture.items, before)
        self.assertEqual(self.fixture.objects, objects_before)

    def test_test_publication_preserves_production_catalog_snapshot_and_legacy_pointer(self):
        self.handler.ENVIRONMENT_NAME = "production"
        self.fixture.authz_rules = [self.fixture.production_authz_rule]
        self.environment = "production"
        self.role = "draft-example-production-deploy"
        self.upsert("production-v1", files({"entries": [entry()]}))
        response = self.publish("production-v1")
        self.assertEqual(response["statusCode"], 200, response["body"])
        production_pointer = copy.deepcopy(self.metadata()["published"])
        self.assertIsNotNone(production_pointer.get("catalogRevision"))
        self.assertEqual(self.metadata()["publishedEnvironments"]["production"], production_pointer)
        self.handler.ENVIRONMENT_NAME = "test"
        self.fixture.authz_rules = [self.fixture.test_authz_rule]
        self.environment = "test"
        self.role = "draft-example-test-deploy"
        self.upsert("test-v2", files({"entries": []}))
        response = self.publish("test-v2")
        self.assertEqual(response["statusCode"], 200, response["body"])
        test_pointer = handler_fixtures.parse(response)["published"]
        self.assertEqual(test_pointer.get("catalogRevision", {}).get("entryCount"), 0)
        self.assertEqual(self.metadata()["publishedEnvironments"]["test"], test_pointer)
        self.assertEqual(self.metadata()["published"], production_pointer)
        self.assertEqual(self.metadata()["publishedEnvironments"]["production"], production_pointer)

    def test_checksum_valid_invalid_catalog_cannot_move_a_pointer(self):
        self.upsert("legacy-v1", files())
        self.fixture.seed_stored_package("invalid-catalog-v2", files({"entries": [entry(kind="unapproved")]}))
        before = copy.deepcopy(self.fixture.items)
        objects_before = copy.deepcopy(self.fixture.objects)
        with patch.object(self.handler, "put_item_if_revision", wraps=self.handler.put_item_if_revision) as conditional_write:
            response = self.publish("invalid-catalog-v2")
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(handler_fixtures.parse(response)["error"], "stored_package_invalid")
        conditional_write.assert_not_called()
        self.assertEqual(self.fixture.items, before)
        self.assertEqual(self.fixture.objects, objects_before)


if __name__ == "__main__":
    unittest.main()
