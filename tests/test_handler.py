import base64
import copy
import contextlib
import importlib
import hashlib
import io
import json
import os
import unittest
from pathlib import Path


SYNTHETIC_STRIPE_TEST_TOKEN = "sk_" + "test_SYNTHETIC1234"
SYNTHETIC_STRIPE_LIVE_TOKEN = "sk_" + "live_SYNTHETIC1234"


class Context:
    aws_request_id = "test-request"


def role_arn(role_name, account_id="123456789012"):
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def event(payload, role_name=None, account_id="123456789012"):
    request_context = {}
    if role_name:
        request_context = {
            "identity": {
                "userArn": f"arn:aws:sts::{account_id}:assumed-role/{role_name}/github-actions"
            }
        }
    return {
        "body": json.dumps(payload),
        "requestContext": request_context,
    }


def parse(response):
    return json.loads(response["body"])


class AuthoringHandlerTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("DEPLOY_AUTHZ_CONFIG_JSON", None)
        os.environ["DEPLOY_AUTHZ_CONFIG_S3_KEY"] = "system/deploy-authz-v2.json"
        os.environ["ENVIRONMENT_NAME"] = "test"
        self.test_authz_rule = {
            "roleArn": role_arn("draft-pamela-test-deploy"),
            "domains": ["pamelabetancourt.com"],
            "environments": ["test"],
            "tenantId": "tenant-example",
            "draftId": "draft-example",
            "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"],
        }
        self.production_authz_rule = {
            "roleArn": role_arn("draft-pamela-production-deploy"),
            "domains": ["pamelabetancourt.com"],
            "environments": ["production"],
            "tenantId": "tenant-example",
            "draftId": "draft-example",
            "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"],
        }
        self.authz_rules = [self.test_authz_rule]
        self.handler = importlib.reload(importlib.import_module("lambda_function"))
        self.items = {}
        self.objects = {}

        def load_item(_table, pk, sk="METADATA"):
            return self.items.get((pk, sk))

        def put_item(_table, item):
            self.items[(item["pk"], item["sk"])] = item

        def put_json(_bucket, key, payload):
            self.objects[key] = payload

        def list_json(_bucket, prefix):
            return sorted(key for key in self.objects if key.startswith(prefix) and key.endswith(".json"))

        def list_objects(_bucket, prefix):
            return sorted(key for key in self.objects if key.startswith(prefix))

        def load_json(_bucket, key):
            if key == "system/deploy-authz-v2.json":
                return self.authz_rules
            return self.objects.get(key)

        def put_item_if_revision(_table, item, expected_revision):
            current = self.items.get((item["pk"], item["sk"]))
            current_revision = int((current or {}).get("revision") or 0)
            if current_revision != expected_revision:
                raise self.handler.RevisionConflictError()
            self.items[(item["pk"], item["sk"])] = item

        self.handler.load_item = load_item
        self.handler.put_item = put_item
        self.handler.put_item_if_revision = put_item_if_revision
        self.handler.put_json_to_s3 = put_json
        self.handler.put_json_to_s3_if_absent = put_json
        self.handler.list_json_keys = list_json
        self.handler.list_object_keys = list_objects
        self.handler.load_json_from_s3 = load_json
        self.handler.describe_secret = lambda _secret_id: {}

    def draft_files(self):
        return [
            {
                "path": "pamelabetancourt.com/site-config.json",
                "content": {
                    "defaultPageId": "default",
                    "aliases": ["pamelabetancourt.com"],
                    "environments": {
                        "test": {
                            "aliases": [
                                "test.pamelabetancourt.com",
                                "test.pamelabetancourt.zoolandingpage.com.mx",
                            ]
                        }
                    },
                    "routes": [{"path": "/", "pageId": "default"}],
                },
            },
            {
                "path": "pamelabetancourt.com/default/page-config.json",
                "content": {"rootIds": []},
            },
        ]

    def active_notification_files(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/notification-policies.json"
        )
        notification = json.loads(fixture_path.read_text(encoding="utf-8"))
        notification["scope"]["domain"] = "pamelabetancourt.com"
        notification["policies"][0]["status"] = "active"
        binding_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/integration-bindings.json"
        )
        bindings = json.loads(binding_path.read_text(encoding="utf-8"))
        bindings["scope"]["domain"] = "pamelabetancourt.com"
        bindings["bindings"].append({
            "id": "smtp-primary",
            "provider": "email.smtp",
            "adapterVersion": "v1",
            "connectionId": "billing-mailbox",
            "status": "active",
            "mode": "test",
            "capabilities": ["send"],
        })
        return self.draft_files() + [
            {
                "path": "pamelabetancourt.com/server/integration-bindings.json",
                "content": bindings,
            },
            {
                "path": "pamelabetancourt.com/server/notification-policies.json",
                "content": notification,
            },
        ]

    def upsert(self, role_name="draft-pamela-test-deploy", version_id="v1", environment_name="test"):
        return self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": environment_name,
            "versionId": version_id,
            "files": self.draft_files(),
        }, role_name), Context())

    def test_rejects_unsigned_write(self):
        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "files": self.draft_files(),
        }), Context())

        self.assertEqual(response["statusCode"], 401)

    def test_inline_authorization_config_is_ignored_without_s3_key(self):
        os.environ.pop("DEPLOY_AUTHZ_CONFIG_S3_KEY", None)
        os.environ["DEPLOY_AUTHZ_CONFIG_JSON"] = json.dumps([
            {
                "roleArn": role_arn("draft-pamela-test-deploy"),
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "tenantId": "tenant-example",
                "draftId": "draft-example",
                "actions": ["upsertDraft"],
            }
        ])
        self.handler = importlib.reload(self.handler)

        rules = self.handler._load_deploy_authz_config()

        self.assertEqual(rules, [])

    def test_accepts_s3_authorization_config(self):
        os.environ["DEPLOY_AUTHZ_CONFIG_S3_KEY"] = "system/deploy-authz-v2.json"
        self.handler = importlib.reload(self.handler)
        self.handler.load_json_from_s3 = lambda _bucket, _key: [
            {
                "roleArn": role_arn("draft-pamela-test-deploy"),
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "tenantId": "tenant-example",
                "draftId": "draft-example",
                "actions": ["upsertDraft"],
            }
        ]

        rules = self.handler._load_deploy_authz_config()

        self.assertEqual(rules[0]["roleArn"], role_arn("draft-pamela-test-deploy"))

    def test_upsert_does_not_mutate_public_alias_metadata_or_records(self):
        response = self.upsert()
        body = parse(response)

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["updatedBy"], "draft-pamela-test-deploy")
        self.assertNotIn("aliases", metadata)
        self.assertNotIn("environmentAliases", metadata)
        self.assertFalse(any(pk.startswith("ALIAS#") for pk, _sk in self.items))

    def test_upsert_preserves_existing_public_alias_metadata(self):
        self.items[("SITE#pamelabetancourt.com", "METADATA")] = {
            "pk": "SITE#pamelabetancourt.com",
            "sk": "METADATA",
            "type": "site-metadata",
            "version": 1,
            "domain": "pamelabetancourt.com",
            "aliases": ["www.pamelabetancourt.com"],
            "environmentAliases": {"test": ["old-test.pamelabetancourt.com"]},
            "lifecycle": {"status": "active"},
        }

        response = self.upsert()

        self.assertEqual(response["statusCode"], 200)
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["aliases"], ["www.pamelabetancourt.com"])
        self.assertEqual(metadata["environmentAliases"], {"test": ["old-test.pamelabetancourt.com"]})

    def test_publish_on_create_is_rejected_before_storage(self):
        response = self.handler.lambda_handler(event({
            "action": "createSite",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "publishOnCreate": True,
            "files": self.draft_files(),
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.objects, {})
        self.assertEqual(self.items, {})

    def test_authorization_rules_require_every_scope(self):
        complete_rule = {
            "roleArn": role_arn("draft-pamela-test-deploy"),
            "domains": ["pamelabetancourt.com"],
            "environments": ["test"],
            "tenantId": "tenant-example",
            "draftId": "draft-example",
            "actions": ["upsertDraft"],
        }
        for missing_scope in ("roleArn", "actions", "domains", "environments", "tenantId", "draftId"):
            with self.subTest(missing_scope=missing_scope):
                self.authz_rules = [{
                    key: value for key, value in complete_rule.items() if key != missing_scope
                }]
                response = self.upsert()
                self.assertEqual(response["statusCode"], 401)

    def test_authorization_rejects_same_role_name_from_another_account(self):
        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "files": self.draft_files(),
        }, "draft-pamela-test-deploy", account_id="999999999999"), Context())

        self.assertEqual(response["statusCode"], 401)

    def test_authorization_rejects_ambiguous_matching_server_scopes(self):
        conflicting = copy.deepcopy(self.authz_rules[0])
        conflicting["tenantId"] = "conflicting-tenant"
        conflicting["draftId"] = "conflicting-draft"
        self.authz_rules.append(conflicting)

        response = self.upsert()

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(self.objects, {})
        self.assertEqual(self.items, {})

    def test_authorization_rejects_all_wildcards(self):
        self.authz_rules = [{
            "roleArn": role_arn("draft-pamela-test-deploy"),
            "domains": ["*"],
            "environments": ["*"],
            "tenantId": "tenant-example",
            "draftId": "draft-example",
            "actions": ["*"],
        }]

        response = self.upsert()

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(self.objects, {})
        self.assertEqual(self.items, {})

    def test_authorization_config_is_exact_and_one_invalid_rule_denies_all(self):
        valid = copy.deepcopy(self.test_authz_rule)
        scenarios = []

        extra = copy.deepcopy(valid)
        extra["roleName"] = "draft-pamela-test-deploy"
        scenarios.append([extra])

        plural_role = copy.deepcopy(valid)
        plural_role["roleArns"] = [plural_role.pop("roleArn")]
        scenarios.append([plural_role])

        for field, value in (
            ("actions", ["upsertDraft", "*"]),
            ("actions", ["upsertDraft", "deleteEverything"]),
            ("domains", ["pamelabetancourt.com", "other.example.com"]),
            ("environments", ["test", "production"]),
        ):
            malformed = copy.deepcopy(valid)
            malformed[field] = value
            scenarios.append([malformed])

        duplicate_role = copy.deepcopy(valid)
        duplicate_role["domains"] = ["other.example.com"]
        duplicate_role["draftId"] = "other-draft"
        scenarios.append([valid, duplicate_role])
        scenarios.append([valid, {"unexpected": True}])

        for index, rules in enumerate(scenarios):
            with self.subTest(index=index):
                self.objects.clear()
                self.items.clear()
                self.authz_rules = rules
                response = self.upsert()
                self.assertEqual(response["statusCode"], 401)
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_rejects_noncanonical_domain_forms(self):
        for domain in (
            "pamelabetancourt.com:443",
            "pamelabetancourt.com/",
            "PAMELABETANCOURT.COM",
            "pamelabetancourt.com.",
            " pamelabetancourt.com",
            "pamelabetancourt.com ",
            "con.example.com",
        ):
            with self.subTest(domain=domain):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": domain,
                    "environment": "test",
                    "files": self.draft_files(),
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_rejects_paths_that_are_not_strict_posix_json_children(self):
        invalid_paths = (
            "pamelabetancourt.com/../escape.json",
            "pamelabetancourt.com/./page.json",
            "pamelabetancourt.com//page.json",
            "pamelabetancourt.com\\page.json",
            "pamelabetancourt.com/page:stream.json",
            "pamelabetancourt.com/\x00page.json",
            "pamelabetancourt.com/page.txt",
            "/pamelabetancourt.com/page.json",
            "C:/pamelabetancourt.com/page.json",
            "pamelabetancourt.com/CON.json",
            "pamelabetancourt.com/COM¹.json",
            "pamelabetancourt.com/page?.json",
            "pamelabetancourt.com/page.json.",
            "pamelabetancourt.com/folder /page.json",
            "pamelabetancourt.com/\x7fpage.json",
            "pamelabetancourt.com/\u200bpage.json",
            "pamelabetancourt.com/cafe\u0301.json",
            "pamelabetancourt.com/ai_notes/private.json",
            "pamelabetancourt.com/AI_NOTES/private.json",
            "pamelabetancourt.com/Findings/private.json",
            "pamelabetancourt.com/draft-repo.config.json",
            "pamelabetancourt.com/DRAFT-REPO.CONFIG.JSON",
        )
        for path in invalid_paths:
            with self.subTest(path=path):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "files": [{"path": path, "content": {}}],
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_version_ids_must_be_canonical_before_storage(self):
        invalid_version_ids = (
            "",
            123,
            " version",
            "version ",
            "../version",
            "folder/version",
            "version\\child",
            "version:stream",
            "versión",
            "version\u200b",
            "v" * 129,
        )
        for version_id in invalid_version_ids:
            with self.subTest(version_id=version_id):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": version_id,
                    "files": self.draft_files(),
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_every_local_only_draft_tree_is_rejected_case_insensitively_before_storage(self):
        local_only_directories = (
            ".git",
            ".github",
            "_repos",
            "ai_notes",
            "findings",
            "errors-reports",
            "cvs_n_photos",
            "node_modules",
            "output",
            "reports",
            "logs",
            "devonly",
            ".superpowers",
            ".agent-coordination",
            "tools",
        )
        paths = [
            f"pamelabetancourt.com/{directory}/nested/config.json"
            for directory in local_only_directories
        ] + [
            f"pamelabetancourt.com/{directory.upper()}/nested/config.json"
            for directory in local_only_directories
        ] + [
            "pamelabetancourt.com/node%5fmodules/pkg/package.json",
            "pamelabetancourt.com/%2esuperpowers/private.json",
        ]

        for path in paths:
            with self.subTest(path=path):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                    "files": [{"path": path, "content": {}}],
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_dev_and_stack_environment_mismatch_are_rejected_before_writes(self):
        for request_environment in ("dev", "production"):
            with self.subTest(request_environment=request_environment):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": request_environment,
                    "versionId": "v1",
                    "files": self.draft_files(),
                }, "draft-pamela-production-deploy" if request_environment == "production" else "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

        self.handler.ENVIRONMENT_NAME = "prod"
        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "production",
            "versionId": "v1",
            "files": self.draft_files(),
        }, "draft-pamela-production-deploy"), Context())
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.objects, {})
        self.assertEqual(self.items, {})

    def test_server_descriptor_kinds_are_exact_and_untrusted_kinds_fail_closed(self):
        expected = {
            "auth-profile-registry.json": "server-auth-profile-registry",
            "integrations.json": "server-integrations",
            "data-spaces.json": "server-data-spaces",
            "commerce.json": "server-commerce",
            "integration-bindings.json": "server-integration-bindings",
            "notification-policies.json": "server-notification-policies",
        }
        for name, kind in expected.items():
            self.assertEqual(
                self.handler._infer_kind(f"pamelabetancourt.com/server/{name}"),
                kind,
            )
            self.assertIsNone(
                self.handler._infer_page_id("pamelabetancourt.com", f"pamelabetancourt.com/server/{name}")
            )
        with self.assertRaisesRegex(ValueError, "unknown_server_descriptor"):
            self.handler._infer_kind("pamelabetancourt.com/server/unknown.json")

        files = self.draft_files() + [{
            "path": "pamelabetancourt.com/server/integrations.json",
            "kind": "server-commerce",
            "content": {},
        }]
        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "kind_mismatch")
        self.assertEqual(self.objects, {})

    def test_duplicate_package_paths_are_rejected_before_writes(self):
        files = self.draft_files()
        files.append(dict(files[0]))
        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "duplicate_path")
        self.assertEqual(self.objects, {})

    def test_server_path_casing_or_nesting_cannot_bypass_server_validation(self):
        invalid_paths = (
            "pamelabetancourt.com/SERVER/integration-bindings.json",
            "pamelabetancourt.com/Server/integration-bindings.json",
            "pamelabetancourt.com/page/server/integration-bindings.json",
            "pamelabetancourt.com/server/nested/integration-bindings.json",
        )
        for path in invalid_paths:
            with self.subTest(path=path):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                    "files": [{"path": path, "content": {}}],
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(parse(response)["error"], "invalid_server_path")
                self.assertEqual(self.objects, {})

    def test_invalid_server_policy_is_rejected_and_redacted_before_s3_writes(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/integration-bindings.json"
        )
        integration = json.loads(fixture_path.read_text(encoding="utf-8"))
        sentinel = "private-provider-response-must-not-echo"
        integration["bindings"][0]["unexpected"] = sentinel
        files = self.draft_files() + [{
            "path": "pamelabetancourt.com/server/integration-bindings.json",
            "content": integration,
        }]
        integration["scope"]["domain"] = "pamelabetancourt.com"

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "server_policy_invalid")
        self.assertNotIn(sentinel, response["body"])
        self.assertEqual(self.objects, {})
        self.assertEqual(self.items, {})

    def test_legacy_server_descriptors_reject_secrets_pii_and_provider_resource_ids_before_writes(self):
        def synthetic_clabe(prefix="12345678901234567"):
            weights = (3, 7, 1)
            check = (10 - sum(int(digit) * weights[index % 3] for index, digit in enumerate(prefix)) % 10) % 10
            return prefix + str(check)

        valid_auth_profile = json.loads((
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/auth-profile-registry.json"
        ).read_text(encoding="utf-8"))
        valid_auth_profile["value"] = synthetic_clabe()
        scenarios = (
            (
                "integrations.json",
                {"version": 1, "apiKey": SYNTHETIC_STRIPE_TEST_TOKEN},
            ),
            (
                "auth-profile-registry.json",
                {"version": 1, "profile": {"email": "person@example.invalid"}},
            ),
            (
                "integrations.json",
                {"version": 1, "connectionId": "acct_syntheticresource"},
            ),
            (
                "integrations.json",
                {"version": 1, "url": "https://example.invalid/file?X-Amz-Signature=SYNTHETIC"},
            ),
            (
                "integrations.json",
                {"version": 1, SYNTHETIC_STRIPE_LIVE_TOKEN: "x"},
            ),
            (
                "integrations.json",
                {"version": 1, "nested": [{"smtpPassword": "SYNTHETIC_VALUE"}]},
            ),
            (
                "integrations.json",
                {"version": 1, "nested": {"stripeSecretKey": "SYNTHETIC_VALUE"}},
            ),
            (
                "integrations.json",
                {"version": 1, "nested": {"accessTokenValue": "SYNTHETIC_VALUE"}},
            ),
            (
                "integrations.json",
                {"version": 1, "nested": {"customerEmailAddress": "not-an-address"}},
            ),
            (
                "integrations.json",
                {"version": 1, "headers": {"Authorization": "Bearer SYNTHETIC_VALUE"}},
            ),
            (
                "integrations.json",
                {"version": 1, "headers": {"X-API-Key": "SYNTHETIC_VALUE"}},
            ),
            (
                "integrations.json",
                {"version": 1, "headers": {"Cookie": "session=SYNTHETIC_VALUE"}},
            ),
            (
                "integrations.json",
                {"version": 1, "credentialRef": "SYNTHETIC_NOT_A_REFERENCE"},
            ),
            (
                "integrations.json",
                {"version": 1, "value": synthetic_clabe()},
            ),
            (
                "auth-profile-registry.json",
                valid_auth_profile,
            ),
        )
        for field_name in (
            "clabe", "iban", "swift", "bic", "bankAccountNumber", "cardNumber",
            "paymentCard", "identityDocument", "governmentId", "webhookSigningKey",
            "webhookKey", "signingKey", "smtpPassphrase", "bearer",
        ):
            scenarios += ((
                "integrations.json",
                {"version": 1, "nested": {field_name: "SYNTHETIC_VALUE"}},
            ),)
        for file_name, content in scenarios:
            with self.subTest(file_name=file_name, content_key=next(iter(content))):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                    "files": self.draft_files() + [{
                        "path": f"pamelabetancourt.com/server/{file_name}",
                        "content": content,
                    }],
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(parse(response)["error"], "server_policy_invalid")
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_new_or_modified_legacy_descriptor_must_migrate_to_closed_server_feature_contract(self):
        files = self.draft_files() + [{
            "path": "pamelabetancourt.com/server/integrations.json",
            "content": {
                "version": 1,
                "sources": [{
                    "id": "catalog-source",
                    "credentialRef": "zoolanding/upstream/content/oauth",
                }],
            },
        }]

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "server_policy_invalid")
        self.assertEqual(self.objects, {})

    def test_legacy_auth_profiles_are_always_bound_to_authorized_tenant_and_domain(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/auth-profile-registry.json"
        )
        scenarios = []

        wrong_tenant = json.loads(fixture_path.read_text(encoding="utf-8"))
        wrong_tenant["profiles"][0]["tenantId"] = "other-tenant"
        scenarios.append(wrong_tenant)

        wrong_domain = json.loads(fixture_path.read_text(encoding="utf-8"))
        wrong_domain["profiles"][0]["domain"] = "other.example"
        scenarios.append(wrong_domain)

        one_of_many_wrong = json.loads(fixture_path.read_text(encoding="utf-8"))
        second_profile = dict(one_of_many_wrong["profiles"][0])
        second_profile["authProfileId"] = "other-profile"
        second_profile["tenantId"] = "other-tenant"
        one_of_many_wrong["profiles"].append(second_profile)
        scenarios.append(one_of_many_wrong)

        for key in (
            "smtpPassword", "customerEmailAddress", "Authorization", "clabe", "iban",
            "swift", "bic", "bankAccountNumber", "cardNumber", "paymentCard",
            "identityDocument", "governmentId", "webhookSigningKey", "webhookKey",
            "signingKey", "smtpPassphrase", "bearer",
        ):
            compound_sensitive_field = json.loads(fixture_path.read_text(encoding="utf-8"))
            compound_sensitive_field["profiles"][0][key] = "SYNTHETIC_VALUE"
            scenarios.append(compound_sensitive_field)

        for index, registry in enumerate(scenarios):
            with self.subTest(index=index):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                    "files": self.draft_files() + [{
                        "path": "pamelabetancourt.com/server/auth-profile-registry.json",
                        "content": registry,
                    }],
                }, "draft-pamela-test-deploy"), Context())

                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(parse(response)["error"], "server_policy_invalid")
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_new_legacy_auth_profile_is_rejected_even_when_secret_refs_are_opaque(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/auth-profile-registry.json"
        )
        for value, expected_status in (
            ("/zoolanding/auth/example/google", 400),
            ("zoolanding/auth/example/google", 400),
            ("arn:aws:ssm:us-east-1:123456789012:parameter/zoolanding/auth/example/google", 400),
            ("arn:aws:secretsmanager:us-east-1:123456789012:secret:zoolanding/auth/example/google-AbCd12", 400),
            ("raw-google-client-secret", 400),
            (f"/{SYNTHETIC_STRIPE_LIVE_TOKEN}", 400),
            ("https://example.com/file?X-Amz-Signature=SYNTHETIC", 400),
            ("https://example.com/not-a-secret-reference", 400),
            ("arn:aws:s3:::example-bucket/object", 400),
            ("C:/zoolanding/auth/example/google", 400),
            ("/zoolanding//auth/example/google", 400),
        ):
            with self.subTest(value=value, expected_status=expected_status):
                self.objects.clear()
                self.items.clear()
                registry = json.loads(fixture_path.read_text(encoding="utf-8"))
                registry["profiles"][0]["socialIdpSecretRefs"] = {
                    "google": {"clientSecret": value},
                }
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                    "files": self.draft_files() + [{
                        "path": "pamelabetancourt.com/server/auth-profile-registry.json",
                        "content": registry,
                    }],
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], expected_status)
                if expected_status == 400:
                    self.assertEqual(parse(response)["error"], "server_policy_invalid")
                    self.assertEqual(self.objects, {})
                    self.assertEqual(self.items, {})

    def test_auth_profile_social_idp_secret_reference_keys_are_constrained(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/auth-profile-registry.json"
        )
        for key in (
            "https://example.invalid/file?X-Amz-Signature=SYNTHETIC",
            SYNTHETIC_STRIPE_LIVE_TOKEN,
            "nested/key",
        ):
            with self.subTest(key=key):
                self.objects.clear()
                self.items.clear()
                registry = json.loads(fixture_path.read_text(encoding="utf-8"))
                registry["profiles"][0]["socialIdpSecretRefs"] = {
                    "google": {key: "/zoolanding/auth/example/google"},
                }
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                    "files": self.draft_files() + [{
                        "path": "pamelabetancourt.com/server/auth-profile-registry.json",
                        "content": registry,
                    }],
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(parse(response)["error"], "server_policy_invalid")
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_request_body_rejects_non_finite_numbers_and_cycles_before_writes(self):
        base_payload = {
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": self.draft_files(),
        }
        requests = []
        for token in ("NaN", "Infinity", "-Infinity"):
            payload = copy.deepcopy(base_payload)
            payload["files"][0]["content"]["synthetic"] = "NON_FINITE"
            request = event(payload, "draft-pamela-test-deploy")
            request["body"] = request["body"].replace('"NON_FINITE"', token)
            requests.append((token, request))

        dict_payload = copy.deepcopy(base_payload)
        dict_payload["files"][0]["content"]["synthetic"] = float("nan")
        dict_request = event({}, "draft-pamela-test-deploy")
        dict_request["body"] = dict_payload
        requests.append(("dict-nan", dict_request))

        cyclic_payload = copy.deepcopy(base_payload)
        cyclic_payload["files"][0]["content"]["cycle"] = cyclic_payload
        cyclic_request = event({}, "draft-pamela-test-deploy")
        cyclic_request["body"] = cyclic_payload
        requests.append(("dict-cycle", cyclic_request))

        invalid_base64_request = event(base_payload, "draft-pamela-test-deploy")
        invalid_base64_request["body"] = base64.b64encode(
            invalid_base64_request["body"].encode("utf-8")
        ).decode("ascii") + "!"
        invalid_base64_request["isBase64Encoded"] = True
        requests.append(("invalid-base64", invalid_base64_request))

        for name, request in requests:
            with self.subTest(name=name):
                self.objects.clear()
                self.items.clear()
                response = self.handler.lambda_handler(request, Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(parse(response)["error"], "invalid_request_body")
                self.assertEqual(self.objects, {})
                self.assertEqual(self.items, {})

    def test_server_policy_scope_must_match_server_owned_authorization_before_writes(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/integration-bindings.json"
        )
        integration = json.loads(fixture_path.read_text(encoding="utf-8"))
        integration["scope"]["domain"] = "pamelabetancourt.com"
        integration["scope"]["tenantId"] = "another-tenant"
        files = self.draft_files() + [{
            "path": "pamelabetancourt.com/server/integration-bindings.json",
            "content": integration,
        }]

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "server_policy_invalid")
        self.assertEqual(self.objects, {})
        self.assertEqual(self.items, {})

    def test_server_owned_scope_is_pinned_and_authz_changes_cannot_rebind_a_draft(self):
        first = self.upsert(version_id="v1")
        self.assertEqual(first["statusCode"], 200)
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["serverScope"], {
            "tenantId": "tenant-example",
            "draftId": "draft-example",
        })
        objects_before = copy.deepcopy(self.objects)
        metadata_before = copy.deepcopy(metadata)
        self.authz_rules[0]["tenantId"] = "replacement-tenant"
        self.authz_rules[0]["draftId"] = "replacement-draft"

        response = self.upsert(version_id="v2")

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "server_policy_invalid")
        self.assertEqual(self.objects, objects_before)
        self.assertEqual(
            self.items[("SITE#pamelabetancourt.com", "METADATA")],
            metadata_before,
        )

        publish = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
        }, "draft-pamela-test-deploy"), Context())
        self.assertEqual(publish["statusCode"], 400)
        self.assertEqual(parse(publish)["error"], "server_policy_invalid")
        self.assertEqual(
            self.items[("SITE#pamelabetancourt.com", "METADATA")],
            metadata_before,
        )

    def test_oversized_notification_preflight_is_rejected_before_storage_or_secret_calls(self):
        files = self.active_notification_files()
        notification = next(
            file["content"] for file in files if file["path"].endswith("notification-policies.json")
        )
        bindings = next(
            file["content"] for file in files if file["path"].endswith("integration-bindings.json")
        )
        first = notification["policies"][0]
        first["recipientSets"] = [
            {"id": f"primary-{index}", "version": 1, "members": [{"id": "member"}]}
            for index in range(10)
        ]
        second = copy.deepcopy(first)
        second["id"] = "billing-ops-secondary"
        second["connectionId"] = "billing-mailbox-secondary"
        second["recipientSets"] = [
            {"id": f"secondary-{index}", "version": 1, "members": [{"id": "member"}]}
            for index in range(10)
        ]
        notification["policies"].append(second)
        bindings["bindings"].append({
            "id": "smtp-secondary",
            "provider": "email.smtp",
            "adapterVersion": "v1",
            "connectionId": "billing-mailbox-secondary",
            "status": "active",
            "mode": "test",
            "capabilities": ["send"],
        })
        described = []
        self.handler.describe_secret = lambda secret_id: described.append(secret_id) or {}

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "server_policy_invalid")
        self.assertEqual(self.objects, {})
        self.assertEqual(self.items, {})
        self.assertEqual(described, [])

    def test_publish_revalidates_historical_package_against_current_authorized_scope(self):
        self.upsert(version_id="v1")
        prefix = "sites/pamelabetancourt.com/versions/v-scope/"
        integration_path = "pamelabetancourt.com/server/integration-bindings.json"
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/server-features/valid/example.com/server/integration-bindings.json"
        )
        integration = json.loads(fixture_path.read_text(encoding="utf-8"))
        integration["scope"]["domain"] = "pamelabetancourt.com"
        integration["scope"]["tenantId"] = "another-tenant"
        content_bytes = json.dumps(integration, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.objects[f"{prefix}{integration_path}"] = integration
        self.objects[f"{prefix}_manifest.json"] = {
            "version": 1,
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v-scope",
            "files": [{
                "path": integration_path,
                "kind": "server-integration-bindings",
                "sha256": hashlib.sha256(content_bytes).hexdigest(),
            }],
        }
        before = copy.deepcopy(self.items)
        described = []
        self.handler.describe_secret = lambda secret_id: described.append(secret_id) or {}

        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v-scope",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "stored_package_invalid")
        self.assertEqual(described, [])
        self.assertEqual(self.items, before)

    def test_version_packages_have_an_exact_hashed_manifest_and_are_immutable(self):
        response = self.upsert(version_id="v1")
        self.assertEqual(response["statusCode"], 200)
        prefix = "sites/pamelabetancourt.com/versions/v1/"
        manifest_key = f"{prefix}_manifest.json"
        self.assertIn(manifest_key, self.objects)
        manifest = self.objects[manifest_key]
        self.assertEqual(manifest["domain"], "pamelabetancourt.com")
        self.assertEqual(manifest["environment"], "test")
        self.assertEqual(manifest["versionId"], "v1")
        self.assertEqual([entry["path"] for entry in manifest["files"]], sorted(file["path"] for file in self.draft_files()))
        for entry in manifest["files"]:
            body = json.dumps(
                self.objects[f"{prefix}{entry['path']}"],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(entry["sha256"], hashlib.sha256(body).hexdigest())

        before = json.loads(json.dumps(self.objects))
        second = self.upsert(version_id="v1")
        self.assertEqual(second["statusCode"], 409)
        self.assertEqual(self.objects, before)

    def test_version_prefix_has_a_trailing_delimiter_and_excludes_v10(self):
        prefix = self.handler.default_version_prefix("pamelabetancourt.com", "v1")
        self.assertEqual(prefix, "sites/pamelabetancourt.com/versions/v1/")
        canonical_prefixes = {
            version_id: self.handler.default_version_prefix("pamelabetancourt.com", version_id)
            for version_id in ("v1", "v1-", "v1.", "v1_")
        }
        self.assertEqual(len(set(canonical_prefixes.values())), len(canonical_prefixes))
        for version_id, version_prefix in canonical_prefixes.items():
            self.assertEqual(version_prefix, f"sites/pamelabetancourt.com/versions/{version_id}/")
        self.objects[f"{prefix}pamelabetancourt.com/site-config.json"] = {"version": 1}
        self.objects["sites/pamelabetancourt.com/versions/v10/pamelabetancourt.com/site-config.json"] = {"version": 10}
        package = self.handler._load_package(
            "pamelabetancourt.com", "draft", "v1", prefix, {"domain": "pamelabetancourt.com"},
        )
        self.assertEqual(len(package["files"]), 1)
        self.assertEqual(package["files"][0]["content"], {"version": 1})

    def test_publish_reloads_and_revalidates_the_exact_stored_manifest(self):
        self.upsert(version_id="v1")
        key = "sites/pamelabetancourt.com/versions/v1/pamelabetancourt.com/site-config.json"
        self.objects[key]["tampered"] = True
        before = copy.deepcopy(self.items)

        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "stored_package_invalid")
        self.assertEqual(self.items, before)

    def test_get_site_verifies_manifest_hashes_and_exact_object_set(self):
        for scenario in ("tampered", "extra-object", "missing-manifest"):
            with self.subTest(scenario=scenario):
                self.objects.clear()
                self.items.clear()
                self.upsert(version_id="v1")
                prefix = "sites/pamelabetancourt.com/versions/v1/"
                if scenario == "tampered":
                    self.objects[f"{prefix}pamelabetancourt.com/site-config.json"]["tamperedByProbe"] = True
                elif scenario == "extra-object":
                    self.objects[f"{prefix}pamelabetancourt.com/extra.json"] = {"unexpected": True}
                else:
                    del self.objects[f"{prefix}_manifest.json"]

                response = self.handler.lambda_handler(event({
                    "action": "getSite",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "stage": "draft",
                }, "draft-pamela-test-deploy"), Context())

                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(parse(response)["error"], "stored_package_invalid")

    def test_get_site_returns_an_intact_manifest_package(self):
        self.upsert(version_id="v1")

        response = self.handler.lambda_handler(event({
            "action": "getSite",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "stage": "draft",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(parse(response)["versionId"], "v1")
        self.assertEqual(len(parse(response)["files"]), len(self.draft_files()))

    def test_publish_can_roll_back_to_an_immutable_version_without_s3_writes(self):
        self.upsert(version_id="v1")
        self.upsert(version_id="v2")
        objects_before_publish = json.loads(json.dumps(self.objects))
        for version_id in ("v2", "v1"):
            response = self.handler.lambda_handler(event({
                "action": "publishDraft",
                "domain": "pamelabetancourt.com",
                "environment": "test",
                "versionId": version_id,
            }, "draft-pamela-test-deploy"), Context())
            self.assertEqual(response["statusCode"], 200)
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["publishedEnvironments"]["test"]["versionId"], "v1")
        self.assertEqual(self.objects, objects_before_publish)

    def test_publish_pointer_uses_expected_revision_cas(self):
        self.upsert(version_id="v1")
        before = copy.deepcopy(self.items)

        def stale_write(_table, _item, _expected_revision):
            raise self.handler.RevisionConflictError()

        self.handler.put_item_if_revision = stale_write
        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 409)
        self.assertEqual(parse(response)["error"], "registry_revision_conflict")
        self.assertEqual(self.items, before)

    def test_draft_pointer_uses_expected_revision_cas(self):
        self.upsert(version_id="v1")
        before = copy.deepcopy(self.items)

        def stale_write(_table, _item, _expected_revision):
            raise self.handler.RevisionConflictError()

        self.handler.put_item_if_revision = stale_write
        response = self.upsert(version_id="v2")

        self.assertEqual(response["statusCode"], 409)
        self.assertEqual(parse(response)["error"], "registry_revision_conflict")
        self.assertEqual(self.items, before)
        self.assertEqual(
            self.items[("SITE#pamelabetancourt.com", "METADATA")]["draft"]["versionId"],
            "v1",
        )

    def test_status_updates_preserve_registry_cas(self):
        self.authz_rules[0]["actions"].append("setSiteStatus")
        self.upsert(version_id="v1")
        response = self.handler.lambda_handler(event({
            "action": "setSiteStatus",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "status": "maintenance",
        }, "draft-pamela-test-deploy"), Context())
        self.assertEqual(response["statusCode"], 200)

        before = copy.deepcopy(self.items)
        self.handler.put_item_if_revision = lambda *_args: (_ for _ in ()).throw(self.handler.RevisionConflictError())
        response = self.handler.lambda_handler(event({
            "action": "setSiteStatus",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "status": "active",
        }, "draft-pamela-test-deploy"), Context())
        self.assertEqual(response["statusCode"], 409)
        self.assertEqual(self.items, before)

    def test_invalid_notification_secret_states_prevent_pointer_movement_without_metadata_leaks(self):
        base_tags = {
            "zoolanding:environment": "test",
            "zoolanding:tenant-id": "tenant-example",
            "zoolanding:draft-id": "draft-example",
            "zoolanding:secret-purpose": "smtp",
            "zoolanding:enabled": "true",
            "zoolanding:connection-id": "billing-mailbox",
        }
        scenarios = {
            "missing": RuntimeError("provider-private-detail"),
            "disabled": {**base_tags, "zoolanding:enabled": "false"},
            "deleting": base_tags,
            "wrong-scope": {**base_tags, "zoolanding:tenant-id": "another-tenant"},
        }
        for name, value in scenarios.items():
            with self.subTest(name=name):
                self.objects.clear()
                self.items.clear()

                def describe(_secret_id, scenario=name, result=value):
                    if isinstance(result, Exception):
                        raise result
                    response = {"Tags": [{"Key": key, "Value": tag_value} for key, tag_value in result.items()]}
                    if scenario == "deleting":
                        response["DeletedDate"] = "synthetic"
                    return response

                self.handler.describe_secret = describe
                upsert = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                    "files": self.active_notification_files(),
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(upsert["statusCode"], 200)
                before = copy.deepcopy(self.items)
                response = self.handler.lambda_handler(event({
                    "action": "publishDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "v1",
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(parse(response)["error"], "notification_secret_unavailable")
                self.assertNotIn("provider-private-detail", response["body"])
                self.assertNotIn("/zoolanding/", response["body"])
                self.assertEqual(self.items, before)

    def test_valid_notification_secret_tags_allow_publish_with_deterministic_paths(self):
        described = []

        def describe(secret_id):
            described.append(secret_id)
            common = {
                "zoolanding:environment": "test",
                "zoolanding:tenant-id": "tenant-example",
                "zoolanding:draft-id": "draft-example",
                "zoolanding:enabled": "true",
            }
            if "/smtp/" in secret_id:
                tags = {
                    **common,
                    "zoolanding:secret-purpose": "smtp",
                    "zoolanding:connection-id": "billing-mailbox",
                }
            else:
                tags = {
                    **common,
                    "zoolanding:secret-purpose": "recipient",
                    "zoolanding:recipient-set-id": "billing-operators",
                    "zoolanding:recipient-set-version": "1",
                    "zoolanding:recipient-member-id": "primary",
                }
            return {"Tags": [{"Key": key, "Value": value} for key, value in tags.items()]}

        self.handler.describe_secret = describe
        self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
            "files": self.active_notification_files(),
        }, "draft-pamela-test-deploy"), Context())
        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "v1",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(described, [
            "/zoolanding/test/tenant-example/draft-example/notifications/smtp/billing-mailbox",
            "/zoolanding/test/tenant-example/draft-example/notifications/recipients/billing-operators/1/primary",
        ])

    def test_unexpected_exception_text_is_never_logged_or_returned(self):
        sentinel = "private-provider-exception-detail"
        original_load = self.handler.load_item
        self.handler.load_item = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(sentinel))
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                response = self.upsert()
        finally:
            self.handler.load_item = original_load

        self.assertEqual(response["statusCode"], 500)
        self.assertNotIn(sentinel, response["body"])
        self.assertNotIn(sentinel, output.getvalue())

    def test_untrusted_value_error_text_is_not_returned(self):
        sentinel = "private-policy-value-in-validation-error"
        original_load = self.handler.load_item
        self.handler.load_item = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(sentinel))
        try:
            response = self.upsert()
        finally:
            self.handler.load_item = original_load

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "invalid_request")
        self.assertNotIn(sentinel, response["body"])

    def test_deploy_contract_uses_only_s3_authorization_config(self):
        root = Path(__file__).resolve().parents[1]
        template = (root / "template.yaml").read_text(encoding="utf-8")
        deploy_surface = "\n".join(
            (root / path).read_text(encoding="utf-8")
            for path in (
                "lambda_function.py",
                "template.yaml",
                ".github/workflows/deploy-test.yml",
                ".github/workflows/deploy-production.yml",
            )
        )

        self.assertNotIn("DeployAuthzConfigJson", deploy_surface)
        self.assertNotIn("DEPLOY_AUTHZ_CONFIG_JSON_BASE64", deploy_surface)
        self.assertNotIn("DEPLOY_AUTHZ_CONFIG_JSON", deploy_surface)
        self.assertEqual(
            (root / "samconfig.toml").read_text(encoding="utf-8").count(
                "DeployAuthzConfigS3Key=system/deploy-authz-v2.json"
            ),
            2,
        )
        put_block_start = template.index("- s3:PutObject")
        put_block_end = template.find("- Effect: Allow", put_block_start + 1)
        put_block = template[put_block_start:put_block_end]
        self.assertIn("arn:aws:s3:::${ConfigPayloadsBucketName}/sites/*", put_block)
        self.assertNotIn("arn:aws:s3:::${ConfigPayloadsBucketName}/*", put_block)
        self.assertIn(
            "arn:aws:s3:::${ConfigPayloadsBucketName}/${DeployAuthzConfigS3Key}",
            template,
        )

    def test_template_grants_describe_only_for_derived_notification_secret_paths(self):
        root = Path(__file__).resolve().parents[1]
        template = (root / "template.yaml").read_text(encoding="utf-8")
        self.assertIn("- secretsmanager:DescribeSecret", template)
        self.assertNotIn("secretsmanager:GetSecretValue", template)
        self.assertNotIn("secretsmanager:ListSecrets", template)
        self.assertIn(
            "secret:/zoolanding/${EnvironmentName}/*/*/notifications/smtp/*-??????",
            template,
        )
        self.assertIn(
            "secret:/zoolanding/${EnvironmentName}/*/*/notifications/recipients/*/*/*-??????",
            template,
        )

    def test_aws_profiles_only_target_test_or_production(self):
        root = Path(__file__).resolve().parents[1]
        template = (root / "template.yaml").read_text(encoding="utf-8")
        samconfig = (root / "samconfig.toml").read_text(encoding="utf-8")
        self.assertIn("AllowedValues: [test, production]", template)
        self.assertNotIn("AllowedValues: [test, prod, production]", template)
        environment_parameter = template[template.index("  EnvironmentName:"):template.index("  ManageStorageResources:")]
        self.assertNotIn("Default: production", environment_parameter)
        self.assertNotIn("[default.deploy.parameters]", samconfig)
        self.assertIn("[test.deploy.parameters]", samconfig)
        self.assertIn("[prod.deploy.parameters]", samconfig)
        self.assertIn('"EnvironmentName=production"', samconfig)
        self.assertNotIn("[dev.deploy.parameters]", samconfig)

    def test_test_role_cannot_publish_production(self):
        self.upsert()
        self.handler.ENVIRONMENT_NAME = "production"
        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "production",
            "versionId": "v1",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 401)

    def test_publish_test_environment_does_not_replace_production_pointer(self):
        self.upsert(version_id="test-v1")
        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "test-v1",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 200)
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["publishedEnvironments"]["test"]["versionId"], "test-v1")
        self.assertNotIn("published", metadata)

    def test_publish_production_sets_legacy_and_environment_pointer(self):
        self.handler.ENVIRONMENT_NAME = "production"
        self.authz_rules = [self.production_authz_rule]
        self.upsert(role_name="draft-pamela-production-deploy", version_id="prod-v1", environment_name="production")
        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "production",
            "versionId": "prod-v1",
        }, "draft-pamela-production-deploy"), Context())

        self.assertEqual(response["statusCode"], 200)
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["published"]["versionId"], "prod-v1")
        self.assertEqual(metadata["publishedEnvironments"]["production"]["versionId"], "prod-v1")

    def test_content_hub_files_are_indexed_in_site_metadata(self):
        files = self.draft_files() + [
            {
                "path": "pamelabetancourt.com/content-hubs/main/hub.json",
                "content": {
                    "hubId": "main",
                    "name": "Blog",
                    "defaultLanguage": "es",
                    "canonicalDraftDomain": "pamelabetancourt.com",
                    "allowedDraftDomains": ["pamelabetancourt.com", "sulandingpage.com.mx"],
                },
            },
            {
                "path": "pamelabetancourt.com/content-hubs/main/articles/primer-post/metadata.json",
                "content": {
                    "articleId": "primer-post",
                    "title": "Primer post",
                    "status": "draft",
                },
            },
        ]

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "test-v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 200)
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["contentHubs"][0]["hubId"], "main")
        self.assertEqual(metadata["contentHubs"][0]["articleIds"], ["primer-post"])

    def test_content_hub_files_reject_server_only_fields(self):
        files = self.draft_files() + [
            {
                "path": "pamelabetancourt.com/content-hubs/main/articles/primer-post/metadata.json",
                "content": {
                    "articleId": "primer-post",
                    "clientSecret": "do-not-store",
                },
            },
        ]

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "test-v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "invalid_request")
        self.assertEqual(self.objects, {})

    def test_percent_encoded_paths_are_rejected_before_storage(self):
        files = self.draft_files()
        files[0]["path"] = "pamelabetancourt.com/%73ite-config.json"

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "encoded-path-v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.objects, {})

    def test_non_json_object_in_version_prefix_invalidates_exact_package(self):
        self.upsert(version_id="exact-object-set-v1")
        prefix = "sites/pamelabetancourt.com/versions/exact-object-set-v1/"
        self.objects[f"{prefix}unexpected.bin"] = {"unexpected": True}

        response = self.handler.lambda_handler(event({
            "action": "publishDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "exact-object-set-v1",
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(parse(response)["error"], "stored_package_invalid")
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertNotIn("publishedEnvironments", metadata)


if __name__ == "__main__":
    unittest.main()
