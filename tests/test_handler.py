import importlib
import json
import os
import unittest
from pathlib import Path


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
        os.environ["DEPLOY_AUTHZ_CONFIG_S3_KEY"] = "system/deploy-authz.json"
        self.authz_rules = [
            {
                "roleArn": role_arn("draft-pamela-test-deploy"),
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"],
            },
            {
                "roleArn": role_arn("draft-pamela-production-deploy"),
                "domains": ["pamelabetancourt.com"],
                "environments": ["production"],
                "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"],
            },
        ]
        self.handler = importlib.reload(importlib.import_module("lambda_function"))
        self.items = {}
        self.objects = {}

        def load_item(_table, pk, sk="METADATA"):
            return self.items.get((pk, sk))

        def put_item(_table, item):
            self.items[(item["pk"], item["sk"])] = item

        def put_json(_bucket, key, payload):
            self.objects[key] = payload

        self.handler.load_item = load_item
        self.handler.put_item = put_item
        self.handler.put_json_to_s3 = put_json
        self.handler.load_json_from_s3 = lambda _bucket, _key: self.authz_rules

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

    def test_rejects_publish_on_create_without_writing(self):
        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "test-v1",
            "publishOnCreate": True,
            "files": self.draft_files(),
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.items, {})
        self.assertEqual(self.objects, {})

    def test_inline_authorization_config_is_ignored_without_s3_key(self):
        os.environ.pop("DEPLOY_AUTHZ_CONFIG_S3_KEY", None)
        os.environ["DEPLOY_AUTHZ_CONFIG_JSON"] = json.dumps([
            {
                "roleArn": role_arn("draft-pamela-test-deploy"),
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "actions": ["upsertDraft"],
            }
        ])
        self.handler = importlib.reload(self.handler)

        rules = self.handler._load_deploy_authz_config()

        self.assertEqual(rules, [])

    def test_accepts_s3_authorization_config(self):
        os.environ["DEPLOY_AUTHZ_CONFIG_S3_KEY"] = "system/deploy-authz.json"
        self.handler = importlib.reload(self.handler)
        self.handler.load_json_from_s3 = lambda _bucket, _key: [
            {
                "roleArn": role_arn("draft-pamela-test-deploy"),
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "actions": ["upsertDraft"],
            }
        ]

        rules = self.handler._load_deploy_authz_config()

        self.assertEqual(rules[0]["roleArn"], role_arn("draft-pamela-test-deploy"))

    def test_deploy_contract_uses_only_s3_authorization_config(self):
        root = Path(__file__).resolve().parents[1]
        template = (root / "template.yaml").read_text(encoding="utf-8")
        deploy_surface = "\n".join(
            (root / path).read_text(encoding="utf-8")
            for path in ("lambda_function.py", "template.yaml")
        )

        self.assertNotIn("DeployAuthzConfigJson", deploy_surface)
        self.assertNotIn("DEPLOY_AUTHZ_CONFIG_JSON", deploy_surface)
        self.assertIn(
            "DeployAuthzConfigS3Key=system/deploy-authz.json",
            (root / "samconfig.toml").read_text(encoding="utf-8"),
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

    def test_authorization_requires_explicit_scope_or_wildcard(self):
        caller_arn = "arn:aws:sts::123456789012:assumed-role/draft-pamela-test-deploy/github-actions"
        complete_rule = {
            "roleArn": role_arn("draft-pamela-test-deploy"),
            "actions": ["upsertDraft"],
            "domains": ["pamelabetancourt.com"],
            "environments": ["test"],
        }

        for missing_scope in ("actions", "domains", "environments"):
            with self.subTest(missing_scope=missing_scope):
                rule = {key: value for key, value in complete_rule.items() if key != missing_scope}
                self.assertFalse(self.handler._rule_allows(
                    rule,
                    caller_arn,
                    "upsertDraft",
                    "pamelabetancourt.com",
                    "test",
                ))

        malformed_rule = {**complete_rule, "actions": "upsertDraft"}
        self.assertFalse(self.handler._rule_allows(
            malformed_rule,
            caller_arn,
            "upsertDraft",
            "pamelabetancourt.com",
            "test",
        ))

        wildcard_rule = {
            "roleArn": role_arn("draft-pamela-test-deploy"),
            "actions": ["*"],
            "domains": ["*"],
            "environments": ["*"],
        }
        self.assertTrue(self.handler._rule_allows(
            wildcard_rule,
            caller_arn,
            "upsertDraft",
            "pamelabetancourt.com",
            "test",
        ))

    def test_role_arn_authorization_preserves_the_account_boundary(self):
        rule = {
            "roleArn": "arn:aws:iam::123456789012:role/draft-pamela-test-deploy",
            "actions": ["upsertDraft"],
            "domains": ["pamelabetancourt.com"],
            "environments": ["test"],
        }

        self.assertFalse(self.handler._rule_allows(
            rule,
            "arn:aws:sts::999999999999:assumed-role/draft-pamela-test-deploy/github-actions",
            "upsertDraft",
            "pamelabetancourt.com",
            "test",
        ))
        self.assertTrue(self.handler._rule_allows(
            rule,
            "arn:aws:sts::123456789012:assumed-role/draft-pamela-test-deploy/github-actions",
            "upsertDraft",
            "pamelabetancourt.com",
            "test",
        ))

    def test_authorization_rejects_role_names_and_malformed_role_arns(self):
        rule = {
            "roleName": "draft-pamela-test-deploy",
            "actions": ["upsertDraft"],
            "domains": ["pamelabetancourt.com"],
            "environments": ["test"],
        }
        caller_arn = "arn:aws:sts::123456789012:assumed-role/draft-pamela-test-deploy/github-actions"

        self.assertFalse(self.handler._rule_allows(
            rule,
            caller_arn,
            "upsertDraft",
            "pamelabetancourt.com",
            "test",
        ))
        self.assertFalse(self.handler._rule_allows(
            {**rule, "roleArn": 123},
            caller_arn,
            "upsertDraft",
            "pamelabetancourt.com",
            "test",
        ))

    def test_domain_requires_a_canonical_hostname(self):
        self.authz_rules = [{
            "roleArn": role_arn("draft-pamela-test-deploy"),
            "actions": ["getSite"],
            "domains": ["*"],
            "environments": ["test"],
        }]
        invalid_domains = (
            "",
            ".",
            "..",
            "https://pamelabetancourt.com",
            "user@pamelabetancourt.com",
            "pamelabetancourt.com:443",
            "pamelabetancourt.com/path",
            "pamelabetancourt.com\\path",
            "pamelabetancourt..com",
            "-pamelabetancourt.com",
            "PAMELABETANCOURT.COM",
            "pamelabetancourt.com.",
            " pamelabetancourt.com",
            "pamelabetancourt.com ",
            "con.example.com",
        )

        for domain in invalid_domains:
            with self.subTest(domain=domain):
                response = self.handler.lambda_handler(event({
                    "action": "getSite",
                    "domain": domain,
                    "environment": "test",
                }, "draft-pamela-test-deploy"), Context())
                self.assertEqual(response["statusCode"], 400)

    def test_draft_paths_must_be_strict_domain_rooted_json_paths(self):
        invalid_paths = (
            "pamelabetancourt.com/../escape.json",
            "pamelabetancourt.com/./site-config.json",
            "pamelabetancourt.com//site-config.json",
            "/pamelabetancourt.com/site-config.json",
            "pamelabetancourt.com\\..\\escape.json",
            "pamelabetancourt.com/page:stream.json",
            "pamelabetancourt.com/\x00page.json",
            " pamelabetancourt.com/page.json",
            "pamelabetancourt.com/page.json ",
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
            "pamelabetancourt.com/not-json.txt",
            "pamelabetancourt.com/",
        )

        for path in invalid_paths:
            with self.subTest(path=path):
                self.items.clear()
                self.objects.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": "test-v1",
                    "files": [{"path": path, "content": {}}],
                }, "draft-pamela-test-deploy"), Context())

                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(self.items, {})
                self.assertEqual(self.objects, {})

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
                self.items.clear()
                self.objects.clear()
                response = self.handler.lambda_handler(event({
                    "action": "upsertDraft",
                    "domain": "pamelabetancourt.com",
                    "environment": "test",
                    "versionId": version_id,
                    "files": self.draft_files(),
                }, "draft-pamela-test-deploy"), Context())

                self.assertEqual(response["statusCode"], 400)
                self.assertEqual(self.items, {})
                self.assertEqual(self.objects, {})

    def test_upsert_does_not_mutate_public_alias_records(self):
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

    def test_invalid_alias_is_rejected_before_storage(self):
        files = self.draft_files()
        files[0]["content"]["environments"]["test"]["aliases"] = [
            "https://test.pamelabetancourt.com",
        ]

        response = self.handler.lambda_handler(event({
            "action": "upsertDraft",
            "domain": "pamelabetancourt.com",
            "environment": "test",
            "versionId": "test-v1",
            "files": files,
        }, "draft-pamela-test-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.items, {})
        self.assertEqual(self.objects, {})

    def test_test_role_cannot_publish_production(self):
        self.upsert()
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


if __name__ == "__main__":
    unittest.main()
