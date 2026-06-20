import base64
import importlib
import json
import os
import unittest


class Context:
    aws_request_id = "test-request"


def event(payload, role_name=None):
    request_context = {}
    if role_name:
        request_context = {
            "identity": {
                "userArn": f"arn:aws:sts::123456789012:assumed-role/{role_name}/github-actions"
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
        os.environ.pop("DEPLOY_AUTHZ_CONFIG_S3_KEY", None)
        os.environ["DEPLOY_AUTHZ_CONFIG_JSON"] = json.dumps([
            {
                "roleName": "draft-pamela-test-deploy",
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"],
            },
            {
                "roleName": "draft-pamela-production-deploy",
                "domains": ["pamelabetancourt.com"],
                "environments": ["production"],
                "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"],
            },
            {
                "roleName": "draft-pamela-dev-deploy",
                "domains": ["pamelabetancourt.com"],
                "environments": ["dev"],
                "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"],
            },
        ])
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

    def test_accepts_base64_encoded_authorization_config(self):
        os.environ["DEPLOY_AUTHZ_CONFIG_JSON"] = base64.b64encode(json.dumps([
            {
                "roleName": "draft-pamela-test-deploy",
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "actions": ["upsertDraft"],
            }
        ]).encode("utf-8")).decode("ascii")
        self.handler = importlib.reload(self.handler)

        rules = self.handler._load_deploy_authz_config()

        self.assertEqual(rules[0]["roleName"], "draft-pamela-test-deploy")

    def test_accepts_s3_authorization_config(self):
        os.environ["DEPLOY_AUTHZ_CONFIG_S3_KEY"] = "system/deploy-authz.json"
        self.handler = importlib.reload(self.handler)
        self.handler.load_json_from_s3 = lambda _bucket, _key: [
            {
                "roleName": "draft-pamela-test-deploy",
                "domains": ["pamelabetancourt.com"],
                "environments": ["test"],
                "actions": ["upsertDraft"],
            }
        ]

        rules = self.handler._load_deploy_authz_config()

        self.assertEqual(rules[0]["roleName"], "draft-pamela-test-deploy")

    def test_upsert_stores_environment_alias_records(self):
        response = self.upsert()
        body = parse(response)

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        metadata = self.items[("SITE#pamelabetancourt.com", "METADATA")]
        self.assertEqual(metadata["updatedBy"], "draft-pamela-test-deploy")
        self.assertEqual(
            metadata["environmentAliases"]["test"],
            ["test.pamelabetancourt.com", "test.pamelabetancourt.zoolandingpage.com.mx"],
        )
        test_alias = self.items[("ALIAS#test.pamelabetancourt.com", "SITE")]
        self.assertEqual(test_alias["domain"], "pamelabetancourt.com")
        self.assertEqual(test_alias["environment"], "test")

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
            "environment": "dev",
            "versionId": "dev-v1",
            "files": files,
        }, "draft-pamela-dev-deploy"), Context())

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
            "environment": "dev",
            "versionId": "dev-v1",
            "files": files,
        }, "draft-pamela-dev-deploy"), Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertIn("server-only", parse(response)["error"])


if __name__ == "__main__":
    unittest.main()
