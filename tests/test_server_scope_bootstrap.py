import hashlib
import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import bootstrap_server_scopes as bootstrap


def registry(*entries):
    return {
        "version": 1,
        "owner": "LynxPardelle",
        "drafts": list(entries),
    }


def draft(domain, repo):
    return {
        "domain": domain,
        "repo": repo,
        "githubUrl": f"https://github.com/LynxPardelle/{repo}.git",
        "localPath": f"drafts/{domain}",
    }


def binding(domain, repo, environment):
    suffix = "test" if environment == "test" else "production"
    role_name = f"{repo}-{suffix}-deploy"
    return {
        "domain": domain,
        "repo": repo,
        "environment": environment,
        "roleArn": f"arn:aws:iam::123456789012:role/{role_name}",
    }


class FakeS3:
    def __init__(
        self,
        *,
        versioning="Enabled",
        ownership="BucketOwnerEnforced",
        public_access_block=True,
    ):
        self.versioning = versioning
        self.ownership = ownership
        self.public_access_block = public_access_block
        self.objects = {}
        self.heads = {}
        self.puts = []

    def bucket_state(self, bucket, expected_owner):
        return {
            "versioning": self.versioning,
            "ownership": self.ownership,
            "publicAccessBlock": self.public_access_block,
        }

    def head_object(self, bucket, key, expected_owner):
        return self.heads.get(key)

    def get_object(self, bucket, key, expected_owner, version_id=None):
        lookup = (key, version_id) if version_id is not None else key
        return self.objects[lookup]

    def put_object(
        self,
        bucket,
        key,
        body,
        expected_owner,
        *,
        if_match=None,
        if_none_match=None,
    ):
        self.puts.append({
            "key": key,
            "body": body,
            "ifMatch": if_match,
            "ifNoneMatch": if_none_match,
        })
        version_id = f"version-{len(self.puts)}"
        etag = f'"etag-{len(self.puts)}"'
        self.objects[key] = body
        self.objects[(key, version_id)] = body
        self.heads[key] = {
            "etag": etag,
            "versionId": version_id,
            "contentLength": len(body),
            "contentType": "application/json",
            "serverSideEncryption": "AES256",
            "checksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
        }
        return {"etag": etag, "versionId": version_id}


class ServerScopeBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.registry = registry(
            draft("example.com", "draft-example-com"),
            draft("zoositioweb.com.mx", "draft-zoositioweb-com-mx"),
        )

    def test_scope_registry_uses_repo_slug_and_explicit_tenant_override(self):
        result = bootstrap.build_scope_registry(
            self.registry,
            expected_draft_count=2,
            tenant_overrides={"zoositioweb.com.mx": "zoosite"},
        )

        self.assertEqual(result["version"], 1)
        self.assertEqual([entry["domain"] for entry in result["scopes"]], [
            "example.com",
            "zoositioweb.com.mx",
        ])
        self.assertEqual(result["scopes"][0], {
            "domain": "example.com",
            "repo": "draft-example-com",
            "tenantId": "draft-example-com",
            "draftId": "draft-example-com",
        })
        self.assertEqual(result["scopes"][1]["tenantId"], "zoosite")
        self.assertEqual(result["scopes"][1]["draftId"], "draft-zoositioweb-com-mx")

    def test_scope_registry_fails_closed_for_duplicate_or_unregistered_override(self):
        duplicate = registry(
            draft("example.com", "draft-example-com"),
            draft("example.com", "draft-other-com"),
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_scope_registry(duplicate, expected_draft_count=2, tenant_overrides={})
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_scope_registry(
                self.registry,
                expected_draft_count=2,
                tenant_overrides={"unregistered.example": "tenant"},
            )

    def test_scope_registry_requires_exact_reviewed_count_and_safe_ids(self):
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_scope_registry(self.registry, expected_draft_count=11, tenant_overrides={})
        unsafe = registry(draft("example.com", "Draft Example"))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_scope_registry(unsafe, expected_draft_count=1, tenant_overrides={})

    def test_authz_rules_are_exact_environment_scoped_and_role_arn_only(self):
        scopes = bootstrap.build_scope_registry(
            self.registry,
            expected_draft_count=2,
            tenant_overrides={"zoositioweb.com.mx": "zoosite"},
        )
        bindings = [
            binding("example.com", "draft-example-com", "test"),
            binding("zoositioweb.com.mx", "draft-zoositioweb-com-mx", "test"),
        ]

        rules = bootstrap.build_authz_rules(scopes, bindings, "test")

        self.assertEqual(len(rules), 2)
        self.assertTrue(all(set(rule) == {
            "roleArn", "tenantId", "draftId", "domains", "environments", "actions"
        } for rule in rules))
        self.assertTrue(all(rule["environments"] == ["test"] for rule in rules))
        self.assertTrue(all("roleName" not in rule for rule in rules))
        self.assertEqual(rules[0]["actions"], [
            "createSite", "upsertDraft", "publishDraft", "getSite"
        ])

    def test_authz_rules_reject_missing_extra_duplicate_or_ambiguous_bindings(self):
        scopes = bootstrap.build_scope_registry(
            self.registry,
            expected_draft_count=2,
            tenant_overrides={"zoositioweb.com.mx": "zoosite"},
        )
        first = binding("example.com", "draft-example-com", "test")
        second = binding("zoositioweb.com.mx", "draft-zoositioweb-com-mx", "test")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_authz_rules(scopes, [first], "test")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_authz_rules(scopes, [first, second, binding("extra.com", "draft-extra", "test")], "test")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_authz_rules(scopes, [first, first, second], "test")
        ambiguous = dict(second, roleArn=first["roleArn"])
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_authz_rules(scopes, [first, ambiguous], "test")

    def test_role_evidence_requires_exact_arn_domain_oidc_environment_and_branch(self):
        expected = binding("example.com", "draft-example-com", "production")
        role_name = expected["roleArn"].split(":role/", 1)[1]
        evidence = {
            "github": {
                "DRAFT_DOMAIN": "example.com",
                "AWS_ROLE_ARN": expected["roleArn"],
            },
            "iam": {
                "Arn": expected["roleArn"],
                "AssumeRolePolicyDocument": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {"StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:ref": "refs/heads/main",
                            "token.actions.githubusercontent.com:sub": "repo:LynxPardelle/draft-example-com:environment:production",
                        }},
                    }],
                },
                "RoleName": role_name,
            },
        }

        verified = bootstrap.verify_role_evidence(
            owner="LynxPardelle",
            domain="example.com",
            repo="draft-example-com",
            environment="production",
            account_id="123456789012",
            evidence=evidence,
        )
        self.assertEqual(verified, expected)

        evidence["iam"]["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:sub"
        ] = "repo:LynxPardelle/other:environment:production"
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.verify_role_evidence(
                owner="LynxPardelle",
                domain="example.com",
                repo="draft-example-com",
                environment="production",
                account_id="123456789012",
                evidence=evidence,
            )

    def test_role_evidence_rejects_extra_trust_conditions_or_statements(self):
        expected = binding("example.com", "draft-example-com", "test")
        role_name = expected["roleArn"].split(":role/", 1)[1]
        statement = {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:ref": "refs/heads/test",
                "token.actions.githubusercontent.com:sub": "repo:LynxPardelle/draft-example-com:environment:test",
                "unexpected": "value",
            }},
        }
        evidence = {
            "github": {
                "DRAFT_DOMAIN": "example.com",
                "AWS_ROLE_ARN": expected["roleArn"],
            },
            "iam": {
                "Arn": expected["roleArn"],
                "AssumeRolePolicyDocument": {"Statement": [statement]},
                "RoleName": role_name,
            },
        }

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.verify_role_evidence(
                owner="LynxPardelle",
                domain="example.com",
                repo="draft-example-com",
                environment="test",
                account_id="123456789012",
                evidence=evidence,
            )

        statement["Condition"]["StringEquals"].pop("unexpected")
        statement["Condition"]["StringLike"] = {"unexpected": "value"}
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.verify_role_evidence(
                owner="LynxPardelle",
                domain="example.com",
                repo="draft-example-com",
                environment="test",
                account_id="123456789012",
                evidence=evidence,
            )

    def test_role_evidence_rejects_same_account_role_not_owned_by_the_draft(self):
        unrelated_arn = "arn:aws:iam::123456789012:role/UnrelatedAdminRole"
        evidence = {
            "github": {
                "DRAFT_DOMAIN": "example.com",
                "AWS_ROLE_ARN": unrelated_arn,
            },
            "iam": {
                "Arn": unrelated_arn,
                "RoleName": "UnrelatedAdminRole",
                "AssumeRolePolicyDocument": {"Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:ref": "refs/heads/main",
                        "token.actions.githubusercontent.com:sub": "repo:LynxPardelle/draft-example-com:environment:production",
                    }},
                }]},
            },
        }
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.verify_role_evidence(
                owner="LynxPardelle",
                domain="example.com",
                repo="draft-example-com",
                environment="production",
                account_id="123456789012",
                evidence=evidence,
            )

    def test_environment_bucket_binding_fails_closed(self):
        bootstrap.require_environment_bucket("test", "zoolanding-config-payloads-test")
        bootstrap.require_environment_bucket("production", "zoolanding-config-payloads")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.require_environment_bucket("test", "zoolanding-config-payloads")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.require_environment_bucket("production", "zoolanding-config-payloads-test")

    def test_scope_bytes_must_be_stable_across_environments(self):
        bootstrap.require_stable_scope_bytes(b"same", b"same")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.require_stable_scope_bytes(b"test", b"production")

    def test_test_green_evidence_is_machine_verified_and_hash_approved(self):
        owner = "LynxPardelle"
        canary_repo = "draft-pokeapi-demo-zoolandingpage-com-mx"
        scope_bytes = bootstrap.canonical_json_bytes({"version": 1, "scopes": [{
            "domain": "pokeapi-demo.zoolandingpage.com.mx",
            "repo": canary_repo,
            "tenantId": canary_repo,
            "draftId": canary_repo,
        }]})
        authz_bytes = bootstrap.canonical_json_bytes([])

        def head(body, etag, version):
            return {
                "etag": etag,
                "versionId": version,
                "contentLength": len(body),
                "contentType": "application/json",
                "serverSideEncryption": "AES256",
                "checksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
                "lastModified": "2026-07-14T20:01:00+00:00",
            }

        commit = "a" * 40
        canary_commit = "b" * 40
        canary_base_commit = "d" * 40
        canary_dev_commit = "e" * 40
        canary_tree = "f" * 40
        authoring_endpoint = "https://example.lambda-url.us-east-1.on.aws/"
        scope_head = head(scope_bytes, '"scope"', "scope-version")
        authz_head = head(authz_bytes, '"authz"', "authz-version")
        snapshot = {
            "remoteRef": {"object": {"sha": commit, "type": "commit"}},
            "authoringWorkflow": {
                "id": 111,
                "name": "Deploy Test",
                "path": ".github/workflows/deploy-test.yml",
                "state": "active",
            },
            "run": {
                "databaseId": 123,
                "runAttempt": 1,
                "status": "completed",
                "conclusion": "success",
                "headSha": commit,
                "headBranch": "test",
                "event": "push",
                "workflowName": "Deploy Test",
                "workflowId": 111,
                "path": ".github/workflows/deploy-test.yml",
                "updatedAt": "2026-07-14T20:00:00Z",
            },
            "canaryRef": {"object": {"sha": canary_commit, "type": "commit"}},
            "canaryCommit": {
                "sha": canary_commit,
                "tree": {"sha": canary_tree},
                "parents": [
                    {"sha": canary_base_commit},
                    {"sha": canary_dev_commit},
                ],
            },
            "canaryDevRef": {
                "object": {"sha": canary_dev_commit, "type": "commit"},
            },
            "canaryDevCommit": {
                "sha": canary_dev_commit,
                "tree": {"sha": canary_tree},
            },
            "canaryPulls": [{
                "number": 8,
                "state": "closed",
                "merged_at": "2026-07-14T20:03:00Z",
                "merge_commit_sha": canary_commit,
                "base": {
                    "ref": "test",
                    "sha": canary_base_commit,
                    "repo": {"full_name": f"{owner}/{canary_repo}"},
                },
                "head": {
                    "ref": "dev",
                    "sha": canary_dev_commit,
                    "repo": {"full_name": f"{owner}/{canary_repo}"},
                },
            }],
            "canaryWorkflow": {
                "id": 222,
                "name": "Deploy test draft",
                "path": ".github/workflows/deploy-test.yml",
                "state": "active",
            },
            "canaryRun": {
                "databaseId": 456,
                "runAttempt": 1,
                "status": "completed",
                "conclusion": "success",
                "headSha": canary_commit,
                "headBranch": "test",
                "event": "workflow_dispatch",
                "workflowName": "Deploy test draft",
                "workflowId": 222,
                "path": ".github/workflows/deploy-test.yml",
                "createdAt": "2026-07-14T20:05:00Z",
            },
            "canaryAuthoringEndpoint": {
                "name": "AUTHORING_ENDPOINT",
                "value": authoring_endpoint,
                "updatedAt": "2026-07-14T20:04:00Z",
            },
            "canaryBinding": {
                "scopeVersionId": scope_head["versionId"],
                "scopeSha256": hashlib.sha256(scope_bytes).hexdigest(),
                "authzVersionId": authz_head["versionId"],
                "authzSha256": hashlib.sha256(authz_bytes).hexdigest(),
            },
            "stack": {"Stacks": [{
                "StackStatus": "UPDATE_COMPLETE",
                "Parameters": [
                    {"ParameterKey": "EnvironmentName", "ParameterValue": "test"},
                    {"ParameterKey": "ManageStorageResources", "ParameterValue": "true"},
                    {"ParameterKey": "ConfigTableName", "ParameterValue": "zoolanding-config-registry-test"},
                    {"ParameterKey": "ConfigPayloadsBucketName", "ParameterValue": "zoolanding-config-payloads-test"},
                    {"ParameterKey": "LogLevel", "ParameterValue": "INFO"},
                    {"ParameterKey": "DeployAuthzConfigS3Key", "ParameterValue": bootstrap.AUTHZ_KEY},
                ],
                "Outputs": [{"OutputKey": "FunctionUrl", "OutputValue": authoring_endpoint}],
            }]},
            "stackResource": {"StackResourceDetail": {
                "PhysicalResourceId": "zoolanding-config-authoring-test-function",
                "ResourceStatus": "UPDATE_COMPLETE",
            }},
            "function": {
                "FunctionName": "zoolanding-config-authoring-test-function",
                "FunctionArn": (
                    "arn:aws:lambda:us-east-1:123456789012:"
                    "function:zoolanding-config-authoring-test-function"
                ),
                "Runtime": "python3.13",
                "State": "Active",
                "LastUpdateStatus": "Successful",
                "CodeSha256": "code-sha",
                "RevisionId": "revision",
                "Environment": {"Variables": {
                    "CONFIG_TABLE_NAME": "zoolanding-config-registry-test",
                    "CONFIG_PAYLOADS_BUCKET_NAME": "zoolanding-config-payloads-test",
                    "ENVIRONMENT_NAME": "test",
                    "LOG_LEVEL": "INFO",
                    "DEPLOY_AUTHZ_CONFIG_S3_KEY": bootstrap.AUTHZ_KEY,
                }},
            },
            "functionUrlConfig": {
                "FunctionUrl": authoring_endpoint,
                "FunctionArn": (
                    "arn:aws:lambda:us-east-1:123456789012:"
                    "function:zoolanding-config-authoring-test-function"
                ),
                "AuthType": "AWS_IAM",
                "InvokeMode": "BUFFERED",
            },
            "artifactEvidence": {
                "sourceCommit": commit,
                "manifestSha256": "c" * 64,
                "lambdaCodeSha256": "code-sha",
            },
            "bucketState": {
                "versioning": "Enabled",
                "ownership": "BucketOwnerEnforced",
                "publicAccessBlock": True,
            },
            "scopeHead": scope_head,
            "authzHead": authz_head,
            "scopeCurrent": scope_bytes,
            "scopeVersioned": scope_bytes,
            "authzCurrent": authz_bytes,
            "authzVersioned": authz_bytes,
            "unsignedApiStatus": 403,
        }
        snapshot["finalState"] = {
            key: copy.deepcopy(snapshot[key])
            for key in (
                "remoteRef",
                "authoringWorkflow",
                "run",
                "canaryRef",
                "canaryWorkflow",
                "canaryRun",
                "canaryCommit",
                "canaryDevRef",
                "canaryDevCommit",
                "canaryPulls",
                "canaryAuthoringEndpoint",
                "stack",
                "stackResource",
                "function",
                "functionUrlConfig",
                "bucketState",
                "scopeHead",
                "authzHead",
                "scopeCurrent",
                "authzCurrent",
                "unsignedApiStatus",
            )
        }

        evidence = bootstrap.validate_test_green_snapshot(
            snapshot,
            owner=owner,
            test_commit=commit,
            test_run_id=123,
            canary_repo=canary_repo,
            canary_run_id=456,
            expected_scope_bytes=scope_bytes,
            expected_authz_bytes=authz_bytes,
        )
        approved = hashlib.sha256(bootstrap.canonical_json_bytes(evidence)).hexdigest()
        bootstrap.require_approved_test_evidence(evidence, approved)
        self.assertEqual(evidence["testCommit"], commit)
        self.assertEqual(evidence["unsignedApiStatus"], 403)

        for path, bad_value in (
            (("run", "conclusion"), "failure"),
            (("run", "runAttempt"), 2),
            (("run", "headBranch"), "dev"),
            (("run", "path"), ".github/workflows/no-op.yml"),
            (("run", "updatedAt"), "2026-07-14T20:05:00Z"),
            (("canaryRun", "conclusion"), "failure"),
            (("canaryRun", "runAttempt"), 2),
            (("canaryRun", "event"), "push"),
            (("canaryRun", "path"), ".github/workflows/no-op.yml"),
            (("canaryAuthoringEndpoint", "value"), "https://other.lambda-url.us-east-1.on.aws/"),
            (("canaryAuthoringEndpoint", "updatedAt"), "2026-07-14T20:05:00Z"),
            (("canaryAuthoringEndpoint", "updatedAt"), "2026-07-14T20:06:00Z"),
            (("canaryBinding", "scopeVersionId"), "stale-scope-version"),
            (("canaryBinding", "authzSha256"), "0" * 64),
            (("stack", "Stacks", 0, "Outputs", 0, "OutputKey"), "ApiUrl"),
            (("scopeHead", "lastModified"), "2026-07-14T20:05:00+00:00"),
            (("scopeHead", "lastModified"), "2026-07-14T20:06:00+00:00"),
            (("authzHead", "lastModified"), "2026-07-14T20:05:00+00:00"),
            (("function", "LastUpdateStatus"), "Failed"),
            (("function", "CodeSha256"), "manually-drifted-code"),
            (("functionUrlConfig", "AuthType"), "NONE"),
            (("functionUrlConfig", "FunctionArn"), "arn:aws:lambda:us-east-1:123456789012:function:other"),
            (("functionUrlConfig", "FunctionUrl"), "https://other.lambda-url.us-east-1.on.aws/"),
            (("functionUrlConfig", "InvokeMode"), "RESPONSE_STREAM"),
            (("bucketState", "versioning"), "Suspended"),
            (("unsignedApiStatus",), 200),
        ):
            with self.subTest(path=path, bad_value=bad_value):
                broken = copy.deepcopy(snapshot)
                target = broken
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = bad_value
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_test_green_snapshot(
                        broken,
                        owner=owner,
                        test_commit=commit,
                        test_run_id=123,
                        canary_repo=canary_repo,
                        canary_run_id=456,
                        expected_scope_bytes=scope_bytes,
                        expected_authz_bytes=authz_bytes,
                    )

        for path, bad_value in (
            (("remoteRef", "object", "sha"), "9" * 40),
            (("run", "status"), "in_progress"),
            (("canaryRef", "object", "sha"), "8" * 40),
            (("canaryRun", "runAttempt"), 2),
            (("canaryDevRef", "object", "sha"), "7" * 40),
            (("canaryAuthoringEndpoint", "updatedAt"), "2026-07-14T20:04:30Z"),
            (("stack", "Stacks", 0, "Outputs", 0, "OutputValue"), "https://other.lambda-url.us-east-1.on.aws/"),
            (("function", "CodeSha256"), "concurrently-drifted-code"),
            (("functionUrlConfig", "AuthType"), "NONE"),
            (("scopeHead", "versionId"), "later-scope-version"),
            (("authzCurrent",), b"later-authorization"),
            (("unsignedApiStatus",), 200),
        ):
            with self.subTest(final_state_path=path, bad_value=bad_value):
                broken = copy.deepcopy(snapshot)
                target = broken["finalState"]
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = bad_value
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_test_green_snapshot(
                        broken,
                        owner=owner,
                        test_commit=commit,
                        test_run_id=123,
                        canary_repo=canary_repo,
                        canary_run_id=456,
                        expected_scope_bytes=scope_bytes,
                        expected_authz_bytes=authz_bytes,
                    )

        for path, bad_value in (
            (("canaryCommit", "parents"), [{"sha": canary_base_commit}]),
            (("canaryDevRef", "object", "sha"), "9" * 40),
            (("canaryDevCommit", "tree", "sha"), "8" * 40),
            (("canaryPulls", 0, "state"), "open"),
            (("canaryPulls", 0, "base", "ref"), "main"),
            (("canaryPulls", 0, "base", "sha"), "7" * 40),
            (("canaryPulls", 0, "head", "sha"), "6" * 40),
            (("canaryPulls", 0, "head", "repo", "full_name"), f"other/{canary_repo}"),
            (("canaryPulls", 0, "merged_at"), "2026-07-14T20:06:00Z"),
            (("canaryPulls",), []),
        ):
            with self.subTest(provenance_path=path, bad_value=bad_value):
                broken = copy.deepcopy(snapshot)
                target = broken
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = bad_value
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_test_green_snapshot(
                        broken,
                        owner=owner,
                        test_commit=commit,
                        test_run_id=123,
                        canary_repo=canary_repo,
                        canary_run_id=456,
                        expected_scope_bytes=scope_bytes,
                        expected_authz_bytes=authz_bytes,
                    )

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.require_approved_test_evidence(evidence, "0" * 64)

    def test_deployed_lambda_artifact_is_exactly_bound_to_the_test_run_source(self):
        source_commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            artifact_root = Path(directory)
            source_bodies = {}
            for index, relative_path in enumerate(bootstrap.RUNTIME_ARTIFACT_FILES):
                body = f"synthetic-runtime-{index}".encode("utf-8")
                source_bodies[relative_path] = body
                path = artifact_root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)

            zip_path = artifact_root / "deployed.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for relative_path, body in source_bodies.items():
                    archive.writestr(relative_path, body)
            zip_bytes = zip_path.read_bytes()
            zip_path.unlink()
            code_sha = base64.b64encode(hashlib.sha256(zip_bytes).digest()).decode("ascii")

            evidence = bootstrap.verify_deployed_artifact(
                artifact_root=artifact_root,
                deployed_zip=zip_bytes,
                function_configuration={"CodeSha256": code_sha},
                source_commit=source_commit,
            )
            self.assertEqual(evidence["sourceCommit"], source_commit)
            self.assertEqual(evidence["lambdaCodeSha256"], code_sha)
            self.assertRegex(evidence["manifestSha256"], r"^[a-f0-9]{64}$")

            tampered_zip = zip_bytes + b"tamper"
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.verify_deployed_artifact(
                    artifact_root=artifact_root,
                    deployed_zip=tampered_zip,
                    function_configuration={"CodeSha256": code_sha},
                    source_commit=source_commit,
                )

    def test_duplicate_github_environment_variables_are_ambiguous(self):
        class DuplicateVariableRunner:
            def run_json(self, arguments):
                return [
                    {"name": "AWS_ROLE_ARN", "value": "first"},
                    {"name": "AWS_ROLE_ARN", "value": "second"},
                ]

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._github_variables(
                DuplicateVariableRunner(), "LynxPardelle", "draft-example-com", "test"
            )

    def test_canary_endpoint_variable_evidence_includes_github_update_time(self):
        class VariableRunner:
            arguments = None

            def run_json(self, arguments):
                self.arguments = arguments
                return {
                    "name": "AUTHORING_ENDPOINT",
                    "value": "https://example.invalid/Prod/config-authoring",
                    "created_at": "2026-07-14T19:00:00Z",
                    "updated_at": "2026-07-14T20:04:00Z",
                }

        runner = VariableRunner()
        evidence = bootstrap._github_environment_variable_evidence(
            runner,
            "LynxPardelle",
            "draft-example-com",
            "test",
            "AUTHORING_ENDPOINT",
        )
        self.assertEqual(evidence, {
            "name": "AUTHORING_ENDPOINT",
            "value": "https://example.invalid/Prod/config-authoring",
            "updatedAt": "2026-07-14T20:04:00Z",
        })
        self.assertEqual(
            runner.arguments,
            [
                "gh", "api",
                "repos/LynxPardelle/draft-example-com/environments/test/variables/AUTHORING_ENDPOINT",
            ],
        )

    def test_safe_metadata_converts_aws_timestamp_to_central_time(self):
        safe = bootstrap._safe_head({
            "etag": '"etag"',
            "versionId": "version",
            "contentLength": 1,
            "lastModified": "2026-07-14T20:51:42+00:00",
        })

        self.assertEqual(safe["lastModifiedCentral"], "2026-07-14T14:51:42-06:00")
        self.assertNotIn("lastModified", safe)

    def test_private_bundle_requires_versioning_ownership_review_hashes_and_etag(self):
        scope_bytes = bootstrap.canonical_json_bytes({"version": 1, "scopes": []})
        authz_bytes = bootstrap.canonical_json_bytes([])
        authz_etag = '"current-authz"'
        old_authz = bootstrap.canonical_json_bytes([{"old": True}])
        s3 = FakeS3()
        s3.heads[bootstrap.AUTHZ_KEY] = {"etag": authz_etag, "versionId": "old-authz"}
        s3.objects[bootstrap.AUTHZ_KEY] = old_authz
        s3.objects[(bootstrap.AUTHZ_KEY, "old-authz")] = old_authz

        result = bootstrap.apply_private_bundle(
            s3,
            bucket="bucket",
            expected_owner="123456789012",
            scope_bytes=scope_bytes,
            authz_bytes=authz_bytes,
            approved_scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
            approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
            expected_current_authz_etag=authz_etag,
            expected_current_authz_version_id="old-authz",
            expected_current_scope_etag="MISSING",
            expected_current_scope_version_id="MISSING",
            expected_current_scope_sha256="MISSING",
        )

        self.assertEqual([call["key"] for call in s3.puts], [bootstrap.SCOPE_KEY, bootstrap.AUTHZ_KEY])
        self.assertEqual(s3.puts[0]["ifNoneMatch"], "*")
        self.assertEqual(s3.puts[1]["ifMatch"], authz_etag)
        self.assertEqual(result["scope"]["versionId"], "version-1")
        self.assertEqual(result["authz"]["versionId"], "version-2")
        self.assertEqual(result["previousAuthz"]["sha256"], hashlib.sha256(old_authz).hexdigest())

        for bad_s3 in (
            FakeS3(versioning="null"),
            FakeS3(ownership="ObjectWriter"),
            FakeS3(public_access_block=False),
        ):
            bad_s3.heads[bootstrap.AUTHZ_KEY] = {"etag": authz_etag, "versionId": "old-authz"}
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.apply_private_bundle(
                    bad_s3,
                    bucket="bucket",
                    expected_owner="123456789012",
                    scope_bytes=scope_bytes,
                    authz_bytes=authz_bytes,
                    approved_scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
                    approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
                    expected_current_authz_etag=authz_etag,
                    expected_current_authz_version_id="old-authz",
                    expected_current_scope_etag="MISSING",
                    expected_current_scope_version_id="MISSING",
                    expected_current_scope_sha256="MISSING",
                )

    def test_v2_bootstrap_creates_parallel_authz_without_touching_legacy_key(self):
        self.assertEqual(bootstrap.LEGACY_AUTHZ_KEY, "system/deploy-authz.json")
        self.assertEqual(bootstrap.AUTHZ_KEY, "system/deploy-authz-v2.json")
        self.assertNotEqual(bootstrap.AUTHZ_KEY, bootstrap.LEGACY_AUTHZ_KEY)
        scope_bytes = bootstrap.canonical_json_bytes({"version": 1, "scopes": []})
        authz_bytes = bootstrap.canonical_json_bytes([])
        legacy_body = bootstrap.canonical_json_bytes([{"roleName": "legacy-test-role"}])
        s3 = FakeS3()
        s3.heads[bootstrap.LEGACY_AUTHZ_KEY] = {
            "etag": '"legacy"',
            "versionId": "legacy-version",
        }
        s3.objects[bootstrap.LEGACY_AUTHZ_KEY] = legacy_body
        s3.objects[(bootstrap.LEGACY_AUTHZ_KEY, "legacy-version")] = legacy_body

        result = bootstrap.apply_private_bundle(
            s3,
            bucket="bucket",
            expected_owner="123456789012",
            scope_bytes=scope_bytes,
            authz_bytes=authz_bytes,
            approved_scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
            approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
            expected_current_authz_etag="MISSING",
            expected_current_authz_version_id="MISSING",
            expected_current_scope_etag="MISSING",
            expected_current_scope_version_id="MISSING",
            expected_current_scope_sha256="MISSING",
        )

        self.assertEqual(
            [call["key"] for call in s3.puts],
            [bootstrap.SCOPE_KEY, bootstrap.AUTHZ_KEY],
        )
        self.assertTrue(all(call["ifNoneMatch"] == "*" for call in s3.puts))
        self.assertTrue(all(call["ifMatch"] is None for call in s3.puts))
        self.assertEqual(s3.objects[bootstrap.LEGACY_AUTHZ_KEY], legacy_body)
        self.assertIsNone(result["previousAuthz"])
        self.assertEqual(result["authz"]["versionId"], "version-2")

    def test_private_bundle_is_idempotent_for_identical_scope_and_rejects_scope_drift(self):
        scope_bytes = bootstrap.canonical_json_bytes({"version": 1, "scopes": []})
        authz_bytes = bootstrap.canonical_json_bytes([])
        s3 = FakeS3()
        scope_head = {
            "etag": '"scope"',
            "versionId": "scope-v1",
            "contentLength": len(scope_bytes),
            "contentType": "application/json",
            "serverSideEncryption": "AES256",
            "checksumSHA256": base64.b64encode(hashlib.sha256(scope_bytes).digest()).decode("ascii"),
        }
        s3.heads[bootstrap.SCOPE_KEY] = scope_head
        s3.objects[bootstrap.SCOPE_KEY] = scope_bytes
        s3.objects[(bootstrap.SCOPE_KEY, "scope-v1")] = scope_bytes
        s3.heads[bootstrap.AUTHZ_KEY] = {"etag": '"authz"', "versionId": "authz-v1"}
        s3.objects[bootstrap.AUTHZ_KEY] = b"old-authz"
        s3.objects[(bootstrap.AUTHZ_KEY, "authz-v1")] = b"old-authz"

        bootstrap.apply_private_bundle(
            s3,
            bucket="bucket",
            expected_owner="123456789012",
            scope_bytes=scope_bytes,
            authz_bytes=authz_bytes,
            approved_scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
            approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
            expected_current_authz_etag='"authz"',
            expected_current_authz_version_id="authz-v1",
            expected_current_scope_etag=scope_head["etag"],
            expected_current_scope_version_id=scope_head["versionId"],
            expected_current_scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
        )
        self.assertEqual([call["key"] for call in s3.puts], [bootstrap.AUTHZ_KEY])

        s3 = FakeS3()
        s3.heads[bootstrap.SCOPE_KEY] = scope_head
        s3.objects[bootstrap.SCOPE_KEY] = b"different"
        s3.objects[(bootstrap.SCOPE_KEY, "scope-v1")] = b"different"
        s3.heads[bootstrap.AUTHZ_KEY] = {"etag": '"authz"', "versionId": "authz-v1"}
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.apply_private_bundle(
                s3,
                bucket="bucket",
                expected_owner="123456789012",
                scope_bytes=scope_bytes,
                authz_bytes=authz_bytes,
                approved_scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
                approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
                expected_current_authz_etag='"authz"',
                expected_current_authz_version_id="authz-v1",
                expected_current_scope_etag=scope_head["etag"],
                expected_current_scope_version_id=scope_head["versionId"],
                expected_current_scope_sha256=hashlib.sha256(b"different").hexdigest(),
            )

    def test_private_bundle_rejects_unverified_new_object_metadata(self):
        class MissingEncryptionS3(FakeS3):
            def put_object(self, *args, **kwargs):
                result = super().put_object(*args, **kwargs)
                key = args[1]
                self.heads[key]["serverSideEncryption"] = None
                return result

        scope_bytes = bootstrap.canonical_json_bytes({"version": 1, "scopes": []})
        authz_bytes = bootstrap.canonical_json_bytes([])
        s3 = MissingEncryptionS3()
        s3.heads[bootstrap.AUTHZ_KEY] = {"etag": '"authz"', "versionId": "authz-v1"}
        s3.objects[bootstrap.AUTHZ_KEY] = b"old-authz"
        s3.objects[(bootstrap.AUTHZ_KEY, "authz-v1")] = b"old-authz"

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.apply_private_bundle(
                s3,
                bucket="bucket",
                expected_owner="123456789012",
                scope_bytes=scope_bytes,
                authz_bytes=authz_bytes,
                approved_scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
                approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
                expected_current_authz_etag='"authz"',
                expected_current_authz_version_id="authz-v1",
                expected_current_scope_etag="MISSING",
                expected_current_scope_version_id="MISSING",
                expected_current_scope_sha256="MISSING",
            )

    def test_scope_updates_are_append_only_conditional_and_regenerate_the_bundle(self):
        existing_contract = bootstrap.build_scope_registry(
            registry(draft("example.com", "draft-example-com")),
            expected_draft_count=1,
            tenant_overrides={},
        )
        expanded_contract = bootstrap.build_scope_registry(
            registry(
                draft("example.com", "draft-example-com"),
                draft("new.example.com", "draft-new-example-com"),
            ),
            expected_draft_count=2,
            tenant_overrides={},
        )
        existing_bytes = bootstrap.canonical_json_bytes(existing_contract)
        expanded_bytes = bootstrap.canonical_json_bytes(expanded_contract)
        bootstrap.validate_append_only_scope_update(existing_bytes, expanded_bytes)

        for invalid_contract in (
            {"version": 1, "scopes": []},
            {
                "version": 1,
                "scopes": [{**expanded_contract["scopes"][0], "tenantId": "changed-tenant"}, expanded_contract["scopes"][1]],
            },
        ):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_append_only_scope_update(
                    existing_bytes,
                    bootstrap.canonical_json_bytes(invalid_contract),
                )

        authz_bytes = bootstrap.canonical_json_bytes([])
        old_authz = bootstrap.canonical_json_bytes([{"old": True}])
        s3 = FakeS3()
        scope_head = {
            "etag": '"scope-old"',
            "versionId": "scope-v1",
            "contentLength": len(existing_bytes),
            "contentType": "application/json",
            "serverSideEncryption": "AES256",
            "checksumSHA256": base64.b64encode(hashlib.sha256(existing_bytes).digest()).decode("ascii"),
        }
        s3.heads[bootstrap.SCOPE_KEY] = scope_head
        s3.objects[bootstrap.SCOPE_KEY] = existing_bytes
        s3.objects[(bootstrap.SCOPE_KEY, "scope-v1")] = existing_bytes
        s3.heads[bootstrap.AUTHZ_KEY] = {"etag": '"authz-old"', "versionId": "authz-v1"}
        s3.objects[bootstrap.AUTHZ_KEY] = old_authz
        s3.objects[(bootstrap.AUTHZ_KEY, "authz-v1")] = old_authz

        result = bootstrap.apply_private_bundle(
            s3,
            bucket="bucket",
            expected_owner="123456789012",
            scope_bytes=expanded_bytes,
            authz_bytes=authz_bytes,
            approved_scope_sha256=hashlib.sha256(expanded_bytes).hexdigest(),
            approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
            expected_current_authz_etag='"authz-old"',
            expected_current_authz_version_id="authz-v1",
            expected_current_scope_etag='"scope-old"',
            expected_current_scope_version_id="scope-v1",
            expected_current_scope_sha256=hashlib.sha256(existing_bytes).hexdigest(),
        )
        self.assertEqual([call["key"] for call in s3.puts], [bootstrap.SCOPE_KEY, bootstrap.AUTHZ_KEY])
        self.assertEqual(s3.puts[0]["ifMatch"], '"scope-old"')
        self.assertTrue(result["scope"]["written"])
        self.assertEqual(result["previousScope"]["sha256"], hashlib.sha256(existing_bytes).hexdigest())

        stale = FakeS3()
        stale.heads.update({bootstrap.SCOPE_KEY: scope_head, bootstrap.AUTHZ_KEY: {"etag": '"authz-old"', "versionId": "authz-v1"}})
        stale.objects.update({
            bootstrap.SCOPE_KEY: existing_bytes,
            (bootstrap.SCOPE_KEY, "scope-v1"): existing_bytes,
        })
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.apply_private_bundle(
                stale,
                bucket="bucket",
                expected_owner="123456789012",
                scope_bytes=expanded_bytes,
                authz_bytes=authz_bytes,
                approved_scope_sha256=hashlib.sha256(expanded_bytes).hexdigest(),
                approved_authz_sha256=hashlib.sha256(authz_bytes).hexdigest(),
                expected_current_authz_etag='"authz-old"',
                expected_current_authz_version_id="authz-v1",
                expected_current_scope_etag='"stale"',
                expected_current_scope_version_id="scope-v1",
                expected_current_scope_sha256=hashlib.sha256(existing_bytes).hexdigest(),
            )
        self.assertEqual(stale.puts, [])

    def test_rollback_restores_a_version_as_a_new_conditional_version(self):
        scope_contract = bootstrap.build_scope_registry(
            registry(draft("example.com", "draft-example-com")),
            expected_draft_count=1,
            tenant_overrides={},
        )
        scope_bytes = bootstrap.canonical_json_bytes(scope_contract)
        old_body = bootstrap.canonical_json_bytes(bootstrap.build_authz_rules(
            scope_contract,
            [binding("example.com", "draft-example-com", "test")],
            "test",
        ))
        s3 = FakeS3()
        s3.heads[bootstrap.AUTHZ_KEY] = {"etag": '"new"', "versionId": "new-version"}
        s3.objects[(bootstrap.AUTHZ_KEY, "old-version")] = old_body

        result = bootstrap.rollback_object(
            s3,
            bucket="bucket",
            key=bootstrap.AUTHZ_KEY,
            expected_owner="123456789012",
            restore_version_id="old-version",
            approved_restore_sha256=hashlib.sha256(old_body).hexdigest(),
            expected_current_etag='"new"',
            canonical_scope_bytes=scope_bytes,
            environment="test",
        )

        self.assertEqual(s3.puts[0]["ifMatch"], '"new"')
        self.assertEqual(s3.puts[0]["body"], old_body)
        self.assertEqual(result["versionId"], "version-1")

        legacy_body = bootstrap.canonical_json_bytes([{"roleName": "legacy-role"}])
        rejected = FakeS3()
        rejected.heads[bootstrap.AUTHZ_KEY] = {"etag": '"current"', "versionId": "current-version"}
        rejected.objects[(bootstrap.AUTHZ_KEY, "legacy-version")] = legacy_body
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.rollback_object(
                rejected,
                bucket="bucket",
                key=bootstrap.AUTHZ_KEY,
                expected_owner="123456789012",
                restore_version_id="legacy-version",
                approved_restore_sha256=hashlib.sha256(legacy_body).hexdigest(),
                expected_current_etag='"current"',
                canonical_scope_bytes=scope_bytes,
                environment="test",
            )

    def test_rollback_contract_rejects_scope_drift_and_cross_scope_or_account_authz(self):
        scope_contract = bootstrap.build_scope_registry(
            registry(draft("example.com", "draft-example-com")),
            expected_draft_count=1,
            tenant_overrides={},
        )
        scope_bytes = bootstrap.canonical_json_bytes(scope_contract)
        valid_rule = bootstrap.build_authz_rules(
            scope_contract,
            [binding("example.com", "draft-example-com", "production")],
            "production",
        )[0]

        bootstrap.validate_restore_contract(
            key=bootstrap.SCOPE_KEY,
            restore_body=scope_bytes,
            canonical_scope_bytes=scope_bytes,
            environment="production",
            expected_owner="123456789012",
        )
        bootstrap.validate_restore_contract(
            key=bootstrap.AUTHZ_KEY,
            restore_body=bootstrap.canonical_json_bytes([valid_rule]),
            canonical_scope_bytes=scope_bytes,
            environment="production",
            expected_owner="123456789012",
        )

        drifted_scope = copy.deepcopy(scope_contract)
        drifted_scope["scopes"][0]["tenantId"] = "other-tenant"
        invalid_rules = []
        for field, value in (
            ("tenantId", "other-tenant"),
            ("roleArn", "arn:aws:iam::999999999999:role/draft-example-com-production-deploy"),
            ("roleArn", "arn:aws:iam::123456789012:role/UnrelatedAdminRole"),
            ("domains", ["other.example.com"]),
            ("actions", ["createSite"]),
            ("environments", ["test"]),
        ):
            candidate = copy.deepcopy(valid_rule)
            candidate[field] = value
            invalid_rules.append(bootstrap.canonical_json_bytes([candidate]))

        rejected = [bootstrap.canonical_json_bytes(drifted_scope), *invalid_rules]
        for index, body in enumerate(rejected):
            with self.subTest(index=index):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_restore_contract(
                        key=bootstrap.SCOPE_KEY if index == 0 else bootstrap.AUTHZ_KEY,
                        restore_body=body,
                        canonical_scope_bytes=scope_bytes,
                        environment="production",
                        expected_owner="123456789012",
                    )


if __name__ == "__main__":
    unittest.main()
