import hashlib
import base64
import copy
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
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


def draft(domain, repo, *, owner=None):
    resolved_owner = owner or "LynxPardelle"
    entry = {
        "domain": domain,
        "repo": repo,
        "githubUrl": f"https://github.com/{resolved_owner}/{repo}.git",
        "localPath": f"drafts/{domain}",
    }
    if owner is not None:
        entry["owner"] = owner
    return entry


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
        return copy.deepcopy(self.heads.get(key))

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
        if if_match is not None and self.heads.get(key, {}).get("etag") != if_match:
            raise bootstrap.BootstrapError("PreconditionFailed")
        if if_none_match == "*" and key in self.heads:
            raise bootstrap.BootstrapError("PreconditionFailed")
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

    def test_isolated_plan_cli_accepts_one_domain_without_production_bucket(self):
        arguments = [
            "plan", "--registry", "registry.json", "--expected-draft-count", "2",
            "--profile", "operator", "--test-bucket", bootstrap.ENVIRONMENT_BUCKETS["test"],
            "--add-domain", "example.com",
        ]
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parsed = bootstrap.parse_args(arguments)
        except SystemExit as exc:
            self.fail(f"isolated plan should accept a single test target: exit {exc.code}")
        self.assertEqual(parsed.add_domain, "example.com")
        self.assertIsNone(parsed.production_bucket)

    def test_isolated_registry_duplicate_keys_fail_before_any_external_access(self):
        raw = json.dumps(self.registry)
        for old, duplicated in (
            ('"owner": "LynxPardelle"', '"owner": "LynxPardelle", "owner": "LynxPardelle"'),
            ('"domain": "example.com"', '"domain": "example.com", "domain": "example.com"'),
        ):
            with self.subTest(field=old), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "registry.json"
                path.write_text(raw.replace(old, duplicated, 1), encoding="utf-8")
                args = bootstrap.parse_args([
                    "plan", "--registry", str(path), "--expected-draft-count", "2",
                    "--profile", "operator", "--test-bucket", bootstrap.ENVIRONMENT_BUCKETS["test"],
                    "--add-domain", "example.com",
                ])
                with mock.patch.object(bootstrap, "CommandRunner") as external:
                    with self.assertRaises(bootstrap.BootstrapError):
                        bootstrap._plan(args)
                external.assert_not_called()

    def test_isolated_cli_rejects_multiple_domains_and_production_inputs(self):
        arguments = [
            "plan", "--registry", "registry.json", "--expected-draft-count", "2",
            "--profile", "operator", "--test-bucket", bootstrap.ENVIRONMENT_BUCKETS["test"],
            "--add-domain", "example.com",
        ]
        for extra in (
            ["--add-domain", "zoositioweb.com.mx"],
            ["--production-bucket", bootstrap.ENVIRONMENT_BUCKETS["production"]],
            ["--tenant-override", "example.com=shared"],
        ):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises((SystemExit, bootstrap.BootstrapError)):
                    bootstrap.parse_args(arguments + extra)
        for domain in ("*", "example.com,zoositioweb.com.mx", "", "EXAMPLE.COM"):
            with self.subTest(domain=domain), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises((SystemExit, bootstrap.BootstrapError)):
                    bootstrap.parse_args(arguments[:-1] + [domain])

    def test_isolated_binding_never_reads_an_unselected_repository_or_role(self):
        expected = binding("example.com", "draft-example-com", "test")
        commands = []

        def run_json(arguments):
            commands.append(arguments)
            if arguments[:3] == ["gh", "api", "repos/LynxPardelle/draft-example-com/actions/oidc/customization/sub"]:
                return {"use_default": True, "sub_claim_prefix": "repo:LynxPardelle/draft-example-com"}
            if arguments[:7] == ["gh", "variable", "list", "--repo", "LynxPardelle/draft-example-com", "--env", "test"]:
                return [{"name": "DRAFT_DOMAIN", "value": "example.com"},
                        {"name": "AWS_ROLE_ARN", "value": expected["roleArn"]}]
            if arguments[:3] == ["aws", "iam", "get-role"] and arguments[arguments.index("--role-name") + 1] == "draft-example-com-test-deploy":
                return {"Role": {
                    "Arn": expected["roleArn"], "RoleName": "draft-example-com-test-deploy",
                    "AssumeRolePolicyDocument": {"Statement": [{
                        "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                        "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
                        "Condition": {"StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:ref": "refs/heads/test",
                            "token.actions.githubusercontent.com:sub": "repo:LynxPardelle/draft-example-com:environment:test",
                        }},
                    }]},
                }}
            self.fail("isolated collection attempted an unselected external read")

        try:
            result = bootstrap.collect_verified_bindings(
                self.registry, environment="test", profile="operator",
                account_id="123456789012", runner=mock.Mock(run_json=run_json),
                domain="example.com",
            )
        except TypeError:
            self.fail("binding collector does not yet support exact isolated selection")
        self.assertEqual(result, [expected])
        self.assertEqual(len(commands), 3)

    def test_isolated_binding_rejects_wrong_role_before_iam_lookup(self):
        commands = []

        def run_json(arguments):
            commands.append(arguments)
            if arguments[:2] == ["gh", "api"]:
                return {"use_default": True, "sub_claim_prefix": "repo:LynxPardelle/draft-example-com"}
            if arguments[:2] == ["gh", "variable"]:
                return [{"name": "DRAFT_DOMAIN", "value": "example.com"},
                        {"name": "AWS_ROLE_ARN", "value": binding("other.example", "draft-other", "test")["roleArn"]}]
            self.fail("wrong role must be rejected before IAM access")

        try:
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.collect_verified_bindings(
                    self.registry, environment="test", profile="operator",
                    account_id="123456789012", runner=mock.Mock(run_json=run_json),
                    domain="example.com",
                )
        except TypeError:
            self.fail("binding collector does not yet guard the isolated role")
        self.assertEqual(len(commands), 2)

    def _isolated_baseline(self):
        scopes = bootstrap.build_scope_registry(
            self.registry, expected_draft_count=2,
            tenant_overrides={"zoositioweb.com.mx": "zoosite"},
        )
        rules = bootstrap.build_authz_rules(scopes, [
            binding(item["domain"], item["repo"], "test") for item in scopes["scopes"]
        ], "test")
        rules.reverse()
        target = {"domain": "middle.example", "repo": "draft-middle-example",
                  "tenantId": "draft-middle-example", "draftId": "draft-middle-example"}
        return bootstrap.canonical_json_bytes(scopes), bootstrap.canonical_json_bytes(rules), target

    def _isolated_candidate(self, scope_bytes, authz_bytes, target):
        try:
            return bootstrap.build_isolated_bundle(
                scope_bytes=scope_bytes, authz_bytes=authz_bytes, target_scope=target,
                target_binding=binding(target["domain"], target["repo"], "test"),
                expected_owner="123456789012",
            )
        except AttributeError:
            self.fail("isolated preserved-bundle generation is not implemented")

    def test_isolated_candidate_preserves_every_existing_entry_and_authz_order(self):
        scopes, rules, target = self._isolated_baseline()
        candidate_scopes, candidate_rules, mode = self._isolated_candidate(scopes, rules, target)
        self.assertEqual(mode, "add")
        old_scopes, old_rules = json.loads(scopes), json.loads(rules)
        new_scopes, new_rules = json.loads(candidate_scopes), json.loads(candidate_rules)
        self.assertEqual(new_scopes["scopes"][1], target)
        self.assertEqual([item for item in new_scopes["scopes"] if item != target], old_scopes["scopes"])
        self.assertEqual(new_rules[:-1], old_rules)
        for old, new in zip(old_rules, new_rules):
            self.assertEqual(bootstrap.canonical_json_bytes(old), bootstrap.canonical_json_bytes(new))
        self.assertEqual(new_rules[-1]["domains"], [target["domain"]])

    def test_isolated_candidate_is_exact_noop_when_both_target_entries_exist(self):
        scopes, rules, target = self._isolated_baseline()
        new_scopes, new_rules, _ = self._isolated_candidate(scopes, rules, target)
        self.assertEqual(self._isolated_candidate(new_scopes, new_rules, target), (new_scopes, new_rules, "noop"))

    def test_isolated_candidate_rejects_one_sided_or_changed_existing_target(self):
        scopes, rules, target = self._isolated_baseline()
        new_scopes, new_rules, _ = self._isolated_candidate(scopes, rules, target)
        for baseline in ((new_scopes, rules), (scopes, new_rules)):
            with self.subTest(kind="one-sided"), self.assertRaises(bootstrap.BootstrapError):
                self._isolated_candidate(*baseline, target)
        changed = {**target, "tenantId": "different-tenant"}
        with self.assertRaises(bootstrap.BootstrapError):
            self._isolated_candidate(new_scopes, new_rules, changed)

    def test_isolated_candidate_rejects_cross_field_identity_collisions(self):
        scopes, rules, target = self._isolated_baseline()
        for key, value in (("tenantId", "zoosite"), ("tenantId", "draft-example-com"),
                           ("draftId", "zoosite"), ("repo", "draft-example-com")):
            with self.subTest(key=key, value=value), self.assertRaises(bootstrap.BootstrapError):
                self._isolated_candidate(scopes, rules, {**target, key: value})
        existing = json.loads(scopes)
        existing["scopes"][0]["tenantId"] = target["repo"]
        existing_scopes = bootstrap.canonical_json_bytes(existing)
        existing_rules = bootstrap.canonical_json_bytes(bootstrap.build_authz_rules(existing, [
            binding(item["domain"], item["repo"], "test") for item in existing["scopes"]
        ], "test"))
        bootstrap.validate_restore_contract(
            key=bootstrap.AUTHZ_KEY, restore_body=existing_rules,
            canonical_scope_bytes=existing_scopes, environment="test", expected_owner="123456789012",
        )
        with self.assertRaisesRegex(bootstrap.BootstrapError, "identity collides"):
            self._isolated_candidate(existing_scopes, existing_rules, target)

    def test_isolated_candidate_rejects_noncanonical_duplicate_or_narrowed_baseline(self):
        scopes, rules, target = self._isolated_baseline()
        altered = json.loads(rules)
        altered[0]["actions"] = ["getSite"]
        invalid_scopes = scopes.replace(b'"version": 1', b'"version": 1, "version": 1')
        for scope_body, rule_body in (
            (scopes + b"\n", rules), (invalid_scopes, rules),
            (scopes, bootstrap.canonical_json_bytes(altered)),
            (scopes, bootstrap.canonical_json_bytes(json.loads(rules) * 2)),
        ):
            with self.subTest(kind="invalid baseline"), self.assertRaises(bootstrap.BootstrapError):
                self._isolated_candidate(scope_body, rule_body, target)

    def _memory_s3(self, client=None):
        adapter = getattr(bootstrap, "InMemoryS3", None)
        self.assertIsNotNone(adapter, "isolated S3 transport is not implemented")
        return adapter(profile="operator", region="us-east-1", client=client)

    def test_isolated_sdk_reads_and_writes_bodies_only_in_memory(self):
        body = b'{"synthetic":true}\n'
        stream = io.BytesIO(body)
        client = mock.Mock()
        client.get_object.return_value = {"Body": stream}
        client.put_object.return_value = {"ETag": '"new"', "VersionId": "version-new"}
        adapter = self._memory_s3(client)
        with mock.patch.object(bootstrap.tempfile, "NamedTemporaryFile", side_effect=AssertionError("private body reached disk")):
            self.assertEqual(adapter.get_object(bootstrap.ENVIRONMENT_BUCKETS["test"], bootstrap.AUTHZ_KEY, "123456789012", "version-old"), body)
            self.assertEqual(adapter.put_object(bootstrap.ENVIRONMENT_BUCKETS["test"], bootstrap.AUTHZ_KEY, body, "123456789012", if_match='"old"'), {"etag": '"new"', "versionId": "version-new"})
        self.assertTrue(stream.closed)
        self.assertEqual(client.get_object.call_args.kwargs["VersionId"], "version-old")
        self.assertEqual(client.put_object.call_args.kwargs["Body"], body)
        self.assertEqual(client.put_object.call_args.kwargs["IfMatch"], '"old"')
        self.assertEqual(client.put_object.call_count, 1)

    def test_isolated_sdk_factory_disables_automatic_retries(self):
        sdk = mock.Mock()
        config = mock.Mock()
        with mock.patch.dict(sys.modules, {"boto3": sdk, "botocore.config": config}):
            self._memory_s3()
        self.assertEqual(config.Config.call_args.kwargs["retries"], {"mode": "standard", "total_max_attempts": 1})
        self.assertEqual(sdk.Session.call_args.kwargs, {"profile_name": "operator"})
        self.assertEqual(sdk.Session.return_value.client.call_args.kwargs["region_name"], "us-east-1")

    def test_isolated_sdk_sanitizes_precondition_failed_without_retry(self):
        class ConditionalFailure(Exception):
            response = {"Error": {"Code": "PreconditionFailed", "Message": "PRIVATE-SENTINEL"}}

        client = mock.Mock()
        client.put_object.side_effect = ConditionalFailure("PRIVATE-SENTINEL")
        adapter = self._memory_s3(client)
        with self.assertRaises(bootstrap.BootstrapError) as raised:
            adapter.put_object(bootstrap.ENVIRONMENT_BUCKETS["test"], bootstrap.AUTHZ_KEY, b"[]\n", "123456789012", if_match='"old"')
        self.assertIn("precondition", str(raised.exception).lower())
        self.assertNotIn("PRIVATE-SENTINEL", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(client.put_object.call_count, 1)

    def _isolated_apply_fixture(self, fake_type=FakeS3):
        scopes, rules, target = self._isolated_baseline()
        proposed_scopes, proposed_rules, _ = self._isolated_candidate(scopes, rules, target)
        store = fake_type()
        bucket, account = bootstrap.ENVIRONMENT_BUCKETS["test"], "123456789012"
        scope_head = store.put_object(bucket, bootstrap.SCOPE_KEY, scopes, account)
        authz_head = store.put_object(bucket, bootstrap.AUTHZ_KEY, rules, account)
        arguments = dict(
            bucket=bucket, expected_owner=account, scope_bytes=proposed_scopes, authz_bytes=proposed_rules,
            approved_scope_sha256=bootstrap.sha256_hex(proposed_scopes),
            approved_authz_sha256=bootstrap.sha256_hex(proposed_rules),
            expected_current_scope_etag=scope_head["etag"], expected_current_scope_version_id=scope_head["versionId"],
            expected_current_scope_sha256=bootstrap.sha256_hex(scopes),
            expected_current_authz_etag=authz_head["etag"], expected_current_authz_version_id=authz_head["versionId"],
            expected_current_authz_sha256=bootstrap.sha256_hex(rules),
        )
        return store, arguments

    def _apply_isolated_fixture(self, store, arguments):
        try:
            return bootstrap.apply_private_bundle(store, **arguments)
        except TypeError:
            self.fail("isolated conditional writer does not yet bind the authz baseline hash")

    def test_isolated_apply_writes_scope_then_authz_with_exact_cas(self):
        store, arguments = self._isolated_apply_fixture()
        self._apply_isolated_fixture(store, arguments)
        self.assertEqual([item["key"] for item in store.puts[2:]], [bootstrap.SCOPE_KEY, bootstrap.AUTHZ_KEY])
        self.assertEqual(store.puts[2]["ifMatch"], arguments["expected_current_scope_etag"])
        self.assertEqual(store.puts[3]["ifMatch"], arguments["expected_current_authz_etag"])
        self.assertEqual(store.objects[bootstrap.AUTHZ_KEY], arguments["authz_bytes"])

    def test_isolated_apply_rejects_each_stale_baseline_before_writing(self):
        for field in ("expected_current_scope_sha256", "expected_current_authz_sha256",
                      "expected_current_scope_version_id", "expected_current_authz_version_id",
                      "expected_current_scope_etag", "expected_current_authz_etag"):
            with self.subTest(field=field):
                store, arguments = self._isolated_apply_fixture()
                arguments[field] = "0" * 64
                with self.assertRaises(bootstrap.BootstrapError):
                    self._apply_isolated_fixture(store, arguments)
                self.assertEqual(len(store.puts), 2)

    def test_isolated_apply_rechecks_scope_version_before_authz_write(self):
        class ScopeDrift(FakeS3):
            def get_object(self, bucket, key, expected_owner, version_id=None):
                if key == bootstrap.AUTHZ_KEY and len(self.puts) == 3:
                    self.heads[bootstrap.SCOPE_KEY]["versionId"] = "concurrent-version"
                    self.objects[(bootstrap.SCOPE_KEY, "concurrent-version")] = self.objects[bootstrap.SCOPE_KEY]
                return super().get_object(bucket, key, expected_owner, version_id)

        store, arguments = self._isolated_apply_fixture(ScopeDrift)
        old_authz = store.objects[bootstrap.AUTHZ_KEY]
        with self.assertRaises(bootstrap.BootstrapError):
            self._apply_isolated_fixture(store, arguments)
        self.assertEqual(len(store.puts), 3)
        self.assertEqual(store.objects[bootstrap.AUTHZ_KEY], old_authz)

    def test_isolated_apply_loses_scope_cas_before_any_operator_write(self):
        class ScopeRace(FakeS3):
            attempts = 0

            def put_object(self, bucket, key, body, expected_owner, **conditions):
                if key == bootstrap.SCOPE_KEY and conditions.get("if_match"):
                    self.attempts += 1
                    super().put_object(bucket, key, b'{"synthetic-concurrent":true}\n', expected_owner)
                return super().put_object(bucket, key, body, expected_owner, **conditions)

        store, arguments = self._isolated_apply_fixture(ScopeRace)
        old_authz = store.objects[bootstrap.AUTHZ_KEY]
        with self.assertRaisesRegex(bootstrap.BootstrapError, "PreconditionFailed"):
            self._apply_isolated_fixture(store, arguments)
        self.assertEqual(store.objects[bootstrap.SCOPE_KEY], b'{"synthetic-concurrent":true}\n')
        self.assertEqual(store.objects[bootstrap.AUTHZ_KEY], old_authz)
        self.assertEqual(store.attempts, 1)
        self.assertEqual(len(store.puts), 3)

    def test_isolated_apply_blocks_bucket_control_drift_before_authz(self):
        for field, value in (("versioning", "Suspended"), ("ownership", "ObjectWriter"),
                             ("publicAccessBlock", False)):
            with self.subTest(field=field):
                class BucketDrift(FakeS3):
                    def bucket_state(self, bucket, expected_owner):
                        state = super().bucket_state(bucket, expected_owner)
                        if len(self.puts) == 3:
                            state[field] = value
                        return state

                store, arguments = self._isolated_apply_fixture(BucketDrift)
                old_authz = store.objects[bootstrap.AUTHZ_KEY]
                with self.assertRaisesRegex(bootstrap.BootstrapError, "controls changed"):
                    self._apply_isolated_fixture(store, arguments)
                self.assertEqual(len(store.puts), 3)
                self.assertEqual(store.objects[bootstrap.AUTHZ_KEY], old_authz)

    def test_isolated_apply_readback_fault_stops_without_retry_or_rollback(self):
        for fault_key, expected_puts in ((bootstrap.SCOPE_KEY, 3), (bootstrap.AUTHZ_KEY, 4)):
            for versioned in (False, True):
                with self.subTest(key=fault_key, versioned=versioned):
                    class ReadbackFault(FakeS3):
                        faults = 0

                        def get_object(self, bucket, key, expected_owner, version_id=None):
                            if key == fault_key and len(self.puts) == expected_puts and (version_id is not None) == versioned:
                                self.faults += 1
                                return b'{"synthetic-readback-fault":true}\n'
                            return super().get_object(bucket, key, expected_owner, version_id)

                    store, arguments = self._isolated_apply_fixture(ReadbackFault)
                    old_authz = store.objects[bootstrap.AUTHZ_KEY]
                    with self.assertRaisesRegex(bootstrap.BootstrapError, "readback"):
                        self._apply_isolated_fixture(store, arguments)
                    self.assertEqual(len(store.puts), expected_puts)
                    self.assertEqual(store.faults, 1)
                    if fault_key == bootstrap.SCOPE_KEY:
                        self.assertEqual(store.objects[bootstrap.AUTHZ_KEY], old_authz)

    def test_isolated_apply_loses_authz_cas_without_overwriting_or_retrying(self):
        class AuthzRace(FakeS3):
            def put_object(self, bucket, key, body, expected_owner, **conditions):
                if key == bootstrap.AUTHZ_KEY and conditions.get("if_match"):
                    super().put_object(bucket, key, b'{"synthetic-concurrent":true}\n', expected_owner)
                return super().put_object(bucket, key, body, expected_owner, **conditions)

        store, arguments = self._isolated_apply_fixture(AuthzRace)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "PreconditionFailed"):
            self._apply_isolated_fixture(store, arguments)
        self.assertEqual(store.objects[bootstrap.AUTHZ_KEY], b'{"synthetic-concurrent":true}\n')
        self.assertEqual(len(store.puts), 4)

    def _isolated_command(self, store, arguments, *, write=False):
        selected = draft("middle.example", "draft-middle-example")
        args = bootstrap.argparse.Namespace(
            registry=Path("synthetic-registry.json"), expected_draft_count=3, tenant_override=[],
            profile="operator", region="us-east-1", add_domain=selected["domain"],
            test_bucket=arguments["bucket"], production_bucket=None, bucket=arguments["bucket"],
            environment="test", approve_scope_sha256=arguments["approved_scope_sha256"],
            approve_authz_sha256=arguments["approved_authz_sha256"],
            **{key: value for key, value in arguments.items() if key.startswith("expected_current_")},
        )
        with mock.patch.object(bootstrap, "_load_json_file", return_value=registry(*self.registry["drafts"], selected)), \
             mock.patch.object(bootstrap, "_account_id", return_value="123456789012"), \
             mock.patch.object(bootstrap, "collect_verified_bindings", return_value=[binding(selected["domain"], selected["repo"], "test")]) as collector, \
             mock.patch.object(bootstrap, "InMemoryS3", return_value=store), \
             mock.patch.object(bootstrap, "_generated_bundle", side_effect=AssertionError("global generation is forbidden in isolated mode")):
            try:
                result = bootstrap._apply(args) if write else bootstrap._plan(args)
            except (bootstrap.BootstrapError, AssertionError) as exc:
                self.fail(f"isolated command did not complete: {exc}")
        self.assertEqual(collector.call_args.kwargs["domain"], selected["domain"])
        return result

    def test_isolated_command_plans_without_writes_and_emits_only_safe_metadata(self):
        store, arguments = self._isolated_apply_fixture()
        result = self._isolated_command(store, arguments)
        self.assertEqual(result["updateMode"], "add")
        self.assertEqual(result["scopeCount"], 3)
        self.assertEqual(result["currentAuthzSha256"], arguments["expected_current_authz_sha256"])
        self.assertTrue(result["existingGrantsPreserved"])
        self.assertEqual(len(store.puts), 2)
        self.assertNotIn("arn:", json.dumps(result))
        self.assertNotIn("roleArn", json.dumps(result))

    def test_isolated_command_applies_and_then_noops_without_a_new_version(self):
        store, arguments = self._isolated_apply_fixture()
        result = self._isolated_command(store, arguments, write=True)
        self.assertEqual(result["updateMode"], "add")
        self.assertEqual(len(store.puts), 4)
        for label, key in (("scope", bootstrap.SCOPE_KEY), ("authz", bootstrap.AUTHZ_KEY)):
            arguments[f"expected_current_{label}_etag"] = store.heads[key]["etag"]
            arguments[f"expected_current_{label}_version_id"] = store.heads[key]["versionId"]
            arguments[f"expected_current_{label}_sha256"] = bootstrap.sha256_hex(store.objects[key])
        result = self._isolated_command(store, arguments, write=True)
        self.assertEqual(result["updateMode"], "noop")
        self.assertFalse(result["scopeWritten"])
        self.assertFalse(result["authzWritten"])
        self.assertEqual(len(store.puts), 4)

    def test_isolated_apply_cli_requires_authz_baseline_hash_and_test(self):
        _, arguments = self._isolated_apply_fixture()
        cli = ["apply", "--registry", "registry.json", "--expected-draft-count", "3",
               "--profile", "operator", "--environment", "test", "--bucket", arguments["bucket"],
               "--add-domain", "middle.example", "--approve-scope-sha256", arguments["approved_scope_sha256"],
               "--approve-authz-sha256", arguments["approved_authz_sha256"]]
        for key, value in arguments.items():
            if key.startswith("expected_current_") and key != "expected_current_authz_sha256":
                cli.extend(["--" + key.replace("_", "-"), value])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises((SystemExit, bootstrap.BootstrapError)):
                bootstrap.parse_args(cli)
            try:
                parsed = bootstrap.parse_args(cli + ["--expected-current-authz-sha256", arguments["expected_current_authz_sha256"]])
            except SystemExit as exc:
                self.fail(f"isolated apply cannot accept its baseline hash: exit {exc.code}")
        self.assertEqual(parsed.environment, "test")
        production_cli = cli + ["--expected-current-authz-sha256", arguments["expected_current_authz_sha256"]]
        production_cli[production_cli.index("--environment") + 1] = "production"
        production_cli[production_cli.index("--bucket") + 1] = bootstrap.ENVIRONMENT_BUCKETS["production"]
        with mock.patch.object(bootstrap, "CommandRunner") as external, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises((SystemExit, bootstrap.BootstrapError)):
                bootstrap.parse_args(production_cli)
        external.assert_not_called()

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

    def test_scope_registry_accepts_an_explicit_per_draft_owner_without_changing_scope_bytes(self):
        mixed_owner_registry = registry(
            draft("example.com", "draft-example-com"),
            draft(
                "thehairnarrative.com",
                "draft-thehairnarrative-com",
                owner="Toydrum",
            ),
        )

        try:
            result = bootstrap.build_scope_registry(
                mixed_owner_registry,
                expected_draft_count=2,
                tenant_overrides={},
            )
        except bootstrap.BootstrapError as exc:
            self.fail(f"explicit per-draft owner was rejected: {exc}")

        self.assertEqual(result["scopes"][1], {
            "domain": "thehairnarrative.com",
            "repo": "draft-thehairnarrative-com",
            "tenantId": "draft-thehairnarrative-com",
            "draftId": "draft-thehairnarrative-com",
        })
        self.assertNotIn("owner", result["scopes"][1])

    def test_scope_registry_rejects_a_per_draft_owner_url_mismatch(self):
        mismatched = draft(
            "thehairnarrative.com",
            "draft-thehairnarrative-com",
            owner="Toydrum",
        )
        mismatched["githubUrl"] = (
            "https://github.com/LynxPardelle/draft-thehairnarrative-com.git"
        )

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_scope_registry(
                registry(mismatched),
                expected_draft_count=1,
                tenant_overrides={},
            )

    def test_v2_registry_filters_test_only_drafts_without_changing_shared_mappings(self):
        shared = draft("example.com", "draft-example-com")
        shared["deploymentEnvironments"] = ["test", "production"]
        test_only = draft(
            "thehairnarrative.com",
            "draft-thehairnarrative-com",
            owner="Toydrum",
        )
        test_only["deploymentEnvironments"] = ["test"]
        scoped_registry = {
            "version": 2,
            "owner": "LynxPardelle",
            "drafts": [shared, test_only],
        }

        test_scopes = bootstrap.build_scope_registry(
            scoped_registry,
            expected_draft_count=2,
            tenant_overrides={},
            environment="test",
        )
        production_scopes = bootstrap.build_scope_registry(
            scoped_registry,
            expected_draft_count=2,
            tenant_overrides={},
            environment="production",
        )

        self.assertEqual(len(test_scopes["scopes"]), 2)
        self.assertEqual(production_scopes["scopes"], [test_scopes["scopes"][0]])
        self.assertEqual(
            bootstrap._registered_repo_owner(scoped_registry, "draft-thehairnarrative-com"),
            "Toydrum",
        )

    def test_registry_version_must_be_an_exact_integer(self):
        for invalid_version in (True, False, 1.0, 2.0):
            with self.subTest(invalid_version=invalid_version):
                entry = draft("example.com", "draft-example-com")
                if invalid_version == 2.0:
                    entry["deploymentEnvironments"] = ["test", "production"]
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.build_scope_registry(
                        {
                            "version": invalid_version,
                            "owner": "LynxPardelle",
                            "drafts": [entry],
                        },
                        expected_draft_count=1,
                        tenant_overrides={},
                        environment="test",
                    )

    def test_v2_registry_validates_test_only_tenant_override_before_production_filter(self):
        shared = draft("example.com", "draft-example-com")
        shared["deploymentEnvironments"] = ["test", "production"]
        test_only = draft("test-only.example", "draft-test-only-example")
        test_only["deploymentEnvironments"] = ["test"]

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_scope_registry(
                {
                    "version": 2,
                    "owner": "LynxPardelle",
                    "drafts": [shared, test_only],
                },
                expected_draft_count=2,
                tenant_overrides={"test-only.example": "INVALID ID WITH SPACES"},
                environment="production",
            )

    def test_v2_registry_rejects_ambiguous_or_unsafe_environment_scopes(self):
        for deployment_environments in (
            None,
            [],
            ["production"],
            ["test", "test"],
            ["production", "test"],
            ["test", "preview"],
        ):
            with self.subTest(deployment_environments=deployment_environments):
                entry = draft("example.com", "draft-example-com")
                if deployment_environments is not None:
                    entry["deploymentEnvironments"] = deployment_environments
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.build_scope_registry(
                        {"version": 2, "owner": "LynxPardelle", "drafts": [entry]},
                        expected_draft_count=1,
                        tenant_overrides={},
                        environment="test",
                    )

    def test_canary_owner_is_resolved_from_the_exact_registered_repository(self):
        mixed_owner_registry = registry(
            draft("grupoastralegal.com", "draft-grupoastralegal-com"),
            draft(
                "thehairnarrative.com",
                "draft-thehairnarrative-com",
                owner="Toydrum",
            ),
        )

        try:
            astra_owner = bootstrap._registered_repo_owner(
                mixed_owner_registry,
                "draft-grupoastralegal-com",
            )
            hair_owner = bootstrap._registered_repo_owner(
                mixed_owner_registry,
                "draft-thehairnarrative-com",
            )
        except (AttributeError, bootstrap.BootstrapError) as exc:
            self.fail(f"registered canary owner was not resolved: {exc}")

        self.assertEqual(astra_owner, "LynxPardelle")
        self.assertEqual(hair_owner, "Toydrum")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._registered_repo_owner(mixed_owner_registry, "draft-missing-com")

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

    def test_role_evidence_accepts_the_exact_github_immutable_subject(self):
        expected = binding(
            "thehairnarrative.com",
            "draft-thehairnarrative-com",
            "test",
        )
        role_name = expected["roleArn"].split(":role/", 1)[1]
        subject = (
            "repo:Toydrum@1234567/"
            "draft-thehairnarrative-com@7654321:environment:test"
        )
        evidence = {
            "github": {
                "DRAFT_DOMAIN": "thehairnarrative.com",
                "AWS_ROLE_ARN": expected["roleArn"],
            },
            "iam": {
                "Arn": expected["roleArn"],
                "AssumeRolePolicyDocument": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": (
                                "arn:aws:iam::123456789012:oidc-provider/"
                                "token.actions.githubusercontent.com"
                            )
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {"StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:ref": "refs/heads/test",
                            "token.actions.githubusercontent.com:sub": subject,
                        }},
                    }],
                },
                "RoleName": role_name,
            },
        }

        try:
            verified = bootstrap.verify_role_evidence(
                owner="Toydrum",
                domain="thehairnarrative.com",
                repo="draft-thehairnarrative-com",
                environment="test",
                account_id="123456789012",
                evidence=evidence,
                oidc_subject=subject,
            )
        except (bootstrap.BootstrapError, TypeError) as exc:
            self.fail(f"exact immutable GitHub subject was rejected: {exc}")

        self.assertEqual(verified, expected)

    def test_immutable_subject_rejects_mismatched_or_wildcard_coordinates(self):
        for subject in (
            (
                "repo:OtherOwner@1234567/"
                "draft-thehairnarrative-com@7654321:environment:test"
            ),
            (
                "repo:Toydrum@1234567/"
                "other-repo@7654321:environment:test"
            ),
            "repo:Toydrum/*:environment:test",
        ):
            with self.subTest(subject=subject):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validated_github_oidc_subject(
                        subject,
                        owner="Toydrum",
                        repo="draft-thehairnarrative-com",
                        environment="test",
                    )

    def test_cross_owner_binding_reads_the_resolved_repository_variables_and_subject(self):
        external = draft(
            "thehairnarrative.com",
            "draft-thehairnarrative-com",
            owner="Toydrum",
        )
        expected = binding(
            "thehairnarrative.com",
            "draft-thehairnarrative-com",
            "test",
        )
        role_name = expected["roleArn"].split(":role/", 1)[1]
        subject_prefix = (
            "repo:Toydrum@1234567/"
            "draft-thehairnarrative-com@7654321"
        )

        class CrossOwnerRunner:
            def __init__(self):
                self.commands = []

            def run_json(self, arguments):
                self.commands.append(arguments)
                if arguments[:2] == ["gh", "api"]:
                    return {
                        "use_default": True,
                        "use_immutable_subject": False,
                        "sub_claim_prefix": subject_prefix,
                    }
                if arguments[:2] == ["gh", "variable"]:
                    if arguments[4:6] != ["Toydrum/draft-thehairnarrative-com", "--env"]:
                        self.fail_unexpected(arguments)
                    return [
                        {"name": "DRAFT_DOMAIN", "value": "thehairnarrative.com"},
                        {"name": "AWS_ROLE_ARN", "value": expected["roleArn"]},
                    ]
                if arguments[:3] == ["aws", "iam", "get-role"]:
                    return {"Role": {
                        "Arn": expected["roleArn"],
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {"Statement": [{
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": (
                                    "arn:aws:iam::123456789012:oidc-provider/"
                                    "token.actions.githubusercontent.com"
                                )
                            },
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {"StringEquals": {
                                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                "token.actions.githubusercontent.com:ref": "refs/heads/test",
                                "token.actions.githubusercontent.com:sub": (
                                    f"{subject_prefix}:environment:test"
                                ),
                            }},
                        }]},
                    }}
                self.fail_unexpected(arguments)

            @staticmethod
            def fail_unexpected(arguments):
                raise AssertionError(f"unexpected command: {arguments}")

        runner = CrossOwnerRunner()
        try:
            bindings = bootstrap.collect_verified_bindings(
                registry(external),
                environment="test",
                profile="default",
                account_id="123456789012",
                runner=runner,
            )
        except (bootstrap.BootstrapError, AssertionError) as exc:
            self.fail(f"cross-owner binding was not verified safely: {exc}")

        self.assertEqual(bindings, [expected])
        self.assertTrue(any(
            command[:5] == [
                "gh", "variable", "list", "--repo",
                "Toydrum/draft-thehairnarrative-com",
            ]
            for command in runner.commands
        ))

    def test_cross_owner_variable_denial_fails_closed_without_fallback(self):
        external = draft(
            "thehairnarrative.com",
            "draft-thehairnarrative-com",
            owner="Toydrum",
        )

        class DeniedRunner:
            def __init__(self):
                self.commands = []

            def run_json(self, arguments):
                self.commands.append(arguments)
                if arguments[:2] == ["gh", "api"]:
                    return {
                        "use_default": True,
                        "sub_claim_prefix": (
                            "repo:Toydrum@1234567/"
                            "draft-thehairnarrative-com@7654321"
                        ),
                    }
                if arguments[:5] == [
                    "gh", "variable", "list", "--repo",
                    "Toydrum/draft-thehairnarrative-com",
                ]:
                    raise bootstrap.BootstrapError("GitHub variables are unavailable")
                raise AssertionError(f"unexpected command: {arguments}")

        runner = DeniedRunner()
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.collect_verified_bindings(
                registry(external),
                environment="test",
                profile="default",
                account_id="123456789012",
                runner=runner,
            )

        self.assertFalse(any(command[:2] == ["aws", "iam"] for command in runner.commands))
        self.assertFalse(any(
            "LynxPardelle/draft-thehairnarrative-com" in command
            for command in runner.commands
        ))

    def test_v2_production_binding_collection_skips_test_only_drafts(self):
        shared = draft("example.com", "draft-example-com")
        shared["deploymentEnvironments"] = ["test", "production"]
        test_only = draft(
            "thehairnarrative.com",
            "draft-thehairnarrative-com",
            owner="Toydrum",
        )
        test_only["deploymentEnvironments"] = ["test"]
        scoped_registry = {
            "version": 2,
            "owner": "LynxPardelle",
            "drafts": [shared, test_only],
        }
        expected = binding("example.com", "draft-example-com", "production")
        role_name = expected["roleArn"].split(":role/", 1)[1]

        class ProductionRunner:
            def __init__(self):
                self.commands = []

            def run_json(self, arguments):
                self.commands.append(arguments)
                joined = " ".join(arguments)
                if "Toydrum" in joined or "thehairnarrative" in joined:
                    raise AssertionError("test-only draft was queried for production")
                if arguments[:2] == ["gh", "api"]:
                    return {
                        "use_default": True,
                        "sub_claim_prefix": "repo:LynxPardelle/draft-example-com",
                    }
                if arguments[:2] == ["gh", "variable"]:
                    return [
                        {"name": "DRAFT_DOMAIN", "value": "example.com"},
                        {"name": "AWS_ROLE_ARN", "value": expected["roleArn"]},
                    ]
                if arguments[:3] == ["aws", "iam", "get-role"]:
                    return {"Role": {
                        "Arn": expected["roleArn"],
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {"Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Federated": (
                                "arn:aws:iam::123456789012:oidc-provider/"
                                "token.actions.githubusercontent.com"
                            )},
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {"StringEquals": {
                                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                "token.actions.githubusercontent.com:ref": "refs/heads/main",
                                "token.actions.githubusercontent.com:sub": (
                                    "repo:LynxPardelle/draft-example-com:environment:production"
                                ),
                            }},
                        }]},
                    }}
                raise AssertionError(f"unexpected command: {arguments}")

        runner = ProductionRunner()
        bindings = bootstrap.collect_verified_bindings(
            scoped_registry,
            environment="production",
            profile="default",
            account_id="123456789012",
            runner=runner,
        )

        self.assertEqual(bindings, [expected])
        self.assertFalse(any("Toydrum" in " ".join(command) for command in runner.commands))

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

    def test_production_scopes_must_be_an_exact_subset_of_test(self):
        shared = {
            "domain": "example.com",
            "repo": "draft-example-com",
            "tenantId": "draft-example-com",
            "draftId": "draft-example-com",
        }
        test_only = {
            "domain": "test-only.example.com",
            "repo": "draft-test-only-example-com",
            "tenantId": "draft-test-only-example-com",
            "draftId": "draft-test-only-example-com",
        }
        test_bytes = bootstrap.canonical_json_bytes({
            "version": 1,
            "scopes": [shared, test_only],
        })
        production_bytes = bootstrap.canonical_json_bytes({
            "version": 1,
            "scopes": [shared],
        })

        bootstrap.require_production_scope_subset(test_bytes, production_bytes)
        bootstrap.require_production_scope_subset(production_bytes, production_bytes)

        mutated = copy.deepcopy(shared)
        mutated["tenantId"] = "other"
        for invalid_production in (
            {"version": 1, "scopes": [mutated]},
            {"version": 1, "scopes": [shared, test_only, {
                "domain": "production-only.example.com",
                "repo": "draft-production-only-example-com",
                "tenantId": "draft-production-only-example-com",
                "draftId": "draft-production-only-example-com",
            }]},
        ):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.require_production_scope_subset(
                    test_bytes,
                    bootstrap.canonical_json_bytes(invalid_production),
                )

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

        external_canary = copy.deepcopy(snapshot)
        for state in (external_canary, external_canary["finalState"]):
            state["canaryPulls"][0]["base"]["repo"]["full_name"] = (
                f"Toydrum/{canary_repo}"
            )
            state["canaryPulls"][0]["head"]["repo"]["full_name"] = (
                f"Toydrum/{canary_repo}"
            )
        try:
            bootstrap.validate_test_green_snapshot(
                external_canary,
                owner=owner,
                canary_owner="Toydrum",
                test_commit=commit,
                test_run_id=123,
                canary_repo=canary_repo,
                canary_run_id=456,
                expected_scope_bytes=scope_bytes,
                expected_authz_bytes=authz_bytes,
            )
        except (TypeError, bootstrap.BootstrapError) as exc:
            self.fail(f"external canary owner was not kept separate: {exc}")

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
