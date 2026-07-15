import copy
import hashlib
import importlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "server-features"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "server-features" / "valid" / "example.com" / "server"
SCHEMA_NAMES = (
    "data-spaces.schema.json",
    "commerce.schema.json",
    "integration-bindings.schema.json",
    "notification-policies.schema.json",
)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class ServerPolicyValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.validator = importlib.import_module("server_policy_validation")
        except ModuleNotFoundError:
            cls.validator = None

    def setUp(self):
        if self.validator is None:
            return
        self.production_legacy_hashes = copy.deepcopy(
            self.validator.LEGACY_DESCRIPTOR_GRANDFATHER_HASHES
        )
        fixture = load_json(FIXTURE_DIR / "auth-profile-registry.json")
        fixture_hash = hashlib.sha256(
            self.validator._canonical_json(fixture).encode("utf-8")
        ).hexdigest()
        patched = copy.deepcopy(self.production_legacy_hashes)
        patched[("example.com", "auth-profile-registry.json")] = {fixture_hash}
        self.validator.LEGACY_DESCRIPTOR_GRANDFATHER_HASHES = patched

    def tearDown(self):
        if self.validator is not None:
            self.validator.LEGACY_DESCRIPTOR_GRANDFATHER_HASHES = self.production_legacy_hashes

    def test_versioned_schemas_and_golden_corpus_validate(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        files = []
        for schema_name in SCHEMA_NAMES:
            schema_path = SCHEMA_DIR / schema_name
            fixture_path = FIXTURE_DIR / schema_name.replace(".schema", "")
            self.assertTrue(schema_path.is_file(), schema_name)
            self.assertTrue(fixture_path.is_file(), fixture_path.name)
            self.validator.assert_supported_schema(load_json(schema_path))
            self.assertEqual(
                self.validator.validate_schema(load_json(schema_path), load_json(fixture_path)),
                [],
            )
            files.append({
                "path": f"example.com/server/{fixture_path.name}",
                "content": load_json(fixture_path),
            })
        auth_registry = FIXTURE_DIR / "auth-profile-registry.json"
        self.assertTrue(auth_registry.is_file())
        files.append({
            "path": "example.com/server/auth-profile-registry.json",
            "content": load_json(auth_registry),
        })
        self.validator.validate_server_policy_files("example.com", "test", files)

    def test_validator_enforces_all_supported_keyword_families(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        schema = {
            "type": "object",
            "required": ["id", "count", "values", "mode"],
            "properties": {
                "id": {"type": "string", "minLength": 2, "maxLength": 4, "pattern": "^[a-z]+$"},
                "count": {"type": "integer", "minimum": 1, "maximum": 2},
                "values": {
                    "type": "array", "minItems": 1, "maxItems": 2,
                    "uniqueItems": True, "items": {"type": "string"},
                },
                "mode": {"enum": ["on", "off"]},
                "detail": {"type": "string"},
            },
            "maxProperties": 5,
            "allOf": [{
                "if": {"properties": {"mode": {"const": "on"}}, "required": ["mode"]},
                "then": {"required": ["detail"]},
            }],
            "additionalProperties": False,
        }
        self.validator.assert_supported_schema(schema)
        errors = self.validator.validate_schema(schema, {
            "id": "A", "count": 2.5, "values": ["x", "x", "z"], "mode": "on", "extra": True,
        })
        codes = {error["code"] for error in errors}
        self.assertTrue({
            "string_min_length", "string_pattern", "integer_required", "array_max_items",
            "array_unique", "required", "property_not_allowed",
        }.issubset(codes))
        with self.assertRaisesRegex(ValueError, "unsupported_schema_keyword"):
            self.validator.assert_supported_schema({"type": "string", "format": "email"})

    def test_meta_schema_rejects_keyword_shapes_the_runtime_does_not_implement(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        invalid_schemas = (
            {"type": "array", "items": [{"type": "string"}]},
            {"type": "object", "additionalProperties": "reject"},
            {"anyOf": [True, {"type": "string"}]},
            {"type": 7},
            {"type": "object", "required": "id"},
            {"type": "array", "minItems": "1"},
            {"type": "string", "pattern": 7},
            {"type": "object", "properties": {"id": True}},
        )
        for schema in invalid_schemas:
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(ValueError, "invalid_schema_keyword_shape"):
                    self.validator.assert_supported_schema(schema)

    def test_invalid_server_policy_is_redacted_and_fails_before_storage(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        sentinel = "provider-private-value-must-not-echo"
        integration["bindings"][0]["unexpected"] = sentinel
        files = [{
            "path": "example.com/server/integration-bindings.json",
            "content": integration,
        }]
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", files)
        self.assertEqual(str(raised.exception), "server_policy_invalid")
        self.assertNotIn(sentinel, repr(raised.exception))

    def test_legacy_descriptors_are_closed_to_three_verified_canonical_hashes(self):
        self.assertEqual(
            {
                ("music.lynxpardelle.com", "integrations.json"): {
                    "e92571c6f7f0661c3fb713f85739776d74a4f8a29783c5029578823af64ce401"
                },
                ("pokeapi-demo.zoolandingpage.com.mx", "integrations.json"): {
                    "8e3716d6041d9ff69760162fc1b9ac29e98c9f3e0f162908ab656fd6a7306145"
                },
                ("zoositioweb.com.mx", "auth-profile-registry.json"): {
                    "88f94c06c748375c85366ee46d15ce771573bc78669d183acd0efb6442a257fa"
                },
            },
            self.production_legacy_hashes,
        )

        synthetic = {"version": 1, "sources": [{"id": "catalog"}]}
        canonical = self.validator._canonical_json(synthetic).encode("utf-8")
        synthetic_hash = hashlib.sha256(canonical).hexdigest()
        self.validator.LEGACY_DESCRIPTOR_GRANDFATHER_HASHES = {
            ("example.com", "integrations.json"): {synthetic_hash}
        }
        self.validator.validate_server_policy_files("example.com", "test", [{
            "path": "example.com/server/integrations.json",
            "content": synthetic,
        }])

        modified = copy.deepcopy(synthetic)
        modified["value"] = "harmless-but-not-grandfathered"
        with self.assertRaises(self.validator.PolicyValidationError):
            self.validator.validate_server_policy_files("example.com", "test", [{
                "path": "example.com/server/integrations.json",
                "content": modified,
            }])

    def test_structural_financial_identifier_detector_rejects_clabe_and_pan_without_length_only_false_positives(self):
        def clabe(prefix: str) -> str:
            weights = (3, 7, 1)
            check = (10 - sum(int(digit) * weights[index % 3] for index, digit in enumerate(prefix)) % 10) % 10
            return prefix + str(check)

        def pan(prefix: str) -> str:
            total = 0
            parity = (len(prefix) + 1) % 2
            for index, digit_text in enumerate(prefix):
                digit = int(digit_text)
                if index % 2 == parity:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                total += digit
            return prefix + str((10 - total % 10) % 10)

        clabe_value = clabe("12345678901234567")
        pan_value = pan("4" + "2" * 14)
        self.assertTrue(self.validator._contains_structured_financial_identifier({"connectionId": clabe_value}))
        self.assertTrue(self.validator._contains_structured_financial_identifier({"value": pan_value[:4] + "-" + pan_value[4:]}))
        self.assertTrue(self.validator._contains_structured_financial_identifier({"path": f"/{clabe_value}"}))
        self.assertTrue(self.validator._contains_structured_financial_identifier({"query": f"/pago?method={pan_value}"}))
        self.assertTrue(self.validator._contains_structured_financial_identifier({"label": f"prefix{clabe_value}suffix"}))
        self.assertTrue(self.validator._contains_structured_financial_identifier({"nested": [{"value": f"id-{pan_value}-end"}]}))
        self.assertFalse(self.validator._contains_structured_financial_identifier({"value": clabe_value[:-1] + str((int(clabe_value[-1]) + 1) % 10)}))
        self.assertFalse(self.validator._contains_structured_financial_identifier({"value": "12345678901234567890"}))
        self.assertFalse(self.validator._contains_structured_financial_identifier({"value": "20260714200500"}))
        self.assertFalse(self.validator._contains_structured_financial_identifier({"value": "catalog-1234567890"}))

        commerce = load_json(FIXTURE_DIR / "commerce.json")
        commerce["commerce"]["checkout"]["successPath"] = f"/{clabe_value}"
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [{
                "path": "example.com/server/commerce.json",
                "content": commerce,
            }])
        self.assertEqual(raised.exception.code, "pii_value_forbidden")

    def test_semantic_mismatches_fail_closed(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        files = []
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            files.append({
                "path": f"example.com/server/{fixture_path.name}",
                "content": load_json(fixture_path),
            })
        invalid = copy.deepcopy(files)
        next(file for file in invalid if file["path"].endswith("data-spaces.json"))["content"]["scope"]["environment"] = "production"
        next(file for file in invalid if file["path"].endswith("commerce.json"))["content"]["commerce"]["payments"]["bindingId"] = "missing"
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", invalid)
        self.assertEqual(str(raised.exception), "server_policy_invalid")

    def test_all_descriptor_scopes_must_match_the_authorized_server_scope(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        files = []
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            files.append({
                "path": f"example.com/server/{fixture_path.name}",
                "content": load_json(fixture_path),
            })

        inconsistent = copy.deepcopy(files)
        next(file for file in inconsistent if file["path"].endswith("commerce.json"))["content"]["scope"]["tenantId"] = "other-tenant"
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files(
                "example.com",
                "test",
                inconsistent,
                expected_scope={"tenantId": "tenant-example", "draftId": "draft-example"},
            )
        self.assertEqual(raised.exception.code, "scope_binding_mismatch")

        authorized_mismatch = copy.deepcopy(files)
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files(
                "example.com",
                "test",
                authorized_mismatch,
                expected_scope={"tenantId": "other-tenant", "draftId": "draft-example"},
            )
        self.assertEqual(raised.exception.code, "scope_binding_mismatch")

    def test_binding_mode_and_provider_contracts_are_environment_bound(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        integration["bindings"][0]["mode"] = "live"
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [{
                "path": "example.com/server/integration-bindings.json",
                "content": integration,
            }])
        self.assertEqual(raised.exception.code, "mode_environment_mismatch")

        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        integration["bindings"][0]["adapterVersion"] = "v999"
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [{
                "path": "example.com/server/integration-bindings.json",
                "content": integration,
            }])
        self.assertEqual(raised.exception.code, "adapter_version_not_supported")

        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        integration["bindings"][0]["capabilities"].append("unreviewed-capability")
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [{
                "path": "example.com/server/integration-bindings.json",
                "content": integration,
            }])
        self.assertEqual(raised.exception.code, "provider_capability_not_supported")

    def test_stripe_settings_and_active_commerce_capabilities_are_required(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        integration["bindings"][0].pop("stripe")
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [{
                "path": "example.com/server/integration-bindings.json",
                "content": integration,
            }])
        self.assertEqual(raised.exception.code, "stripe_settings_required")

        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        integration["bindings"][0]["capabilities"].remove("subscriptions")
        commerce = load_json(FIXTURE_DIR / "commerce.json")
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [
                {"path": "example.com/server/integration-bindings.json", "content": integration},
                {"path": "example.com/server/commerce.json", "content": commerce},
            ])
        self.assertEqual(raised.exception.code, "commerce_provider_capability_required")

    def test_active_notification_policy_requires_matching_send_binding(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        integration["bindings"].append({
            "id": "smtp-primary",
            "provider": "email.smtp",
            "adapterVersion": "v1",
            "connectionId": "billing-mailbox",
            "status": "active",
            "mode": "test",
            "capabilities": ["send"],
        })
        notification = load_json(FIXTURE_DIR / "notification-policies.json")
        notification["policies"][0]["status"] = "active"

        no_smtp = copy.deepcopy(integration)
        no_smtp["bindings"].pop()
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [
                {"path": "example.com/server/integration-bindings.json", "content": no_smtp},
                {"path": "example.com/server/notification-policies.json", "content": notification},
            ])
        self.assertEqual(raised.exception.code, "notification_binding_not_found")

        integration["bindings"][1]["capabilities"] = ["receive"]
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [
                {"path": "example.com/server/integration-bindings.json", "content": integration},
                {"path": "example.com/server/notification-policies.json", "content": notification},
            ])
        self.assertIn(
            raised.exception.code,
            {"provider_capability_not_supported", "notification_send_capability_required"},
        )

    def test_commerce_notification_references_and_fiscal_disclosures_are_code_owned(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        files = []
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            files.append({
                "path": f"example.com/server/{fixture_path.name}",
                "content": load_json(fixture_path),
            })
        commerce = next(file for file in files if file["path"].endswith("commerce.json"))["content"]["commerce"]
        commerce["notificationPolicyIds"] = ["missing-policy"]
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", files)
        self.assertEqual(raised.exception.code, "notification_policy_not_found")

        commerce["notificationPolicyIds"] = ["billing-ops"]
        commerce["fiscal"] = {
            "enabled": True,
            "manual": True,
            "disclosureId": "draft-authored-message",
            "taxBehavior": "exclusive",
            "retentionDays": 90,
            "requestWindowHours": 72,
        }
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", files)
        self.assertEqual(raised.exception.code, "unknown_fiscal_disclosure")

        commerce["fiscal"]["disclosureId"] = "manual-invoice-v1"
        self.validator.validate_server_policy_files("example.com", "test", files)

    def test_phase_one_capability_and_notification_allowlists_are_code_owned(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")

        def golden_files():
            return [
                {
                    "path": f"example.com/server/{fixture_path.name}",
                    "content": load_json(fixture_path),
                }
                for fixture_path in sorted(FIXTURE_DIR.glob("*.json"))
            ]

        scenarios = (
            (
                "data_space_capability_not_supported",
                lambda files: next(file for file in files if file["path"].endswith("data-spaces.json"))
                ["content"]["spaces"][0]["access"]["capabilities"].append("data-space:record:delete"),
            ),
            (
                "commerce_capability_not_supported",
                lambda files: next(file for file in files if file["path"].endswith("commerce.json"))
                ["content"]["commerce"]["adminAccess"]["capabilities"].append("commerce:catalog:delete"),
            ),
            (
                "notification_type_not_supported",
                lambda files: next(file for file in files if file["path"].endswith("notification-policies.json"))
                ["content"]["policies"][0]["notificationTypes"].append("refund-issued"),
            ),
            (
                "notification_template_not_supported",
                lambda files: next(file for file in files if file["path"].endswith("notification-policies.json"))
                ["content"]["policies"][0]["templateIds"].append("refund-issued-v1"),
            ),
            (
                "notification_template_mismatch",
                lambda files: next(file for file in files if file["path"].endswith("notification-policies.json"))
                ["content"]["policies"][0].update({"templateIds": ["payment-succeeded-v1"]}),
            ),
            (
                "subscription_payments_required",
                lambda files: next(file for file in files if file["path"].endswith("commerce.json"))
                ["content"]["commerce"]["payments"].update({"subscriptions": False}),
            ),
        )
        for expected_code, mutate in scenarios:
            with self.subTest(expected_code=expected_code):
                files = golden_files()
                mutate(files)
                with self.assertRaises(self.validator.PolicyValidationError) as raised:
                    self.validator.validate_server_policy_files("example.com", "test", files)
                self.assertEqual(raised.exception.code, expected_code)

    def test_protected_features_require_an_active_auth_profile_in_the_same_scope(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")

        def golden_files():
            return [
                {
                    "path": f"example.com/server/{fixture_path.name}",
                    "content": load_json(fixture_path),
                }
                for fixture_path in sorted(FIXTURE_DIR.glob("*.json"))
            ]

        files = [file for file in golden_files() if not file["path"].endswith("auth-profile-registry.json")]
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", files)
        self.assertEqual(raised.exception.code, "auth_profile_registry_required")

        scenarios = (
            (
                "auth_profile_not_found",
                lambda files: next(file for file in files if file["path"].endswith("commerce.json"))
                ["content"]["commerce"]["adminAccess"].update({"authProfileId": "missing-profile"}),
            ),
            (
                "auth_profile_inactive",
                lambda files: next(file for file in files if file["path"].endswith("auth-profile-registry.json"))
                ["content"]["profiles"][0].update({"status": "suspended"}),
            ),
            (
                "auth_profile_scope_mismatch",
                lambda files: next(file for file in files if file["path"].endswith("auth-profile-registry.json"))
                ["content"]["profiles"][0].update({"tenantId": "other-tenant"}),
            ),
            (
                "auth_profile_scope_mismatch",
                lambda files: next(file for file in files if file["path"].endswith("auth-profile-registry.json"))
                ["content"]["profiles"][0].update({"domain": "other.example.com"}),
            ),
        )
        for expected_code, mutate in scenarios:
            with self.subTest(expected_code=expected_code):
                files = golden_files()
                mutate(files)
                registry_content = next(
                    file for file in files
                    if file["path"].endswith("auth-profile-registry.json")
                )["content"]
                registry_hash = hashlib.sha256(
                    self.validator._canonical_json(registry_content).encode("utf-8")
                ).hexdigest()
                self.validator.LEGACY_DESCRIPTOR_GRANDFATHER_HASHES.setdefault(
                    ("example.com", "auth-profile-registry.json"), set()
                ).add(registry_hash)
                with self.assertRaises(self.validator.PolicyValidationError) as raised:
                    self.validator.validate_server_policy_files("example.com", "test", files)
                self.assertEqual(raised.exception.code, expected_code)

        duplicate = golden_files()
        registry = next(file for file in duplicate if file["path"].endswith("auth-profile-registry.json"))["content"]
        registry["profiles"].append(copy.deepcopy(registry["profiles"][0]))
        duplicate_hash = hashlib.sha256(
            self.validator._canonical_json(registry).encode("utf-8")
        ).hexdigest()
        self.validator.LEGACY_DESCRIPTOR_GRANDFATHER_HASHES.setdefault(
            ("example.com", "auth-profile-registry.json"), set()
        ).add(duplicate_hash)
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", duplicate)
        self.assertEqual(raised.exception.code, "duplicate_id")

    def test_notification_secret_preflight_has_a_bounded_call_budget(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        notification = load_json(FIXTURE_DIR / "notification-policies.json")
        base_policy = notification["policies"][0]
        base_policy["status"] = "active"
        base_policy["recipientSets"] = [
            {"id": f"recipients-{index}", "version": 1, "members": [{"id": "primary"}]}
            for index in range(10)
        ]
        second = copy.deepcopy(base_policy)
        second["id"] = "billing-ops-secondary"
        second["connectionId"] = "billing-mailbox-secondary"
        second["recipientSets"] = [
            {"id": f"secondary-{index}", "version": 1, "members": [{"id": "primary"}]}
            for index in range(10)
        ]
        notification["policies"].append(second)
        described = []

        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_notification_secrets(
                [{"path": "example.com/server/notification-policies.json", "content": notification}],
                "test",
                lambda secret_id: described.append(secret_id) or {},
            )
        self.assertEqual(raised.exception.code, "notification_secret_limit_exceeded")
        self.assertEqual(described, [])

    def test_provider_names_come_from_code_owned_allowlists(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        integration = load_json(FIXTURE_DIR / "integration-bindings.json")
        integration["bindings"][0]["provider"] = "unreviewed-provider"
        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "test", [{
                "path": "example.com/server/integration-bindings.json",
                "content": integration,
            }])
        self.assertEqual(raised.exception.code, "unknown_provider")

    def test_descriptor_approval_ids_cannot_self_authorize_production(self):
        self.assertIsNotNone(self.validator, "server_policy_validation.py must exist")
        files = []
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            content = load_json(fixture_path)
            if "scope" in content:
                content["scope"]["environment"] = "production"
            files.append({"path": f"example.com/server/{fixture_path.name}", "content": content})
        binding = next(file for file in files if file["path"].endswith("integration-bindings.json"))["content"]["bindings"][0]
        binding["mode"] = "live"
        binding["stripe"]["taxMode"] = "stripe-tax"
        binding["stripe"]["taxApprovalId"] = "self-asserted-tax-approval"
        next(file for file in files if file["path"].endswith("integration-bindings.json"))["content"]["bindings"].append({
            "id": "smtp-primary",
            "provider": "email.smtp",
            "adapterVersion": "v1",
            "connectionId": "billing-mailbox",
            "status": "active",
            "mode": "live",
            "capabilities": ["send"],
        })
        notification = next(file for file in files if file["path"].endswith("notification-policies.json"))["content"]["policies"][0]
        notification["status"] = "active"
        notification["transportApprovalId"] = "self-asserted-transport-approval"

        with self.assertRaises(self.validator.PolicyValidationError) as raised:
            self.validator.validate_server_policy_files("example.com", "production", files)
        self.assertEqual(raised.exception.code, "live_gate_unverified")


if __name__ == "__main__":
    unittest.main()
