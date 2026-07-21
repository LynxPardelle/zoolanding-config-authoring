import hashlib
import json
import math
import re
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, Optional


MAX_DESCRIPTOR_BYTES = 256 * 1024
MAX_DEPTH = 32
MAX_ERRORS = 64
SCHEMA_DIR = Path(__file__).resolve().parent / "schemas" / "server-features"
SERVER_SCHEMA_FILES = {
    "data-spaces.json": "data-spaces.schema.json",
    "commerce.json": "commerce.schema.json",
    "integration-bindings.json": "integration-bindings.schema.json",
    "notification-policies.json": "notification-policies.schema.json",
}
LEGACY_SERVER_FILES = {"auth-profile-registry.json", "integrations.json"}
# Closed compatibility manifest verified July 14, 2026 Central Time against the
# canonical hub files and the currently referenced test/production S3 versions.
# New or modified legacy descriptors must migrate to a closed server-feature contract.
LEGACY_DESCRIPTOR_GRANDFATHER_HASHES = {
    ("music.lynxpardelle.com", "integrations.json"): {
        "e92571c6f7f0661c3fb713f85739776d74a4f8a29783c5029578823af64ce401",
    },
    ("pokeapi-demo.zoolandingpage.com.mx", "integrations.json"): {
        "8e3716d6041d9ff69760162fc1b9ac29e98c9f3e0f162908ab656fd6a7306145",
    },
    ("zoositioweb.com.mx", "auth-profile-registry.json"): {
        "88f94c06c748375c85366ee46d15ce771573bc78669d183acd0efb6442a257fa",
    },
}
INTEGRATION_PROVIDER_CONTRACTS = {
    "stripe": {
        "adapterVersions": {"v1"},
        "capabilities": {
            "connect-onboarding", "checkout", "one-time-payments", "subscriptions",
            "prices", "coupons", "customer-portal",
        },
    },
    "email.smtp": {
        "adapterVersions": {"v1"},
        "capabilities": {"send"},
    },
}
NOTIFICATION_PROVIDERS = {"email.smtp"}
FISCAL_DISCLOSURES = {"manual-invoice-v1"}
DATA_SPACE_CAPABILITIES = {
    "data-space:record:read",
    "data-space:record:write",
    "data-space:schema:write",
    "data-space:publish",
}
COMMERCE_CAPABILITIES = {
    "commerce:catalog:read",
    "commerce:catalog:write",
    "commerce:inventory:write",
    "commerce:subscription:manage",
    "commerce:fiscal:manage",
}
NOTIFICATION_TEMPLATES_BY_TYPE = {
    "payment-succeeded": "payment-succeeded-v1",
    "payment-failed": "payment-failed-v1",
}
MAX_NOTIFICATION_SECRET_CHECKS = 20
SUPPORTED_SCHEMA_KEYWORDS = {
    "$schema", "$id", "$ref", "title", "description", "definitions", "type", "required",
    "properties", "additionalProperties", "propertyNames", "minProperties", "maxProperties",
    "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern",
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "const", "anyOf",
    "oneOf", "allOf", "not", "if", "then", "else",
}
SIGNED_URL_MARKER_PATTERN = re.compile(
    r"[?&](?:"
    r"X-Amz-(?:Algorithm|Credential|Date|Expires|SignedHeaders|Signature|Security-Token)"
    r"|X-Goog-(?:Algorithm|Credential|Date|Expires|SignedHeaders|Signature)"
    r"|AWSAccessKeyId|GoogleAccessId|Signature|Policy|Key-Pair-Id|sig"
    r")=",
    re.IGNORECASE,
)
GENERIC_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:api[_-]?key|secret|token|password|passwd|pwd|client_secret|private_key|access_token|refresh_token)"
    r"\b\s*[:=]\s*[\"']?[^\"'`\s]{8,}",
    re.IGNORECASE,
)
CONCRETE_SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{4,}", re.IGNORECASE),
    re.compile(r"\bwhsec_[A-Za-z0-9_-]{4,}", re.IGNORECASE),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b", re.IGNORECASE),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", re.IGNORECASE),
    SIGNED_URL_MARKER_PATTERN,
)
SECRET_VALUE_PATTERNS = CONCRETE_SECRET_VALUE_PATTERNS + (GENERIC_SECRET_ASSIGNMENT_PATTERN,)
PII_VALUE_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"(?:wa\.me/\d{8,}|\+\d[\d\s().-]{7,}\d)", re.IGNORECASE),
    re.compile(r"\b(?:CURP|RFC|NSS|SSN|passport|pasaporte|INE|credencial(?:es)?|identificacion|identificación)\b", re.IGNORECASE),
)
SECRET_FIELD_NAME_PATTERN = re.compile(
    r"^(?:api[-_]?key|secret|token|password|passwd|pwd|client[-_]?secret|private[-_]?key|access[-_]?token|refresh[-_]?token)$",
    re.IGNORECASE,
)
PII_FIELD_NAME_PATTERN = re.compile(
    r"^(?:email|mail|phone|telefono|teléfono|whatsapp|address|direccion|dirección|rfc|curp|nss|ssn|passport|pasaporte|ine)$",
    re.IGNORECASE,
)
PROVIDER_RESOURCE_ID_PATTERN = re.compile(
    r"^(?:acct|cus|price|prod|sub|si|cs|pi|pm|src|ch|in|evt|seti|sess)_[A-Za-z0-9]",
    re.IGNORECASE,
)
LEGACY_SECRET_REF_SEGMENT = r"[A-Za-z0-9_.+=@-]+"
LEGACY_OPAQUE_SECRET_REF_PATTERN = re.compile(
    rf"^(?:/{LEGACY_SECRET_REF_SEGMENT}(?:/{LEGACY_SECRET_REF_SEGMENT})*"
    rf"|{LEGACY_SECRET_REF_SEGMENT}/{LEGACY_SECRET_REF_SEGMENT}(?:/{LEGACY_SECRET_REF_SEGMENT})*)$"
)
LEGACY_AWS_SECRET_REF_PATTERN = re.compile(
    rf"^arn:(?:aws|aws-us-gov|aws-cn):(?:"
    rf"ssm:[a-z0-9-]+:\d{{12}}:parameter/{LEGACY_SECRET_REF_SEGMENT}(?:/{LEGACY_SECRET_REF_SEGMENT})*"
    rf"|secretsmanager:[a-z0-9-]+:\d{{12}}:secret:{LEGACY_SECRET_REF_SEGMENT}(?:/{LEGACY_SECRET_REF_SEGMENT})*"
    rf")$"
)
LEGACY_PROVIDER_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
LEGACY_SECRET_REF_KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
LEGACY_SECRET_FIELD_COMPACT_PATTERN = re.compile(
    r"(?:apikey|secret|token|password|passwd|pwd|credential|clientsecret|privatekey|"
    r"accesstoken|refreshtoken|authorization|proxyauth|cookie|signingkey|webhookkey|"
    r"passphrase|bearer)",
)
LEGACY_PII_FIELD_COMPACT_PATTERN = re.compile(
    r"(?:email|mail|phone|telefono|whatsapp|address|direccion|rfc|curp|nss|ssn|"
    r"passport|pasaporte|clabe|iban|swift|bic|bankaccount|accountnumber|routingnumber|"
    r"sortcode|cardnumber|paymentcard|creditcard|debitcard|identitydocument|"
    r"governmentid|nationalid|taxid|identitynumber|documentnumber)",
)
LEGACY_SAFE_SECRET_METADATA_FIELDS = {
    "tokenUrl",
    "clientSecretField",
    "allowedTokenUses",
    "passwordRecovery",
    "csrfCookieName",
    "challengeCsrfCookieName",
    "mfaEnrollCsrfCookieName",
}
FINANCIAL_IDENTIFIER_CANDIDATE_PATTERN = re.compile(r"\d(?:[ -]*\d){11,}")


class PolicyValidationError(ValueError):
    def __init__(self, code: str = "server_policy_invalid"):
        self.code = code
        public_code = "notification_secret_unavailable" if code == "notification_secret_unavailable" else "server_policy_invalid"
        self.public_code = public_code
        super().__init__(public_code)


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _child_schemas(schema: Dict[str, Any]) -> list[Dict[str, Any]]:
    children: list[Dict[str, Any]] = []
    for key in ("definitions", "properties"):
        if _is_object(schema.get(key)):
            children.extend(child for child in schema[key].values() if _is_object(child))
    for key in ("items", "additionalProperties", "propertyNames", "not", "if", "then", "else"):
        if _is_object(schema.get(key)):
            children.append(schema[key])
    for key in ("anyOf", "oneOf", "allOf"):
        if isinstance(schema.get(key), list):
            children.extend(child for child in schema[key] if _is_object(child))
    return children


def assert_supported_schema(schema: Dict[str, Any], max_depth: int = MAX_DEPTH) -> None:
    json_types = {"null", "array", "object", "integer", "number", "boolean", "string"}

    def invalid_shape() -> None:
        raise ValueError("invalid_schema_keyword_shape")

    def visit(node: Dict[str, Any], depth: int) -> None:
        if not _is_object(node):
            raise ValueError("invalid_schema_node")
        if depth > max_depth:
            raise ValueError("schema_depth_exceeded")
        for key in node:
            if key not in SUPPORTED_SCHEMA_KEYWORDS:
                raise ValueError(f"unsupported_schema_keyword:{key}")

        for key in ("$schema", "$id", "title", "description"):
            if key in node and not isinstance(node[key], str):
                invalid_shape()
        if "$ref" in node:
            if not isinstance(node["$ref"], str) or not node["$ref"].startswith("#/"):
                invalid_shape()
            _resolve_ref(schema, node["$ref"])

        declared_type = node.get("type")
        if "type" in node:
            if isinstance(declared_type, str):
                if declared_type not in json_types:
                    invalid_shape()
            elif isinstance(declared_type, list):
                if (
                    not declared_type
                    or any(not isinstance(item, str) or item not in json_types for item in declared_type)
                    or len(declared_type) != len(set(declared_type))
                ):
                    invalid_shape()
            else:
                invalid_shape()

        for key in ("definitions", "properties"):
            if key in node and (
                not _is_object(node[key])
                or any(not isinstance(name, str) or not _is_object(child) for name, child in node[key].items())
            ):
                invalid_shape()
        if "required" in node and (
            not isinstance(node["required"], list)
            or any(not isinstance(item, str) for item in node["required"])
            or len(node["required"]) != len(set(node["required"]))
        ):
            invalid_shape()
        for key in ("items", "propertyNames", "not", "if", "then", "else"):
            if key in node and not _is_object(node[key]):
                invalid_shape()
        if "additionalProperties" in node and not isinstance(node["additionalProperties"], (bool, dict)):
            invalid_shape()
        for key in ("anyOf", "oneOf", "allOf"):
            if key in node and (
                not isinstance(node[key], list)
                or not node[key]
                or any(not _is_object(child) for child in node[key])
            ):
                invalid_shape()
        for key in ("minProperties", "maxProperties", "minItems", "maxItems", "minLength", "maxLength"):
            if key in node and (
                not isinstance(node[key], int)
                or isinstance(node[key], bool)
                or node[key] < 0
            ):
                invalid_shape()
        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            invalid_shape()
        if "pattern" in node and not isinstance(node["pattern"], str):
            invalid_shape()
        for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            if key in node and (
                not isinstance(node[key], (int, float))
                or isinstance(node[key], bool)
                or not math.isfinite(node[key])
            ):
                invalid_shape()
        if "enum" in node and (
            not isinstance(node["enum"], list)
            or not node["enum"]
            or len({_canonical_json(item) for item in node["enum"]}) != len(node["enum"])
        ):
            invalid_shape()

        if isinstance(node.get("pattern"), str):
            try:
                re.compile(node["pattern"])
            except re.error as exc:
                raise ValueError("invalid_schema_pattern") from exc
        for child in _child_schemas(node):
            visit(child, depth + 1)

    visit(schema, 0)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _same_json(left: Any, right: Any) -> bool:
    return _canonical_json(left) == _canonical_json(right)


def _type_matches(type_name: str, value: Any) -> bool:
    if type_name == "null":
        return value is None
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "object":
        return _is_object(value)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool) and -(2**53 - 1) <= value <= 2**53 - 1
    if type_name == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value))
        )
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "string":
        return isinstance(value, str)
    return False


def _resolve_ref(root: Dict[str, Any], ref: Any) -> Dict[str, Any]:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError("unsupported_schema_ref")
    current: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not _is_object(current) or part not in current:
            raise ValueError("unresolved_schema_ref")
        current = current[part]
    if not _is_object(current):
        raise ValueError("unresolved_schema_ref")
    return current


def validate_schema(
    schema: Dict[str, Any],
    value: Any,
    *,
    max_depth: int = MAX_DEPTH,
    max_errors: int = MAX_ERRORS,
) -> list[Dict[str, str]]:
    assert_supported_schema(schema, max_depth)

    def inspect(node: Dict[str, Any], current: Any, pointer: str, depth: int, errors: list[Dict[str, str]]) -> None:
        if len(errors) >= max_errors:
            return
        if depth > max_depth:
            errors.append({"code": "instance_depth_exceeded", "pointer": pointer})
            return

        def add(code: str) -> None:
            if len(errors) < max_errors:
                errors.append({"code": code, "pointer": pointer})

        if "$ref" in node:
            inspect(_resolve_ref(schema, node["$ref"]), current, pointer, depth + 1, errors)
            return
        if "const" in node and not _same_json(current, node["const"]):
            add("const_mismatch")
        if isinstance(node.get("enum"), list) and not any(_same_json(current, item) for item in node["enum"]):
            add("enum_mismatch")

        declared_types = node.get("type")
        if isinstance(declared_types, str):
            declared_types = [declared_types]
        elif not isinstance(declared_types, list):
            declared_types = []
        if declared_types and not any(_type_matches(type_name, current) for type_name in declared_types):
            add("integer_required" if "integer" in declared_types else "type_mismatch")
            return

        def branch_errors(candidate: Dict[str, Any]) -> list[Dict[str, str]]:
            result: list[Dict[str, str]] = []
            inspect(candidate, current, pointer, depth + 1, result)
            return result

        if isinstance(node.get("anyOf"), list) and not any(not branch_errors(candidate) for candidate in node["anyOf"]):
            add("any_of")
        if isinstance(node.get("oneOf"), list):
            matches = sum(1 for candidate in node["oneOf"] if not branch_errors(candidate))
            if matches != 1:
                add("one_of")
        for candidate in node.get("allOf") or []:
            inspect(candidate, current, pointer, depth + 1, errors)
        if _is_object(node.get("not")) and not branch_errors(node["not"]):
            add("not_allowed")
        if _is_object(node.get("if")):
            condition_matches = not branch_errors(node["if"])
            selected = node.get("then") if condition_matches else node.get("else")
            if _is_object(selected):
                inspect(selected, current, pointer, depth + 1, errors)

        if isinstance(current, str):
            if "minLength" in node and len(current) < node["minLength"]:
                add("string_min_length")
            if "maxLength" in node and len(current) > node["maxLength"]:
                add("string_max_length")
            if isinstance(node.get("pattern"), str) and re.search(node["pattern"], current) is None:
                add("string_pattern")

        if isinstance(current, (int, float)) and not isinstance(current, bool):
            if "minimum" in node and current < node["minimum"]:
                add("number_minimum")
            if "maximum" in node and current > node["maximum"]:
                add("number_maximum")
            if "exclusiveMinimum" in node and current <= node["exclusiveMinimum"]:
                add("number_exclusive_minimum")
            if "exclusiveMaximum" in node and current >= node["exclusiveMaximum"]:
                add("number_exclusive_maximum")

        if isinstance(current, list):
            if "minItems" in node and len(current) < node["minItems"]:
                add("array_min_items")
            if "maxItems" in node and len(current) > node["maxItems"]:
                add("array_max_items")
            if node.get("uniqueItems"):
                canonical_items = [_canonical_json(item) for item in current]
                if len(canonical_items) != len(set(canonical_items)):
                    add("array_unique")
            if _is_object(node.get("items")):
                for index, item in enumerate(current):
                    inspect(node["items"], item, f"{pointer}/{index}", depth + 1, errors)

        if _is_object(current):
            keys = list(current)
            if "minProperties" in node and len(keys) < node["minProperties"]:
                add("object_min_properties")
            if "maxProperties" in node and len(keys) > node["maxProperties"]:
                add("object_max_properties")
            for required_key in node.get("required") or []:
                if required_key not in current:
                    add("required")
            properties = node.get("properties") if _is_object(node.get("properties")) else {}
            for key in keys:
                if _is_object(node.get("propertyNames")):
                    inspect(node["propertyNames"], key, pointer, depth + 1, errors)
                escaped_key = key.replace("~", "~0").replace("/", "~1")
                if _is_object(properties.get(key)):
                    inspect(properties[key], current[key], f"{pointer}/{escaped_key}", depth + 1, errors)
                elif node.get("additionalProperties") is False:
                    add("property_not_allowed")
                elif _is_object(node.get("additionalProperties")):
                    inspect(node["additionalProperties"], current[key], pointer, depth + 1, errors)

    errors: list[Dict[str, str]] = []
    inspect(schema, value, "$", 0, errors)
    return errors


def _contains_pattern(
    value: Any,
    patterns: tuple[re.Pattern[str], ...],
    field_name_pattern: Optional[re.Pattern[str]] = None,
    depth: int = 0,
) -> bool:
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in patterns)
    if isinstance(value, list):
        return any(_contains_pattern(item, patterns, field_name_pattern, depth + 1) for item in value)
    if _is_object(value):
        return any(
            (field_name_pattern is not None and field_name_pattern.fullmatch(str(key)) is not None)
            or any(pattern.search(str(key)) for pattern in patterns)
            or _contains_pattern(item, patterns, field_name_pattern, depth + 1)
            for key, item in value.items()
        )
    return False


def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not 12 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit_text in enumerate(digits):
        digit = int(digit_text)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _clabe_valid(digits: str) -> bool:
    if len(digits) != 18 or not digits.isdigit():
        return False
    weights = (3, 7, 1)
    expected_check_digit = (
        10 - sum(int(digit) * weights[index % 3] for index, digit in enumerate(digits[:17])) % 10
    ) % 10
    return int(digits[-1]) == expected_check_digit


def _contains_structured_financial_identifier(value: Any, depth: int = 0) -> bool:
    """Detect checksum-valid CLABE/PAN strings without treating length alone as PII."""
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, str):
        for match in FINANCIAL_IDENTIFIER_CANDIDATE_PATTERN.finditer(value):
            digits = re.sub(r"[ -]", "", match.group(0))
            if _clabe_valid(digits) or _luhn_valid(digits):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_structured_financial_identifier(item, depth + 1) for item in value)
    if _is_object(value):
        return any(_contains_structured_financial_identifier(item, depth + 1) for item in value.values())
    return False


def _assert_grandfathered_legacy_descriptor(domain: str, name: str, content: Dict[str, Any]) -> None:
    digest = hashlib.sha256(_canonical_json(content).encode("utf-8")).hexdigest()
    if digest not in LEGACY_DESCRIPTOR_GRANDFATHER_HASHES.get((domain, name), set()):
        raise PolicyValidationError("legacy_descriptor_not_grandfathered")


def _is_approved_legacy_secret_ref(value: str) -> bool:
    if LEGACY_AWS_SECRET_REF_PATTERN.fullmatch(value):
        reference_name = value.split(":parameter/", 1)[1] if ":parameter/" in value else value.split(":secret:", 1)[1]
        patterns = CONCRETE_SECRET_VALUE_PATTERNS
    elif LEGACY_OPAQUE_SECRET_REF_PATTERN.fullmatch(value):
        reference_name = value.lstrip("/")
        patterns = SECRET_VALUE_PATTERNS
    else:
        return False

    if any(segment in {".", ".."} for segment in reference_name.split("/")):
        return False
    return not _contains_pattern(value, patterns)


def _compact_field_name(value: Any) -> str:
    normalized = unicodedata.normalize("NFKD", str(value))
    ascii_name = "".join(character for character in normalized if not unicodedata.combining(character))
    return re.sub(r"[^a-z0-9]", "", ascii_name.casefold())


def _validate_legacy_integration_sensitive_fields(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise PolicyValidationError("server_policy_invalid")
    if isinstance(value, list):
        for item in value:
            _validate_legacy_integration_sensitive_fields(item, depth + 1)
        return
    if not _is_object(value):
        return
    for key, item in value.items():
        if key == "credentialRef":
            if not isinstance(item, str) or not _is_approved_legacy_secret_ref(item):
                raise PolicyValidationError("secret_value_forbidden")
            continue
        if key in LEGACY_SAFE_SECRET_METADATA_FIELDS:
            if key == "clientSecretField" and (
                not isinstance(item, str)
                or not LEGACY_SECRET_REF_KEY_PATTERN.fullmatch(item)
            ):
                raise PolicyValidationError("secret_value_forbidden")
            _validate_legacy_integration_sensitive_fields(item, depth + 1)
            continue
        compact_name = _compact_field_name(key)
        if LEGACY_SECRET_FIELD_COMPACT_PATTERN.search(compact_name):
            raise PolicyValidationError("secret_value_forbidden")
        if (
            LEGACY_PII_FIELD_COMPACT_PATTERN.search(compact_name)
            or compact_name in {"ine", "ineid", "inenumber", "inenumero"}
        ):
            raise PolicyValidationError("pii_value_forbidden")
        _validate_legacy_integration_sensitive_fields(item, depth + 1)


def _validated_legacy_auth_profiles(
    content: Dict[str, Any],
    domain: str,
    expected_scope: Optional[Dict[str, str]],
) -> Dict[str, Dict[str, Any]]:
    profiles = content.get("profiles")
    if not isinstance(profiles, list):
        raise PolicyValidationError("auth_profile_scope_mismatch")
    profiles_by_id: Dict[str, Dict[str, Any]] = {}
    for profile in profiles:
        if not _is_object(profile):
            raise PolicyValidationError("auth_profile_scope_mismatch")
        profile_id = profile.get("authProfileId")
        tenant_id = profile.get("tenantId")
        if isinstance(profile_id, str) and profile_id in profiles_by_id:
            raise PolicyValidationError("duplicate_id")
        if (
            not isinstance(profile_id, str)
            or not LEGACY_PROVIDER_ID_PATTERN.fullmatch(profile_id)
            or not isinstance(tenant_id, str)
            or not LEGACY_PROVIDER_ID_PATTERN.fullmatch(tenant_id)
            or (expected_scope is not None and tenant_id != expected_scope.get("tenantId"))
            or (profile.get("domain") is not None and profile.get("domain") != domain)
        ):
            raise PolicyValidationError("auth_profile_scope_mismatch")
        profiles_by_id[profile_id] = profile
    return profiles_by_id


def _auth_registry_secret_scan_view(content: Dict[str, Any]) -> Dict[str, Any]:
    profiles = content.get("profiles")
    if not isinstance(profiles, list):
        return content
    sanitized_profiles = []
    for profile in profiles:
        if not _is_object(profile):
            sanitized_profiles.append(profile)
            continue
        sanitized_profile = dict(profile)
        if "socialIdpSecretRefs" in sanitized_profile:
            refs = sanitized_profile.pop("socialIdpSecretRefs")
            if not _is_object(refs):
                raise PolicyValidationError("secret_value_forbidden")
            for provider, provider_refs in refs.items():
                if (
                    not isinstance(provider, str)
                    or not LEGACY_PROVIDER_ID_PATTERN.fullmatch(provider)
                    or _contains_pattern(provider, CONCRETE_SECRET_VALUE_PATTERNS)
                ):
                    raise PolicyValidationError("secret_value_forbidden")
                if isinstance(provider_refs, str):
                    if not _is_approved_legacy_secret_ref(provider_refs):
                        raise PolicyValidationError("secret_value_forbidden")
                    continue
                if not _is_object(provider_refs) or any(
                    not isinstance(key, str)
                    or not LEGACY_SECRET_REF_KEY_PATTERN.fullmatch(key)
                    or _contains_pattern(key, CONCRETE_SECRET_VALUE_PATTERNS)
                    or not isinstance(value, str)
                    or not _is_approved_legacy_secret_ref(value)
                    for key, value in provider_refs.items()
                ):
                    raise PolicyValidationError("secret_value_forbidden")
        sanitized_profiles.append(sanitized_profile)
    sanitized_content = dict(content)
    sanitized_content["profiles"] = sanitized_profiles
    return sanitized_content


def _duplicate_ids(items: Any) -> bool:
    if not isinstance(items, list):
        return False
    ids = [item.get("id") for item in items if _is_object(item) and isinstance(item.get("id"), str)]
    return len(ids) != len(set(ids))


def _notification_secret_check_keys(policies: Any) -> set[tuple[Any, ...]]:
    checks: set[tuple[Any, ...]] = set()
    for policy in policies if isinstance(policies, list) else []:
        if not _is_object(policy) or policy.get("status") != "active":
            continue
        checks.add(("smtp", policy.get("connectionId")))
        for recipient_set in policy.get("recipientSets") or []:
            if not _is_object(recipient_set):
                continue
            for member in recipient_set.get("members") or []:
                checks.add((
                    "recipient",
                    recipient_set.get("id"),
                    recipient_set.get("version"),
                    member.get("id") if _is_object(member) else None,
                ))
    return checks


def _load_schemas() -> Dict[str, Dict[str, Any]]:
    return {
        descriptor: json.loads((SCHEMA_DIR / schema_file).read_text(encoding="utf-8"))
        for descriptor, schema_file in SERVER_SCHEMA_FILES.items()
    }


def _validate_code_owned_descriptor_values(name: str, content: Dict[str, Any]) -> None:
    if name == "data-spaces.json":
        for space in content.get("spaces") or []:
            access = space.get("access") if _is_object(space) else None
            if (
                _is_object(access)
                and access.get("mode") == "auth-profile"
                and isinstance(access.get("capabilities"), list)
                and any(capability not in DATA_SPACE_CAPABILITIES for capability in access["capabilities"])
            ):
                raise PolicyValidationError("data_space_capability_not_supported")
        return
    if name == "commerce.json":
        commerce = content.get("commerce")
        if not _is_object(commerce):
            return
        admin_access = commerce.get("adminAccess")
        if (
            _is_object(admin_access)
            and admin_access.get("mode") == "auth-profile"
            and isinstance(admin_access.get("capabilities"), list)
            and any(capability not in COMMERCE_CAPABILITIES for capability in admin_access["capabilities"])
        ):
            raise PolicyValidationError("commerce_capability_not_supported")
        payments = commerce.get("payments")
        if (
            isinstance(commerce.get("sellableTypes"), list)
            and "subscription" in commerce["sellableTypes"]
            and _is_object(payments)
            and payments.get("subscriptions") is not True
        ):
            raise PolicyValidationError("subscription_payments_required")
        fiscal = commerce.get("fiscal")
        if _is_object(fiscal) and fiscal.get("enabled") is True and fiscal.get("disclosureId") not in FISCAL_DISCLOSURES:
            raise PolicyValidationError("unknown_fiscal_disclosure")
        if _is_object(fiscal) and fiscal.get("enabled") is True and (
            not _is_object(admin_access)
            or admin_access.get("mode") != "auth-profile"
            or "commerce:fiscal:manage" not in (admin_access.get("capabilities") or [])
        ):
            raise PolicyValidationError("fiscal_admin_access_required")
        return
    if name == "notification-policies.json":
        for policy in content.get("policies") or []:
            if not _is_object(policy):
                continue
            notification_types = policy.get("notificationTypes")
            template_ids = policy.get("templateIds")
            if isinstance(notification_types, list) and any(
                notification_type not in NOTIFICATION_TEMPLATES_BY_TYPE for notification_type in notification_types
            ):
                raise PolicyValidationError("notification_type_not_supported")
            if isinstance(template_ids, list) and any(
                template_id not in NOTIFICATION_TEMPLATES_BY_TYPE.values() for template_id in template_ids
            ):
                raise PolicyValidationError("notification_template_not_supported")
            if isinstance(notification_types, list) and isinstance(template_ids, list):
                expected_templates = {
                    NOTIFICATION_TEMPLATES_BY_TYPE[notification_type]
                    for notification_type in notification_types
                }
                if set(template_ids) != expected_templates:
                    raise PolicyValidationError("notification_template_mismatch")


def validate_server_policy_files(
    domain: str,
    environment: str,
    files: list[Dict[str, Any]],
    expected_scope: Optional[Dict[str, str]] = None,
) -> None:
    schemas = _load_schemas()
    descriptors: Dict[str, Dict[str, Any]] = {}
    legacy_descriptors: Dict[str, Dict[str, Any]] = {}
    scope_reference: Optional[tuple[str, str, str, str]] = None
    for entry in files:
        path = str(entry.get("path") or "").replace("\\", "/")
        parts = path.split("/")
        if any(part.casefold() == "server" for part in parts) and (len(parts) != 3 or parts[1] != "server"):
            raise PolicyValidationError("invalid_server_path")
        marker = "/server/"
        if marker not in path:
            continue
        name = path.rsplit("/", 1)[-1]
        content = entry.get("content")
        if not _is_object(content):
            raise PolicyValidationError("server_policy_invalid")
        if len(_canonical_json(content).encode("utf-8")) > MAX_DESCRIPTOR_BYTES:
            raise PolicyValidationError("descriptor_too_large")
        secret_scan_content = _auth_registry_secret_scan_view(content) if name == "auth-profile-registry.json" else content
        if name in LEGACY_SERVER_FILES:
            _validate_legacy_integration_sensitive_fields(secret_scan_content)
        if _contains_pattern(secret_scan_content, SECRET_VALUE_PATTERNS, SECRET_FIELD_NAME_PATTERN):
            raise PolicyValidationError("secret_value_forbidden")
        if _contains_pattern(content, PII_VALUE_PATTERNS, PII_FIELD_NAME_PATTERN):
            raise PolicyValidationError("pii_value_forbidden")
        if _contains_structured_financial_identifier(content):
            raise PolicyValidationError("pii_value_forbidden")
        if _contains_pattern(content, (PROVIDER_RESOURCE_ID_PATTERN,)):
            raise PolicyValidationError("provider_resource_id_forbidden")
        if name in LEGACY_SERVER_FILES:
            _assert_grandfathered_legacy_descriptor(domain, name, content)
            legacy_descriptors[name] = content
            continue
        if name not in SERVER_SCHEMA_FILES:
            raise PolicyValidationError("unknown_server_descriptor")
        _validate_code_owned_descriptor_values(name, content)
        if validate_schema(schemas[name], content):
            raise PolicyValidationError("schema_invalid")
        scope = content.get("scope")
        if not _is_object(scope) or scope.get("domain") != domain or scope.get("environment") != environment:
            raise PolicyValidationError("scope_mismatch")
        current_scope = (
            scope.get("environment"),
            scope.get("tenantId"),
            scope.get("draftId"),
            scope.get("domain"),
        )
        if scope_reference is not None and current_scope != scope_reference:
            raise PolicyValidationError("scope_binding_mismatch")
        if expected_scope is not None and (
            scope.get("tenantId") != expected_scope.get("tenantId")
            or scope.get("draftId") != expected_scope.get("draftId")
        ):
            raise PolicyValidationError("scope_binding_mismatch")
        scope_reference = current_scope
        descriptors[name] = content

    data_spaces = descriptors.get("data-spaces.json", {})
    bindings = descriptors.get("integration-bindings.json", {}).get("bindings", [])
    notifications = descriptors.get("notification-policies.json", {}).get("policies", [])
    expected_mode = "live" if environment == "production" else "test"
    for binding in bindings:
        if not _is_object(binding):
            continue
        provider = binding.get("provider")
        provider_contract = INTEGRATION_PROVIDER_CONTRACTS.get(provider)
        if provider_contract is None:
            raise PolicyValidationError("unknown_provider")
        if binding.get("adapterVersion") not in provider_contract["adapterVersions"]:
            raise PolicyValidationError("adapter_version_not_supported")
        if any(capability not in provider_contract["capabilities"] for capability in binding.get("capabilities") or []):
            raise PolicyValidationError("provider_capability_not_supported")
        if binding.get("mode") != expected_mode:
            raise PolicyValidationError("mode_environment_mismatch")
        if provider == "stripe" and not _is_object(binding.get("stripe")):
            raise PolicyValidationError("stripe_settings_required")
        if provider != "stripe" and binding.get("stripe") is not None:
            raise PolicyValidationError("stripe_settings_not_allowed")
    if any(policy.get("provider") not in NOTIFICATION_PROVIDERS for policy in notifications if _is_object(policy)):
        raise PolicyValidationError("unknown_provider")
    if _duplicate_ids(data_spaces.get("spaces")) or _duplicate_ids(bindings) or _duplicate_ids(notifications):
        raise PolicyValidationError("duplicate_id")
    for space in data_spaces.get("spaces") or []:
        access = space.get("access") if _is_object(space) else None
        if (
            _is_object(access)
            and access.get("mode") == "auth-profile"
            and any(capability not in DATA_SPACE_CAPABILITIES for capability in access.get("capabilities") or [])
        ):
            raise PolicyValidationError("data_space_capability_not_supported")
    for policy in notifications:
        if _duplicate_ids(policy.get("recipientSets")):
            raise PolicyValidationError("duplicate_id")
        for recipient_set in policy.get("recipientSets") or []:
            if _duplicate_ids(recipient_set.get("members")):
                raise PolicyValidationError("duplicate_id")
        notification_types = policy.get("notificationTypes") or []
        template_ids = policy.get("templateIds") or []
        if any(notification_type not in NOTIFICATION_TEMPLATES_BY_TYPE for notification_type in notification_types):
            raise PolicyValidationError("notification_type_not_supported")
        if any(template_id not in NOTIFICATION_TEMPLATES_BY_TYPE.values() for template_id in template_ids):
            raise PolicyValidationError("notification_template_not_supported")
        expected_templates = {NOTIFICATION_TEMPLATES_BY_TYPE[notification_type] for notification_type in notification_types}
        if set(template_ids) != expected_templates:
            raise PolicyValidationError("notification_template_mismatch")
        if policy.get("status") == "active":
            matching_binding = next((
                binding
                for binding in bindings
                if _is_object(binding)
                and binding.get("status") == "active"
                and binding.get("provider") == policy.get("provider")
                and binding.get("connectionId") == policy.get("connectionId")
            ), None)
            if matching_binding is None:
                raise PolicyValidationError("notification_binding_not_found")
            if "send" not in (matching_binding.get("capabilities") or []):
                raise PolicyValidationError("notification_send_capability_required")
    if len(_notification_secret_check_keys(notifications)) > MAX_NOTIFICATION_SECRET_CHECKS:
        raise PolicyValidationError("notification_secret_limit_exceeded")

    commerce = descriptors.get("commerce.json", {}).get("commerce", {})
    if commerce:
        admin_access = commerce.get("adminAccess")
        if (
            _is_object(admin_access)
            and admin_access.get("mode") == "auth-profile"
            and any(capability not in COMMERCE_CAPABILITIES for capability in admin_access.get("capabilities") or [])
        ):
            raise PolicyValidationError("commerce_capability_not_supported")
        if "subscription" in (commerce.get("sellableTypes") or []) and commerce.get("payments", {}).get("subscriptions") is not True:
            raise PolicyValidationError("subscription_payments_required")
        if commerce.get("status") == "active":
            payment_binding = next((
                binding
                for binding in bindings
                if _is_object(binding) and binding.get("id") == commerce.get("payments", {}).get("bindingId")
            ), None)
            if payment_binding is None:
                raise PolicyValidationError("binding_not_found")
            if payment_binding.get("status") != "active":
                raise PolicyValidationError("binding_inactive")
            if payment_binding.get("provider") != "stripe":
                raise PolicyValidationError("commerce_payment_provider_not_supported")
            required_capabilities = set()
            payments = commerce.get("payments", {})
            if payments.get("oneTime") or payments.get("subscriptions"):
                required_capabilities.add("checkout")
            if payments.get("oneTime"):
                required_capabilities.add("one-time-payments")
            if payments.get("subscriptions"):
                required_capabilities.add("subscriptions")
            if payments.get("editablePrices"):
                required_capabilities.add("prices")
            if payments.get("coupons"):
                required_capabilities.add("coupons")
            if not required_capabilities.issubset(set(payment_binding.get("capabilities") or [])):
                raise PolicyValidationError("commerce_provider_capability_required")
        if "physical" in commerce.get("sellableTypes", []) and commerce.get("inventory", {}).get("enabled") is not True:
            raise PolicyValidationError("physical_inventory_required")
        if "physical" in commerce.get("sellableTypes", []) and commerce.get("shipping", {}).get("enabled") is not True:
            raise PolicyValidationError("physical_shipping_required")
        notification_ids = {policy.get("id") for policy in notifications if _is_object(policy)}
        if any(policy_id not in notification_ids for policy_id in commerce.get("notificationPolicyIds") or []):
            raise PolicyValidationError("notification_policy_not_found")
        fiscal = commerce.get("fiscal")
        if _is_object(fiscal) and fiscal.get("enabled") is True and fiscal.get("disclosureId") not in FISCAL_DISCLOSURES:
            raise PolicyValidationError("unknown_fiscal_disclosure")
        if _is_object(fiscal) and fiscal.get("enabled") is True and (
            not _is_object(admin_access)
            or admin_access.get("mode") != "auth-profile"
            or "commerce:fiscal:manage" not in (admin_access.get("capabilities") or [])
        ):
            raise PolicyValidationError("fiscal_admin_access_required")

    auth_registry = legacy_descriptors.get("auth-profile-registry.json")
    profiles_by_id = (
        _validated_legacy_auth_profiles(auth_registry, domain, expected_scope)
        if _is_object(auth_registry)
        else {}
    )
    auth_profile_references: list[tuple[Any, Any]] = []
    for space in data_spaces.get("spaces") or []:
        access = space.get("access") if _is_object(space) else None
        if _is_object(access) and access.get("mode") == "auth-profile":
            auth_profile_references.append((access.get("authProfileId"), data_spaces.get("scope")))
    admin_access = commerce.get("adminAccess") if commerce else None
    if _is_object(admin_access) and admin_access.get("mode") == "auth-profile":
        auth_profile_references.append((
            admin_access.get("authProfileId"),
            descriptors.get("commerce.json", {}).get("scope"),
        ))
    if auth_profile_references:
        if not _is_object(auth_registry):
            raise PolicyValidationError("auth_profile_registry_required")
        for auth_profile_id, reference_scope in auth_profile_references:
            profile = profiles_by_id.get(auth_profile_id)
            if not _is_object(profile):
                raise PolicyValidationError("auth_profile_not_found")
            if profile.get("status") != "active":
                raise PolicyValidationError("auth_profile_inactive")
            if (
                not _is_object(reference_scope)
                or profile.get("tenantId") != reference_scope.get("tenantId")
                or (profile.get("domain") is not None and profile.get("domain") != reference_scope.get("domain"))
            ):
                raise PolicyValidationError("auth_profile_scope_mismatch")

    if environment == "production":
        for binding in bindings:
            stripe = binding.get("stripe") if binding.get("provider") == "stripe" else None
            if binding.get("status") == "active" and _is_object(stripe):
                if stripe.get("taxMode") == "unconfigured" or not stripe.get("taxApprovalId"):
                    raise PolicyValidationError("tax_configuration_unapproved")
                if stripe.get("platformFeeMode") != "disabled":
                    raise PolicyValidationError("platform_fee_not_supported")
        fiscal = commerce.get("fiscal") if commerce else None
        if _is_object(fiscal) and fiscal.get("enabled") is True and not fiscal.get("accountantApprovalId"):
            raise PolicyValidationError("fiscal_approval_required")
        if any(policy.get("status") == "active" and not policy.get("transportApprovalId") for policy in notifications):
            raise PolicyValidationError("notification_transport_approval_required")
        if (
            any(binding.get("status") == "active" for binding in bindings)
            or commerce.get("status") == "active"
            or any(policy.get("status") == "active" for policy in notifications)
        ):
            raise PolicyValidationError("live_gate_unverified")


def validate_notification_secrets(
    files: list[Dict[str, Any]],
    environment: str,
    describe: Callable[[str], Dict[str, Any]],
) -> None:
    notification = next(
        (
            entry.get("content")
            for entry in files
            if str(entry.get("path") or "").endswith("/server/notification-policies.json")
        ),
        None,
    )
    if not _is_object(notification):
        return
    scope = notification.get("scope")
    if not _is_object(scope) or scope.get("environment") != environment:
        raise PolicyValidationError("notification_secret_unavailable")

    safe_id = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
    tenant_id = scope.get("tenantId")
    draft_id = scope.get("draftId")
    if not isinstance(tenant_id, str) or not safe_id.fullmatch(tenant_id):
        raise PolicyValidationError("notification_secret_unavailable")
    if not isinstance(draft_id, str) or not safe_id.fullmatch(draft_id):
        raise PolicyValidationError("notification_secret_unavailable")

    checks: list[tuple[str, Dict[str, str]]] = []
    base_tags = {
        "zoolanding:environment": environment,
        "zoolanding:tenant-id": tenant_id,
        "zoolanding:draft-id": draft_id,
        "zoolanding:enabled": "true",
    }
    for policy in notification.get("policies") or []:
        if not _is_object(policy) or policy.get("status") != "active":
            continue
        connection_id = policy.get("connectionId")
        if not isinstance(connection_id, str) or not safe_id.fullmatch(connection_id):
            raise PolicyValidationError("notification_secret_unavailable")
        checks.append((
            f"/zoolanding/{environment}/{tenant_id}/{draft_id}/notifications/smtp/{connection_id}",
            {
                **base_tags,
                "zoolanding:secret-purpose": "smtp",
                "zoolanding:connection-id": connection_id,
            },
        ))
        for recipient_set in policy.get("recipientSets") or []:
            recipient_set_id = recipient_set.get("id") if _is_object(recipient_set) else None
            recipient_set_version = recipient_set.get("version") if _is_object(recipient_set) else None
            if not isinstance(recipient_set_id, str) or not safe_id.fullmatch(recipient_set_id):
                raise PolicyValidationError("notification_secret_unavailable")
            if not isinstance(recipient_set_version, int) or isinstance(recipient_set_version, bool) or recipient_set_version < 1:
                raise PolicyValidationError("notification_secret_unavailable")
            for member in recipient_set.get("members") or []:
                member_id = member.get("id") if _is_object(member) else None
                if not isinstance(member_id, str) or not safe_id.fullmatch(member_id):
                    raise PolicyValidationError("notification_secret_unavailable")
                checks.append((
                    f"/zoolanding/{environment}/{tenant_id}/{draft_id}/notifications/recipients/{recipient_set_id}/{recipient_set_version}/{member_id}",
                    {
                        **base_tags,
                        "zoolanding:secret-purpose": "recipient",
                        "zoolanding:recipient-set-id": recipient_set_id,
                        "zoolanding:recipient-set-version": str(recipient_set_version),
                        "zoolanding:recipient-member-id": member_id,
                    },
                ))

    if len({secret_id for secret_id, _required_tags in checks}) > MAX_NOTIFICATION_SECRET_CHECKS:
        raise PolicyValidationError("notification_secret_limit_exceeded")

    seen: set[str] = set()
    for secret_id, required_tags in checks:
        if secret_id in seen:
            continue
        seen.add(secret_id)
        try:
            response = describe(secret_id)
        except Exception:
            raise PolicyValidationError("notification_secret_unavailable") from None
        raw_tags = response.get("Tags") if _is_object(response) else None
        if not isinstance(raw_tags, list) or response.get("DeletedDate") is not None:
            raise PolicyValidationError("notification_secret_unavailable")
        tags: Dict[str, str] = {}
        for tag in raw_tags:
            if not _is_object(tag) or not isinstance(tag.get("Key"), str) or not isinstance(tag.get("Value"), str):
                raise PolicyValidationError("notification_secret_unavailable")
            if tag["Key"] in tags:
                raise PolicyValidationError("notification_secret_unavailable")
            tags[tag["Key"]] = tag["Value"]
        if any(tags.get(key) != value for key, value in required_tags.items()):
            raise PolicyValidationError("notification_secret_unavailable")
