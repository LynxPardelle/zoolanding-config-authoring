import copy
import hashlib
import json
import os
import re
import unicodedata
from typing import Any, Dict, Optional
from urllib.parse import unquote

from server_policy_validation import PolicyValidationError, validate_notification_secrets, validate_server_policy_files
from zoolanding_lambda_common import (
    bad_request,
    build_version_id,
    conflict,
    default_version_prefix,
    describe_secret,
    get_request_id,
    join_s3_key,
    list_json_keys,
    list_object_keys,
    load_item,
    load_json_from_s3,
    log,
    not_found,
    now_iso,
    ObjectAlreadyExistsError,
    ok,
    parse_json_body,
    put_item_if_revision,
    put_json_to_s3_if_absent,
    RevisionConflictError,
    server_error,
    site_pk,
    unauthorized,
)


CONFIG_TABLE_NAME = os.getenv("CONFIG_TABLE_NAME", "zoolanding-config-registry")
CONFIG_PAYLOADS_BUCKET_NAME = os.getenv("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads")
DEPLOY_AUTHZ_CONFIG_S3_KEY = os.getenv("DEPLOY_AUTHZ_CONFIG_S3_KEY", "").strip()
ENVIRONMENT_NAME = os.getenv("ENVIRONMENT_NAME", "test").strip().lower()

WRITE_ACTIONS = {"createSite", "upsertDraft", "publishDraft", "setSiteStatus"}
ALL_ACTIONS = WRITE_ACTIONS | {"getSite"}
ENVIRONMENTS = {"production", "test"}
SAFE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,78}[a-z0-9]$")
SERVER_SCOPE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DEPLOY_ROLE_ARN_PATTERN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+$"
)
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
VERSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
WINDOWS_INVALID_PATH_CHARACTER_PATTERN = re.compile(r'[<>:"|?*]')
WINDOWS_RESERVED_PATH_BASENAME_PATTERN = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])$",
    re.IGNORECASE,
)
LOCAL_DRAFT_CONTEXT_FOLDERS = {
    ".git", ".github", "_repos", "ai_notes", "findings", "errors-reports",
    "cvs_n_photos", "node_modules", "output", "reports", "logs", "devonly",
    ".superpowers", ".agent-coordination", "tools",
}
LOCAL_DRAFT_CONTEXT_FILES = {"draft-repo.config.json"}
SERVER_ONLY_KEY_PATTERN = re.compile(r"(secret|token|credential|password|privatekey|authorization)", re.IGNORECASE)
MAX_RUNTIME_CONTENT_HUBS = 4
MANIFEST_FILE_NAME = "_manifest.json"
DEPLOY_AUTHZ_RULE_KEYS = {
    "roleArn", "tenantId", "draftId", "domains", "environments", "actions"
}


class VersionAlreadyExistsError(Exception):
    pass


class StoredPackageError(ValueError):
    def __init__(self):
        super().__init__("stored_package_invalid")


SAFE_VALIDATION_CODES = {
    "duplicate_path",
    "environment_invalid",
    "environment_mismatch",
    "invalid_server_path",
    "kind_mismatch",
    "runtime_content_hub_limit_exceeded",
    "unknown_server_descriptor",
}


def _safe_validation_code(error: ValueError) -> str:
    code = error.args[0] if len(error.args) == 1 and isinstance(error.args[0], str) else ""
    return code if code in SAFE_VALIDATION_CODES else "invalid_request"


def _initial_lifecycle(updated_at: str, updated_by: str) -> Dict[str, Any]:
    return {
        "status": "active",
        "fallbackMode": "system",
        "updatedAt": updated_at,
        "updatedBy": updated_by,
    }


def _read_site_file(files: list[Dict[str, Any]], suffix: str) -> Optional[Dict[str, Any]]:
    for entry in files:
        if str(entry.get("path") or "").endswith(suffix):
            content = entry.get("content")
            if isinstance(content, dict):
                return content
    return None


def _normalize_environment(value: Any) -> str:
    environment = str(value or "").strip().lower()
    if environment in ENVIRONMENTS:
        return environment
    raise ValueError("environment_invalid")


def _stack_environment() -> str:
    return _normalize_environment(ENVIRONMENT_NAME)


def _assert_stack_environment(payload: Dict[str, Any]) -> str:
    environment = _normalize_environment(payload.get("environment") or payload.get("stageEnvironment"))
    if environment != _stack_environment():
        raise ValueError("environment_mismatch")
    return environment


def _is_windows_reserved_path_segment(segment: str) -> bool:
    base_name = segment.split(".", 1)[0].rstrip(" .")
    return bool(WINDOWS_RESERVED_PATH_BASENAME_PATTERN.fullmatch(base_name))


def _has_unsafe_unicode_path_character(value: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)


def _decode_draft_path_segment(value: str) -> str:
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("invalid_draft_path")
    try:
        decoded = unquote(value, errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise ValueError("invalid_draft_path") from None
    if (
        not decoded
        or decoded != value
        or re.search(r"%[0-9A-Fa-f]{2}", decoded)
        or "/" in decoded
        or "\\" in decoded
        or _has_unsafe_unicode_path_character(decoded)
    ):
        raise ValueError("invalid_draft_path")
    return decoded


def _strict_domain(value: Any, field_name: str = "domain") -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a hostname")
    domain = value
    if (
        not domain
        or len(domain) > 253
        or domain != domain.strip()
        or domain != domain.lower()
        or any(character in domain for character in "/\\:")
        or _is_windows_reserved_path_segment(domain)
    ):
        raise ValueError(f"{field_name} must be a canonical hostname without scheme, port, or path")
    labels = domain.split(".")
    if any(not DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError(f"{field_name} must be a valid hostname")
    return domain


def _strict_version_id(value: Any) -> str:
    if not isinstance(value, str) or not VERSION_ID_PATTERN.fullmatch(value):
        raise ValueError("versionId must use 1-128 ASCII letters, numbers, dots, dashes, or underscores")
    return value


def _safe_content_id(value: Any, field_name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not SAFE_ID_PATTERN.fullmatch(normalized):
        raise ValueError(f"{field_name} must be a safe id using lowercase letters, numbers, dots, dashes, or underscores")
    return normalized


def _reject_server_only_content(value: Any, path: str = "content") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key or "")
            if SERVER_ONLY_KEY_PATTERN.search(key_text):
                raise ValueError(f"{path}.{key_text} cannot contain server-only or credential-like fields")
            _reject_server_only_content(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_server_only_content(child, f"{path}[{index}]")


def _validate_site_config_runtime_limits(content: Dict[str, Any]) -> None:
    runtime = content.get("runtime")
    content_hubs = runtime.get("contentHubs") if isinstance(runtime, dict) else None
    if isinstance(content_hubs, list) and len(content_hubs) > MAX_RUNTIME_CONTENT_HUBS:
        raise ValueError("runtime_content_hub_limit_exceeded")


def _content_hub_file_info(domain: str, path: str) -> Optional[tuple[str, Optional[str]]]:
    prefix = f"{domain}/content-hubs/"
    if not path.startswith(prefix):
        return None
    parts = path[len(prefix):].split("/")
    if len(parts) < 2:
        raise ValueError("Content hub files must live under content-hubs/{hubId}/...")
    hub_id = _safe_content_id(parts[0], "contentHubId")
    article_id = None
    if len(parts) >= 4 and parts[1] == "articles":
        article_id = _safe_content_id(parts[2], "articleId")
    return hub_id, article_id


def _derive_content_hub_fields(domain: str, files: list[Dict[str, Any]]) -> Dict[str, Any]:
    hubs: dict[str, Dict[str, Any]] = {}
    for entry in files:
        path = str(entry.get("path") or "")
        info = _content_hub_file_info(domain, path)
        if not info:
            continue
        hub_id, article_id = info
        _reject_server_only_content(entry.get("content"), path)
        hub = hubs.setdefault(hub_id, {"hubId": hub_id, "articleIds": []})
        if article_id and article_id not in hub["articleIds"]:
            hub["articleIds"].append(article_id)

    site_config = _read_site_file(files, "site-config.json") or {}
    configured_hubs = site_config.get("contentHubs")
    if isinstance(configured_hubs, list):
        for configured in configured_hubs:
            if not isinstance(configured, dict):
                continue
            hub_id = _safe_content_id(configured.get("hubId") or configured.get("id"), "contentHubId")
            hub = hubs.setdefault(hub_id, {"hubId": hub_id, "articleIds": []})
            hub["name"] = str(configured.get("name") or hub_id).strip() or hub_id
            hub["defaultLanguage"] = str(configured.get("defaultLanguage") or "es").strip() or "es"
            hub["canonicalDraftDomain"] = _strict_domain(configured.get("canonicalDraftDomain") or domain, "canonicalDraftDomain")
            allowed_domains = configured.get("allowedDraftDomains")
            if isinstance(allowed_domains, list):
                hub["allowedDraftDomains"] = [_strict_domain(item, "allowedDraftDomain") for item in allowed_domains]

    return {"contentHubs": sorted(hubs.values(), key=lambda item: item["hubId"])}


def _normalize_aliases(domain: Any, aliases: Any) -> list[str]:
    canonical_domain = _strict_domain(domain)
    if not isinstance(aliases, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        alias_domain = _strict_domain(alias, "alias")
        if alias_domain == canonical_domain or alias_domain in seen:
            continue
        seen.add(alias_domain)
        normalized.append(alias_domain)

    return normalized


def _normalize_environment_aliases(domain: str, environments: Any) -> Dict[str, list[str]]:
    if not isinstance(environments, dict):
        return {}

    normalized: Dict[str, list[str]] = {}
    for environment, config in environments.items():
        try:
            normalized_environment = _normalize_environment(environment)
        except ValueError:
            continue
        if not isinstance(config, dict):
            continue
        aliases = _normalize_aliases(domain, config.get("aliases"))
        if aliases:
            normalized[normalized_environment] = aliases

    return normalized


def _derive_site_fields(domain: str, files: list[Dict[str, Any]]) -> Dict[str, Any]:
    site_config = _read_site_file(files, "site-config.json") or {}
    content_hub_fields = _derive_content_hub_fields(domain, files)
    return {
        "aliases": _normalize_aliases(domain, site_config.get("aliases")),
        "environmentAliases": _normalize_environment_aliases(domain, site_config.get("environments")),
        "defaultPageId": str(site_config.get("defaultPageId") or "").strip() or "default",
        "routes": site_config.get("routes") if isinstance(site_config.get("routes"), list) else [],
        **content_hub_fields,
    }


def _load_deploy_authz_config() -> list[Dict[str, Any]]:
    if not DEPLOY_AUTHZ_CONFIG_S3_KEY:
        log("ERROR", "DEPLOY_AUTHZ_CONFIG_S3_KEY is required")
        return []
    try:
        parsed = load_json_from_s3(CONFIG_PAYLOADS_BUCKET_NAME, DEPLOY_AUTHZ_CONFIG_S3_KEY)
    except Exception:
        log("ERROR", "DEPLOY_AUTHZ_CONFIG_S3_KEY could not be loaded")
        return []
    if not isinstance(parsed, list):
        log("ERROR", "Deploy authorization config S3 object must be an array")
        return []
    if not parsed:
        log("ERROR", "Deploy authorization config S3 object must not be empty")
        return []

    environment = _stack_environment()
    role_arns: set[str] = set()
    domains: set[str] = set()
    draft_ids: set[str] = set()
    validated: list[Dict[str, Any]] = []
    try:
        for entry in parsed:
            if not isinstance(entry, dict) or set(entry) != DEPLOY_AUTHZ_RULE_KEYS:
                raise ValueError("authorization rule shape is invalid")
            role_arn = entry.get("roleArn")
            tenant_id = entry.get("tenantId")
            draft_id = entry.get("draftId")
            rule_domains = entry.get("domains")
            rule_environments = entry.get("environments")
            actions = entry.get("actions")
            if (
                not isinstance(role_arn, str)
                or not DEPLOY_ROLE_ARN_PATTERN.fullmatch(role_arn)
                or not isinstance(tenant_id, str)
                or not SERVER_SCOPE_ID_PATTERN.fullmatch(tenant_id)
                or not isinstance(draft_id, str)
                or not SERVER_SCOPE_ID_PATTERN.fullmatch(draft_id)
                or not isinstance(rule_domains, list)
                or len(rule_domains) != 1
                or not isinstance(rule_environments, list)
                or rule_environments != [environment]
                or not isinstance(actions, list)
                or not actions
                or any(not isinstance(action, str) or action not in ALL_ACTIONS for action in actions)
                or len(actions) != len(set(actions))
            ):
                raise ValueError("authorization rule values are invalid")
            domain = _strict_domain(rule_domains[0], "authorization domain")
            if (
                role_arn in role_arns
                or domain in domains
                or draft_id in draft_ids
            ):
                raise ValueError("authorization rule ownership is ambiguous")
            role_arns.add(role_arn)
            domains.add(domain)
            draft_ids.add(draft_id)
            validated.append(entry)
    except ValueError:
        log("ERROR", "Deploy authorization config S3 object is not exact")
        return []
    return validated


def _extract_nested(mapping: Any, path: list[str]) -> Any:
    current = mapping
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _caller_arn(event: Dict[str, Any]) -> str:
    request_context = event.get("requestContext") or {}
    candidates = [
        _extract_nested(request_context, ["identity", "userArn"]),
        _extract_nested(request_context, ["authorizer", "iam", "userArn"]),
        _extract_nested(request_context, ["authorizer", "iam", "callerArn"]),
        _extract_nested(request_context, ["authorizer", "principalId"]),
    ]
    for candidate in candidates:
        arn = str(candidate or "").strip()
        if arn.startswith("arn:"):
            return arn
    return ""


def _role_name_from_arn(arn: str) -> str:
    match = re.search(r":assumed-role/([^/]+)/", arn)
    if match:
        return match.group(1)
    match = re.search(r":role/(.+)$", arn)
    if match:
        return match.group(1).split("/")[-1]
    return ""


def _role_arn_matches(rule_arn: str, caller_arn: str) -> bool:
    rule_match = re.fullmatch(r"arn:([^:]+):iam::(\d{12}):role/(.+)", rule_arn)
    caller_match = re.fullmatch(r"arn:([^:]+):(?:iam|sts)::(\d{12}):(?:role/(.+)|assumed-role/([^/]+)/[^/]+)", caller_arn)
    if not rule_match or not caller_match:
        return False
    rule_role_name = rule_match.group(3).rsplit("/", 1)[-1]
    caller_role_name = (caller_match.group(3) or caller_match.group(4) or "").rsplit("/", 1)[-1]
    return (
        rule_match.group(1) == caller_match.group(1)
        and rule_match.group(2) == caller_match.group(2)
        and rule_role_name == caller_role_name
    )


def _authorized_server_scope(rule: Dict[str, Any]) -> Optional[Dict[str, str]]:
    tenant_id = rule.get("tenantId")
    draft_id = rule.get("draftId")
    if not isinstance(tenant_id, str) or not SERVER_SCOPE_ID_PATTERN.fullmatch(tenant_id):
        return None
    if not isinstance(draft_id, str) or not SERVER_SCOPE_ID_PATTERN.fullmatch(draft_id):
        return None
    return {"tenantId": tenant_id, "draftId": draft_id}


def _rule_allows(rule: Dict[str, Any], caller_arn: str, action: str, domain: str, environment: str) -> bool:
    role_arn = rule.get("roleArn")
    actions = rule.get("actions")
    domain_values = rule.get("domains")
    environment_values = rule.get("environments")
    if (
        not isinstance(role_arn, str)
        or not isinstance(actions, list)
        or not isinstance(domain_values, list)
        or not isinstance(environment_values, list)
        or _authorized_server_scope(rule) is None
    ):
        return False
    if not _role_arn_matches(role_arn, caller_arn):
        return False
    if action not in actions:
        return False
    if domain_values != [domain]:
        return False
    if environment_values != [environment]:
        return False
    return True


def _authorize_request(
    event: Dict[str, Any],
    payload: Dict[str, Any],
    action: str,
) -> tuple[bool, str, Optional[Dict[str, str]]]:
    domain = _strict_domain(payload.get("domain"))
    environment = _normalize_environment(payload.get("environment") or payload.get("stageEnvironment"))

    caller_arn = _caller_arn(event)
    if not caller_arn:
        return False, "Missing signed deploy identity", None

    matching_scopes = [
        _authorized_server_scope(rule)
        for rule in _load_deploy_authz_config()
        if _rule_allows(rule, caller_arn, action, domain, environment)
    ]
    unique_scopes = {
        (scope["tenantId"], scope["draftId"])
        for scope in matching_scopes
        if scope is not None
    }
    if len(unique_scopes) == 1:
        tenant_id, draft_id = next(iter(unique_scopes))
        return True, caller_arn, {"tenantId": tenant_id, "draftId": draft_id}
    if len(unique_scopes) > 1:
        return False, "Deploy identity has ambiguous server scope authorization", None

    return False, "Deploy identity is not authorized for this action, domain, environment, and server scope", None


def _updated_by(payload: Dict[str, Any], request_id: str) -> str:
    trusted_identity = str(payload.get("_authorizedUpdatedBy") or "").strip()
    return trusted_identity or request_id


def _request_server_scope(payload: Dict[str, Any]) -> Dict[str, str]:
    scope = payload.get("_authorizedServerScope")
    if not isinstance(scope, dict) or set(scope) != {"tenantId", "draftId"}:
        raise PolicyValidationError("scope_binding_mismatch")
    tenant_id = scope.get("tenantId")
    draft_id = scope.get("draftId")
    if (
        not isinstance(tenant_id, str)
        or not SERVER_SCOPE_ID_PATTERN.fullmatch(tenant_id)
        or not isinstance(draft_id, str)
        or not SERVER_SCOPE_ID_PATTERN.fullmatch(draft_id)
    ):
        raise PolicyValidationError("scope_binding_mismatch")
    return {"tenantId": tenant_id, "draftId": draft_id}


def _assert_metadata_server_scope(metadata: Dict[str, Any], expected_scope: Dict[str, str]) -> None:
    pinned_scope = metadata.get("serverScope")
    if pinned_scope is None:
        return
    if not isinstance(pinned_scope, dict) or pinned_scope != expected_scope:
        raise PolicyValidationError("scope_binding_mismatch")


def _normalize_files(
    domain: str,
    environment: str,
    files: Any,
    expected_scope: Optional[Dict[str, str]] = None,
) -> list[Dict[str, Any]]:
    if not isinstance(files, list) or not files:
        raise ValueError("files must be a non-empty array")

    normalized: list[Dict[str, Any]] = []
    seen_paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("Each file entry must be an object")

        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path or raw_path != raw_path.strip():
            raise ValueError("Each file entry requires a path")
        path = raw_path
        if path in seen_paths:
            raise ValueError("duplicate_path")
        seen_paths.add(path)
        parts = path.split("/")
        try:
            decoded_parts = [_decode_draft_path_segment(part) for part in parts]
        except ValueError:
            raise ValueError("Each file entry path must be a strict JSON path below the requested domain") from None
        server_segments = [index for index, part in enumerate(decoded_parts) if part.casefold() == "server"]
        if server_segments and (len(parts) != 3 or parts[1] != "server"):
            raise ValueError("invalid_server_path")
        if (
            path != unicodedata.normalize("NFC", path)
            or "\\" in path
            or WINDOWS_INVALID_PATH_CHARACTER_PATTERN.search(path)
            or path.startswith("/")
            or _has_unsafe_unicode_path_character(path)
            or any(part != unicodedata.normalize("NFC", part) for part in decoded_parts)
            or len(parts) < 2
            or parts[0] != domain
            or any(not part or part in {".", ".."} for part in parts)
            or any(part in {".", ".."} for part in decoded_parts)
            or any(part.endswith((".", " ")) for part in decoded_parts)
            or any(_is_windows_reserved_path_segment(part) for part in decoded_parts)
            or any(
                part.casefold() in LOCAL_DRAFT_CONTEXT_FOLDERS
                or part.casefold() in LOCAL_DRAFT_CONTEXT_FILES
                for part in decoded_parts[1:]
            )
            or not path.endswith(".json")
        ):
            raise ValueError("Each file entry path must be a strict JSON path below the requested domain")
        content = entry.get("content")
        if not isinstance(content, dict):
            raise ValueError("Each file entry content must be a JSON object")
        if path == f"{domain}/site-config.json":
            _validate_site_config_runtime_limits(content)
        _content_hub_file_info(domain, path)

        inferred_kind = _infer_kind(path)
        supplied_kind = entry.get("kind")
        if supplied_kind not in {None, ""} and supplied_kind != inferred_kind:
            raise ValueError("kind_mismatch")

        normalized.append({
            "path": path,
            "kind": inferred_kind,
            "pageId": entry.get("pageId"),
            "lang": entry.get("lang"),
            "content": content,
        })

    validate_server_policy_files(domain, environment, normalized, expected_scope=expected_scope)
    return normalized


def _json_payload_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _store_files(domain: str, version_id: str, environment: str, files: list[Dict[str, Any]]) -> str:
    prefix = default_version_prefix(domain, version_id)
    if list_object_keys(CONFIG_PAYLOADS_BUCKET_NAME, prefix):
        raise VersionAlreadyExistsError()

    manifest_files = []
    for entry in sorted(files, key=lambda item: item["path"]):
        manifest_files.append({
            "path": entry["path"],
            "kind": entry["kind"],
            "sha256": hashlib.sha256(_json_payload_bytes(entry["content"])).hexdigest(),
        })
    try:
        put_json_to_s3_if_absent(CONFIG_PAYLOADS_BUCKET_NAME, join_s3_key(prefix, MANIFEST_FILE_NAME), {
            "version": 1,
            "domain": domain,
            "environment": environment,
            "versionId": version_id,
            "files": manifest_files,
        })
        for entry in sorted(files, key=lambda item: item["path"]):
            put_json_to_s3_if_absent(
                CONFIG_PAYLOADS_BUCKET_NAME,
                join_s3_key(prefix, entry["path"]),
                entry["content"],
            )
    except ObjectAlreadyExistsError:
        raise VersionAlreadyExistsError() from None
    return prefix


def _load_integrity_checked_stored_files(
    domain: str,
    environment: str,
    version_id: str,
) -> tuple[str, list[Dict[str, Any]]]:
    prefix = default_version_prefix(domain, version_id)
    manifest_key = join_s3_key(prefix, MANIFEST_FILE_NAME)
    manifest = load_json_from_s3(CONFIG_PAYLOADS_BUCKET_NAME, manifest_key)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"version", "domain", "environment", "versionId", "files"}
        or manifest.get("version") != 1
        or manifest.get("domain") != domain
        or manifest.get("environment") != environment
        or manifest.get("versionId") != version_id
        or not isinstance(manifest.get("files"), list)
        or not manifest["files"]
    ):
        raise StoredPackageError()

    raw_files: list[Dict[str, Any]] = []
    expected_keys = {manifest_key}
    seen_paths: set[str] = set()
    for manifest_entry in manifest["files"]:
        if (
            not isinstance(manifest_entry, dict)
            or set(manifest_entry) != {"path", "kind", "sha256"}
            or not isinstance(manifest_entry.get("path"), str)
            or not isinstance(manifest_entry.get("kind"), str)
            or not isinstance(manifest_entry.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", manifest_entry["sha256"])
            or manifest_entry["path"] in seen_paths
        ):
            raise StoredPackageError()
        seen_paths.add(manifest_entry["path"])
        key = join_s3_key(prefix, manifest_entry["path"])
        expected_keys.add(key)
        content = load_json_from_s3(CONFIG_PAYLOADS_BUCKET_NAME, key)
        if not isinstance(content, dict):
            raise StoredPackageError()
        if hashlib.sha256(_json_payload_bytes(content)).hexdigest() != manifest_entry["sha256"]:
            raise StoredPackageError()
        raw_files.append({
            "path": manifest_entry["path"],
            "kind": manifest_entry["kind"],
            "content": content,
        })

    if set(list_object_keys(CONFIG_PAYLOADS_BUCKET_NAME, prefix)) != expected_keys:
        raise StoredPackageError()
    return prefix, raw_files


def _load_validated_stored_files(
    domain: str,
    environment: str,
    version_id: str,
    expected_scope: Optional[Dict[str, str]] = None,
) -> tuple[str, list[Dict[str, Any]]]:
    prefix, raw_files = _load_integrity_checked_stored_files(domain, environment, version_id)
    try:
        normalized = _normalize_files(domain, environment, raw_files, expected_scope=expected_scope)
    except (PolicyValidationError, ValueError):
        raise StoredPackageError() from None
    return prefix, normalized


def _load_package(domain: str, stage: str, version_id: str, prefix: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    prefix = default_version_prefix(domain, version_id)
    keys = list_json_keys(CONFIG_PAYLOADS_BUCKET_NAME, prefix)
    files: list[Dict[str, Any]] = []
    for key in keys:
        relative_key = key[len(prefix):].lstrip('/')
        if relative_key == MANIFEST_FILE_NAME:
            continue
        content = load_json_from_s3(CONFIG_PAYLOADS_BUCKET_NAME, key)
        if content is None:
            continue
        files.append({
            "path": relative_key,
            "kind": _infer_kind(relative_key),
            "pageId": _infer_page_id(domain, relative_key),
            "lang": _infer_lang(relative_key),
            "content": content,
        })

    return {
        "version": 1,
        "domain": domain,
        "stage": stage,
        "versionId": version_id,
        "files": files,
        "metadata": {
            "registry": {
                "aliases": metadata.get("aliases", []),
                "environmentAliases": metadata.get("environmentAliases", {}),
                "defaultPageId": metadata.get("defaultPageId"),
                "routes": metadata.get("routes", []),
                "lifecycle": metadata.get("lifecycle", {}),
            },
        },
    }


def _infer_kind(relative_path: str) -> str:
    server_kinds = {
        "server/auth-profile-registry.json": "server-auth-profile-registry",
        "server/integrations.json": "server-integrations",
        "server/data-spaces.json": "server-data-spaces",
        "server/commerce.json": "server-commerce",
        "server/integration-bindings.json": "server-integration-bindings",
        "server/notification-policies.json": "server-notification-policies",
    }
    package_path = relative_path.split("/", 1)[1] if "/" in relative_path else relative_path
    if package_path.startswith("server/"):
        if package_path not in server_kinds:
            raise ValueError("unknown_server_descriptor")
        return server_kinds[package_path]
    if relative_path.endswith("site-config.json"):
        return "site-config"
    if relative_path.endswith("/components.json") and relative_path.count("/") == 1:
        return "shared-components"
    if relative_path.endswith("/variables.json") and relative_path.count("/") == 1:
        return "shared-variables"
    if relative_path.endswith("/angora-combos.json") and relative_path.count("/") == 1:
        return "shared-angora-combos"
    if "/i18n/" in relative_path and relative_path.endswith(".json") and relative_path.count("/") == 2:
        return "shared-i18n"
    if relative_path.endswith("/page-config.json"):
        return "page-config"
    if relative_path.endswith("/components.json"):
        return "page-components"
    if relative_path.endswith("/variables.json"):
        return "variables"
    if relative_path.endswith("/angora-combos.json"):
        return "angora-combos"
    if "/i18n/" in relative_path and relative_path.endswith(".json"):
        return "i18n"
    return "page-components"


def _infer_page_id(domain: str, relative_path: str) -> Optional[str]:
    parts = relative_path.split('/')
    if len(parts) < 2:
        return None
    if parts[0] != domain:
        return None
    if len(parts) >= 3 and parts[1] not in {'i18n', 'server'}:
        return parts[1]
    return None


def _infer_lang(relative_path: str) -> Optional[str]:
    if "/i18n/" not in relative_path:
        return None
    file_name = relative_path.rsplit('/', 1)[-1]
    return file_name[:-5] if file_name.endswith('.json') else None


def _load_registry(domain: str) -> Optional[Dict[str, Any]]:
    return load_item(CONFIG_TABLE_NAME, site_pk(domain))


def _save_registry_conditionally(metadata: Dict[str, Any], expected_revision: int) -> None:
    put_item_if_revision(CONFIG_TABLE_NAME, metadata, expected_revision)


def _create_or_replace_draft(payload: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    domain = _strict_domain(payload.get("domain"))
    environment = _normalize_environment(payload.get("environment"))
    authorized_scope = _request_server_scope(payload)
    if "publishOnCreate" in payload:
        return bad_request("publishOnCreate is not supported; use the separately authorized publishDraft action")

    files = _normalize_files(
        domain,
        environment,
        payload.get("files"),
        expected_scope=authorized_scope,
    )
    loaded_existing = _load_registry(domain)
    if loaded_existing:
        _assert_metadata_server_scope(loaded_existing, authorized_scope)
    if payload.get("action") == "createSite" and loaded_existing and not payload.get("allowOverwrite"):
        return conflict("Site already exists", domain=domain)

    raw_version_id = payload["versionId"] if "versionId" in payload else build_version_id(request_id)
    version_id = _strict_version_id(raw_version_id)
    derived = _derive_site_fields(domain, files)
    prefix = default_version_prefix(domain, version_id)
    updated_at = now_iso()
    updated_by = _updated_by(payload, request_id)

    expected_revision = int((loaded_existing or {}).get("revision") or 0)
    metadata = copy.deepcopy(loaded_existing) if loaded_existing else {
        "pk": site_pk(domain),
        "sk": "METADATA",
        "type": "site-metadata",
        "version": 1,
        "domain": domain,
        "lifecycle": _initial_lifecycle(updated_at, updated_by),
    }
    metadata["defaultPageId"] = derived["defaultPageId"]
    metadata["serverScope"] = authorized_scope
    metadata["routes"] = derived["routes"]
    metadata["contentHubs"] = derived["contentHubs"]
    metadata["draft"] = {
        "versionId": version_id,
        "prefix": prefix,
        "manifestVersion": 1,
        "updatedAt": updated_at,
        "updatedBy": updated_by,
    }
    metadata["updatedAt"] = updated_at
    metadata["updatedBy"] = updated_by
    metadata["revision"] = expected_revision + 1

    response = ok({
        "domain": domain,
        "draft": metadata.get("draft"),
        "published": metadata.get("published"),
        "lifecycle": metadata.get("lifecycle"),
    })
    _store_files(domain, version_id, environment, files)
    _save_registry_conditionally(metadata, expected_revision)
    return response


def _get_site(payload: Dict[str, Any]) -> Dict[str, Any]:
    domain = _strict_domain(payload.get("domain"))
    stage = str(payload.get("stage") or "draft").strip() or "draft"
    if stage not in {"draft", "published"}:
        return bad_request("stage must be 'draft' or 'published'")
    environment = _normalize_environment(payload.get("environment") or payload.get("stageEnvironment"))

    metadata = _load_registry(domain)
    if not metadata:
        return not_found("Site metadata not found", domain=domain)
    _assert_metadata_server_scope(metadata, _request_server_scope(payload))

    pointer = metadata.get(stage)
    if stage == "published":
        published_environments = metadata.get("publishedEnvironments") if isinstance(metadata.get("publishedEnvironments"), dict) else {}
        if environment != "production":
            pointer = published_environments.get(environment)
        elif not isinstance(pointer, dict):
            pointer = published_environments.get("production")
    if not isinstance(pointer, dict):
        return not_found(f"No {stage} package found", domain=domain)

    version_id = str(pointer.get("versionId") or "").strip()
    prefix = str(pointer.get("prefix") or default_version_prefix(domain, version_id)).strip()
    manifest_key = join_s3_key(default_version_prefix(domain, version_id), MANIFEST_FILE_NAME)
    manifest = load_json_from_s3(CONFIG_PAYLOADS_BUCKET_NAME, manifest_key)
    if manifest is None and pointer.get("manifestVersion") != 1:
        package = _load_package(domain, stage, version_id, prefix, metadata)
    else:
        _verified_prefix, verified_files = _load_integrity_checked_stored_files(domain, environment, version_id)
        package = {
            "version": 1,
            "domain": domain,
            "stage": stage,
            "versionId": version_id,
            "files": [
                {
                    **entry,
                    "pageId": _infer_page_id(domain, entry["path"]),
                    "lang": _infer_lang(entry["path"]),
                }
                for entry in verified_files
            ],
            "metadata": {
                "registry": {
                    "aliases": metadata.get("aliases", []),
                    "environmentAliases": metadata.get("environmentAliases", {}),
                    "defaultPageId": metadata.get("defaultPageId"),
                    "routes": metadata.get("routes", []),
                    "lifecycle": metadata.get("lifecycle", {}),
                },
            },
        }
    package["environment"] = environment
    return ok(package)


def _publish_draft(payload: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    domain = _strict_domain(payload.get("domain"))
    environment = _normalize_environment(payload.get("environment"))
    loaded_metadata = _load_registry(domain)
    if not loaded_metadata:
        return not_found("Site metadata not found", domain=domain)
    authorized_scope = _request_server_scope(payload)
    _assert_metadata_server_scope(loaded_metadata, authorized_scope)

    draft_pointer = loaded_metadata.get("draft")
    if not isinstance(draft_pointer, dict):
        return not_found("Draft package not found", domain=domain)

    requested_version_id = _strict_version_id(payload.get("versionId") or draft_pointer.get("versionId"))
    prefix, stored_files = _load_validated_stored_files(
        domain,
        environment,
        requested_version_id,
        expected_scope=authorized_scope,
    )
    validate_notification_secrets(stored_files, environment, describe_secret)

    expected_revision = int(loaded_metadata.get("revision") or 0)
    metadata = copy.deepcopy(loaded_metadata)
    updated_at = now_iso()
    published_pointer = {
        "versionId": requested_version_id,
        "prefix": prefix,
        "manifestVersion": 1,
        "updatedAt": updated_at,
        "updatedBy": _updated_by(payload, request_id),
    }
    published_environments = metadata.get("publishedEnvironments") if isinstance(metadata.get("publishedEnvironments"), dict) else {}
    published_environments[environment] = published_pointer
    metadata["publishedEnvironments"] = published_environments
    metadata["serverScope"] = authorized_scope
    if environment == "production":
        metadata["published"] = published_pointer
    metadata["updatedAt"] = updated_at
    metadata["updatedBy"] = _updated_by(payload, request_id)
    metadata["revision"] = expected_revision + 1
    response = ok({
        "domain": domain,
        "environment": environment,
        "published": published_pointer,
        "draft": metadata.get("draft"),
        "lifecycle": metadata.get("lifecycle"),
    })
    _save_registry_conditionally(metadata, expected_revision)
    return response


def _set_site_status(payload: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    domain = _strict_domain(payload.get("domain"))
    status = str(payload.get("status") or "").strip()
    if status not in {"active", "maintenance", "suspended"}:
        return bad_request("status must be one of: active, maintenance, suspended")

    loaded_metadata = _load_registry(domain)
    if not loaded_metadata:
        return not_found("Site metadata not found", domain=domain)
    authorized_scope = _request_server_scope(payload)
    _assert_metadata_server_scope(loaded_metadata, authorized_scope)

    expected_revision = int(loaded_metadata.get("revision") or 0)
    metadata = copy.deepcopy(loaded_metadata)
    updated_at = now_iso()
    lifecycle = metadata.get("lifecycle") if isinstance(metadata.get("lifecycle"), dict) else {}
    lifecycle.update({
        "status": status,
        "fallbackMode": str(payload.get("fallbackMode") or lifecycle.get("fallbackMode") or "system"),
        "message": payload.get("message") or lifecycle.get("message"),
        "reason": payload.get("reason") or lifecycle.get("reason"),
        "supportEmail": payload.get("supportEmail") or lifecycle.get("supportEmail"),
        "supportPhone": payload.get("supportPhone") or lifecycle.get("supportPhone"),
        "updatedAt": updated_at,
        "updatedBy": _updated_by(payload, request_id),
    })
    metadata["lifecycle"] = lifecycle
    metadata["serverScope"] = authorized_scope
    metadata["updatedAt"] = updated_at
    metadata["updatedBy"] = _updated_by(payload, request_id)
    metadata["revision"] = expected_revision + 1
    response = ok({"domain": domain, "lifecycle": lifecycle})
    _save_registry_conditionally(metadata, expected_revision)
    return response


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    request_id = get_request_id(context)
    try:
        payload = parse_json_body(event)
    except ValueError:
        return bad_request("invalid_request_body")
    except Exception:
        log("ERROR", "Invalid authoring request body", requestId=request_id, errorCode="invalid_request_body")
        return bad_request("Body is not valid JSON")

    action = str(payload.get("action") or "").strip()
    if action not in ALL_ACTIONS:
        return bad_request("Unsupported action")

    try:
        _assert_stack_environment(payload)
        authorized, auth_message, authorized_scope = _authorize_request(event, payload, action)
        if not authorized:
            return unauthorized(auth_message)
        payload["_authorizedUpdatedBy"] = _role_name_from_arn(auth_message) or auth_message
        payload["_authorizedServerScope"] = authorized_scope

        if action in {"createSite", "upsertDraft"}:
            return _create_or_replace_draft(payload, request_id)
        if action == "getSite":
            return _get_site(payload)
        if action == "publishDraft":
            return _publish_draft(payload, request_id)
        return _set_site_status(payload, request_id)
    except VersionAlreadyExistsError:
        return conflict("version_already_exists")
    except RevisionConflictError:
        return conflict("registry_revision_conflict")
    except PolicyValidationError as exc:
        return bad_request(exc.public_code)
    except StoredPackageError:
        return bad_request("stored_package_invalid")
    except ValueError as exc:
        return bad_request(_safe_validation_code(exc))
    except Exception:
        log("ERROR", "Config authoring lambda failed", requestId=request_id, action=action, errorCode="authoring_internal_error")
        return server_error()
