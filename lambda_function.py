import os
from typing import Any, Dict, Optional

from zoolanding_lambda_common import (
    alias_pk,
    bad_request,
    build_version_id,
    conflict,
    default_version_prefix,
    get_request_id,
    join_s3_key,
    list_json_keys,
    load_item,
    load_json_from_s3,
    log,
    normalize_domain,
    not_found,
    now_iso,
    ok,
    parse_json_body,
    put_item,
    put_json_to_s3,
    server_error,
    site_pk,
)


CONFIG_TABLE_NAME = os.getenv("CONFIG_TABLE_NAME", "zoolanding-config-registry")
CONFIG_PAYLOADS_BUCKET_NAME = os.getenv("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads")


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


def _normalize_aliases(domain: Any, aliases: Any) -> list[str]:
    canonical_domain = normalize_domain(domain)
    if not canonical_domain or not isinstance(aliases, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        alias_domain = normalize_domain(alias)
        if not alias_domain or alias_domain == canonical_domain or alias_domain in seen:
            continue
        seen.add(alias_domain)
        normalized.append(alias_domain)

    return normalized


def _derive_site_fields(domain: str, files: list[Dict[str, Any]]) -> Dict[str, Any]:
    site_config = _read_site_file(files, "site-config.json") or {}
    return {
        "aliases": _normalize_aliases(domain, site_config.get("aliases")),
        "defaultPageId": str(site_config.get("defaultPageId") or "").strip() or "default",
        "routes": site_config.get("routes") if isinstance(site_config.get("routes"), list) else [],
    }


def _save_alias_records(domain: str, aliases: list[str], updated_at: str, updated_by: str) -> None:
    for alias in aliases:
        put_item(CONFIG_TABLE_NAME, {
            "pk": alias_pk(alias),
            "sk": "SITE",
            "type": "site-alias",
            "alias": alias,
            "domain": domain,
            "updatedAt": updated_at,
            "updatedBy": updated_by,
        })


def _normalize_files(domain: str, files: Any) -> list[Dict[str, Any]]:
    if not isinstance(files, list) or not files:
        raise ValueError("files must be a non-empty array")

    normalized: list[Dict[str, Any]] = []
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("Each file entry must be an object")

        path = str(entry.get("path") or "").strip().replace('\\', '/')
        if not path:
            raise ValueError("Each file entry requires a path")
        if not path.startswith(f"{domain}/"):
            raise ValueError(f"File path '{path}' must start with '{domain}/'")
        content = entry.get("content")
        if not isinstance(content, dict):
            raise ValueError(f"File '{path}' content must be a JSON object")

        normalized.append({
            "path": path,
            "kind": entry.get("kind"),
            "pageId": entry.get("pageId"),
            "lang": entry.get("lang"),
            "content": content,
        })

    return normalized


def _store_files(domain: str, version_id: str, files: list[Dict[str, Any]]) -> str:
    prefix = default_version_prefix(domain, version_id)
    for entry in files:
        key = join_s3_key(prefix, entry["path"])
        put_json_to_s3(CONFIG_PAYLOADS_BUCKET_NAME, key, entry["content"])
    return prefix


def _load_package(domain: str, stage: str, version_id: str, prefix: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    keys = list_json_keys(CONFIG_PAYLOADS_BUCKET_NAME, prefix)
    files: list[Dict[str, Any]] = []
    for key in keys:
        relative_key = key[len(prefix):].lstrip('/')
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
                "defaultPageId": metadata.get("defaultPageId"),
                "routes": metadata.get("routes", []),
                "lifecycle": metadata.get("lifecycle", {}),
            },
        },
    }


def _infer_kind(relative_path: str) -> str:
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
    if len(parts) >= 3 and parts[1] != 'i18n':
        return parts[1]
    return None


def _infer_lang(relative_path: str) -> Optional[str]:
    if "/i18n/" not in relative_path:
        return None
    file_name = relative_path.rsplit('/', 1)[-1]
    return file_name[:-5] if file_name.endswith('.json') else None


def _load_registry(domain: str) -> Optional[Dict[str, Any]]:
    return load_item(CONFIG_TABLE_NAME, site_pk(domain))


def _save_registry(metadata: Dict[str, Any]) -> None:
    put_item(CONFIG_TABLE_NAME, metadata)


def _create_or_replace_draft(payload: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    domain = normalize_domain(payload.get("domain"))
    if not domain:
        return bad_request("Missing domain")

    files = _normalize_files(domain, payload.get("files"))
    existing = _load_registry(domain)
    if payload.get("action") == "createSite" and existing and not payload.get("allowOverwrite"):
        return conflict("Site already exists", domain=domain)

    version_id = str(payload.get("versionId") or build_version_id(request_id)).strip()
    prefix = _store_files(domain, version_id, files)
    derived = _derive_site_fields(domain, files)
    updated_at = now_iso()
    updated_by = str(payload.get("updatedBy") or request_id)

    metadata = existing or {
        "pk": site_pk(domain),
        "sk": "METADATA",
        "type": "site-metadata",
        "version": 1,
        "domain": domain,
        "lifecycle": _initial_lifecycle(updated_at, updated_by),
    }
    metadata["defaultPageId"] = derived["defaultPageId"]
    metadata["aliases"] = derived["aliases"]
    metadata["routes"] = derived["routes"]
    metadata["draft"] = {
        "versionId": version_id,
        "prefix": prefix,
        "updatedAt": updated_at,
        "updatedBy": updated_by,
    }
    metadata["updatedAt"] = updated_at
    metadata["updatedBy"] = updated_by

    _save_alias_records(domain, derived["aliases"], updated_at, updated_by)

    if payload.get("publishOnCreate"):
        metadata["published"] = metadata["draft"]
        metadata["lifecycle"] = {
            **metadata.get("lifecycle", {}),
            "status": "active",
            "updatedAt": updated_at,
            "updatedBy": updated_by,
        }

    _save_registry(metadata)
    return ok({
        "domain": domain,
        "draft": metadata.get("draft"),
        "published": metadata.get("published"),
        "lifecycle": metadata.get("lifecycle"),
    })


def _get_site(payload: Dict[str, Any]) -> Dict[str, Any]:
    domain = normalize_domain(payload.get("domain"))
    stage = str(payload.get("stage") or "draft").strip() or "draft"
    if stage not in {"draft", "published"}:
        return bad_request("stage must be 'draft' or 'published'")

    metadata = _load_registry(domain)
    if not metadata:
        return not_found("Site metadata not found", domain=domain)

    pointer = metadata.get(stage)
    if not isinstance(pointer, dict):
        return not_found(f"No {stage} package found", domain=domain)

    version_id = str(pointer.get("versionId") or "").strip()
    prefix = str(pointer.get("prefix") or default_version_prefix(domain, version_id)).strip()
    package = _load_package(domain, stage, version_id, prefix, metadata)
    return ok(package)


def _publish_draft(payload: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    domain = normalize_domain(payload.get("domain"))
    metadata = _load_registry(domain)
    if not metadata:
        return not_found("Site metadata not found", domain=domain)

    draft_pointer = metadata.get("draft")
    if not isinstance(draft_pointer, dict):
        return not_found("Draft package not found", domain=domain)

    requested_version_id = str(payload.get("versionId") or draft_pointer.get("versionId") or "").strip()
    if requested_version_id and requested_version_id != str(draft_pointer.get("versionId") or ""):
        return bad_request("Only the current draft version can be published in this initial implementation")

    updated_at = now_iso()
    metadata["published"] = {
        **draft_pointer,
        "updatedAt": updated_at,
        "updatedBy": str(payload.get("updatedBy") or request_id),
    }
    metadata["updatedAt"] = updated_at
    metadata["updatedBy"] = str(payload.get("updatedBy") or request_id)
    _save_registry(metadata)
    return ok({
        "domain": domain,
        "published": metadata.get("published"),
        "draft": metadata.get("draft"),
        "lifecycle": metadata.get("lifecycle"),
    })


def _set_site_status(payload: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    domain = normalize_domain(payload.get("domain"))
    status = str(payload.get("status") or "").strip()
    if status not in {"active", "maintenance", "suspended"}:
        return bad_request("status must be one of: active, maintenance, suspended")

    metadata = _load_registry(domain)
    if not metadata:
        return not_found("Site metadata not found", domain=domain)

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
        "updatedBy": str(payload.get("updatedBy") or request_id),
    })
    metadata["lifecycle"] = lifecycle
    metadata["updatedAt"] = updated_at
    metadata["updatedBy"] = str(payload.get("updatedBy") or request_id)
    _save_registry(metadata)
    return ok({"domain": domain, "lifecycle": lifecycle})


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    request_id = get_request_id(context)
    try:
        payload = parse_json_body(event)
    except ValueError as exc:
        return bad_request(str(exc))
    except Exception as exc:
        log("ERROR", "Invalid authoring request body", requestId=request_id, error=str(exc))
        return bad_request("Body is not valid JSON")

    action = str(payload.get("action") or "").strip()
    if action not in {"createSite", "upsertDraft", "getSite", "publishDraft", "setSiteStatus"}:
        return bad_request("Unsupported action")

    try:
        if action in {"createSite", "upsertDraft"}:
            return _create_or_replace_draft(payload, request_id)
        if action == "getSite":
            return _get_site(payload)
        if action == "publishDraft":
            return _publish_draft(payload, request_id)
        return _set_site_status(payload, request_id)
    except ValueError as exc:
        return bad_request(str(exc))
    except Exception as exc:
        log("ERROR", "Config authoring lambda failed", requestId=request_id, action=action, error=str(exc))
        return server_error()
