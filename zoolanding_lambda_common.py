import base64
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore
except Exception:  # pragma: no cover - local fallback when boto3 is unavailable
    boto3 = None
    ClientError = Exception  # type: ignore


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DRY_RUN = os.getenv("DRY_RUN", "0").strip().lower() in {"1", "true", "yes", "on"}
_S3_CLIENT = None
_DYNAMODB_RESOURCE = None


def should_log(level: str) -> bool:
    order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
    return order.get(level, 20) >= order.get(LOG_LEVEL, 20)


def log(level: str, message: str, **fields: Any) -> None:
    if not should_log(level):
        return

    record = {"level": level, "message": message, **fields}
    try:
        print(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        print({"level": level, "message": message, "fields": str(fields)})


def json_response(status_code: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }


def ok(payload: Dict[str, Any]) -> Dict[str, Any]:
    return json_response(200, {"ok": True, **payload})


def bad_request(message: str, **extra: Any) -> Dict[str, Any]:
    return json_response(400, {"ok": False, "error": message, **extra})


def not_found(message: str, **extra: Any) -> Dict[str, Any]:
    return json_response(404, {"ok": False, "error": message, **extra})


def conflict(message: str, **extra: Any) -> Dict[str, Any]:
    return json_response(409, {"ok": False, "error": message, **extra})


def server_error(message: str = "Internal error", **extra: Any) -> Dict[str, Any]:
    return json_response(500, {"ok": False, "error": message, **extra})


def get_request_id(context: Any) -> str:
    request_id = getattr(context, "aws_request_id", None)
    if isinstance(request_id, str) and request_id.strip():
        return request_id.strip()
    return f"local-{uuid.uuid4().hex[:12]}"


def parse_json_body(event: Dict[str, Any]) -> Dict[str, Any]:
    body = event.get("body")
    if body is None or body == "":
        raise ValueError("Missing body")

    if event.get("isBase64Encoded"):
        if not isinstance(body, str):
            raise ValueError("Body is base64Encoded but not a string")
        body = base64.b64decode(body).decode("utf-8")

    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8")

    if isinstance(body, str):
        parsed = json.loads(body)
    elif isinstance(body, dict):
        parsed = body
    else:
        raise ValueError("Body must be valid JSON")

    if not isinstance(parsed, dict):
        raise ValueError("Body must decode into a JSON object")

    return parsed


def get_query_value(event: Dict[str, Any], key: str, default: str = "") -> str:
    params = event.get("queryStringParameters") or {}
    value = params.get(key, default)
    return str(value or default).strip()


def get_header_value(event: Dict[str, Any], key: str, default: str = "") -> str:
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        return default

    lookup = {str(name).lower(): value for name, value in headers.items()}
    return str(lookup.get(key.lower(), default) or default).strip()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_version_id(request_id: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{sanitize_key_segment(request_id)[-12:]}"


def sanitize_key_segment(value: str, fallback: str = "value") -> str:
    normalized = re.sub(r"[^A-Za-z0-9._/-]+", "-", str(value or "").strip())
    normalized = re.sub(r"/{2,}", "/", normalized).strip("-./")
    return normalized or fallback


def normalize_domain(value: str) -> str:
    domain = str(value or "").strip().lower()
    domain = domain.split(":", 1)[0]
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.strip("/ ")
    return domain


def normalize_route_path(value: str) -> str:
    path = str(value or "/").strip()
    if not path.startswith("/"):
        path = f"/{path}"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path or "/"


def get_s3_client():
    global _S3_CLIENT
    if _S3_CLIENT is not None:
        return _S3_CLIENT
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    _S3_CLIENT = boto3.client("s3")
    return _S3_CLIENT


def get_dynamodb_resource():
    global _DYNAMODB_RESOURCE
    if _DYNAMODB_RESOURCE is not None:
        return _DYNAMODB_RESOURCE
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    _DYNAMODB_RESOURCE = boto3.resource("dynamodb")
    return _DYNAMODB_RESOURCE


def get_table(table_name: str):
    return get_dynamodb_resource().Table(table_name)


def load_json_from_s3(bucket: str, key: str) -> Optional[Dict[str, Any]]:
    s3 = get_s3_client()
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
    except ClientError as exc:  # type: ignore[misc]
        code = str(getattr(exc, "response", {}).get("Error", {}).get("Code"))
        if code in {"NoSuchKey", "404", "NotFound"}:
            return None
        raise

    raw = response["Body"].read().decode("utf-8")
    return json.loads(raw) if raw.strip() else {}


def list_json_keys(bucket: str, prefix: str) -> list[str]:
    s3 = get_s3_client()
    keys: list[str] = []
    continuation_token: Optional[str] = None

    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token
        response = s3.list_objects_v2(**kwargs)
        for entry in response.get("Contents", []):
            key = str(entry.get("Key") or "")
            if key.endswith(".json"):
                keys.append(key)

        if not response.get("IsTruncated"):
            break
        continuation_token = response.get("NextContinuationToken")

    return keys


def put_json_to_s3(bucket: str, key: str, payload: Dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if DRY_RUN:
        log("INFO", "Dry run: skipping S3 JSON upload", bucket=bucket, key=key, size=len(encoded))
        return

    get_s3_client().put_object(
        Bucket=bucket,
        Key=key,
        Body=encoded,
        ContentType="application/json",
        CacheControl="no-cache",
    )


def put_bytes_to_s3(bucket: str, key: str, payload: bytes, content_type: str) -> None:
    if DRY_RUN:
        log("INFO", "Dry run: skipping S3 binary upload", bucket=bucket, key=key, size=len(payload), contentType=content_type)
        return

    get_s3_client().put_object(
        Bucket=bucket,
        Key=key,
        Body=payload,
        ContentType=content_type,
        CacheControl="public, max-age=31536000, immutable",
    )


def load_item(table_name: str, pk: str, sk: str = "METADATA") -> Optional[Dict[str, Any]]:
    response = get_table(table_name).get_item(Key={"pk": pk, "sk": sk})
    item = response.get("Item")
    return item if isinstance(item, dict) else None


def put_item(table_name: str, item: Dict[str, Any]) -> None:
    if DRY_RUN:
        log("INFO", "Dry run: skipping DynamoDB put_item", table=table_name, pk=item.get("pk"), sk=item.get("sk"))
        return
    get_table(table_name).put_item(Item=item)


def site_pk(domain: str) -> str:
    return f"SITE#{normalize_domain(domain)}"


def alias_pk(domain: str) -> str:
    return f"ALIAS#{normalize_domain(domain)}"


def default_version_prefix(domain: str, version_id: str) -> str:
    normalized_domain = sanitize_key_segment(normalize_domain(domain), fallback="site")
    normalized_version = sanitize_key_segment(version_id, fallback="version")
    return f"sites/{normalized_domain}/versions/{normalized_version}"


def join_s3_key(*parts: Iterable[str] | str) -> str:
    flattened: list[str] = []
    for part in parts:
        if isinstance(part, str):
            flattened.extend(segment for segment in part.split("/") if segment)
        else:
            flattened.extend(segment for segment in part if segment)
    return "/".join(flattened)
