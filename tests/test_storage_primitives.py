import contextlib
import io
import json
import unittest
from decimal import Decimal
from unittest.mock import patch

import zoolanding_lambda_common as common


class StoragePrimitiveTest(unittest.TestCase):
    def test_catalog_reads_are_strongly_consistent_and_writes_require_a_newer_sequence(self):
        self.assertTrue(hasattr(common, "load_item_consistently"))
        self.assertTrue(hasattr(common, "put_catalog_projection_if_newer"))
        calls = []

        class Table:
            def get_item(self, **kwargs):
                calls.append(("get", kwargs))
                return {"Item": {"sequence": 2}}

            def put_item(self, **kwargs):
                calls.append(("put", kwargs))

        item = {"pk": "CATALOG#test", "sk": "SOURCE#DRAFT#example.com", "sequence": 2}
        with patch.object(common, "get_table", return_value=Table()), patch.object(common, "DRY_RUN", False):
            self.assertEqual(common.load_item_consistently("table", item["pk"], item["sk"]), {"sequence": 2})
            common.put_catalog_projection_if_newer("table", item)
        self.assertEqual(calls[0], ("get", {"Key": {"pk": item["pk"], "sk": item["sk"]}, "ConsistentRead": True}))
        self.assertEqual(calls[1][1]["ConditionExpression"], "attribute_not_exists(#pk) OR #sequence < :sequence")
        self.assertEqual(calls[1][1]["ExpressionAttributeNames"], {"#pk": "pk", "#sequence": "sequence"})
        self.assertEqual(calls[1][1]["ExpressionAttributeValues"], {":sequence": 2})

    def test_catalog_sequence_condition_failure_is_reported_without_retry(self):
        item = {"pk": "CATALOG#test", "sk": "SOURCE#DRAFT#example.com", "sequence": 2}
        class ConditionalFailure(common.ClientError):
            def __init__(self):
                self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}

        error = ConditionalFailure()
        with patch.object(common, "get_table") as table, patch.object(common, "DRY_RUN", False):
            table.return_value.put_item.side_effect = error
            with self.assertRaises(common.RevisionConflictError):
                common.put_catalog_projection_if_newer("table", item)
            table.return_value.put_item.assert_called_once()

    def test_json_response_serializes_nested_integral_decimals_as_json_numbers(self):
        response = common.ok({
            "registry": {
                "revision": Decimal("2"),
                "draft": {"manifestVersion": Decimal("1")},
            }
        })

        body = json.loads(response["body"])
        self.assertEqual(body["registry"]["revision"], 2)
        self.assertIs(type(body["registry"]["revision"]), int)
        self.assertEqual(body["registry"]["draft"]["manifestVersion"], 1)
        self.assertIs(type(body["registry"]["draft"]["manifestVersion"]), int)

    def test_json_response_rejects_unsupported_and_non_integral_values(self):
        for value in (Decimal("1.5"), Decimal("NaN"), object()):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(TypeError):
                    common.ok({"value": value})

    def test_immutable_json_put_uses_s3_if_none_match(self):
        self.assertTrue(hasattr(common, "put_json_to_s3_if_absent"))
        calls = []

        class S3:
            def put_object(self, **kwargs):
                calls.append(kwargs)

        original_client = common._S3_CLIENT
        original_dry_run = common.DRY_RUN
        try:
            common._S3_CLIENT = S3()
            common.DRY_RUN = False
            common.put_json_to_s3_if_absent("bucket", "key", {"version": 1})
        finally:
            common._S3_CLIENT = original_client
            common.DRY_RUN = original_dry_run

        self.assertEqual(calls[0]["IfNoneMatch"], "*")

    def test_secret_preflight_uses_describe_secret_only(self):
        self.assertTrue(hasattr(common, "describe_secret"))
        calls = []

        class SecretsManager:
            def describe_secret(self, **kwargs):
                calls.append(kwargs)
                return {"Tags": []}

        original_client = common._SECRETSMANAGER_CLIENT
        try:
            common._SECRETSMANAGER_CLIENT = SecretsManager()
            response = common.describe_secret("synthetic-secret-id")
        finally:
            common._SECRETSMANAGER_CLIENT = original_client

        self.assertEqual(response, {"Tags": []})
        self.assertEqual(calls, [{"SecretId": "synthetic-secret-id"}])

    def test_s3_json_reader_rejects_non_finite_constants(self):
        class Body:
            def read(self):
                return b'{"amount":NaN}'

        class S3:
            def get_object(self, **_kwargs):
                return {"Body": Body()}

        original_client = common._S3_CLIENT
        try:
            common._S3_CLIENT = S3()
            with self.assertRaises(ValueError):
                common.load_json_from_s3("bucket", "key")
        finally:
            common._S3_CLIENT = original_client

    def test_log_serialization_fallback_never_prints_field_values(self):
        class SensitiveValue:
            def __str__(self):
                return "whsec_do-not-print"

            def __repr__(self):
                return "whsec_do-not-print"

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            common.log("ERROR", "serialization failed safely", provider=SensitiveValue())

        rendered = output.getvalue()
        self.assertNotIn("whsec_do-not-print", rendered)
        self.assertIn("fieldKeys", rendered)


if __name__ == "__main__":
    unittest.main()
