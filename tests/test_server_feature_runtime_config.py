import copy
import unittest

from server_policy_validation import validate_server_feature_runtime_config


DOMAIN = "example.com"


DATA_SPACE_READS = {
    "collectionList": ([], ["limit", "cursor"]),
    "collectionSchema": (["collectionId"], ["collectionId"]),
    "recordList": (["collectionId"], ["collectionId", "limit", "cursor"]),
    "recordDetail": (["collectionId", "recordId"], ["collectionId", "recordId"]),
}
COMMERCE_READS = {
    "itemList": ([], ["limit", "cursor"]),
    "itemDetail": (["resourceId"], ["resourceId"]),
    "offerList": ([], ["limit", "cursor"]),
    "offerDetail": (["resourceId"], ["resourceId"]),
    "discountList": ([], ["limit", "cursor"]),
    "discountDetail": (["resourceId"], ["resourceId"]),
}
ACTION_INPUTS = {
    "createCollection": ["collectionId", "schema"],
    "updateCollection": ["collectionId", "schema", "expectedRevision"],
    "createRecord": ["collectionId", "recordId", "data"],
    "updateRecord": ["collectionId", "recordId", "data", "expectedRevision"],
    "publishRecord": ["collectionId", "recordId", "expectedRevision"],
    "unpublishRecord": ["collectionId", "recordId", "expectedRevision"],
    "createItem": ["itemId", "sellableType"],
    "createOfferVersion": ["versionId", "catalogItemId", "revision", "sellableType", "unitPrice", "taxBehavior"],
    "createDiscountVersion": ["versionId", "revision", "duration", "percentageBasisPoints"],
    "advanceOfferLifecycle": ["versionId", "targetState", "expectedRevision"],
    "updateOfferPresentation": ["versionId", "expectedRevision"],
    "advanceDiscountLifecycle": ["versionId", "targetState", "expectedRevision"],
    "updateDiscountPresentation": ["versionId", "expectedRevision"],
    "adjustStock": ["stockId", "delta", "expectedRevision"],
    "changePlan": ["subscriptionId", "targetOfferVersionId", "expectedRevision"],
    "applyDiscount": ["subscriptionId", "discountVersionId", "expectedRevision"],
    "removeDiscount": ["subscriptionId", "expectedRevision"],
    "pause": ["subscriptionId", "expectedRevision"],
    "resume": ["subscriptionId", "expectedRevision"],
    "openPortal": ["subscriptionId"],
    "migrationPreview": ["sourceOfferVersionId", "targetOfferVersionId"],
    "migrationExecute": ["commercialRequestId", "dryRunRevision", "dryRunHash", "confirmation"],
    "migrationPause": ["commercialRequestId", "expectedRevision"],
    "migrationResume": ["commercialRequestId", "expectedRevision"],
    "migrationCancel": ["commercialRequestId", "expectedRevision"],
    "migrationStatus": ["commercialRequestId"],
    "admitCheckout": ["lines"],
    "disable": ["connectionId", "expectedRevision"],
    "requestReconnect": ["connectionId", "expectedRevision"],
    "stripeOnboardingStart": [],
    "stripeOnboardingReturn": [],
    "stripeOnboardingDeauthorize": [],
}
DATA_SPACE_ACTIONS = {
    "createCollection", "updateCollection", "createRecord", "updateRecord", "publishRecord", "unpublishRecord",
}
INTEGRATION_ACTIONS = {
    "disable", "requestReconnect", "stripeOnboardingStart", "stripeOnboardingReturn", "stripeOnboardingDeauthorize",
}
GESTURE_ACTIONS = {"openPortal", "admitCheckout", "stripeOnboardingStart", "stripeOnboardingDeauthorize"}


def package_files(site_config, extra=None):
    return [
        {
            "path": f"{DOMAIN}/site-config.json",
            "kind": "site-config",
            "content": site_config,
        },
        *(extra or []),
    ]


def site(runtime=None, routes=None):
    return {
        "version": 1,
        "domain": DOMAIN,
        "routes": routes or [],
        "runtime": runtime or {},
    }


def values(fields):
    return {field: "synthetic" for field in fields}


def action(operation, fields=None):
    fields = ACTION_INPUTS[operation] if fields is None else fields
    kind = (
        "data-space"
        if operation in DATA_SPACE_ACTIONS
        else "integrations"
        if operation in INTEGRATION_ACTIONS
        else "commerce"
    )
    binding_key = "dataSpace" if kind == "data-space" else kind
    onboarding = operation.startswith("stripeOnboarding")
    result = {
        "id": f"action-{operation}",
        "kind": kind,
        binding_key: {
            "action": operation,
            **({"spaceId": "example-space"} if kind == "data-space" else {}),
            **({"bindingId": "stripe-main"} if onboarding else {}),
        },
    }
    if fields:
        result["inputFields"] = fields
    if operation in GESTURE_ACTIONS:
        result["requiresUserGesture"] = True
    return result


class ServerFeatureRuntimeConfigTest(unittest.TestCase):
    def validate(self, site_config, extra=None):
        files = package_files(site_config, extra)
        validate_server_feature_runtime_config(DOMAIN, site_config, files)

    def assert_invalid(self, site_config, extra=None):
        with self.assertRaisesRegex(ValueError, "^server_feature_runtime_invalid$"):
            self.validate(site_config, extra)

    def test_legacy_runtime_is_an_opt_in_no_op(self):
        self.validate(site({
            "apiActions": [
                {"id": "duplicate", "proxyActionId": "one", "method": "GET"},
                {"id": "duplicate", "proxyActionId": "two", "method": "PATCH"},
            ],
        }))

    def test_all_read_input_contracts_are_closed(self):
        for kind, contracts in (("data-space", DATA_SPACE_READS), ("commerce", COMMERCE_READS)):
            for operation, (required, allowed) in contracts.items():
                with self.subTest(kind=kind, operation=operation):
                    binding_key = "dataSpace" if kind == "data-space" else kind
                    binding = {
                        "read": operation,
                        **({"spaceId": "example-space"} if kind == "data-space" else {}),
                    }
                    source = {
                        "id": f"read-{operation}",
                        "kind": kind,
                        binding_key: binding,
                        "input": values(required),
                        "target": "result",
                    }
                    self.validate(site({"dataSources": [source]}))
                    source["input"] = values(allowed)
                    self.validate(site({"dataSources": [source]}))
                    source["input"] = values(required[1:]) if required else {"unexpected": "value"}
                    self.assert_invalid(site({"dataSources": [source]}))

    def test_public_read_and_ssr_contracts_are_closed(self):
        valid_sources = [
            {
                "id": "public-records",
                "kind": "data-space",
                "dataSpace": {"read": "recordList", "spaceId": "example-space", "access": "public"},
                "input": {"collectionId": "articles"},
                "target": "records",
                "ssr": True,
            },
            {
                "id": "public-offer",
                "kind": "commerce",
                "commerce": {"read": "offerDetail", "access": "public"},
                "input": {"offerVersionId": "offer-v1"},
                "target": "offer",
                "ssr": True,
            },
        ]
        self.validate(site({"dataSources": valid_sources}))
        for invalid in (
            {**valid_sources[0], "dataSpace": {"read": "collectionList", "spaceId": "example-space", "access": "public"}},
            {**valid_sources[0], "dataSpace": {"read": "recordList", "spaceId": "example-space"}},
            {**valid_sources[1], "input": {"resourceId": "offer-v1"}},
            {
                "id": "connections",
                "kind": "integrations",
                "integrations": {"read": "connectionList"},
                "target": "connections",
                "ssr": True,
            },
        ):
            self.assert_invalid(site({"dataSources": [invalid]}))

    def test_all_action_input_contracts_are_closed(self):
        for operation, required in ACTION_INPUTS.items():
            with self.subTest(operation=operation):
                self.validate(site({"apiActions": [action(operation)]}))
                invalid_fields = required[1:] if required else ["unexpected"]
                self.assert_invalid(site({"apiActions": [action(operation, invalid_fields)]}))

    def test_binding_alias_method_gesture_and_global_ids_fail_closed(self):
        invalid_actions = [
            {**action("createRecord"), "proxyActionId": "legacy"},
            {**action("createRecord"), "method": "PATCH"},
            {**action("createRecord"), "commerce": {"action": "createItem"}},
            {**action("admitCheckout"), "requiresUserGesture": False},
            {**action("changePlan"), "inputFields": [*ACTION_INPUTS["changePlan"], "tenantId"]},
            {**action("stripeOnboardingStart"), "inputFields": None},
        ]
        for invalid in invalid_actions:
            self.assert_invalid(site({"apiActions": [invalid]}))
        duplicate = [
            {"id": "duplicate", "proxyActionId": "legacy"},
            {**action("createRecord"), "id": "duplicate"},
        ]
        self.assert_invalid(site({"apiActions": duplicate}))

    def test_discount_requires_exactly_one_amount_shape(self):
        self.validate(site({"apiActions": [action(
            "createDiscountVersion",
            ["versionId", "revision", "duration", "fixedAmount"],
        )]}))
        for fields in (
            ["versionId", "revision", "duration"],
            ["versionId", "revision", "duration", "percentageBasisPoints", "fixedAmount"],
        ):
            self.assert_invalid(site({"apiActions": [action("createDiscountVersion", fields)]}))

    def test_route_load_requires_one_protected_unique_non_auth_route(self):
        callback = {
            **action("stripeOnboardingReturn"),
            "trigger": "route-load",
            "pageIds": ["stripe-return"],
        }
        protected = {"path": "/provider-return", "pageId": "stripe-return", "auth": {"required": True}}
        self.validate(site({"apiActions": [callback]}, [protected]))
        for invalid_site in (
            site({"apiActions": [{**callback, "pageIds": ["one", "two"]}]}),
            site({"apiActions": [{**callback, "pageIds": [{"not": "a-page-id"}]}]}),
            site({"apiActions": [callback]}, [protected, {**protected, "path": "/other"}]),
            site({"apiActions": [callback]}, [{**protected, "auth": {"required": False}}]),
            site({"apiActions": [callback, {**callback, "id": "second"}]}, [protected]),
            site({"auth": {"callbackPageId": "stripe-return"}, "apiActions": [callback]}, [protected]),
            site({"auth": {"redirectPath": "/auth/callback"}, "apiActions": [callback]}, [{**protected, "path": "/auth/:provider"}]),
        ):
            self.assert_invalid(invalid_site)

    def test_explicit_null_read_input_is_not_treated_as_omitted(self):
        self.assert_invalid(site({
            "dataSources": [{
                "id": "connections",
                "kind": "integrations",
                "integrations": {"read": "connectionList"},
                "input": None,
                "target": "connections",
            }],
        }))

    def test_remote_auth_callback_must_resolve_and_remain_separate(self):
        callback = {
            **action("stripeOnboardingReturn"),
            "trigger": "route-load",
            "pageIds": ["stripe-return"],
        }
        protected = {"path": "/provider-return", "pageId": "stripe-return", "auth": {"required": True}}
        remote_site = site({
            "authRemote": {"authProfileId": "staff", "endpoint": "/auth/runtime"},
            "apiActions": [callback],
        }, [protected])
        self.assert_invalid(remote_site)
        registry = {
            "path": f"{DOMAIN}/server/auth-profile-registry.json",
            "kind": "server-auth-profile-registry",
            "content": {
                "profiles": [{
                    "domain": DOMAIN,
                    "authProfileId": "staff",
                    "callbackPageId": "auth-callback",
                    "callbackUrls": [f"https://{DOMAIN}/provider-return"],
                }],
            },
        }
        self.assert_invalid(remote_site, [registry])
        separate = copy.deepcopy(registry)
        separate["content"]["profiles"][0]["callbackUrls"] = [f"https://{DOMAIN}/auth/callback"]
        self.validate(remote_site, [separate])


if __name__ == "__main__":
    unittest.main()
