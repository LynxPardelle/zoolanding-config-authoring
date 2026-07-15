# Zoolanding Config Authoring

Agent entrypoint: [AGENTS.md](./AGENTS.md). Historical changes: [changelog/README.md](./changelog/README.md).

This Lambda handles create, pull, update, publish, and lifecycle status changes for site draft packages.

## Responsibilities

- Create a new site registry record.
- Store authoring payload files into the versioned S3 layout.
- Validate proposed aliases inside the versioned draft package without mutating public alias metadata or lookup records during draft upsert.
- Pull a draft or published package back into the local draft format.
- Publish the current draft pointer for `production` or `test`.
- Mark a site as `active`, `maintenance`, or `suspended`.
- Require signed AWS IAM deploy identity for authoring actions.
- Index optional content hub package metadata for blog/article features while preserving the same draft-package S3 layout.

## AWS dependencies

- DynamoDB table: `zoolanding-config-registry`
- S3 bucket: `zoolanding-config-payloads`
- API Gateway: `POST /config-authoring`
- CloudWatch Logs

## Environment variables

- `CONFIG_TABLE_NAME`
- `CONFIG_PAYLOADS_BUCKET_NAME`
- `ENVIRONMENT_NAME`
- `LOG_LEVEL`
- `DEPLOY_AUTHZ_CONFIG_S3_KEY`

`DEPLOY_AUTHZ_CONFIG_S3_KEY` points to a JSON array in `CONFIG_PAYLOADS_BUCKET_NAME`. Every rule requires an exact IAM role ARN, plus non-empty actions, domains, and environments. Wildcards work only when `"*"` is explicit. Example:

```json
[
  {
    "roleArn": "arn:aws:iam::123456789012:role/draft-pamelabetancourt-com-test-deploy",
    "domains": ["pamelabetancourt.com"],
    "environments": ["test"],
    "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"]
  },
  {
    "roleArn": "arn:aws:iam::123456789012:role/draft-pamelabetancourt-com-production-deploy",
    "domains": ["pamelabetancourt.com"],
    "environments": ["production"],
    "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"]
  }
]
```

## Deploy

`ConfigAuthoringFunction` uses the generated `.build/config-authoring` `CodeUri`. Run `python tools/build_lambda_artifact.py` before `sam validate` or `sam build`; the builder copies only the two runtime Python modules. CI and both deploy workflows verify the exact built inventory before AWS credentials are configured. `.aws-samignore` is defense in depth, not artifact evidence.

For repeatable deployments from this repository:

```bash
sam deploy
```

The checked-in `samconfig.toml` includes `dev`, `test`, and `prod` deployment profiles in `us-east-1`.

- `dev` uses `zoolanding-config-registry-dev` and `zoolanding-config-payloads-dev`.
- `test` uses `zoolanding-config-registry-test` and `zoolanding-config-payloads-test`.
- `prod` uses the existing production table and bucket names.

The checked-in deploy profiles use `system/deploy-authz.json`. Upload and validate that object in the environment's private config bucket before deploying; missing or malformed authorization configuration denies every request.

Deploy with the checked-in environment profile so the S3 authorization key and environment-specific storage names stay together:

```bash
sam deploy --config-env prod --no-confirm-changeset --no-fail-on-empty-changeset
```

Use the output `ApiUrl` as the base for the local draft round-trip CLI in the main app repo.

Current deployed endpoint:

```text
https://2dvjmiwjod.execute-api.us-east-1.amazonaws.com/Prod/config-authoring
```

## Supported actions

- `createSite`
- `upsertDraft`
- `getSite`
- `publishDraft`
- `setSiteStatus`

Proposed production aliases are authored in `site-config.json` through an optional `aliases` array. Proposed test aliases are authored under `site-config.json.environments.test.aliases`.

Draft upsert keeps those proposals only inside the versioned package. Public alias metadata, claim, and revocation remain unchanged until Zoolanding defines an explicit alias allowlist and an atomic ownership/collision contract. Do not treat a successful draft upsert as an alias claim.

`publishOnCreate` is unsupported. Publication always requires the separately authorized `publishDraft` action.

## Content hub package files

Content hub files are optional and live inside the normal draft package:

```text
{domain}/content-hubs/{hubId}/hub.json
{domain}/content-hubs/{hubId}/categories.json
{domain}/content-hubs/{hubId}/tags.json
{domain}/content-hubs/{hubId}/articles/{articleId}/metadata.json
```

`hubId` and `articleId` must be lowercase safe ids. Content hub JSON is rejected when it contains credential-like or server-only field names such as `secret`, `token`, `credential`, `password`, `privateKey`, or `authorization`.

The Lambda stores a compact `contentHubs` index in site metadata so runtime readers can expose safe public hub metadata without scanning S3.

Example:

```json
{
  "aliases": ["pamelabetancourt.com"],
  "environments": {
    "test": {
      "aliases": [
        "test.pamelabetancourt.com",
        "test.pamelabetancourt.zoolandingpage.com.mx"
      ]
    }
  }
}
```

## Manual smoke tests

The deployed API uses AWS IAM authorization. Unsigned requests should fail. Use GitHub Actions OIDC or a SigV4-capable AWS SDK client that relies on the standard credential provider chain and whose exact role ARN is allowed by the S3 authorization object. Never place an AWS secret access key or session token in command-line arguments.

Run the local handler tests before any authenticated smoke test:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Payload layout

The Lambda stores JSON files under the same S3 structure used by the runtime reader:

```text
sites/{domain}/versions/{versionId}/
  {domain}/site-config.json
  {domain}/components.json
  {domain}/variables.json
  {domain}/angora-combos.json
  {domain}/i18n/{lang}.json
  {domain}/{pageId}/page-config.json
  {domain}/{pageId}/components.json
  {domain}/{pageId}/variables.json
  {domain}/{pageId}/angora-combos.json
  {domain}/{pageId}/i18n/{lang}.json
```

That layout is intentionally symmetrical with `drafts/{domain}/...` in the Angular workspace, which is served locally at `/drafts/...`. Shared domain-level variables, combos, and i18n act like shared components: they provide defaults for all pages and can be overridden per page.
