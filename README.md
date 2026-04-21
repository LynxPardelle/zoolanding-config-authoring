# Zoolanding Config Authoring

This Lambda handles create, pull, update, publish, and lifecycle status changes for site draft packages.

## Responsibilities

- Create a new site registry record.
- Store authoring payload files into the versioned S3 layout.
- Persist alias lookup records based on `site-config.json.aliases`.
- Pull a draft or published package back into the local draft format.
- Publish the current draft pointer.
- Mark a site as `active`, `maintenance`, or `suspended`.

## AWS dependencies

- DynamoDB table: `zoolanding-config-registry`
- S3 bucket: `zoolanding-config-payloads`
- API Gateway: `POST /config-authoring`
- CloudWatch Logs

## Environment variables

- `CONFIG_TABLE_NAME`
- `CONFIG_PAYLOADS_BUCKET_NAME`
- `LOG_LEVEL`

## Deploy

For repeatable deployments from this repository:

```bash
sam deploy
```

The checked-in `samconfig.toml` already targets `us-east-1` with the correct stack name and parameter overrides.

The first non-interactive deployment command used was:

```bash
sam deploy --stack-name zoolanding-config-authoring --region us-east-1 --capabilities CAPABILITY_IAM --resolve-s3 --no-confirm-changeset --no-fail-on-empty-changeset --parameter-overrides ConfigTableName=zoolanding-config-registry ConfigPayloadsBucketName=zoolanding-config-payloads LogLevel=INFO
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

Site aliases are authored in `site-config.json` through an optional `aliases` array. Those hosts resolve to the canonical `domain` at runtime, which lets you test landings on preview subdomains or temporary domains without cloning the full site entry.

## Manual smoke tests

Create or replace a draft:

```bash
curl -X POST "https://your-api-id.execute-api.us-east-1.amazonaws.com/Prod/config-authoring" \
  -H "Content-Type: application/json" \
  -d @sample-create-site.json
```

Publish the current draft:

```bash
curl -X POST "https://your-api-id.execute-api.us-east-1.amazonaws.com/Prod/config-authoring" \
  -H "Content-Type: application/json" \
  -d '{"action":"publishDraft","domain":"test.zoolandingpage.com.mx"}'
```

Suspend a site with a professional fallback message:

```bash
curl -X POST "https://your-api-id.execute-api.us-east-1.amazonaws.com/Prod/config-authoring" \
  -H "Content-Type: application/json" \
  -d '{"action":"setSiteStatus","domain":"test.zoolandingpage.com.mx","status":"suspended","fallbackMode":"system","message":"This site is currently unavailable. Please contact support."}'
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
