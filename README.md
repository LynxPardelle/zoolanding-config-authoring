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
- Validate generic server-only feature descriptors and bind them to one authorized tenant/draft scope before any package write.
- Keep package versions immutable and revalidate their exact object set, manifest, and hashes before moving draft or published pointers.
- Inspect only deterministic notification-secret metadata; this service never reads secret values.

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

`DEPLOY_AUTHZ_CONFIG_S3_KEY` points to a JSON array in `CONFIG_PAYLOADS_BUCKET_NAME`. Every rule has exactly six keys: one IAM role ARN, one valid `tenantId`, one valid `draftId`, one canonical domain, the current stack environment, and unique code-owned actions. Wildcards, plural role fields, extra keys, unknown actions, duplicate roles/domains/drafts, or one malformed entry reject the complete authorization object. Example:

```json
[
  {
    "roleArn": "arn:aws:iam::123456789012:role/example-draft-test-deploy",
    "tenantId": "example-draft",
    "draftId": "example-draft",
    "domains": ["example.com"],
    "environments": ["test"],
    "actions": ["createSite", "upsertDraft", "publishDraft", "getSite"]
  }
]
```

Each bucket contains rules for only its own environment. Production uses the corresponding production role ARN and `"production"` environment; test and production keep the same reviewed tenant/draft IDs.

## Deploy

`ConfigAuthoringFunction` uses the generated `.build/config-authoring` `CodeUri`. Run `python tools/build_lambda_artifact.py` before `sam validate` or `sam build`; the builder copies exactly three Python modules and four code-owned JSON schemas. CI verifies the same seven-file inventory. Test writes a canonical source-commit/file-size/SHA-256 manifest into the SAM build. Production requires an exact two-parent promotion with the same Git tree as the promoted test parent, downloads the immutable artifact from that exact successful test run, verifies its manifest and bytes against the checked-out source, and reuses that build. Only the dependent deployment job receives GitHub OIDC permission. `.aws-samignore` is defense in depth, not artifact evidence.

For repeatable deployments from this repository:

The checked-in `samconfig.toml` includes only explicit `test` and `prod` deployment profiles in `us-east-1`. Development is local-only and has no AWS stack, bucket, table, or deploy profile.

- `test` uses `zoolanding-config-registry-test` and `zoolanding-config-payloads-test`.
- `prod` uses the existing production table and bucket names.

The checked-in deploy profiles use the parallel `system/deploy-authz-v2.json` key. Bootstrap and validate that object in the environment's private config bucket before deploying the new Lambda; missing or malformed authorization configuration denies every request. The legacy `system/deploy-authz.json` object remains untouched so the currently deployed role-name runtime and a protected code rollback keep their original contract.

### Private server-scope bootstrap

`tools/bootstrap_server_scopes.py` is the operator-only bootstrap for the private scope registry and runtime authorization object. It is not part of the Lambda artifact. It derives the exact draft set from the hub's `docs/drafts-registry.json`, verifies each repository's environment-scoped `DRAFT_DOMAIN` and `AWS_ROLE_ARN`, and verifies the matching IAM role's exact GitHub OIDC trust before generating any bytes.

The reviewed ID rule is deliberately small:

- `draftId` is the canonical draft repository slug.
- `tenantId` is the same isolated repository slug unless an explicit reviewed override is supplied.
- Zoosite currently uses the explicit `zoositioweb.com.mx=zoosite` tenant override; its `draftId` remains its repository slug.
- Sharing a tenant across drafts always requires another explicit reviewed override.

Plan from the authoring repository without writing AWS state:

```powershell
python tools/bootstrap_server_scopes.py plan `
  --registry ..\zoolandingpage\docs\drafts-registry.json `
  --expected-draft-count 11 `
  --tenant-override zoositioweb.com.mx=zoosite `
  --profile ADMIN-AIM-CLI `
  --region us-east-1 `
  --test-bucket zoolanding-config-payloads-test `
  --production-bucket zoolanding-config-payloads
```

Review and retain only the plan's safe metadata: counts, SHA-256 values, bucket state, ETags, version IDs, lengths, and timestamps. Do not capture generated object bodies, GitHub variable dumps, IAM responses, credentials, or environment values. The initial plan must prove exactly 11 scopes and 11 rules per environment, identical scope bytes across environments, enforced bucket ownership, all four S3 public-access blocks, and the reviewed current scope and v2 authorization ETag/version/SHA-256 values when present. It reports `scopeUpdateMode` as `create`, `idempotent`, or `append`.

Use `apply --help` for the conditional write arguments. Apply test first with the exact plan hashes and reviewed current metadata. Use the literal `MISSING` triplet when the planned current scope does not exist, and the literal `MISSING` ETag/version pair when the planned v2 authorization object does not exist. Missing objects use `If-None-Match: *`; an unchanged scope is idempotent; an update uses `If-Match` only when it strictly appends canonical drafts without changing or removing any existing mapping. The scope is written first, the complete v2 authorization object is generated second, and both current and version-specific objects are read back exactly. A partial failure can therefore leave a new scope without a grant, never a grant without its scope. The tool reports prior v2 versions and hashes when they exist; the separate legacy authorization key is never a bootstrap or rollback target. It refuses an unknown or environment-mismatched bucket, disabled versioning, non-enforced ownership, incomplete public-access block, changed object metadata, unreviewed hashes, scope mutation/deletion, duplicate bindings, or non-exact OIDC trust.

Production requires this evidence chain, in order:

1. Apply the reviewed private bundle to test under `system/server-scopes.json` and the parallel `system/deploy-authz-v2.json` key. Both use conditional/versioned writes and exact readback; never overwrite or delete the legacy `system/deploy-authz.json` key.
2. Promote the authoring repository only through `feature -> dev -> test`. The test workflow accepts exactly a two-parent merge whose first parent is the previous `test` tip and whose second parent is the current `dev` tip, and it requires the merge commit's Git tree to equal that exact source-tip tree. Conflict resolution or other untested merge-result bytes fail closed.
3. Let `Deploy Test` finish successfully. Its deploy job packages normalized allowlisted bytes under a unique run prefix in the environment's private payload bucket, creates one deterministically named CloudFormation change set, waits for and describes that exact ARN, rejects removals and every `Replacement` value other than `False` or absent, then executes only that reviewed ARN. An exact CloudFormation no-change response is deleted and treated as a no-op.
4. Dispatch `Deploy test draft` in one canonical draft repository after the authoring test run. This is the positive signed authorization canary; the unsigned endpoint probe must independently return `403`.
5. Run `verify-test` with the exact authoring test commit/run and canonical draft canary repository/run. The verifier binds the exact active workflow paths and IDs, stack endpoint, current scope/authz S3 version IDs and hashes, canary timing, unsigned `403`, workflow artifact manifest, deployed Lambda ZIP bytes, and Lambda `CodeSha256`/revision to the source commit. The current GitHub Environment `AUTHORING_ENDPOINT` must equal the stack endpoint and its API-provided `updated_at` must be strictly earlier than the canary run's `created_at`; equality fails closed because GitHub timestamps do not prove ordering within the same instant. Correcting the variable after an old run cannot validate that run. Retain the safe evidence object and `evidenceSha256` outside the repository. Production `apply` requires those identifiers and the exact approved evidence hash, then re-collects the live evidence instead of trusting a saved claim. A canary-run artifact that records the endpoint at execution time is a stronger future binding and requires a separately promoted draft-workflow change.
6. Only after that gate, enable production bucket versioning, read back `Enabled`, and apply the production bundle. Promote code only through `test -> main`; production requires the same exact tree rule, a unique successful `Deploy Test` run for the second parent, and that run's exact manifest-bound SAM artifact. Before creating production exposure, it downloads the current live test Lambda ZIP and proves its `CodeSha256` and seven bytes equal the promoted artifact. After packaging production, it validates the JSON template's exact run-scoped S3 key, downloads that exact production ZIP, and requires its full `CodeSha256` and contents to equal the bound live test artifact before it creates the change set. It re-reads the test `CodeSha256` immediately before executing the reviewed change set. The post-deploy test/production `CodeSha256` comparison remains defense in depth.

Do not add lifecycle rules and do not delete versions. Do not capture generated object bodies, GitHub variable dumps, IAM responses, credentials, or environment values in evidence. GitHub workflow artifacts are retained for seven days so the production gate can inspect the exact tested build. S3 packaging uses a unique `system/deploy-artifacts/{commit}/{run}/{attempt}` prefix and currently has no automatic cleanup: the present seven raw source files total about 116,350 bytes, or about 0.116 GB per 1,000 runs before ZIP compression (excluding request charges and template overhead). Measure actual stored versions before budgeting; a prefix-scoped lifecycle policy remains a separate cost/rollback decision. The deployment workflows are the supported path; do not bypass their deterministic reviewed change-set flow with a direct `sam deploy` command.

Rollback uses `rollback --help` to copy an explicitly approved prior version back as a new conditional version. It never deletes or mutates historical versions. A scope-registry rollback is allowed only when the prior bytes are identical to the current canonical registry. An authorization rollback may restore earlier role ARNs, but its rules must still exactly cover every current canonical scope, AWS account, environment, domain, tenant/draft ID, and code-owned action. Legacy `roleName` or differently shaped authorization versions are intentionally not restorable. If only the Lambda/runtime release is faulty, roll back the stack or Lambda release while retaining the canonical authorization object. S3 versioning cost is driven by the full bytes retained for every version plus the associated S3 requests; calculate it from measured object sizes and version counts rather than assuming a fixed monthly amount.

Scope removals, canonical ID changes, and tenant split/merge migrations are outside Phase 1. They require a separately reviewed migration and must not be represented as an append or rollback.

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

## Server-only feature descriptors

Server-only descriptors live at the domain root under `{domain}/server/`. Paths, kinds, and filenames are closed: unknown, nested, case-altered, percent-encoded, local-only, duplicate, or mismatched entries fail before S3 writes.

The four generic policy descriptors are schema-validated and must share the exact authorized `environment`, `tenantId`, `draftId`, and `domain` scope:

```text
{domain}/server/data-spaces.json
{domain}/server/commerce.json
{domain}/server/integration-bindings.json
{domain}/server/notification-policies.json
```

Legacy compatibility is closed, not an arbitrary JSON extension point. Only these canonical domain/file/SHA-256 triples are grandfathered:

| Domain | File | Canonical JSON SHA-256 |
| --- | --- | --- |
| `music.lynxpardelle.com` | `integrations.json` | `e92571c6f7f0661c3fb713f85739776d74a4f8a29783c5029578823af64ce401` |
| `pokeapi-demo.zoolandingpage.com.mx` | `integrations.json` | `8e3716d6041d9ff69760162fc1b9ac29e98c9f3e0f162908ab656fd6a7306145` |
| `zoositioweb.com.mx` | `auth-profile-registry.json` | `88f94c06c748375c85366ee46d15ce771573bc78669d183acd0efb6442a257fa` |

Those hashes were verified read-only on July 14, 2026 Central Time against the canonical hub files and every currently referenced test/production copy; no object body was retained in evidence. Any new or modified legacy descriptor fails closed and must migrate through a separately reviewed closed server-feature contract. Existing blogs need not migrate while their exact grandfathered bytes remain unchanged, and future blogs may use the generic path. The recursive secret/PII/provider-identifier scanner remains defense in depth and additionally rejects checksum-valid 18-digit CLABE and 12–19 digit Luhn PAN subsequences anywhere inside a string after normalizing spaces/hyphens, including paths, queries, labels, and nested values; length alone is not treated as proof. Drafts contain opaque identifiers and policy only. Credentials, tokens, bank/fiscal PII, provider resource identifiers, signed URLs, and secret values are rejected.

Test descriptors use provider mode `test`. Production descriptors use mode `live`, but any active integration, commerce, or notification policy is deliberately blocked by the code-owned `live_gate_unverified` guard until a later approved phase closes the live operational controls. Notification activation also fails closed unless each deterministic SMTP and recipient secret exists, is enabled, is not scheduled for deletion, and has the exact environment/tenant/draft ownership tags. Only `DescribeSecret` is permitted.

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
