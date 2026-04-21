---
name: "SAM Deploy Check"
description: "Review this config authoring Lambda for AWS SAM deploy readiness. Use when preparing to deploy changes that may affect POST /config-authoring, action contracts, alias persistence, payload storage layout, env vars, IAM, or documentation in zoolanding-config-authoring."
argument-hint: "Changed files, diff, or deploy concern"
agent: "agent"
---

Review this repository for deploy readiness after the current change.

Follow [Zoolanding Lambda Workflow](../skills/zoolanding-lambda-workflow/SKILL.md) and inspect the repo contract files:

- [README](../../README.md)
- [Lambda Handler](../../lambda_function.py)
- [SAM Template](../../template.yaml)
- [SAM Config](../../samconfig.toml)

Use the user's arguments plus the current diff or changed files.

Check specifically for:

- handler and template wiring for `POST /config-authoring`
- drift in `createSite`, `upsertDraft`, `getSite`, `publishDraft`, or `setSiteStatus`
- alias persistence behavior derived from `site-config.json.aliases`
- symmetry between the stored payload layout and frontend draft expectations
- env var, IAM, or parameter-override mismatches
- docs drift between code, README, and SAM template

Return:

1. findings first, ordered by severity
2. the deploy command to use, or a note that plain `sam deploy` is sufficient
3. the smallest post-deploy smoke test
4. doc or rollout notes still required