---
name: zoolanding-lambda-workflow
description: 'Zoolanding Lambda workflow for config authoring. Use when changing draft package storage, alias persistence, site lifecycle status, API actions, or SAM deployment for zoolanding-config-authoring.'
user-invocable: true
---

# Zoolanding Lambda Workflow

Use this skill for work in the config authoring Lambda.

## Repo Focus

- This service owns create, pull, update, publish, and lifecycle status changes for draft packages.
- It must stay symmetrical with the draft file layout used by the Angular repo.
- Alias records derived from `site-config.json.aliases` are part of the runtime contract.

## Workflow

1. Read the current contract.
   - Start with `README.md`, then inspect `lambda_function.py` and `template.yaml`.

2. Preserve storage symmetry.
   - Keep the S3 versioned layout aligned with `drafts/{domain}/...` expectations from the frontend workflow.
   - Treat alias persistence and publish pointers as contract-sensitive behavior.

3. Change only the requested behavior.
   - Keep action names and payload shapes stable unless the task explicitly changes them.
   - Avoid mixing frontend workflow rewrites into this repo.

4. Verify with focused contract checks.
   - Prefer targeted payload or handler checks around `createSite`, `upsertDraft`, `publishDraft`, or `setSiteStatus`.
   - If the action contract changes, update examples and docs with the code.

5. Keep deployment docs current.
   - If env vars, outputs, or API behavior change, update `README.md` in the same diff.

## Recommended Repo-Local Skills

- Pair this workflow with the repo-local `karpathy-guidelines` skill for scoped implementation, `systematic-debugging` for root-cause analysis, `risk-review` for review-only asks, and `test-driven-development` for behavior-changing code.
- Use the repo-local `zoolanding-pr-followup` skill for CI, reviewer, and merge-readiness work.
- For shared workspace customization audits or consolidated cross-repo summaries, use the community prompts [Workspace AI Customization Audit](../../../../zoolandingpage/.github/prompts/workspace-ai-customization-audit.prompt.md) and [Workspace Change Summary](../../../../zoolandingpage/.github/prompts/workspace-change-summary.prompt.md).
- Use the repo-local `zoolanding-production-readiness` agent for deploy-gate review and the repo-local `zoolanding-config-platform-audit` agent when a change may require coordinated updates in the frontend or sibling services.
- Use the repo-local `sam-deploy-check` prompt before shipping contract or SAM changes.

## Resources

- [Validation Checklist](./references/validation-checklist.md)