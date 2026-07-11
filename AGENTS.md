# Config Authoring Agent Workflow

Use this file as the repository entrypoint.

## Read order

1. Read README.md for the current service contract.
2. Inspect lambda_function.py and template.yaml for behavior and trust boundaries.
3. Inspect samconfig.toml and the relevant workflow before any deployment change.
4. Read changelog/ only when implementation history is needed.

## Working rules

- Treat authorization as fail-closed. Rules come only from the private S3 object and require exact IAM role ARNs plus explicit action, domain, and environment scopes.
- Never put AWS access keys, session tokens, authorization JSON, signed URLs, or raw environment values in command-line arguments, logs, examples, commits, or notes.
- Draft upsert may validate alias proposals but must not claim, overwrite, or revoke public aliases. Alias publication stays disabled until an allowlist and atomic ownership contract are approved.
- Validate domain, version ID, and every package path before any S3 or DynamoDB write.
- Keep S3 write permission limited to versioned site payloads; authorization configuration is read-only.
- Do not deploy unless the environment-specific authorization object exists and its exact role ARNs are verified.
- Run python -m unittest discover -s tests -v and validate the SAM template before closeout.
- Put current rules in README.md, chronology in changelog/, and do not create Codex.md as a second knowledge store.
