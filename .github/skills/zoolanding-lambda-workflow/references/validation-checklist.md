# Validation Checklist

## Contract

- Action names must stay explicit and documented.
- Alias persistence must remain consistent with `site-config.json.aliases`.
- Published pointer behavior must remain stable for runtime readers.
- S3 payload layout must stay symmetrical with frontend draft expectations.

## Verification

- Check the affected action with a focused request body or handler invocation.
- Verify docs/examples when request or response shapes move.
- Keep cross-platform narrative docs in `zoolandingpage`, not here.
