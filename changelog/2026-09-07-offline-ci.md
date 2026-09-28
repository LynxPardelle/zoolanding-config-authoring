# Offline CI validation

Date: 2026-09-07 (Central Time)

The new `Offline tests (no AWS)` workflow runs the full Python unit suite in an isolated Linux network namespace after dependency installation. The test process has no inherited credentials, uses an isolated home and cannot reach AWS. Validation has read-only repository permissions, a standard Ubuntu runner, a 15-minute timeout, no cache and no artifact upload. Existing deployment, promotion and rollback workflows are unchanged.

Local validation: 214 tests passed with zero Python network attempts. GitHub validates the Linux namespace separately; the PR check is the source of truth for that result. This does not replace live integration or rollback verification.

