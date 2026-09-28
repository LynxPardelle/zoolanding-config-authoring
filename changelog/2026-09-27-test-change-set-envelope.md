# TEST change-set envelope validation — 2026-09-27

The shared TEST reviewer could return `execute` for a response with an unreviewed next page, nested preview metadata, a conflicting reported stack ARN, or a child change-set reference. These cases were reproduced locally against the current reviewer. They are completeness/identity gaps; no evidence ties them to the recent THN deployment failures.

The reviewer now rejects pagination, parent/root change-set markers, actual nested-stack resources, and child change-set references. A supplied stack ARN must match the expected stack name and the partition, region, and account of the pinned change-set ARN. Existing compatibility with fixtures omitting `StackId` remains; live AWS responses supply it. `IncludeNestedStacks=true` alone remains accepted for a flat preview, matching the observed CDK behavior. Resource action and replacement restrictions are unchanged.

Regression tests failed before the patch and passed afterward. The full local unit suite passed after resolving local dependency prerequisites. At audit completion, these changes were local and had not been committed, pushed, or deployed. No AWS permissions, application code, QA users, or articles were changed.


Integration verification on current dev: 274 tests passed. This patch is approved for dev integration only; no TEST promotion or service deployment is part of this release.
