# THN production source and release separation

Added closed source-only promotion and reviewed activation selectors, retained native preview/execute, exact real TEST release provenance and explicit THN production profile checks. Existing non-THN TEST automatic provenance remains. Production authorization, IAM and live native inventory are prerequisites, not local test conclusions.

- Independent review repairs: raw duplicate/escaped selector keys fail before credentials; fresh live MAIN/TEST and actual role/trust/inline-policy fingerprints are retained at mutation boundaries; native CreationTime enforces24h expiry. Sealed authority tooling stays outside Lambda ZIP. Authoring retains no-checkout OIDC artifact boundary; Runtime transport includes helper and exact SHA checkout. Existing production CFN execution role identity is preserved.

The first Authoring CI run exposed a schema-test hash pinned to a Windows CRLF
worktree instead of the committed LF blob. The test now normalizes only CRLF
to LF and pins the committed schema bytes. A regression exercises both checkout
line endings and still rejects schema mutations and lone-CR changes. Application
validation and deployed package, S3 and recovery byte hashes are unchanged.

The real ShellCheck gate now recognizes intentional literal JMESPath backtick queries through narrowly documented per-statement annotations.
No global lint exclusions were added; release coordinates, query arguments and
summary bytes remain unchanged.

## TEST activation dependency repair

- Transport and hash-check the strict activation parser outside the unchanged eight-file Lambda payload. The deploy job uses this sealed helper without requiring a checkout.
- Keep the exact twelve-file outer transport and the unchanged ten-file build inventory; production verifies the promoted TEST helper against reviewed source.
- Reproduce the previous missing-module failure in an isolated artifact directory; verify successful parsing and rejection of duplicate selectors, missing helpers and substituted helper bytes before credentials.

- CI dependency correction: the new transport regressions extract unique literal workflow blocks using only the Python standard library. They no longer inherit PyYAML from a local development environment. Both modules pass with site-packages disabled (`python -S`), preserving the actual isolated parser/operator commands and hash-substitution rejection.

## Successful TEST run selection

- Filter exact successful Deploy Test runs through their actual completed deployment and immutable smoke jobs before requiring one unique deployed run. Code-only pushes and review-only runs do not compete with deployed evidence.
- Preserve exact workflow/repository/source/branch/event/attempt metadata, fail closed on unavailable job evidence, and reject zero or multiple genuine deployments. The unchanged artifact resolver stays bound to the selected run.
- Reproduce the three-run source-only/review/execute sequence using the actual production inline command with a closed offline GitHub subprocess fixture; verify wrong source/job/artifact coordinates and ambiguous deployments are rejected.
## Protected manual code-only review

- Reproduced the actual TEST and production inline reviewers accepting unrelated
  resource additions and Lambda Tags, Environment, Role and Metadata changes.
- Manual review and execution now admit only a nonreplacement Code modification
  of ConfigAuthoringFunction, with an exact native resource scope and nonempty
  Code-only details. Direct and reference-based Code causes remain accepted.
- Preserved legacy push decisions, parameter and change-set identity checks,
  exact no-op handling, retained preview/digest, source provenance and fresh
  baseline checks. No template, runtime ZIP, IAM permission or AWS resource changed.
- Seven standard-library regression tests execute both real workflow blocks; the
  failing cases first reproduced the gap and passed after the narrow guard fix.
