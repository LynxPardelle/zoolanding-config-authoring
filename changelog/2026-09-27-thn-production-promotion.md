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
