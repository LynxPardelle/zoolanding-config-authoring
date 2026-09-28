# THN production source and release separation

Added closed source-only promotion and reviewed activation selectors, retained native preview/execute, exact real TEST release provenance and explicit THN production profile checks. Existing non-THN TEST automatic provenance remains. Production authorization, IAM and live native inventory are prerequisites, not local test conclusions.

- Independent review repairs: raw duplicate/escaped selector keys fail before credentials; fresh live MAIN/TEST and actual role/trust/inline-policy fingerprints are retained at mutation boundaries; native CreationTime enforces24h expiry. Sealed authority tooling stays outside Lambda ZIP. Authoring retains no-checkout OIDC artifact boundary; Runtime transport includes helper and exact SHA checkout. Existing production CFN execution role identity is preserved.
