# THN validation-only candidate

Date: 2026-09-07 (Central Time)

- Add an isolated GitHub validation workflow triggered only by `codex/thn-task029-config-authoring`.
- The job has read-only repository permissions, no cloud credentials or environment approval, and no deployment or promotion step.
- Run the owning repository's tests and build checks; retain an explicitly non-deployable candidate package and source/run/digest receipt for 30 days.
- Existing deployment triggers, activation defaults and other drafts are unchanged. The artifact is QA evidence, not a legacy recovery migration or a deployment authorization.

Validation: parsed workflow boundary checks and Actionlint. Remote test results belong to the corresponding GitHub run, not this source document.
