import base64
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

CHECKOUT_ACTION = "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"
SETUP_PYTHON_ACTION = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
SETUP_SAM_ACTION = "aws-actions/setup-sam@89ddb14d60e682855e3fea4be85b3c56485de310"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ARTIFACT_ACTION = "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131"
GITHUB_SCRIPT_ACTION = "actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd"
CONFIGURE_AWS_ACTION = "aws-actions/configure-aws-credentials@517a711dbcd0e402f90c77e7e2f81e849156e31d"
RUNTIME_FILES = (
    "lambda_function.py",
    "schemas/server-features/commerce.schema.json",
    "schemas/server-features/data-spaces.schema.json",
    "schemas/server-features/integration-bindings.schema.json",
    "schemas/server-features/notification-policies.schema.json",
    "server_policy_validation.py",
    "zoolanding_lambda_common.py",
)


def workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def marked_blocks(text: str, marker: str) -> list[str]:
    start = f"# {marker}:start"
    end = f"# {marker}:end"
    blocks: list[str] = []
    remaining = text
    while start in remaining:
        _, remaining = remaining.split(start, 1)
        body, remaining = remaining.split(end, 1)
        blocks.append(textwrap.dedent(body).strip())
    return blocks


def run_inline_python(code: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class WorkflowIdentityBoundaryTest(unittest.TestCase):
    def test_documentation_records_the_artifact_identity_boundary(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "changelog" / "2026-07.md").read_text(encoding="utf-8")

        for phrase in (
            "immutable artifact ID, coordinated name, and outer-manifest SHA-256",
            "does not check out the repository, install Python, or execute repository scripts",
            "A failed deploy-job rerun consumes the same validation-job outputs",
            "inline, fail-closed CloudFormation and Lambda-package checks",
        ):
            self.assertIn(phrase, readme)
        self.assertIn("artifact identity boundary", changelog)

    def test_every_action_is_immutable_and_sam_is_exactly_pinned(self):
        expected_actions = {
            CHECKOUT_ACTION,
            SETUP_PYTHON_ACTION,
            SETUP_SAM_ACTION,
            UPLOAD_ARTIFACT_ACTION,
            DOWNLOAD_ARTIFACT_ACTION,
            GITHUB_SCRIPT_ACTION,
            CONFIGURE_AWS_ACTION,
        }
        combined = "\n".join(
            workflow(name)
            for name in ("ci.yml", "deploy-test.yml", "deploy-production.yml")
        )
        used_actions = set()
        for line in combined.splitlines():
            stripped = line.strip().removeprefix("- ")
            if stripped.startswith("uses: "):
                used_actions.add(stripped.removeprefix("uses: ").split(" #", 1)[0])

        self.assertLessEqual(used_actions, expected_actions)
        for action in used_actions:
            self.assertRegex(action, r"^[^@\s]+@[a-f0-9]{40}$")
        self.assertIn(UPLOAD_ARTIFACT_ACTION, used_actions)
        self.assertIn(DOWNLOAD_ARTIFACT_ACTION, used_actions)
        self.assertIn(GITHUB_SCRIPT_ACTION, used_actions)
        self.assertIn(CONFIGURE_AWS_ACTION, used_actions)
        self.assertNotIn("actions/upload-artifact@v4", combined)
        self.assertNotIn("actions/download-artifact@v4", combined)

        setup_sam_count = combined.count(SETUP_SAM_ACTION)
        self.assertGreaterEqual(setup_sam_count, 5)
        self.assertEqual(combined.count("version: 1.163.0"), setup_sam_count)

    def test_oidc_jobs_consume_one_exact_artifact_without_repository_execution(self):
        cases = {
            "deploy-test.yml": "test",
            "deploy-production.yml": "production",
        }
        for workflow_name, environment in cases.items():
            with self.subTest(workflow=workflow_name):
                text = workflow(workflow_name)
                validate_start = text.index("\n  validate:")
                deploy_start = text.index("\n  deploy:")
                validate = text[validate_start:deploy_start]
                deploy = text[deploy_start:]

                self.assertNotIn("id-token: write", validate)
                self.assertIn("python -m unittest", validate)
                self.assertIn("tools/verify_promotion_provenance.py", validate)
                self.assertIn("--normalize-artifact", validate)
                self.assertIn("--verify-sam-build", validate)
                self.assertIn("sha256sum", validate)
                self.assertIn("artifact_id: ${{ steps.upload.outputs.artifact-id }}", validate)
                self.assertIn("artifact_name: ${{ steps.artifact_metadata.outputs.name }}", validate)
                self.assertIn("manifest_digest: ${{ steps.manifest.outputs.digest }}", validate)
                self.assertIn(f"uses: {UPLOAD_ARTIFACT_ACTION}", validate)

                first_step = next(
                    line.strip()
                    for line in deploy[deploy.index("\n    steps:") + len("\n    steps:"):].splitlines()
                    if line.strip()
                )
                self.assertEqual(first_step, "- name: Validate artifact handoff metadata")
                self.assertIn("^[1-9][0-9]*$", deploy)
                self.assertIn("^[a-f0-9]{64}$", deploy)
                self.assertIn(
                    f"artifact_name_pattern=\"^config-authoring-{environment}-"
                    "${GITHUB_RUN_ID}-[1-9][0-9]*-${GITHUB_SHA}$\"",
                    deploy,
                )
                self.assertIn(f"uses: {DOWNLOAD_ARTIFACT_ACTION}", deploy)
                self.assertIn("artifact-ids: ${{ needs.validate.outputs.artifact_id }}", deploy)
                self.assertIn("sha256sum --check --strict -", deploy)
                self.assertIn("sha256sum --check --strict ../build-manifest.sha256", deploy)
                self.assertIn("artifact_link_invalid", deploy)
                self.assertIn("expected-build-files.txt", deploy)
                self.assertIn("expected-artifact-files.txt", deploy)

                download_start = deploy.index(DOWNLOAD_ARTIFACT_ACTION)
                download_end = deploy.index("\n      - name:", download_start)
                download_step = deploy[download_start:download_end]
                self.assertNotIn("name:", download_step)
                self.assertNotIn("run-id:", download_step)
                self.assertNotIn("github-token:", download_step)

                self.assertNotIn(CHECKOUT_ACTION, deploy)
                self.assertNotIn(SETUP_PYTHON_ACTION, deploy)
                self.assertNotIn("tools/", deploy)
                self.assertNotIn("python -m unittest", deploy)
                self.assertNotRegex(deploy, r"(?m)^\s+run:\s+python(?:\s|$)")

                verify_index = deploy.index("sha256sum --check --strict ../build-manifest.sha256")
                setup_sam_index = deploy.index(SETUP_SAM_ACTION)
                provenance_index = deploy.index(GITHUB_SCRIPT_ACTION)
                credentials_index = deploy.index(CONFIGURE_AWS_ACTION)
                self.assertLess(verify_index, setup_sam_index)
                self.assertLess(setup_sam_index, provenance_index)
                self.assertLess(provenance_index, credentials_index)
                between = deploy[provenance_index:credentials_index]
                self.assertEqual(between.count("\n      - "), 1)

                self.assertIn("id-token: write", deploy)
                self.assertIn("contents: read", deploy)
                self.assertNotIn("pull-requests: read", deploy)

    def test_change_set_and_production_artifact_gates_remain_present(self):
        for workflow_name in ("deploy-test.yml", "deploy-production.yml"):
            text = workflow(workflow_name)
            deploy = text[text.index("\n  deploy:"):]
            self.assertEqual(deploy.count("--change-set-type UPDATE"), 1)
            self.assertIn("cloudformation describe-change-set", deploy)
            self.assertIn("cloudformation execute-change-set", deploy)
            self.assertIn("cloudformation wait stack-update-complete", deploy)
            self.assertNotIn("cloudformation list-change-sets", deploy)
            for parameter in (
                "ParameterKey=EnvironmentName,ParameterValue=$EXPECTED_ENVIRONMENT",
                "ParameterKey=ManageStorageResources,ParameterValue=$EXPECTED_MANAGE_STORAGE",
                "ParameterKey=ConfigTableName,ParameterValue=$EXPECTED_TABLE",
                "ParameterKey=ConfigPayloadsBucketName,ParameterValue=$EXPECTED_BUCKET",
                "ParameterKey=LogLevel,ParameterValue=INFO",
                "ParameterKey=DeployAuthzConfigS3Key,ParameterValue=system/deploy-authz-v2.json",
            ):
                self.assertIn(parameter, deploy)

        production = workflow("deploy-production.yml")
        self.assertIn("# inline-lambda-zip-verifier:start", production[production.index("\n  deploy:"):])
        self.assertIn("lambda get-function", production)
        self.assertGreaterEqual(production.count("CodeSha256"), 3)
        self.assertIn('test "$current_test_code_sha" = "$bound_test_code_sha"', production)
        self.assertIn('test "$production_code_sha" = "$test_code_sha"', production)

    def test_production_selects_the_latest_validated_artifact_across_failed_job_reruns(self):
        production = workflow("deploy-production.yml")
        validate = production[
            production.index("\n  validate:"):production.index("\n  deploy:")
        ]

        self.assertIn("artifact_attempt <= expected_run_attempt", production)
        self.assertIn("latest_attempt = max(attempt for attempt, _ in matches)", production)
        self.assertIn("test_artifact_name={selected['name']}", production)
        self.assertLess(validate.index(CHECKOUT_ACTION), validate.index(DOWNLOAD_ARTIFACT_ACTION))
        self.assertIn("artifact_link_invalid", validate)

    def test_inline_change_set_reviewer_is_executable_and_fail_closed(self):
        blocks = [
            marked_blocks(workflow(name), "inline-change-set-review")
            for name in ("deploy-test.yml", "deploy-production.yml")
        ]
        self.assertEqual([len(group) for group in blocks], [1, 1])
        self.assertEqual(blocks[0][0], blocks[1][0])
        reviewer = blocks[0][0]

        parameters = {
            "EnvironmentName": "test",
            "ManageStorageResources": "true",
            "ConfigTableName": "zoolanding-config-registry-test",
            "ConfigPayloadsBucketName": "zoolanding-config-payloads-test",
            "LogLevel": "INFO",
            "DeployAuthzConfigS3Key": "system/deploy-authz-v2.json",
        }
        name = "zoolanding-123-1"
        arn = (
            "arn:aws:cloudformation:us-east-1:765932874577:"
            "changeSet/zoolanding-123-1/00000000-0000-0000-0000-000000000000"
        )
        payload = {
            "ChangeSetName": name,
            "ChangeSetId": arn,
            "StackName": "zoolanding-config-authoring-test",
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Parameters": [
                {"ParameterKey": key, "ParameterValue": value}
                for key, value in parameters.items()
            ],
            "Changes": [
                {
                    "Type": "Resource",
                    "ResourceChange": {
                        "Action": "Modify",
                        "Replacement": "False",
                    },
                }
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            description = pathlib.Path(directory) / "change-set.json"

            def review(candidate: dict) -> subprocess.CompletedProcess[str]:
                description.write_text(json.dumps(candidate), encoding="utf-8")
                return run_inline_python(
                    reviewer,
                    str(description),
                    "zoolanding-config-authoring-test",
                    name,
                    arn,
                    json.dumps(parameters, separators=(",", ":"), sort_keys=True),
                )

            accepted = review(payload)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.strip(), "execute")

            for action, replacement in (
                ("Remove", "False"),
                ("Modify", "True"),
                ("Modify", "Conditional"),
            ):
                candidate = json.loads(json.dumps(payload))
                candidate["Changes"][0]["ResourceChange"].update(
                    Action=action,
                    Replacement=replacement,
                )
                with self.subTest(action=action, replacement=replacement):
                    self.assertNotEqual(review(candidate).returncode, 0)

            wrong_parameters = json.loads(json.dumps(payload))
            wrong_parameters["Parameters"][0]["ParameterValue"] = "production"
            self.assertNotEqual(review(wrong_parameters).returncode, 0)

            noop = json.loads(json.dumps(payload))
            noop.update(
                Status="FAILED",
                ExecutionStatus="UNAVAILABLE",
                StatusReason=(
                    "The submitted information didn't contain changes. "
                    "Submit different information to create a change set."
                ),
                Changes=[],
            )
            accepted_noop = review(noop)
            self.assertEqual(accepted_noop.returncode, 0, accepted_noop.stderr)
            self.assertEqual(accepted_noop.stdout.strip(), "noop")

    def test_inline_test_artifact_resolver_handles_deploy_only_reruns(self):
        production = workflow("deploy-production.yml")
        blocks = marked_blocks(production, "inline-test-artifact-resolver")
        self.assertEqual(len(blocks), 1)
        resolver = blocks[0]
        run_id = 123
        source_sha = "a" * 40

        def artifact(artifact_id: int, attempt: int) -> dict:
            return {
                "id": artifact_id,
                "name": f"config-authoring-test-{run_id}-{attempt}-{source_sha}",
                "size_in_bytes": 100,
                "expired": False,
                "workflow_run": {
                    "id": run_id,
                    "head_branch": "test",
                    "head_sha": source_sha,
                },
            }

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            payload_path = root / "artifacts.json"
            output_path = root / "output.txt"

            def resolve(candidates: list[dict]) -> subprocess.CompletedProcess[str]:
                payload_path.write_text(
                    json.dumps({"artifacts": candidates}),
                    encoding="utf-8",
                )
                output_path.unlink(missing_ok=True)
                return run_inline_python(
                    resolver,
                    str(payload_path),
                    str(run_id),
                    "3",
                    source_sha,
                    str(output_path),
                )

            accepted = resolve([artifact(10, 1), artifact(20, 2), artifact(40, 4)])
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                (
                    "test_artifact_id=20\n"
                    f"test_artifact_name=config-authoring-test-{run_id}-2-{source_sha}\n"
                ),
            )

            ambiguous = resolve([artifact(20, 2), artifact(21, 2)])
            self.assertNotEqual(ambiguous.returncode, 0)

    def test_inline_lambda_zip_verifier_binds_live_and_packaged_code_bytes(self):
        production = workflow("deploy-production.yml")
        blocks = marked_blocks(production, "inline-lambda-zip-verifier")
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0], blocks[1])
        verifier = blocks[0]

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            artifact = root / "artifact"
            archive = root / "lambda.zip"
            artifact.mkdir()
            for relative_path in RUNTIME_FILES:
                destination = artifact / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative_path).read_bytes())
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
                for relative_path in RUNTIME_FILES:
                    output.writestr(relative_path, (artifact / relative_path).read_bytes())
            code_sha = base64.b64encode(hashlib.sha256(archive.read_bytes()).digest()).decode("ascii")

            accepted = run_inline_python(verifier, str(artifact), str(archive), code_sha)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            wrong_sha = run_inline_python(verifier, str(artifact), str(archive), "wrong")
            self.assertNotEqual(wrong_sha.returncode, 0)

            (artifact / "lambda_function.py").write_bytes(b"tampered")
            tampered = run_inline_python(verifier, str(artifact), str(archive), code_sha)
            self.assertNotEqual(tampered.returncode, 0)

    def test_inline_packaged_key_parser_is_exactly_run_scoped(self):
        production = workflow("deploy-production.yml")
        blocks = marked_blocks(production, "inline-packaged-key-parser")
        self.assertEqual(len(blocks), 1)
        parser = blocks[0]
        sha = "a" * 40
        bucket = "zoolanding-config-payloads"
        prefix = f"system/deploy-artifacts/{sha}/123/1"
        key = f"{prefix}/{'b' * 32}"

        with tempfile.TemporaryDirectory() as directory:
            template = pathlib.Path(directory) / "packaged.json"
            template.write_text(
                json.dumps({
                    "Resources": {
                        "ConfigAuthoringFunction": {
                            "Properties": {"CodeUri": f"s3://{bucket}/{key}"},
                        },
                    },
                }),
                encoding="utf-8",
            )
            accepted = run_inline_python(parser, str(template), bucket, prefix)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.strip(), key)

            rejected = run_inline_python(parser, str(template), "other-bucket", prefix)
            self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
