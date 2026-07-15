from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.verify_promotion_provenance import PromotionProvenanceError, verify_promotion_provenance


class RepositoryHygieneTest(unittest.TestCase):
    def test_local_and_sam_artifacts_are_ignored(self):
        gitignore_path = ROOT / ".gitignore"
        samignore_path = ROOT / ".aws-samignore"
        self.assertTrue(gitignore_path.is_file())
        self.assertTrue(samignore_path.is_file())
        gitignore = gitignore_path.read_text(encoding="utf-8").splitlines()
        samignore = samignore_path.read_text(encoding="utf-8").splitlines()

        self.assertTrue({"__pycache__/", "*.py[cod]", ".aws-sam/", ".build/", ".venv/", ".env", ".env.*"}.issubset(gitignore))
        self.assertTrue({".git/", ".github/", ".aws-sam/", "__pycache__/", "*.py[cod]", "tests/", "README.md"}.issubset(samignore))

    def test_ci_and_deploy_jobs_verify_the_allowlisted_sam_artifact(self):
        ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python tools/build_lambda_artifact.py", ci_workflow)
        self.assertIn(
            "python tools/build_lambda_artifact.py --verify-artifact .aws-sam/build/ConfigAuthoringFunction",
            ci_workflow,
        )

        for workflow_name in ("deploy-test.yml", "deploy-production.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            self.assertIn("AWS_DEFAULT_REGION: ${{ vars.AWS_REGION || 'us-east-1' }}", workflow)
            self.assertIn("AWS_REGION: ${{ vars.AWS_REGION || 'us-east-1' }}", workflow)
            self.assertIn("SAM_CLI_TELEMETRY: 0", workflow)
            build_index = workflow.index("python tools/build_lambda_artifact.py\n")
            verify_index = workflow.index(
                "python tools/build_lambda_artifact.py --verify-artifact .aws-sam/build/ConfigAuthoringFunction"
            )
            credentials_index = workflow.index("aws-actions/configure-aws-credentials")
            deploy_index = workflow.index("          change_set_arn=\"$(aws cloudformation create-change-set \\\n")
            self.assertLess(build_index, verify_index)
            self.assertLess(verify_index, credentials_index)
            self.assertLess(credentials_index, deploy_index)

    def test_deploy_workflows_are_not_temporarily_disabled(self):
        for workflow_name in ("deploy-test.yml", "deploy-production.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            self.assertNotIn("if: false", workflow)
            self.assertNotIn("if: ${{ false }}", workflow)

    def test_untrusted_validation_runs_without_oidc_and_deploy_rechecks_exact_artifact(self):
        for workflow_name in ("deploy-test.yml", "deploy-production.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            self.assertIn("  validate:\n", workflow)
            self.assertIn("actions/upload-artifact@v4", workflow)
            self.assertIn("actions/download-artifact@v4", workflow)
            validate_section = workflow[workflow.index("  validate:\n"):workflow.index("  deploy:\n")]
            deploy_section = workflow[workflow.index("  deploy:\n"):]
            self.assertNotIn("id-token: write", validate_section)
            self.assertIn("id-token: write", deploy_section)
            self.assertIn("python -m unittest", validate_section)
            self.assertNotIn("python -m unittest", deploy_section)
            self.assertIn("--normalize-artifact .aws-sam/build/ConfigAuthoringFunction", deploy_section)

    def test_deploy_workflows_serialize_and_execute_only_reviewed_nonreplacement_change_sets(self):
        reviewer = (ROOT / "tools" / "review_cloudformation_change_set.py").read_text(encoding="utf-8")
        self.assertIn('resource.get("Replacement") not in (None, "False")', reviewer)
        for workflow_name in ("deploy-test.yml", "deploy-production.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            self.assertIn("concurrency:\n", workflow)
            self.assertIn("cancel-in-progress: false", workflow)
            self.assertIn('CHANGE_SET_NAME: "zoolanding-${{ github.run_id }}-${{ github.run_attempt }}"', workflow)
            self.assertIn("cloudformation create-change-set", workflow)
            self.assertEqual(workflow.count("--change-set-type UPDATE"), 1)
            self.assertIn("cloudformation describe-change-set", workflow)
            self.assertIn("tools/review_cloudformation_change_set.py", workflow)
            self.assertIn('--s3-bucket "$EXPECTED_BUCKET"', workflow)
            self.assertIn(
                'system/deploy-artifacts/${GITHUB_SHA}/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}',
                workflow,
            )
            self.assertNotIn("--resolve-s3", workflow)
            self.assertIn("cloudformation execute-change-set", workflow)
            self.assertIn("cloudformation wait stack-update-complete", workflow)
            self.assertNotIn("cloudformation list-change-sets", workflow)
            self.assertNotIn("sam deploy --template-file .aws-sam/build/template.yaml --config-env test --no-confirm-changeset", workflow)
            self.assertNotIn("sam deploy --template-file .aws-sam/build/template.yaml --config-env prod --no-confirm-changeset", workflow)

    def test_parallel_v2_authorization_key_is_exact_across_deploy_surfaces(self):
        v2_key = "system/deploy-authz-v2.json"
        legacy_key = "system/deploy-authz.json"
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        samconfig = (ROOT / "samconfig.toml").read_text(encoding="utf-8")
        bootstrap = (ROOT / "tools" / "bootstrap_server_scopes.py").read_text(encoding="utf-8")
        self.assertIn(f"Default: {v2_key}", template)
        self.assertEqual(samconfig.count(f"DeployAuthzConfigS3Key={v2_key}"), 2)
        self.assertIn(f'LEGACY_AUTHZ_KEY = "{legacy_key}"', bootstrap)
        self.assertIn(f'AUTHZ_KEY = "{v2_key}"', bootstrap)
        for workflow_name in ("deploy-test.yml", "deploy-production.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            self.assertEqual(
                workflow.count(
                    f"ParameterKey=DeployAuthzConfigS3Key,ParameterValue={v2_key}"
                ),
                1,
            )
            self.assertEqual(workflow.count(f"DeployAuthzConfigS3Key={v2_key}"), 1)
            self.assertNotIn(f"DeployAuthzConfigS3Key={legacy_key}", workflow)

    def test_production_guard_requires_successful_test_deployment_run(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy-production.yml").read_text(encoding="utf-8")
        self.assertIn("actions: read", workflow)
        self.assertIn("actions/workflows/deploy-test.yml/runs", workflow)
        self.assertIn('run.get("status") == "completed"', workflow)
        self.assertIn('run.get("conclusion") == "success"', workflow)
        self.assertIn('run.get("path") == ".github/workflows/deploy-test.yml"', workflow)
        self.assertIn("test_run_id", workflow)
        self.assertIn("test_source_sha", workflow)

    def test_production_reuses_exact_test_run_artifact_and_checks_live_test_before_execution(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy-production.yml").read_text(encoding="utf-8")
        self.assertIn("run-id: ${{ needs.guard.outputs.test_run_id }}", workflow)
        self.assertIn("config-authoring-test-${{ needs.guard.outputs.test_source_sha }}", workflow)
        self.assertIn("--verify-sam-build .aws-sam/promoted-test", workflow)
        self.assertIn("--verify-deployed-zip", workflow)
        self.assertIn("--expected-code-sha256", workflow)
        self.assertIn("lambda get-function", workflow)
        self.assertIn("lambda get-function-configuration", workflow)
        self.assertIn("unset code_location", workflow)
        self.assertNotIn("live-test-function.json", workflow)
        self.assertIn("--use-json", workflow)
        self.assertIn("--extract-packaged-code-key", workflow)
        self.assertIn("s3api get-object", workflow)
        self.assertGreaterEqual(workflow.count("--verify-deployed-zip"), 2)
        pre_execute = workflow.index("--verify-deployed-zip")
        execute = workflow.index("cloudformation execute-change-set")
        self.assertLess(pre_execute, execute)

    def test_production_deploy_requires_exact_test_lambda_code_hash(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy-production.yml").read_text(encoding="utf-8")
        self.assertIn("zoolanding-config-authoring-test", workflow)
        self.assertIn("cloudformation describe-stacks", workflow)
        self.assertIn("OutputKey==`FunctionArn`", workflow)
        self.assertIn("lambda get-function-configuration", workflow)
        self.assertIn("--query 'CodeSha256'", workflow)
        self.assertIn('test "$production_code_sha" = "$test_code_sha"', workflow)
        self.assertNotIn("cloudformation describe-stack-resource", workflow)

    def test_template_exports_function_arn_without_pinning_a_physical_name(self):
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertIn("  FunctionArn:\n", template)
        self.assertIn("Fn::GetAtt: ConfigAuthoringFunction.Arn", template)
        function_section = template[template.index("  ConfigAuthoringFunction:\n"):template.index("Outputs:\n")]
        self.assertNotIn("FunctionName:", function_section)

    def test_promotion_provenance_requires_exact_previous_tip_and_current_source_tip(self):
        commit = "a" * 40
        before = "b" * 40
        source_tip = "c" * 40
        self.assertEqual(
            verify_promotion_provenance(
                commit=commit,
                parents=[before, source_tip],
                before_sha=before,
                source_tip=source_tip,
                commit_tree="d" * 40,
                source_tree="d" * 40,
            ),
            source_tip,
        )

        for parents in (
            ["d" * 40, source_tip],
            [before, "e" * 40],
            [before],
            [before, source_tip, "f" * 40],
        ):
            with self.subTest(parents=parents):
                with self.assertRaises(PromotionProvenanceError):
                    verify_promotion_provenance(
                        commit=commit,
                        parents=parents,
                        before_sha=before,
                        source_tip=source_tip,
                        commit_tree="d" * 40,
                        source_tree="d" * 40,
                    )

        with self.assertRaisesRegex(PromotionProvenanceError, "tree"):
            verify_promotion_provenance(
                commit=commit,
                parents=[before, source_tip],
                before_sha=before,
                source_tip=source_tip,
                commit_tree="d" * 40,
                source_tree="e" * 40,
            )

    def test_workflows_call_exact_promotion_provenance_guard(self):
        for workflow_name, source_branch in (
            ("deploy-test.yml", "dev"),
            ("deploy-production.yml", "test"),
        ):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            self.assertIn("tools/verify_promotion_provenance.py", workflow)
            self.assertIn("BEFORE_SHA: ${{ github.event.before }}", workflow)
            self.assertIn(f'SOURCE_BRANCH: "{source_branch}"', workflow)
            self.assertIn('--commit-tree "$commit_tree"', workflow)
            self.assertIn('--source-tree "$source_tree"', workflow)
            self.assertNotIn('git merge-base --is-ancestor "$second_parent"', workflow)


if __name__ == "__main__":
    unittest.main()
