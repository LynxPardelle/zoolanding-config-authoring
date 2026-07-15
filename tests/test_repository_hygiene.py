from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


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
            build_index = workflow.index("python tools/build_lambda_artifact.py\n")
            verify_index = workflow.index(
                "python tools/build_lambda_artifact.py --verify-artifact .aws-sam/build/ConfigAuthoringFunction"
            )
            credentials_index = workflow.index("aws-actions/configure-aws-credentials")
            deploy_index = workflow.index("sam deploy --config-env")
            self.assertLess(build_index, verify_index)
            self.assertLess(verify_index, credentials_index)
            self.assertLess(credentials_index, deploy_index)


if __name__ == "__main__":
    unittest.main()
