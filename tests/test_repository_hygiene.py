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

        self.assertTrue({"__pycache__/", "*.py[cod]", ".aws-sam/", ".venv/", ".env", ".env.*"}.issubset(gitignore))
        self.assertTrue({".git/", ".github/", ".aws-sam/", "__pycache__/", "*.py[cod]", "tests/", "README.md"}.issubset(samignore))


if __name__ == "__main__":
    unittest.main()
