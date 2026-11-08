import pathlib
import subprocess
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts/ci/classify-change.sh"


def classify(names):
    result = subprocess.run(["sh", str(SCRIPT)], input=names, text=True,
                            capture_output=True, check=True)
    return result.stdout.strip()


class ClassifyChangeTest(unittest.TestCase):
    def test_markdown_only_changes_are_documentation_only(self):
        for names in ("README.md\n", "docs/pam.md\ndocs/releases/0.2.0-prerelease.md\n",
                      "FEATURES.md\ndemo/README.md\n", "docs/a.md"):
            with self.subTest(names=names):
                self.assertEqual(classify(names), "true")

    def test_anything_else_runs_the_full_suite(self):
        for names in ("shared/claims.c\n", "docs/pam.md\nshared/claims.c\n",
                      "docs/selinux/pg_oauth_https.cil\n", "docs/pam.md\nMakefile\n",
                      "LICENSE\n", "THIRD-PARTY-NOTICES.md.txt\n", "docs/pam.md.sh\n",
                      "tests/pam/test_pam_copies.py\n", "docs/pam.md\n.github/workflows/ci.yml\n"):
            with self.subTest(names=names):
                self.assertEqual(classify(names), "false")

    def test_workflow_markdown_and_odd_paths_are_never_documentation_only(self):
        for names in (".github/PULL_REQUEST_TEMPLATE.md\n", "/etc/x.md\n", "../x.md\n",
                      "docs/../scripts/x.md\n", "docs/..\n", "docs/pam.md\n\n"):
            with self.subTest(names=names):
                self.assertEqual(classify(names), "false")

    def test_empty_input_runs_the_full_suite(self):
        for names in ("", "\n"):
            with self.subTest(names=names):
                self.assertEqual(classify(names), "false")

    def test_a_file_without_a_trailing_newline_is_still_checked(self):
        self.assertEqual(classify("docs/pam.md\nshared/claims.c"), "false")


if __name__ == "__main__":
    unittest.main()
