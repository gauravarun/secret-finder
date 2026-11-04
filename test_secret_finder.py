"""Tests for secret_finder. Run with: python -m unittest -v

Fake secrets are built from pieces so this file itself doesn't trip
secret scanners (including GitHub push protection).
"""
import shutil
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

from secret_finder import scan_diff

FAKE_AWS_ID = "AKIA" + "Z7QW3RT9YP2LKM4X"
FAKE_PASSWORD = "Tr0ub4dor" + "&3xQ!92"
FAKE_GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


class DiffParsingTests(unittest.TestCase):
    def test_reports_correct_file_and_line_for_added_secrets(self):
        diff = (
            "diff --git a/config.py b/config.py\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -10,3 +10,5 @@ import os\n"
            " DEBUG = False\n"
            f"-OLD_KEY = '{FAKE_AWS_ID}'\n"            # removed: must NOT be reported
            f"+AWS_ACCESS_KEY_ID = '{FAKE_AWS_ID}'\n"  # new line 11
            " TIMEOUT = 30\n"                          # line 12
            f"+db_password = \"{FAKE_PASSWORD}\"\n"    # line 13
            # Unquoted values in config files are caught too.
            "diff --git a/.env b/.env\n"
            "+++ b/.env\n"
            "@@ -0,0 +1,3 @@\n"
            "+DEBUG=true\n"
            f"+DB_PASSWORD={FAKE_PASSWORD}\n"          # line 2
            f"+export API_TOKEN={FAKE_PASSWORD}9\n"    # line 3
        )
        findings = scan_diff(diff)
        got = sorted((f.file, f.line, f.rule) for f in findings)
        self.assertEqual(got, [
            (".env", 2, "hardcoded-secret"),
            (".env", 3, "hardcoded-secret"),
            ("config.py", 11, "aws-access-key-id"),
            ("config.py", 13, "hardcoded-secret"),
        ])
        # The report must not echo the full secret back.
        for f in findings:
            self.assertNotIn(FAKE_AWS_ID, f.snippet)
            self.assertNotIn(FAKE_PASSWORD, f.snippet)

    def test_ignores_placeholders_env_lookups_and_marked_lines(self):
        diff = (
            "+++ b/settings.yml\n"
            "@@ -0,0 +1,6 @@\n"
            "+password: \"changeme\"\n"
            "+api_key: \"${API_KEY}\"\n"
            "+token = os.environ['TOKEN']\n"
            "+secret: \"<your-secret-here>\"\n"
            "+db_url: \"postgres://user:${DB_PASS}@localhost/db\"\n"
            f"+fixture_token = \"{FAKE_PASSWORD}\"  # secret-finder:ignore\n"
            "+auth: oauth_only\n"
            "+db_password: ${DB_PASSWORD}\n"
            # Unquoted right-hand sides in source code are variables, not secrets.
            "+++ b/app.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+api_token = load_token_from_vault(Config.REGION2)\n"
            "+password = settings.DB_PASSWORD_V2\n"
        )
        self.assertEqual(scan_diff(diff), [])


@unittest.skipUnless(shutil.which("git"), "git not installed")
class CliGitTests(unittest.TestCase):
    def test_commit_hash_mode_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            def git(*a):
                subprocess.run(["git", *a], cwd=d, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.com")
            git("config", "user.name", "t")
            Path(d, "app.js").write_text("const x = 1;\n")
            git("add", ".")
            git("commit", "-qm", "init")
            Path(d, "app.js").write_text(f"const x = 1;\nconst gh = '{FAKE_GH_TOKEN}';\n")
            git("commit", "-qam", "oops")

            script = Path(__file__).with_name("secret_finder.py")
            res = subprocess.run(
                [sys.executable, str(script), "--commit", "HEAD", "--repo", d],
                capture_output=True, text=True,
            )
            self.assertEqual(res.returncode, 1, res.stderr)
            self.assertIn("app.js:2: [github-token]", res.stdout)

            # The first commit has no secrets.
            res = subprocess.run(
                [sys.executable, str(script), "--commit", "HEAD~1", "--repo", d],
                capture_output=True, text=True,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
