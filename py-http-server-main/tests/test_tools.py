"""Verify the marking metric counts all source text without exclusions."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]


class CharacterCountTests(unittest.TestCase):
    def test_subverted_source_meets_the_47_character_budget(self):
        source = (PROJECT / "py_http_server" / "middlewares" / "digest_auth_subverted.py").read_text(encoding="utf-8")
        self.assertLessEqual(sum(source.count(char) for char in "(:,"), 47)

    def test_comments_and_strings_are_included_in_character_counts(self):
        tool = PROJECT / "tools" / "count_digest_chars.py"
        self.assertTrue(tool.exists(), "Missing planned character-count tool")
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.py"
            fixture.write_text('# (:,\ntext = "(:"\n', encoding="utf-8")
            result = subprocess.run([sys.executable, str(tool), str(fixture)],
                                    capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["counts"], {"(": 2, ":": 2, ",": 1})
        self.assertEqual(report["total"], 5)


if __name__ == "__main__":
    unittest.main()
