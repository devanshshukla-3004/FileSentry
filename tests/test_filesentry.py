import json
import tempfile
import unittest
from pathlib import Path

from filesentry import collect_files, compare_files, create_baseline, load_baseline, sha256_file


class FileSentryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "watched"
        self.root.mkdir()
        (self.root / "keep.txt").write_text("stable", encoding="utf-8")
        (self.root / "change.txt").write_text("before", encoding="utf-8")
        self.baseline_path = Path(self.temp.name) / "baseline.json"
        self.baseline = create_baseline(self.root, self.baseline_path)

    def test_sha256_is_deterministic(self):
        self.assertEqual(sha256_file(self.root / "keep.txt"), sha256_file(self.root / "keep.txt"))

    def test_unchanged_files_are_unchanged(self):
        current, errors = collect_files(self.root)
        result = compare_files(self.baseline, current)
        self.assertEqual(errors, [])
        self.assertEqual(result["unchanged_count"], 2)
        self.assertEqual(result["modified"], [])
        self.assertEqual(result["deleted"], [])
        self.assertEqual(result["new"], [])

    def test_detects_modification(self):
        (self.root / "change.txt").write_text("after", encoding="utf-8")
        current, _ = collect_files(self.root)
        result = compare_files(self.baseline, current)
        self.assertEqual([x["path"] for x in result["modified"]], ["change.txt"])

    def test_detects_deletion(self):
        (self.root / "keep.txt").unlink()
        current, _ = collect_files(self.root)
        result = compare_files(self.baseline, current)
        self.assertEqual([x["path"] for x in result["deleted"]], ["keep.txt"])

    def test_detects_new_file(self):
        (self.root / "new.txt").write_text("new", encoding="utf-8")
        current, _ = collect_files(self.root)
        result = compare_files(self.baseline, current)
        self.assertEqual([x["path"] for x in result["new"]], ["new.txt"])

    def test_baseline_round_trip(self):
        loaded = load_baseline(self.baseline_path)
        self.assertEqual(loaded["schema_version"], 1)
        self.assertIn("change.txt", loaded["files"])

    def test_excludes_paths(self):
        (self.root / "private").mkdir()
        (self.root / "private" / "secret.txt").write_text("secret", encoding="utf-8")
        current, _ = collect_files(self.root, ["private"])
        self.assertNotIn("private/secret.txt", current)

    def test_baseline_is_valid_json(self):
        parsed = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        self.assertEqual(parsed["algorithm"], "sha256")


if __name__ == "__main__":
    unittest.main()
