import importlib.util
import pathlib
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "rpm_candidates", ROOT / "scripts/ci/check-rpm-candidates.py",
)
candidates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidates)


class CandidateTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.first = pathlib.Path(temporary.name) / "first"
        self.second = pathlib.Path(temporary.name) / "second"
        for root in (self.first, self.second):
            for name in ("RPMS/aarch64/postgresql18-pg_oauth_validator-0.1.3-1.aarch64.rpm",
                         "RPMS/aarch64/postgresql18-pg_oauth_validator-pam-0.1.3-1.aarch64.rpm",
                         "SRPMS/postgresql18-pg_oauth_validator-0.1.3-1.src.rpm",
                         "inputs/INPUTS.sha256", "inputs/SOURCES/SHA256SUMS",
                         "inputs/SPECS/pg_oauth_validator.spec", "BUILD-ENVIRONMENT.txt"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic comparison fixture\n")

    def test_equal_bundles_emit_complete_checksums(self):
        candidates.compare(self.first, self.second)
        lines = (self.first / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(lines), 7)
        self.assertTrue(all(len(line.split()[0]) == 64 for line in lines))
        self.assertFalse((self.second / "SHA256SUMS").exists())

    def test_changed_bytes_block_manifest(self):
        for relative in candidates.inventory(self.second):
            with self.subTest(path=relative):
                path = self.second / relative
                original = path.read_bytes()
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    candidates.compare(self.first, self.second)
                self.assertFalse((self.first / "SHA256SUMS").exists())
                path.write_bytes(original)

    def test_missing_files_and_links_fail_closed(self):
        for relative in candidates.inventory(self.second):
            path = self.second / relative
            original = path.read_bytes()
            path.unlink()
            with self.subTest(path=relative), self.assertRaises(ValueError):
                candidates.compare(self.first, self.second)
            path.symlink_to(self.first / relative)
            with self.assertRaises(ValueError):
                candidates.compare(self.first, self.second)
            path.unlink()
            path.write_bytes(original)
        self.assertFalse((self.first / "SHA256SUMS").exists())

    def test_extra_package_blocks_comparison(self):
        path = self.second / "RPMS/extra.rpm"
        path.write_bytes(b"unexpected")
        with self.assertRaises(ValueError):
            candidates.compare(self.first, self.second)

    def test_bundle_without_pam_rpm_remains_valid_for_older_baselines(self):
        for root in (self.first, self.second):
            (root / "RPMS/aarch64/postgresql18-pg_oauth_validator-pam-0.1.3-1.aarch64.rpm").unlink()
        candidates.compare(self.first, self.second)
        self.assertEqual(len((self.first / "SHA256SUMS").read_text().splitlines()), 6)

    def test_duplicate_pam_rpm_or_missing_validator_blocks_comparison(self):
        for root in (self.first, self.second):
            extra = root / "RPMS/x86_64/postgresql18-pg_oauth_validator-pam-0.1.3-1.x86_64.rpm"
            extra.parent.mkdir()
            extra.write_bytes(b"second pam package")
        with self.assertRaises(ValueError):
            candidates.compare(self.first, self.second)
        for root in (self.first, self.second):
            (root / "RPMS/x86_64/postgresql18-pg_oauth_validator-pam-0.1.3-1.x86_64.rpm").unlink()
            (root / "RPMS/aarch64/postgresql18-pg_oauth_validator-0.1.3-1.aarch64.rpm").unlink()
        with self.assertRaises(ValueError):
            candidates.compare(self.first, self.second)

    def test_existing_manifest_is_not_overwritten(self):
        path = self.first / "SHA256SUMS"
        path.write_text("keep")
        with self.assertRaises(FileExistsError):
            candidates.compare(self.first, self.second)
        self.assertEqual(path.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
