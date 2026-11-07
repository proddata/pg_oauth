import pathlib
import stat
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/integration"))
import rpm_pam_upgrade
import rpm_upgrade


class ConfigurationRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.data = pathlib.Path(self.temporary.name)
        for name in rpm_upgrade.CONFIG_FILES:
            path = self.data / name
            path.write_text(f"fixture {name}\n")
            path.chmod(0o600)
        (self.data / "postgresql.conf").write_text(
            f"pg_oauth_validator.audiences = '{rpm_upgrade.AUDIENCE_A}'\n"
        )

    def test_restore_exact_bytes_permissions_and_ownership(self):
        baseline = rpm_upgrade.snapshot_configuration(self.data)
        candidate = rpm_upgrade.candidate_configuration(baseline)
        rpm_upgrade.restore_configuration(self.data, candidate)
        self.assertEqual(rpm_upgrade.snapshot_configuration(self.data), candidate)
        self.assertIn(rpm_upgrade.AUDIENCE_B.encode(), (self.data / "postgresql.conf").read_bytes())
        (self.data / "server.key").unlink()
        (self.data / "pg_ident.conf").write_text("changed mapping\n")
        (self.data / "pg_ident.conf").chmod(0o640)
        rpm_upgrade.restore_configuration(self.data, baseline)
        self.assertEqual(rpm_upgrade.snapshot_configuration(self.data), baseline)
        self.assertEqual(stat.S_IMODE((self.data / "server.key").stat().st_mode), 0o600)

    def test_snapshot_rejects_missing_symlink_and_oversized_files(self):
        path = self.data / "server.key"
        path.write_bytes(b"x" * (1024 * 1024))
        rpm_upgrade.snapshot_configuration(self.data)
        path.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(RuntimeError, "configuration_size"):
            rpm_upgrade.snapshot_configuration(self.data)
        path.unlink()
        with self.assertRaisesRegex(RuntimeError, "configuration_file"):
            rpm_upgrade.snapshot_configuration(self.data)
        path.symlink_to(self.data / "server.crt")
        with self.assertRaisesRegex(RuntimeError, "configuration_file"):
            rpm_upgrade.snapshot_configuration(self.data)

    def test_restore_rejects_unknown_paths_and_symlinks(self):
        baseline = rpm_upgrade.snapshot_configuration(self.data)
        for invalid in ({}, {**baseline, "../outside": baseline["server.key"]}):
            with self.assertRaisesRegex(RuntimeError, "configuration_manifest"):
                rpm_upgrade.restore_configuration(self.data, invalid)
        outside = self.data / "retain"
        outside.write_text("unchanged\n")
        path = self.data / "server.key"
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "configuration_symlink"):
            rpm_upgrade.restore_configuration(self.data, baseline)
        self.assertEqual(outside.read_text(), "unchanged\n")

    def test_candidate_requires_one_exact_baseline_audience(self):
        path = self.data / "postgresql.conf"
        for content in ("", "unrelated audience\n", path.read_text() * 2):
            path.write_text(content)
            with self.assertRaisesRegex(RuntimeError, "configuration_audience"):
                rpm_upgrade.candidate_configuration(rpm_upgrade.snapshot_configuration(self.data))


class PamConfigurationRecoveryTest(unittest.TestCase):
    """The PAM subpackage rehearsal compares and restores the operator's files."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.owned = []
        for name in (*rpm_pam_upgrade.CONFIG_FILES, "pam-service", "provider-ca.pem"):
            path = self.root / name
            path.write_text(f"fixture {name}\n")
            path.chmod(0o600)
            self.owned.append(path)

    def test_restore_exact_bytes_and_permissions(self):
        saved = rpm_pam_upgrade.snapshot(self.owned)
        service = self.root / "pam-service"
        service.write_text("changed policy\n")
        service.chmod(0o644)
        (self.root / "server.key").unlink()
        rpm_pam_upgrade.restore(saved, self.owned)
        self.assertEqual(rpm_pam_upgrade.snapshot(self.owned), saved)
        self.assertEqual(stat.S_IMODE(service.stat().st_mode), 0o600)

    def test_an_upgrade_that_touches_a_file_is_visible(self):
        saved = rpm_pam_upgrade.snapshot(self.owned)
        (self.root / "pam-service").write_text("rewritten by the package\n")
        self.assertNotEqual(rpm_pam_upgrade.snapshot(self.owned), saved)
        (self.root / "pam-service").write_text("fixture pam-service\n")
        (self.root / "pam-service").chmod(0o644)
        self.assertNotEqual(rpm_pam_upgrade.snapshot(self.owned), saved)

    def test_snapshot_rejects_missing_symlink_and_oversized_files(self):
        path = self.root / "server.key"
        path.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(RuntimeError, "configuration_size"):
            rpm_pam_upgrade.snapshot(self.owned)
        path.unlink()
        with self.assertRaisesRegex(RuntimeError, "configuration_file"):
            rpm_pam_upgrade.snapshot(self.owned)
        path.symlink_to(self.root / "server.crt")
        with self.assertRaisesRegex(RuntimeError, "configuration_file"):
            rpm_pam_upgrade.snapshot(self.owned)

    def test_restore_writes_only_the_files_it_snapshotted(self):
        saved = rpm_pam_upgrade.snapshot(self.owned)
        outside = self.root / "outside"
        outside.write_text("unchanged\n")
        for invalid in ({}, {**saved, str(outside): saved[str(self.owned[0])]}):
            with self.assertRaisesRegex(RuntimeError, "configuration_manifest"):
                rpm_pam_upgrade.restore(invalid, self.owned)
        self.assertEqual(outside.read_text(), "unchanged\n")
        target = self.root / "server.key"
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "configuration_symlink"):
            rpm_pam_upgrade.restore(saved, self.owned)
        self.assertEqual(outside.read_text(), "unchanged\n")

    def test_the_stack_names_the_module_and_policy_on_both_lines(self):
        stack = rpm_pam_upgrade.service_text("/m/pg_oauth_pam.so", "issuer=a audience=b")
        self.assertEqual(stack.splitlines(), [
            "auth [success=ok default=die] /m/pg_oauth_pam.so issuer=a audience=b",
            "account [success=ok default=die] /m/pg_oauth_pam.so issuer=a audience=b",
        ])

    def test_the_two_audiences_differ_so_a_changed_policy_is_observable(self):
        self.assertNotEqual(rpm_pam_upgrade.AUDIENCE_A, rpm_pam_upgrade.AUDIENCE_B)


if __name__ == "__main__":
    unittest.main()
