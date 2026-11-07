import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/integration"))
import selinux_support
import selinux_denial
sys.path.insert(0, str(ROOT / "tests/pam"))
import selinux_check


class EnforcementTest(unittest.TestCase):
    def result(self, output):
        return subprocess.CompletedProcess([], 0, output, "")

    def test_enforcing_domain_is_accepted(self):
        with mock.patch.object(selinux_support, "run", side_effect=[
            self.result("Enforcing\n"), self.result("Builtin Permissive Types\n")
        ]):
            selinux_support.require_enforcing()

    def test_disabled_or_globally_permissive_is_rejected(self):
        for value in ["Disabled", "Permissive", "", "enforcing"]:
            with self.subTest(value=value), mock.patch.object(
                selinux_support, "run", return_value=self.result(value)
            ), self.assertRaises(RuntimeError):
                selinux_support.require_enforcing()

    def test_permissive_postgresql_is_rejected(self):
        with mock.patch.object(selinux_support, "run", side_effect=[
            self.result("Enforcing\n"),
            self.result("Customized Permissive Types\npostgresql_t\n")
        ]), self.assertRaises(RuntimeError):
            selinux_support.require_enforcing()

    def test_missing_policy_tools_fail_closed(self):
        with mock.patch.object(selinux_support, "run", side_effect=FileNotFoundError), \
                self.assertRaises(FileNotFoundError):
            selinux_support.require_enforcing()


class PamDenialFilterTest(unittest.TestCase):
    DENIAL = ("type=AVC msg=audit(1.2:3): avc:  denied  { read } for pid=42 "
              "scontext=system_u:system_r:postgresql_t:s0 "
              "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0")

    def test_postgresql_denials_are_reported(self):
        self.assertEqual(selinux_check.postgres_denials({self.DENIAL}), [self.DENIAL])

    def test_other_domains_and_non_denials_are_ignored(self):
        records = {self.DENIAL.replace("postgresql_t", "unconfined_t"),
                   self.DENIAL.replace("denied", "granted"),
                   "type=USER msg=audit(1.2:4): pam: scontext=postgresql_t",
                   # postgresql_t as the target of another domain is not a backend denial.
                   self.DENIAL.replace("scontext=system_u:system_r:postgresql_t:s0",
                                       "scontext=system_u:system_r:unconfined_t:s0")
                   .replace("etc_t", "postgresql_t")}
        self.assertEqual(selinux_check.postgres_denials(records), [])


class AuditEvidenceTest(unittest.TestCase):
    RECORD = ("type=AVC msg=audit(1.2:3): avc: denied { name_connect } "
              "for pid=42 dest=45000 scontext=system_u:system_r:postgresql_t:s0 "
              "tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0")

    def test_exact_enforcing_https_denial_is_accepted(self):
        self.assertTrue(selinux_denial.matches_https_denial(self.RECORD, 45000))

    def test_wrong_or_incomplete_evidence_is_rejected(self):
        for record in [self.RECORD.replace("dest=45000", "dest=45001"),
                       self.RECORD.replace("postgresql_t", "unconfined_t"),
                       self.RECORD.replace("http_port_t", "postgresql_port_t"),
                       self.RECORD.replace("tcp_socket", "udp_socket"),
                       self.RECORD.replace("permissive=0", "permissive=1"),
                       self.RECORD.replace("name_connect", "name_bind"),
                       self.RECORD.replace("denied", "granted"), ""]:
            with self.subTest(record=record):
                self.assertFalse(selinux_denial.matches_https_denial(record, 45000))


class LauncherTest(unittest.TestCase):
    def test_ready_server_requires_the_exact_live_domain(self):
        expected = "system_u:system_r:postgresql_t:s0"
        for context in [expected, "unconfined_u:unconfined_r:unconfined_t:s0", "", "postgresql_t"]:
            with self.subTest(context=context), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                cluster = types.SimpleNamespace(
                    root=root, log=root / "postgres.log", port=54321,
                    bindir=root, data=root / "data", logs=lambda: "",
                )
                success = subprocess.CompletedProcess([], 0, "", "")
                with mock.patch("builtins.print"), \
                        mock.patch.object(selinux_support, "require_enforcing"), \
                        mock.patch.object(selinux_support, "label_port"), \
                        mock.patch.object(selinux_support, "run", return_value=success), \
                        mock.patch.object(pathlib.Path, "read_text", side_effect=["123\n", context]):
                    launcher = selinux_support.ConfinedPostgres(cluster)
                    if context == expected:
                        launcher.start()
                    else:
                        with self.assertRaisesRegex(RuntimeError, "escaped"):
                            launcher.start()
                    launcher.stop()

    def test_failed_launch_still_removes_its_port_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cluster = types.SimpleNamespace(root=root, log=root / "postgres.log",
                                            port=54321, bindir=root, data=root / "data",
                                            logs=lambda: "")
            with mock.patch.object(selinux_support, "require_enforcing"), \
                    mock.patch.object(selinux_support, "label_port") as label, \
                    mock.patch.object(selinux_support, "run") as run:
                launcher = selinux_support.ConfinedPostgres(cluster)
                run.side_effect = [None,
                                   subprocess.CalledProcessError(1, "systemd-run", stderr="failed"),
                                   subprocess.CompletedProcess([], 0, "startup journal", "")]
                with self.assertRaisesRegex(RuntimeError, "startup journal"):
                    launcher.start()
                label.assert_called_once_with(54321, "postgresql_port_t")
                run.side_effect = None
                launcher.stop()
                self.assertIn(mock.call("semanage", "port", "-d", "-p", "tcp", 54321),
                              run.call_args_list)
                self.assertFalse(launcher.port_labeled)


if __name__ == "__main__":
    unittest.main()
