import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release", ROOT / "scripts/ci/rpm-release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.policy = json.loads((ROOT / "packaging/rpm/release-baseline.json").read_text())
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(json.dumps(self.policy))

    def bundle(self, name, version="0.1.3", revision="c" * 40):
        root = self.root / name
        for relative in (f"RPMS/aarch64/postgresql18-pg_oauth_validator-{version}-1.aarch64.rpm",
                         f"SRPMS/postgresql18-pg_oauth_validator-{version}-1.src.rpm",
                         "inputs/INPUTS.sha256", "inputs/SOURCES/SHA256SUMS", "BUILD-ENVIRONMENT.txt"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic retained artifact\n")
        spec = root / "inputs/SPECS/pg_oauth_validator.spec"
        spec.parent.mkdir()
        spec.write_text(f"Version: {version}\n%global source_revision {revision}\n")
        release.seal(root)
        return root

    def test_complete_manifest_identity_and_reproducibility(self):
        first, second = self.bundle("first"), self.bundle("second")
        self.assertEqual(release.identity(first), ("0.1.3", "c" * 40))
        release.compare(first, second)
        with self.assertRaises(FileExistsError):
            release.seal(first)

    def test_every_changed_or_missing_input_fails_verification(self):
        bundle = self.bundle("candidate")
        for name in release.candidates.inventory(bundle):
            path = bundle / name
            original = path.read_bytes()
            for operation in ("change", "remove", "link"):
                path.unlink()
                if operation == "change":
                    path.write_bytes(b"corrupt")
                elif operation == "link":
                    path.symlink_to(self.policy_path)
                with self.subTest(name=name, operation=operation), self.assertRaises(ValueError):
                    release.verify(bundle)
                if path.exists() or path.is_symlink():
                    path.unlink()
                path.write_bytes(original)

    def test_unrecorded_root_files_fail_verification(self):
        bundle = self.bundle("candidate")
        (bundle / "unexpected.log").write_text("must not be retained")
        with self.assertRaises(ValueError):
            release.verify(bundle)

    def test_checksum_manifest_cannot_be_missing_linked_or_rewritten(self):
        bundle = self.bundle("candidate")
        manifest = bundle / "SHA256SUMS"
        for content in (None, b"changed", b"x" * 65537):
            manifest.unlink(missing_ok=True)
            if content is not None:
                manifest.write_bytes(content)
            with self.assertRaises(ValueError):
                release.verify(bundle)
        manifest.unlink()
        manifest.symlink_to(self.policy_path)
        with self.assertRaises(ValueError):
            release.verify(bundle)

    def test_versioned_baseline_policy_rejects_ambiguous_or_unordered_releases(self):
        self.assertEqual(release.baseline_policy(self.policy_path, "0.1.3"), self.policy)
        for candidate in ("0.1.2", "0.1.1", "01.1.3", "0.1.3-rc1", None, "1" * 40):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                release.baseline_policy(self.policy_path, candidate)
        for key, value in (("tag", "main"), ("source_revision", "HEAD"),
                           ("classification", "published-rpm"), ("extra", True), ("version", [])):
            policy = {**self.policy, key: value}
            self.policy_path.write_text(json.dumps(policy))
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.baseline_policy(self.policy_path, "0.1.3")
        self.policy_path.write_text('{"version":"0.1.2","version":"0.1.3"}')
        with self.assertRaises(ValueError):
            release.baseline_policy(self.policy_path, "0.1.3")

    def test_historical_suite_only_accepts_exact_reviewed_source_version_and_empty_destination(self):
        inputs = self.bundle("baseline", self.policy["version"], self.policy["source_revision"]) / "inputs"
        destination = self.root / "source"
        destination.mkdir()
        with mock.patch.object(release.subprocess, "check_output", return_value=b"git archive") as archive, \
                mock.patch.object(release.subprocess, "run") as extract:
            release.baseline_suite(inputs, destination)
            self.assertEqual(archive.call_args.args[0][-1], self.policy["source_revision"])
            self.assertEqual(extract.call_args.kwargs["input"], b"git archive")
        spec = inputs / "SPECS/pg_oauth_validator.spec"
        original = spec.read_text()
        for text in (original.replace(self.policy["version"], "0.1.3"),
                     original.replace(self.policy["source_revision"], "d" * 40), original + original):
            spec.write_text(text)
            with mock.patch.object(release.subprocess, "check_output") as archive:
                with self.assertRaises(ValueError):
                    release.baseline_suite(inputs, destination)
                archive.assert_not_called()
        spec.write_text(original)
        (destination / "existing").write_text("preserve")
        with self.assertRaises(ValueError):
            release.baseline_suite(inputs, destination)

    def test_offline_gate_handles_sysfs_control_files_but_rejects_active_interfaces(self):
        network = self.root / "net"
        (network / "lo").mkdir(parents=True)
        (network / "bonding_masters").write_text("")
        interface = network / "eth0"
        interface.mkdir()
        (interface / "flags").write_text("0x0")
        with mock.patch.object(release.os, "geteuid", return_value=0), \
                mock.patch.dict(release.os.environ, {"RPM_RELEASE_REHEARSAL": "1"}), \
                mock.patch.object(release.pathlib, "Path", return_value=network):
            release.require_offline()
            (interface / "flags").write_text("0x1")
            with self.assertRaises(ValueError):
                release.require_offline()

    def evidence(self, name, baseline):
        root = self.root / name
        candidate = self.bundle(name + "/candidate")
        (root / "SOURCE-REVISION").write_text("c" * 40 + "\n")
        (root / "builders.lock.json").write_bytes((ROOT / "packaging/rpm/builders.lock.json").read_bytes())
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        receipt = {
            "format_version": 1, "baseline_version": self.policy["version"], "candidate_version": "0.1.3",
            "baseline_source_revision": self.policy["source_revision"], "candidate_source_revision": "c" * 40,
            "baseline_classification": "rebuilt-source-release; no previously published RPM",
            "baseline_rpm_sha256": digest(release.package(baseline)),
            "candidate_rpm_sha256": digest(release.package(candidate)),
            "baseline_bundle_manifest_sha256": digest(baseline / "SHA256SUMS"),
            "candidate_bundle_manifest_sha256": digest(candidate / "SHA256SUMS"),
            "restored_library_sha256": "e" * 64,
            "restored_configuration_sha256": {name: "f" * 64 for name in (
                "postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf",
                "oauth-ca.pem", "server.crt", "server.key",
            )},
            "phases": ["baseline", "candidate", "rollback"],
            "checks": ["retained_data", "restart", "authorization", "denial", "rotation",
                       "provider_outage_recovery", "invalid_configuration_recovery", "redaction"],
        }
        (root / "rehearsal.json").write_text(json.dumps(receipt))
        return root, receipt

    def test_receipts_bound_to_actual_retained_artifacts_and_all_recovery_checks(self):
        baseline = self.bundle("baseline", self.policy["version"], self.policy["source_revision"])
        first, receipt = self.evidence("first", baseline)
        second, _ = self.evidence("second", baseline)
        release.compare_evidence(first, second, baseline)
        for key in receipt:
            corrupt = copy.deepcopy(receipt)
            corrupt.pop(key)
            (second / "rehearsal.json").write_text(json.dumps(corrupt))
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.compare_evidence(first, second, baseline)
        for corrupt in ({**receipt, "format_version": True}, {**receipt, "unexpected": "field"}):
            (second / "rehearsal.json").write_text(json.dumps(corrupt))
            with self.assertRaises(ValueError):
                release.compare_evidence(first, second, baseline)
        (second / "rehearsal.json").write_text(json.dumps(receipt))
        (second / "SOURCE-REVISION").write_text("d" * 40)
        with self.assertRaises(ValueError):
            release.compare_evidence(first, second, baseline)


if __name__ == "__main__":
    unittest.main()
