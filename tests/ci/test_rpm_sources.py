import hashlib
import importlib.util
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "rpm_sources", ROOT / "scripts/ci/prepare-rpm-sources.py",
)
rpm_sources = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rpm_sources)


class RpmSourcesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repo"
        self.dependencies = self.root / "dependencies"
        self.repository.mkdir()
        self.dependencies.mkdir()
        self.patch = mock.patch.object(rpm_sources, "ROOT", self.repository)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        (self.repository / "scripts/ci").mkdir(parents=True)
        (self.repository / "packaging/rpm").mkdir(parents=True)
        (self.repository / "packaging/rpm/pg_oauth_validator.spec.in").write_text(
            (ROOT / "packaging/rpm/pg_oauth_validator.spec.in").read_text()
        )
        for name in rpm_sources.DEPENDENCIES:
            data = f"deterministic {name} source fixture".encode()
            (self.dependencies / f"{name}.tar.gz").write_bytes(data)
            (self.repository / f"scripts/ci/install-{name}.sh").write_text(
                f"{name.upper()}_COMMIT={'a' * 40}\n"
                f"{name.upper()}_SHA256={hashlib.sha256(data).hexdigest()}\n"
            )
        (self.repository / "README.md").write_text("committed source\n")
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=RPM test", "-c", "user.email=rpm@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "--quiet", "-m", "fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output([
            "git", "-C", str(self.repository), *args,
        ], text=True)

    def prepare(self, output="inputs", version="0.1.0", revision=None):
        target = self.root / output
        rpm_sources.prepare(version, revision or self.revision, self.dependencies, target)
        return target

    def test_exact_commit_and_reproducible_inputs_without_network(self):
        (self.repository / "README.md").write_text("uncommitted edit\n")
        (self.repository / "untracked-secret").write_text("must not be packaged")
        original_run = subprocess.run

        def offline(argv, **kwargs):
            self.assertEqual(argv[0], "git", "preparation tried a network command")
            return original_run(argv, **kwargs)

        with mock.patch.object(rpm_sources.subprocess, "run", side_effect=offline):
            first = self.prepare()
            second = self.prepare("second")
        for path in first.rglob("*"):
            if path.is_file():
                self.assertEqual(path.read_bytes(), (second / path.relative_to(first)).read_bytes())
        with tarfile.open(first / "SOURCES/pg_oauth_validator-0.1.0.tar.gz") as archive:
            self.assertEqual(archive.extractfile("pg_oauth_validator-0.1.0/README.md").read(), b"committed source\n")
            self.assertFalse(any("untracked-secret" in name for name in archive.getnames()))
        spec = (first / "SPECS/pg_oauth_validator.spec").read_text()
        self.assertIn(self.revision, spec)
        self.assertNotIn("@VERSION@", spec)
        self.assertIn("Version:        0.1.0", spec)

    def test_pam_subpackage_follows_the_packaged_source(self):
        """A retained older release has no PAM module and must be rebuilt without it."""
        without = (self.prepare("without") / "SPECS/pg_oauth_validator.spec").read_text()
        self.assertIn("%global with_pam 0\n", without)
        self.assertNotIn("@WITH_PAM@", without)
        (self.repository / "pam").mkdir()
        (self.repository / "pam/pg_oauth_pam.c").write_text("/* PAM module fixture */\n")
        self.git("add", ".")
        self.git("-c", "user.name=RPM test", "-c", "user.email=rpm@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "--quiet", "-m", "adds pam")
        revision = self.git("rev-parse", "HEAD").strip()
        with_pam = (self.prepare("with", revision=revision) / "SPECS/pg_oauth_validator.spec").read_text()
        self.assertIn("%global with_pam 1\n", with_pam)
        # The older revision is still prepared from its own tree, not the newer one.
        again = (self.prepare("again", revision=self.revision) / "SPECS/pg_oauth_validator.spec").read_text()
        self.assertIn("%global with_pam 0\n", again)

    def test_invalid_versions_and_revisions_do_not_create_outputs(self):
        for version in ("", "01.2.3", "1.2", "1.2.3-rc.1", "1.2.3%{lua:bad}", "1.2.3\nName: bad"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.prepare(version=version)
        for revision in ("HEAD", "../path", "a" * 39, "a" * 40 + "\n"):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                self.prepare(revision=revision)
        self.assertFalse((self.root / "inputs").exists())

    def test_missing_corrupt_and_symlink_sources_fail_closed(self):
        path = self.dependencies / "jansson.tar.gz"
        for kind in ("corrupt", "missing", "symlink", "directory"):
            with self.subTest(kind=kind):
                if path.is_symlink() or path.is_file():
                    path.unlink()
                if kind == "corrupt":
                    path.write_bytes(b"wrong source")
                elif kind == "symlink":
                    path.symlink_to(self.dependencies / "libjwt.tar.gz")
                elif kind == "directory":
                    path.mkdir()
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assertFalse((self.root / "inputs").exists())

    def test_existing_output_is_never_replaced(self):
        target = self.prepare()
        marker = target / "keep"
        marker.write_text("retain existing inputs")
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(marker.read_text(), "retain existing inputs")

    def test_fetch_reuses_verified_sources_and_rejects_corruption_without_network(self):
        with mock.patch.object(rpm_sources.subprocess, "run", side_effect=AssertionError("network")):
            rpm_sources.fetch(self.dependencies)
            (self.dependencies / "libjwt.tar.gz").write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                rpm_sources.fetch(self.dependencies)

    def test_missing_and_ambiguous_pins_are_rejected(self):
        for script in ("", "JANSSON_COMMIT=bad\n", f"JANSSON_COMMIT={'a' * 40}\n" * 2):
            with self.assertRaises(ValueError):
                rpm_sources.pins("jansson", script)

    def test_fetch_publishes_only_verified_downloads(self):
        fixtures = {name: (self.dependencies / f"{name}.tar.gz").read_bytes()
                    for name in rpm_sources.DEPENDENCIES}
        for path in self.dependencies.iterdir():
            path.unlink()

        def download(argv, check):
            self.assertTrue(check)
            name = "jansson" if "/jansson/" in argv[-1] else "libjwt"
            pathlib.Path(argv[argv.index("--output") + 1]).write_bytes(fixtures[name])

        with mock.patch.object(rpm_sources.subprocess, "run", side_effect=download):
            rpm_sources.fetch(self.dependencies)
        for name, data in fixtures.items():
            self.assertEqual((self.dependencies / f"{name}.tar.gz").read_bytes(), data)
        (self.dependencies / "jansson.tar.gz").unlink()
        fixtures["jansson"] = b"tampered download"
        with mock.patch.object(rpm_sources.subprocess, "run", side_effect=download):
            with self.assertRaises(ValueError):
                rpm_sources.fetch(self.dependencies)
        self.assertFalse((self.dependencies / "jansson.tar.gz").exists())
        (self.dependencies / "jansson.tar.gz").symlink_to(self.root / "missing")
        with mock.patch.object(rpm_sources.subprocess, "run", side_effect=AssertionError("network")):
            with self.assertRaises(ValueError):
                rpm_sources.fetch(self.dependencies)


if __name__ == "__main__":
    unittest.main()
