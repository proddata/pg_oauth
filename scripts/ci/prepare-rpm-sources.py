#!/usr/bin/env python3
"""Fetch reviewed dependencies, or prepare an SRPM input set without networking."""

import argparse
import gzip
import hashlib
import pathlib
import re
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEPENDENCIES = {
    "jansson": "akheron/jansson",
    "libjwt": "benmcollins/libjwt",
}


def git(*args):
    return subprocess.check_output([
        "git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *args,
    ])


def pins(name, script):
    values = []
    for suffix, length in (("COMMIT", 40), ("SHA256", 64)):
        matches = re.findall(
            rf"^{name.upper()}_{suffix}=([0-9a-f]{{{length}}})$",
            script, re.MULTILINE,
        )
        if len(matches) != 1:
            raise ValueError(f"missing or ambiguous {name} {suffix} pin")
        values.append(matches[0])
    return values


def verify(path, expected):
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"source must be a regular file: {path}")
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError(f"source archive exceeds 16 MiB: {path.name}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise ValueError(f"source digest mismatch: {path.name}")
    return digest


def fetch(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name, upstream in DEPENDENCIES.items():
        commit, digest = pins(name, (ROOT / f"scripts/ci/install-{name}.sh").read_text())
        target = directory / f"{name}.tar.gz"
        if target.exists() or target.is_symlink():
            verify(target, digest)
            continue
        # Fetching is a separate online operation. Neither prepare nor rpmbuild
        # may download missing sources; the digest remains the trust boundary.
        with tempfile.TemporaryDirectory(dir=directory) as temporary:
            archive = pathlib.Path(temporary) / "archive"
            subprocess.run([
                "curl", "--fail", "--location", "--proto", "=https",
                "--proto-redir", "=https", "--tlsv1.2", "--connect-timeout", "15",
                "--max-time", "120", "--max-filesize", str(16 * 1024 * 1024),
                "--output", str(archive),
                f"https://codeload.github.com/{upstream}/tar.gz/{commit}",
            ], check=True)
            verify(archive, digest)
            # Publish only verified complete bytes, without following a link
            # created at the destination between the existence check and copy.
            archive.replace(target)


def prepare(version, revision, dependencies, output):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("RPM version must be MAJOR.MINOR.PATCH")
    if not re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", revision):
        raise ValueError("source revision must be a full Git commit hash")
    actual = git("rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
    if actual != revision:
        raise ValueError("source revision must name the exact commit")
    epoch = git("show", "-s", "--format=%ct", revision).decode().strip()
    sources = {}
    for name in DEPENDENCIES:
        script = git("show", f"{revision}:scripts/ci/install-{name}.sh").decode()
        _, expected = pins(name, script)
        path = dependencies / f"{name}.tar.gz"
        sources[name] = (path, verify(path, expected))
    if output.exists():
        raise ValueError("output directory must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        stage = pathlib.Path(temporary)
        source_dir = stage / "SOURCES"
        spec_dir = stage / "SPECS"
        source_dir.mkdir()
        spec_dir.mkdir()
        filename = f"pg_oauth_validator-{version}.tar.gz"
        archive = git("archive", "--format=tar", f"--prefix=pg_oauth_validator-{version}/", revision)
        (source_dir / filename).write_bytes(gzip.compress(archive, mtime=0))
        checksums = [f"{hashlib.sha256((source_dir / filename).read_bytes()).hexdigest()}  {filename}\n"]
        for name, (path, digest) in sources.items():
            shutil.copyfile(path, source_dir / f"{name}.tar.gz")
            checksums.append(f"{digest}  {name}.tar.gz\n")
        (source_dir / "SHA256SUMS").write_text("".join(checksums))
        # The spec is a separately reviewable SRPM input. Until committed, it
        # may differ from Source0; never attribute its bytes to source_revision.
        spec = (ROOT / "packaging/rpm/pg_oauth_validator.spec.in").read_text()
        # The PAM subpackage exists only for sources that contain the module. A
        # retained older release is rebuilt with the current spec template, and
        # must neither require pam-devel nor invoke targets its source lacks.
        with_pam = "1" if git("ls-tree", "--name-only", revision, "pam/pg_oauth_pam.c").strip() else "0"
        for key, value in (("VERSION", version), ("SOURCE_REVISION", revision), ("SOURCE_DATE_EPOCH", epoch),
                           ("WITH_PAM", with_pam)):
            spec = spec.replace(f"@{key}@", value)
        (spec_dir / "pg_oauth_validator.spec").write_text(spec)
        spec_digest = hashlib.sha256(spec.encode()).hexdigest()
        (stage / "INPUTS.sha256").write_text(
            f"{spec_digest}  SPECS/pg_oauth_validator.spec\n" +
            "".join(line.replace("  ", "  SOURCES/", 1) for line in checksums) +
            f"{hashlib.sha256((source_dir / 'SHA256SUMS').read_bytes()).hexdigest()}  SOURCES/SHA256SUMS\n"
        )
        shutil.copytree(stage, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    online = sub.add_parser("fetch", help="download the pinned dependency sources")
    online.add_argument("directory", type=pathlib.Path)
    offline = sub.add_parser("prepare", help="prepare inputs offline from an exact Git commit")
    offline.add_argument("version")
    offline.add_argument("revision")
    offline.add_argument("dependencies", type=pathlib.Path)
    offline.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.command == "fetch":
            fetch(args.directory)
        else:
            prepare(args.version, args.revision, args.dependencies, args.output)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
