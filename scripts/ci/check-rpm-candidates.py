#!/usr/bin/env python3
"""Compare complete unsigned candidate bundles from two isolated builds."""
import argparse
import hashlib
import pathlib
import re


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("candidate must be a directory")
    files = {}
    for directory in ("RPMS", "SRPMS", "inputs"):
        base = root / directory
        if base.is_symlink() or not base.is_dir():
            raise ValueError(f"missing candidate directory: {directory}")
        for path in sorted(base.rglob("*")):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ValueError("candidate contains a link or special file")
            if path.is_file():
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                files[path.relative_to(root).as_posix()] = digest
    binaries = [name for name in files if name.startswith("RPMS/") and
                re.fullmatch(r"postgresql18-pg_oauth_validator-[0-9].*\.rpm",
                             pathlib.PurePosixPath(name).name)]
    sources = [name for name in files if name.startswith("SRPMS/") and name.endswith(".src.rpm")]
    if len(binaries) != 1 or len(sources) != 1:
        raise ValueError("candidate requires exactly one validator RPM and SRPM")
    for name in ("inputs/INPUTS.sha256", "inputs/SOURCES/SHA256SUMS",
                 "inputs/SPECS/pg_oauth_validator.spec"):
        if name not in files:
            raise ValueError(f"missing candidate input: {name}; observed: " +
                             ", ".join(sorted(files)))
    environment = root / "BUILD-ENVIRONMENT.txt"
    if environment.is_symlink() or not environment.is_file():
        raise ValueError("missing build environment record")
    files[environment.name] = hashlib.sha256(environment.read_bytes()).hexdigest()
    return files


def compare(first, second):
    left, right = inventory(first), inventory(second)
    if left.keys() != right.keys():
        raise ValueError("candidate file inventories differ")
    different = [name for name in left if left[name] != right[name]]
    if different:
        raise ValueError("candidate bytes differ: " + ", ".join(different))
    # Write only after complete equality. Checksums do not constitute signatures.
    manifest = first / "SHA256SUMS"
    with manifest.open("x", encoding="utf-8") as stream:
        for name, digest in sorted(left.items()):
            stream.write(f"{digest}  {name}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=pathlib.Path)
    parser.add_argument("second", type=pathlib.Path)
    args = parser.parse_args()
    try:
        compare(args.first, args.second)
    except (ValueError, OSError) as error:
        parser.exit(1, f"error: {error}\n")
    print("Unsigned RPM/SRPM, inputs, and build inventories match in both containers")


if __name__ == "__main__":
    main()
