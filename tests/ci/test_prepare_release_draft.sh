#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
preparer=$repo_root/scripts/ci/prepare-release-draft.sh
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

version=0.1.0-rc.1
revision=0123456789abcdef0123456789abcdef01234567
artifacts=$work_dir/artifacts

make_artifact()
{
	major=$1
	pg_version=$2
	input=$artifacts/pg$major
	package=pg_oauth_validator-$version-pg$pg_version
	root=$work_dir/root/$package
	rm -rf "$work_dir/root"
	mkdir -p "$input" "$root"
	{
		echo "release-version: $version"
		echo "source-revision: $revision"
		echo "postgresql-major: $major"
		echo "architecture: x86_64"
	} >"$root/BUILD-MANIFEST"
	tar -C "$work_dir/root" -cf - "$package" |
		gzip -n >"$input/$package.tar.gz"
	(cd "$input" && sha256sum "$package.tar.gz" >"$package.tar.gz.sha256")
	cp "$root/BUILD-MANIFEST" "$input/$package.tar.gz.manifest"
	echo "PostgreSQL $major build evidence" >"$input/RELEASE-EVIDENCE.md"
}

expect_rejection()
{
	rm -rf "$artifacts/publish"
	if sh "$preparer" "$version" "$revision" "$artifacts" \
		>"$work_dir/output" 2>&1; then
		echo "error: invalid release artifacts were accepted" >&2
		exit 1
	fi
}

make_artifact 18 18.7
make_artifact 19 19.0
sh "$preparer" "$version" "$revision" "$artifacts"
test "$(find "$artifacts/publish" -maxdepth 1 -type f | wc -l)" -eq 9
(cd "$artifacts/publish" && sha256sum --check SHA256SUMS)

printf '\n' >>"$artifacts/pg18/pg_oauth_validator-$version-pg18.7.tar.gz.manifest"
expect_rejection
make_artifact 18 18.7

echo unexpected >"$artifacts/pg19/unexpected.txt"
expect_rejection
rm "$artifacts/pg19/unexpected.txt"

printf 'tampered' >>"$artifacts/pg19/pg_oauth_validator-$version-pg19.0.tar.gz"
expect_rejection
make_artifact 19 19.0

sed 's|\.tar.gz$|.other.tar.gz|' \
	"$artifacts/pg19/pg_oauth_validator-$version-pg19.0.tar.gz.sha256" \
	>"$work_dir/wrong-checksum"
cp "$work_dir/wrong-checksum" \
	"$artifacts/pg19/pg_oauth_validator-$version-pg19.0.tar.gz.sha256"
expect_rejection
make_artifact 19 19.0

rm "$artifacts/pg18/RELEASE-EVIDENCE.md"
expect_rejection
