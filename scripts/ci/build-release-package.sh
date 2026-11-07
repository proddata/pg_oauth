#!/bin/sh
set -eu

usage()
{
	echo "usage: $0 RELEASE_VERSION PG_CONFIG OUTPUT_DIR" >&2
	exit 2
}

test "$#" -eq 3 || usage

release_version=$1
pg_config=$2
output_dir=$3

if ! printf '%s\n' "$release_version" |
	LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$'; then
	echo "error: release version must be a safe semantic version: $release_version" >&2
	exit 2
fi

case "${SOURCE_DATE_EPOCH-}" in
	''|*[!0-9]*)
		echo "error: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
		exit 2
		;;
esac

case "$pg_config" in
	*/*) ;;
	*) pg_config=$(command -v "$pg_config" || true) ;;
esac
test -n "$pg_config" && test -x "$pg_config" || {
	echo "error: PG_CONFIG is not executable" >&2
	exit 2
}

pg_version=$($pg_config --version)
case "$pg_version" in
	"PostgreSQL 18"*) pg_major=18 ;;
	"PostgreSQL 19"*) pg_major=19 ;;
	*)
		echo "error: PostgreSQL 18 or 19 is required (found: $pg_version)" >&2
		exit 2
		;;
esac
pg_release_full=${pg_version#PostgreSQL }
pg_release=${pg_release_full%% *}
case "$pg_release" in
	''|*[!0-9A-Za-z.-]*)
		echo "error: unsafe PostgreSQL release from pg_config: $pg_release" >&2
		exit 2
		;;
esac

command -v tar >/dev/null 2>&1 || {
	echo "error: tar is required" >&2
	exit 1
}
command -v gzip >/dev/null 2>&1 || {
	echo "error: gzip is required" >&2
	exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
	sha256_file()
	{
		sha256sum "$1" | awk '{print $1}'
	}
elif command -v shasum >/dev/null 2>&1; then
	sha256_file()
	{
		shasum -a 256 "$1" | awk '{print $1}'
	}
else
	echo "error: sha256sum or shasum is required" >&2
	exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
source_revision=${SOURCE_REVISION-}
if test -z "$source_revision"; then
	source_revision=$(git -C "$source_dir" rev-parse --verify HEAD 2>/dev/null || true)
fi
if test -z "$source_revision"; then
	source_revision=unavailable
elif ! printf '%s\n' "$source_revision" |
	LC_ALL=C grep -Eq '^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$'; then
	echo "error: SOURCE_REVISION must be a 40- or 64-digit commit hash" >&2
	exit 2
fi
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT INT TERM
snapshot_dir=$work_dir/source
build_dir=$work_dir/build
stage_dir=$work_dir/stage
package_name=pg_oauth_validator-$release_version-pg$pg_release
package_root=$work_dir/$package_name
archive=$output_dir/$package_name.tar.gz
checksum=$archive.sha256
sidecar_manifest=$archive.manifest
build_cc=${CC:-cc}
reproducible_cflags="-ffile-prefix-map=$work_dir=/build -fdebug-prefix-map=$work_dir=/build"
reproducible_bitcode_cflags="-O2 $reproducible_cflags"

# Build the exact revision recorded in the manifest. Besides making the
# provenance claim enforceable, this prevents generated files in a developer's
# source tree from satisfying VPATH prerequisites in the clean build tree.
test "$source_revision" != unavailable || {
	echo "error: release packages require a Git source revision" >&2
	exit 1
}
git -C "$source_dir" cat-file -e "$source_revision^{commit}" 2>/dev/null || {
	echo "error: SOURCE_REVISION is not a local Git commit" >&2
	exit 1
}
mkdir -p "$snapshot_dir"
git -C "$source_dir" archive "$source_revision" | tar -x -C "$snapshot_dir"

dependency_version()
{
	if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists "$1"; then
		pkg-config --modversion "$1"
	else
		echo unavailable
	fi
}

mkdir -p "$build_dir/shared" "$build_dir/validator" "$build_dir/tests/integration" "$stage_dir" "$output_dir"
# Keep VPATH relative so Clang's LLVM module source_filename is independent of
# the random secure temporary directory. Clang's prefix-map flags do not rewrite
# that bitcode field.
make -C "$build_dir" -f ../source/Makefile VPATH=../source \
	PG_CONFIG="$pg_config" EXPECTED_PG_MAJOR="$pg_major" CC="$build_cc" \
	PG_CFLAGS="$reproducible_cflags" \
	BITCODE_CFLAGS="$reproducible_bitcode_cflags" all
make -C "$build_dir" -f ../source/Makefile VPATH=../source \
	PG_CONFIG="$pg_config" EXPECTED_PG_MAJOR="$pg_major" \
	CC="$build_cc" PG_CFLAGS="$reproducible_cflags" \
	BITCODE_CFLAGS="$reproducible_bitcode_cflags" \
	install DESTDIR="$stage_dir"
# The PAM module is part of the package. Its place in an operator's PAM stack
# depends on the distribution, and libpam accepts an absolute module path, so it
# is installed beside the validator in the PostgreSQL library directory.
make -C "$build_dir" -f ../source/Makefile VPATH=../source \
	PG_CONFIG="$pg_config" EXPECTED_PG_MAJOR="$pg_major" \
	CC="$build_cc" PG_CFLAGS="$reproducible_cflags" \
	PAM_MODULE_DIR="$($pg_config --pkglibdir)" install-pam DESTDIR="$stage_dir"
sh "$snapshot_dir/scripts/ci/check-staged-install.sh" "$stage_dir" "$pg_config"

mv "$stage_dir" "$package_root"
license_dir=$package_root/THIRD-PARTY-LICENSES
mkdir -p "$license_dir"
install -m 0644 "$snapshot_dir/LICENSE" "$package_root/LICENSE"
install -m 0644 "$snapshot_dir/THIRD-PARTY-NOTICES.md" \
	"$package_root/THIRD-PARTY-NOTICES.md"
install -m 0644 /usr/local/share/doc/libjwt/LICENSE \
	"$license_dir/LIBJWT-MPL-2.0"
jansson_license=/usr/local/share/doc/jansson/LICENSE
test -f "$jansson_license" || {
	echo "error: Jansson license file is unavailable" >&2
	exit 1
}
install -m 0644 "$jansson_license" "$license_dir/JANSSON"
find "$package_root" -type d -exec chmod 0755 {} +
find "$package_root" -type f -exec chmod 0644 {} +
chmod 0755 "$package_root$($pg_config --pkglibdir)/pg_oauth_validator.so"
chmod 0755 "$package_root$($pg_config --pkglibdir)/pg_oauth_pam.so"

manifest=$package_root/BUILD-MANIFEST
{
	echo "format-version: 1"
	echo "package: pg_oauth_validator"
	echo "release-version: $release_version"
	echo "source-revision: $source_revision"
	echo "postgresql-version: $pg_release_full"
	echo "postgresql-major: $pg_major"
	echo "source-date-epoch: $SOURCE_DATE_EPOCH"
	echo "architecture: $(uname -m)"
	echo "compiler: $($build_cc --version | sed -n '1p')"
	echo "libjwt-version: $(dependency_version libjwt)"
	echo "jansson-version: $(dependency_version jansson)"
	echo "libcurl-version: $(dependency_version libcurl)"
	echo "openssl-version: $(dependency_version openssl)"
	if test -f /etc/pg-oauth-build-inputs; then
		sed 's/^/build-input-/' /etc/pg-oauth-build-inputs
	else
		echo "build-input-debian-snapshot: unavailable"
	fi
	echo "debian-packages:"
	for package in libcurl4 libcurl4-openssl-dev libpam0g libpam0g-dev libpq-dev libssl3 libssl-dev; do
		if dpkg-query -W -f='${Package} ${Version}\n' "$package" 2>/dev/null; then
			:
		else
			echo "  $package unavailable"
		fi
	done | LC_ALL=C sort | sed 's/^/  /'
	echo "files:"
	find "$package_root" -type f ! -name BUILD-MANIFEST -print | LC_ALL=C sort |
	while IFS= read -r file; do
		relative=${file#"$package_root"/}
		digest=$(sha256_file "$file")
		printf '  %s  %s\n' "$digest" "$relative"
	done
} >"$manifest"
chmod 0644 "$manifest"

rm -f "$archive" "$checksum" "$sidecar_manifest"
tar --sort=name --format=posix \
	--pax-option=delete=atime,delete=ctime \
	--mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
	-C "$work_dir" -cf - "$package_name" | gzip -n -9 >"$archive"
archive_digest=$(sha256_file "$archive")
printf '%s  %s\n' "$archive_digest" "$(basename "$archive")" >"$checksum"
cp "$manifest" "$sidecar_manifest"
chmod 0644 "$archive" "$checksum" "$sidecar_manifest"

echo "$archive"
