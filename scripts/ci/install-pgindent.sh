#!/bin/sh

set -eu

PGINDENT_VERSION=19.0
PGINDENT_SHA256=a89fd70efbad6a08c7dbed8d4872e3af30170d9e5ca9dc7906523be95b4e692d
PGINDENT_URL="https://ftp.postgresql.org/pub/source/v${PGINDENT_VERSION}/postgresql-${PGINDENT_VERSION}.tar.bz2"

repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
install_root=${PGINDENT_INSTALL_ROOT:-$repo_root/.tools/pgindent-$PGINDENT_VERSION}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/pg-oauth-pgindent.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

archive=$work_dir/postgresql.tar.bz2
source_dir=$work_dir/postgresql-$PGINDENT_VERSION

curl --fail --location --proto '=https' --tlsv1.2 --output "$archive" \
	"$PGINDENT_URL"

if command -v sha256sum >/dev/null 2>&1; then
	actual_sha256=$(sha256sum "$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
	actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
else
	echo "error: sha256sum or shasum is required" >&2
	exit 1
fi
test "$actual_sha256" = "$PGINDENT_SHA256" || {
	echo "error: PostgreSQL source archive checksum mismatch" >&2
	exit 1
}

tar --extract --bzip2 --file "$archive" --directory "$work_dir"

(
	cd "$source_dir"
	./configure --quiet --without-icu --without-lz4 --without-readline \
		--without-zlib --without-zstd
	make -s -C src/tools/pg_bsd_indent
)

mkdir -p "$install_root/bin" "$install_root/share"
install -m 0755 "$source_dir/src/tools/pg_bsd_indent/pg_bsd_indent" \
	"$install_root/bin/pg_bsd_indent"
install -m 0755 "$source_dir/src/tools/pgindent/pgindent" \
	"$install_root/bin/pgindent"
install -m 0644 "$source_dir/src/tools/pgindent/typedefs.list" \
	"$install_root/share/postgresql.typedefs"

"$install_root/bin/pg_bsd_indent" --version
