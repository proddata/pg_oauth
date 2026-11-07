#!/bin/sh

set -eu

usage()
{
	echo "usage: $0 [--check]" >&2
	exit 2
}

check_option=
case "$#:$*" in
	0:) ;;
	1:--check) check_option=--check ;;
	*) usage ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tool_root=${PGINDENT_INSTALL_ROOT:-$repo_root/.tools/pgindent-19beta3}
pgindent=$tool_root/bin/pgindent
pg_bsd_indent=$tool_root/bin/pg_bsd_indent
postgres_typedefs=$tool_root/share/postgresql.typedefs
project_typedefs=$repo_root/tools/pgindent/project.typedefs

for required in "$pgindent" "$pg_bsd_indent" "$postgres_typedefs" \
	"$project_typedefs"
do
	test -f "$required" || {
		echo "error: missing pgindent input: $required" >&2
		echo "hint: run ./scripts/ci/install-pgindent.sh" >&2
		exit 1
	}
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/pg-oauth-format.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
typedefs=$work_dir/typedefs.list
sort -u "$postgres_typedefs" "$project_typedefs" >"$typedefs"

cd "$repo_root"
"$pgindent" $check_option --typedefs="$typedefs" \
	--indent="$pg_bsd_indent" shared validator pam tests
