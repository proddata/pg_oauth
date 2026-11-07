#!/bin/sh
set -eu

if test "$#" -ne 2; then
    echo "usage: $0 STAGE_ROOT PG_CONFIG" >&2
    exit 2
fi

stage=$1
pg_config=$2
pkglibdir=$($pg_config --pkglibdir)
docdir=$($pg_config --docdir)
library="$stage$pkglibdir/pg_oauth_validator.so"
staged_docdir="$stage$docdir/contrib"

test -f "$library"
test -f "$staged_docdir/README.md"
test -f "$staged_docdir/operations.md"
test -f "$staged_docdir/PROVIDER-COMPATIBILITY.md"
test -f "$staged_docdir/LICENSE"
test -f "$staged_docdir/THIRD-PARTY-NOTICES.md"

if find "$stage" -type f -perm /022 | grep -q .; then
    echo "error: staged package contains group/world-writable files" >&2
    exit 1
fi

if ldd "$library" | grep -Eq 'lib(jwt|jansson)'; then
    echo "error: libjwt and Jansson must remain statically embedded" >&2
    exit 1
fi

nm -D "$library" | grep -q '_PG_oauth_validator_module_init'

file_count=$(find "$stage" -type f | wc -l | tr -d ' ')
bitcode_dir="$stage$pkglibdir/bitcode/pg_oauth_validator"
if test -d "$bitcode_dir"; then
    test -f "$stage$pkglibdir/bitcode/pg_oauth_validator.index.bc"
    bitcode_count=$(find "$bitcode_dir" -type f -name '*.bc' | wc -l | tr -d ' ')
    test "$bitcode_count" -eq 19
    expected_count=26
else
    expected_count=6
fi

if test "$file_count" -ne "$expected_count"; then
    echo "error: unexpected staged package manifest ($file_count files)" >&2
    find "$stage" -type f -print >&2
    exit 1
fi
