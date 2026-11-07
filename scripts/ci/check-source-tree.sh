#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

# Keep this check independent of optional developer tools. Compiler formatting
# belongs in a checked-in style configuration before it becomes a merge gate.
git diff --check
if git rev-parse --verify HEAD >/dev/null 2>&1; then
    git log -1 --check --pretty=format:
fi

find scripts demo -type f -name '*.sh' -exec sh -n {} +

python_cache=$(mktemp -d "${TMPDIR:-/tmp}/pg-oauth-python.XXXXXX")
trap 'rm -rf "$python_cache"' EXIT HUP INT TERM
PYTHONPYCACHEPREFIX="$python_cache" python3 -m compileall -q tests

# A checkout must not leave the job token in .git/config where later steps,
# including third-party code run by the job, could read it. The only exception
# is a checkout whose step carries a comment stating why it needs the token.
python3 -I - <<'PY'
import glob
import re
import sys

failures = []
for path in sorted(glob.glob(".github/workflows/*.yml")):
    lines = open(path, encoding="utf-8").read().split("\n")
    for index, line in enumerate(lines):
        if not re.match(r"\s*uses: actions/checkout@", line):
            continue
        step = []
        for following in lines[index + 1:index + 9]:
            if re.match(r"\s*(- |uses:)", following):
                break
            step.append(following)
        text = "\n".join(step)
        if "persist-credentials: false" not in text and "keeps the read-only" not in text:
            failures.append(f"{path}:{index + 1}")
if failures:
    print("error: checkout without persist-credentials: false: " + ", ".join(failures),
          file=sys.stderr)
    sys.exit(1)
PY

if find . -type f \( -name '*.orig' -o -name '*.rej' -o -name '*~' \) \
    -not -path './.git/*' | grep -q .; then
    echo "error: source tree contains editor or patch artifacts" >&2
    exit 1
fi
