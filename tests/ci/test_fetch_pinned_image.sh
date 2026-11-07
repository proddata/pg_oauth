#!/bin/sh
# Tests for scripts/ci/fetch-pinned-image.sh with a stub curl: every source
# behaviour (unreachable, expired certificate, wrong content, good content) is
# simulated without a network.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
helper=$repo_root/scripts/ci/fetch-pinned-image.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

mkdir -p "$work/bin"
printf 'the pinned image\n' >"$work/good"
printf 'a different image\n' >"$work/bad"
good_sha=$(sha256sum "$work/good" | cut -d' ' -f1)

# The stub reads one file per host in $PLAN: "fail CODE" or "serve FILE".
cat >"$work/bin/curl" <<'STUB'
#!/bin/sh
echo "$*" >>"$PLAN/args"
url=
out=
while test "$#" -gt 0; do
	case "$1" in
		-o) out=$2; shift ;;
		https://*) url=$1 ;;
	esac
	shift
done
host=${url#https://}
host=${host%%/*}
echo "$host" >>"$PLAN/calls"
read -r action argument <"$PLAN/$host"
case "$action" in
	fail) exit "$argument" ;;
	serve) cp "$argument" "$out" ;;
esac
STUB
chmod +x "$work/bin/curl"

fail()
{
	echo "error: $1" >&2
	exit 1
}

# run_case NAME "host=behaviour ..." expected-exit-status
# Hosts are tried in the order given. Calls are recorded in $PLAN/calls.
run_case()
{
	name=$1
	plan_spec=$2
	expected_status=$3
	export PLAN="$work/plan-$name"
	mkdir -p "$PLAN"
	: >"$PLAN/calls"
	: >"$PLAN/args"
	urls=
	for entry in $plan_spec; do
		host=${entry%%=*}
		behaviour=${entry#*=}
		printf '%s\n' "$(printf '%s' "$behaviour" | tr ',' ' ')" >"$PLAN/$host"
		urls="$urls https://$host/images/file"
	done
	rm -f "$work/out-$name"
	status=0
	# shellcheck disable=SC2086
	PATH="$work/bin:$PATH" sh "$helper" "$good_sha" "$work/out-$name" $urls \
		>"$PLAN/stdout" 2>"$PLAN/stderr" || status=$?
	test "$status" -eq "$expected_status" ||
		fail "$name: exit status $status, expected $expected_status ($(cat "$PLAN/stderr"))"
}

assert_output_is_good()
{
	cmp -s "$work/out-$1" "$work/good" || fail "$1: output is not the pinned content"
}

assert_no_output()
{
	test ! -e "$work/out-$1" || fail "$1: output exists although no source was valid"
	test ! -e "$work/out-$1.partial" || fail "$1: a partial download was left behind"
}

assert_calls()
{
	actual=$(tr '\n' ' ' <"$work/plan-$1/calls")
	test "$actual" = "$2 " || fail "$1: sources tried were '$actual', expected '$2'"
}

# The first source works: no other source is contacted.
run_case first_ok "one.example=serve,$work/good two.example=serve,$work/good" 0
assert_output_is_good first_ok
assert_calls first_ok "one.example"

# An expired certificate (curl exit 60) on the first source falls through.
run_case expired_cert "one.example=fail,60 two.example=serve,$work/good" 0
assert_output_is_good expired_cert
assert_calls expired_cert "one.example two.example"

# Unreachable and then wrong content on the next sources, then a good one.
run_case mixed "a.example=fail,7 b.example=serve,$work/bad c.example=serve,$work/good" 0
assert_output_is_good mixed
assert_calls mixed "a.example b.example c.example"

# Wrong content is never accepted, even from the only source.
run_case all_bad "one.example=serve,$work/bad two.example=serve,$work/bad" 1
assert_no_output all_bad
assert_calls all_bad "one.example two.example"
grep -q 'no source delivered the pinned file' "$work/plan-all_bad/stderr" ||
	fail "all_bad: the failure was not explained"

# Nothing reachable.
run_case all_down "one.example=fail,60 two.example=fail,28" 1
assert_no_output all_down

# The security flags are kept on every request and verification is never off.
for flag in "--proto =https" "--proto-redir =https" "--tlsv1.2" "--fail"; do
	grep -q -- "$flag" "$work/plan-mixed/args" || fail "curl was called without $flag"
done
if grep -q -- '--insecure\| -k ' "$work/plan-mixed/args"; then
	fail "curl was called with certificate verification disabled"
fi

# A malformed digest is a usage error and contacts nothing.
export PLAN="$work/plan-usage"
mkdir -p "$PLAN"
: >"$PLAN/calls"
status=0
PATH="$work/bin:$PATH" sh "$helper" not-a-digest "$work/out-usage" https://x.example/f \
	>/dev/null 2>&1 || status=$?
test "$status" -eq 2 || fail "a malformed digest was not rejected (status $status)"
test ! -s "$PLAN/calls" || fail "a source was contacted despite the malformed digest"

# Once the deadline has passed no further source is started, even a good one.
export PLAN="$work/plan-deadline"
mkdir -p "$PLAN"
: >"$PLAN/calls"
: >"$PLAN/args"
printf 'serve %s\n' "$work/good" >"$PLAN/one.example"
status=0
FETCH_DEADLINE_SECONDS=0 PATH="$work/bin:$PATH" \
	sh "$helper" "$good_sha" "$work/out-deadline" https://one.example/f \
	>/dev/null 2>&1 || status=$?
test "$status" -eq 1 || fail "deadline: exit status $status, expected 1"
test ! -s "$PLAN/calls" || fail "deadline: a source was contacted after the deadline"
assert_no_output deadline
echo "fetch-pinned-image tests passed"
