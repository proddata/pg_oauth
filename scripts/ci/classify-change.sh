#!/bin/sh
# Classify a pull request from its changed file names (one per line on stdin).
#
# Prints "true" only when at least one name is given and every name is a
# Markdown file outside .github/. Anything else, including empty input, odd
# paths or read errors, prints "false" so the full test suite runs: a wrong
# "false" only costs CI time, a wrong "true" would skip tests.
#
# Documentation files are never build or test inputs: the build and packaging
# only check that a few of them exist. Non-Markdown documentation such as
# docs/selinux/*.cil is policy that the SELinux test compares byte for byte, so
# it deliberately does not qualify.
set -eu

count=0
# "|| test -n" keeps a final line that has no trailing newline: read returns
# non-zero for it, and dropping it would let an unchecked file slip through.
while IFS= read -r name || test -n "$name"; do
	case "$name" in
	'' | /* | .github/* | ../* | */../* | */..)
		echo false
		exit 0
		;;
	*.md) count=$((count + 1)) ;;
	*)
		echo false
		exit 0
		;;
	esac
done

if test "$count" -gt 0; then
	echo true
else
	echo false
fi
