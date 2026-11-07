#!/bin/sh
# Download one file whose SHA-256 is known in advance, trying several sources.
#
# Usage: fetch-pinned-image.sh SHA256 OUTPUT URL [URL...]
#
# The digest is checked after every download, so where the bytes came from does
# not matter: a source that is unreachable, has an invalid certificate, or serves
# different content is skipped and the next one is tried. TLS verification is
# never disabled, only https is accepted (including after a redirect), and
# OUTPUT exists only if a source delivered exactly the pinned content.
#
# FETCH_DEADLINE_SECONDS (default 720) is the time after which no further source
# is started, so the caller's job timeout is not consumed by a hanging mirror.
set -eu

if test "$#" -lt 3; then
	echo "usage: $0 SHA256 OUTPUT URL [URL...]" >&2
	exit 2
fi
expected=$1
output=$2
shift 2

case "$expected" in
	*[!0-9a-f]* | "")
		echo "error: the SHA-256 must be 64 lowercase hexadecimal digits" >&2
		exit 2
		;;
esac
if test "${#expected}" -ne 64; then
	echo "error: the SHA-256 must be 64 lowercase hexadecimal digits" >&2
	exit 2
fi

deadline=${FETCH_DEADLINE_SECONDS:-720}
started=$(date +%s)
partial=$output.partial
trap 'rm -f "$partial"' EXIT HUP INT TERM
rm -f "$output" "$partial"

for url in "$@"; do
	if test "$(($(date +%s) - started))" -ge "$deadline"; then
		echo "fetch-pinned-image: deadline of ${deadline}s reached before $url" >&2
		break
	fi
	if curl --fail --location --proto '=https' --proto-redir '=https' \
		--tlsv1.2 --connect-timeout 15 --max-time 240 \
		--retry 1 --retry-delay 5 --retry-all-errors \
		"$url" -o "$partial"; then
		if printf '%s  %s\n' "$expected" "$partial" | sha256sum -c - >/dev/null 2>&1; then
			mv "$partial" "$output"
			echo "fetch-pinned-image: verified download from $url" >&2
			exit 0
		fi
		echo "fetch-pinned-image: $url served content with a different SHA-256" >&2
	else
		echo "fetch-pinned-image: $url could not be downloaded (curl exit $?)" >&2
	fi
	rm -f "$partial"
done
echo "error: no source delivered the pinned file" >&2
exit 1
