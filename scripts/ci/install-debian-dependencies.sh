#!/bin/sh

set -eu

usage()
{
	echo "usage: $0 18|19" >&2
	exit 2
}

test "$#" -eq 1 || usage
pg_major=$1
case "$pg_major" in
	18)
		pg_dev_version=18.6-1.pgdg12+2
		debian_snapshot=20260803T000000Z
		ssl_version=3.0.20-1~deb12u2
		;;
	19)
		pg_dev_version=19~rc1-1.pgdg12+1
		debian_snapshot=20261005T000000Z
		ssl_version=3.0.22-1~deb12u1
		;;
	*) usage ;;
esac

# This is the Debian snapshot recorded by the pinned postgres:*-bookworm base
# images. Keep it immutable and update it deliberately with the image digests
# and the reviewed package versions below.
debian_sources=/etc/apt/sources.list.d/debian.sources

test "$(id -u)" -eq 0 || {
	echo "error: dependency installation must run as root" >&2
	exit 1
}
test -f "$debian_sources" || {
	echo "error: expected deb822 Debian sources at $debian_sources" >&2
	exit 1
}

sed -i \
	-e "s|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/$debian_snapshot|" \
	-e "s|URIs: http://deb.debian.org/debian|URIs: http://snapshot.debian.org/archive/debian/$debian_snapshot|" \
	"$debian_sources"

if grep -q 'deb.debian.org' "$debian_sources"; then
	echo "error: mutable Debian repository remains configured" >&2
	exit 1
fi

printf '%s\n' 'Acquire::Check-Valid-Until "false";' \
	>/etc/apt/apt.conf.d/99-pg-oauth-snapshot

# Jansson and libjwt are not installed from Debian: the module embeds them and
# requires PIC static archives. Use scripts/ci/install-jansson.sh and
# scripts/ci/install-libjwt.sh for those pinned source builds.
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
	build-essential=12.9 \
	bison=2:3.8.2+dfsg-1+b1 \
	ca-certificates=20230311+deb12u1 \
	clang=1:14.0-55.7~deb12u1 \
	clang-tools=1:14.0-55.7~deb12u1 \
	cmake=3.25.1-1 \
	curl=7.88.1-10+deb12u15 \
	flex=2.6.4-8.2 \
	git=1:2.39.5-0+deb12u3 \
	libclang-rt-dev=1:14.0-55.7~deb12u1 \
	libcurl4-openssl-dev=7.88.1-10+deb12u15 \
	libkrb5-dev=1.20.1-2+deb12u5 \
	libpam0g-dev=1.5.2-6+deb12u2 \
	libssl-dev=$ssl_version \
	openssl=$ssl_version \
	pkg-config=1.8.1-1 \
	libpq-dev=$pg_dev_version \
	postgresql-server-dev-$pg_major=$pg_dev_version \
	python3=3.11.2-1+b1 \
	python3-pytest=7.2.1-2 \
	python3-pytest-xdist=3.1.0-1

# Fail if apt silently selected a different direct dependency version.
check_version()
{
	package=$1
	expected=$2
	actual=$(dpkg-query -W -f='${Version}' "$package")
	test "$actual" = "$expected" || {
		echo "error: $package version $actual does not match $expected" >&2
		exit 1
	}
}

check_version libcurl4-openssl-dev 7.88.1-10+deb12u15
check_version libssl-dev "$ssl_version"
check_version bison 2:3.8.2+dfsg-1+b1
check_version flex 2.6.4-8.2
check_version libpq-dev "$pg_dev_version"
check_version libpam0g-dev 1.5.2-6+deb12u2
check_version postgresql-server-dev-$pg_major "$pg_dev_version"
check_version python3-pytest-xdist 3.1.0-1

printf '%s\n' \
	"debian-snapshot: $debian_snapshot" \
	"postgresql-dev-version: $pg_dev_version" \
	>/etc/pg-oauth-build-inputs
