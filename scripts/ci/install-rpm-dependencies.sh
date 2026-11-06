#!/bin/sh

set -eu

usage()
{
	echo "usage: $0 fedora43|fedora44|el10" >&2
	exit 2
}

test "$#" -eq 1 || usage
platform=$1

test "$(id -u)" -eq 0 || {
	echo "error: dependency installation must run as root" >&2
	exit 1
}

common_packages='ca-certificates clang llvm cmake curl-minimal diffutils findutils gcc git gzip make
openssl openssl-devel libcurl-devel pkgconf-pkg-config python3 python3-pytest tar binutils util-linux
krb5-devel redhat-rpm-config'

case "$platform" in
	fedora43|fedora44)
		# Fedora packages the server-side PGXS selector separately from libpq's
		# pg_config. The project must build against pg_server_config.
		dnf install --assumeyes $common_packages \
			postgresql postgresql-server postgresql-server-devel
		pg_config=/usr/bin/pg_server_config
		;;
	el10)
		case "$(rpm --eval '%{_arch}')" in
			x86_64)
				pgdg_repo_arch=x86_64
				pgdg_repo_sha256=6f6272b26ec3a26f2701ed47c69c580691affdf59ef26fa5a9c5a78f94f40a5d
				;;
			aarch64)
				pgdg_repo_arch=aarch64
				pgdg_repo_sha256=494f3404ee8a3803d40a494d261c9da7b6d49fab65e7c5753946df8102553960
				;;
			*)
				echo "error: unsupported PGDG repository architecture" >&2
				exit 1
				;;
		esac
		pgdg_repo_url="https://download.postgresql.org/pub/repos/yum/reporpms/EL-10-$pgdg_repo_arch/pgdg-redhat-repo-42.0-69.rhel10PGDG.noarch.rpm"
		work_dir=$(mktemp -d)
		trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
		pgdg_repo=$work_dir/pgdg-redhat-repo.noarch.rpm
		dnf install --assumeyes ca-certificates curl-minimal
		curl --fail --location --proto '=https' --tlsv1.2 \
			--output "$pgdg_repo" "$pgdg_repo_url"
		printf '%s  %s\n' "$pgdg_repo_sha256" "$pgdg_repo" |
			sha256sum --check --status
		dnf install --assumeyes "$pgdg_repo"
		dnf install --assumeyes dnf-plugins-core
		dnf config-manager --set-enabled crb
		dnf install --assumeyes $common_packages \
			postgresql18 postgresql18-server postgresql18-devel
		pg_config=/usr/pgsql-18/bin/pg_config
		;;
	*)
		usage
		;;
esac

# Installing build dependencies does not update unrelated packages inherited
# from the pinned base (including the system CA bundle). Apply published vendor
# security updates during online capture, before archiving the complete image.
# Offline release consumers never run this installer or resolve repositories.
dnf upgrade --assumeyes --security

test -x "$pg_config" || {
	echo "error: expected PostgreSQL configuration program at $pg_config" >&2
	exit 1
}
case "$($pg_config --version)" in
	"PostgreSQL 18"*) ;;
	*)
		echo "error: PostgreSQL 18 development files are required" >&2
		exit 1
		;;
esac

{
	echo "rpm-platform: $platform"
	echo "rpm-architecture: $(rpm --eval '%{_arch}')"
	echo "postgresql-version: $($pg_config --version)"
	echo "rpm-packages:"
	rpm -q --qf '  %{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' \
		gcc cmake openssl-devel libcurl-devel |
		LC_ALL=C sort
} >/etc/pg-oauth-build-inputs
