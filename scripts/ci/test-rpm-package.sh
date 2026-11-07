#!/bin/sh

# Run as root only inside a disposable, --network=none RPM test container.
set -eu

test "$#" -ge 1 && test "$#" -le 2 || {
	echo "usage: $0 BASELINE_INPUT_DIR [CANDIDATE_INPUT_DIR]" >&2
	exit 2
}
: "${PG_CONFIG_PATH:?PG_CONFIG_PATH is required}"
test "$(id -u)" -eq 0
inputs=$(CDPATH= cd -- "$1" && pwd)
repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
# RPM embeds the expanded spec (including build paths) in the SRPM header.
# A fixed path is a recorded build input inside each disposable container/VM.
# Atomic mkdir rejects a pre-existing path, including links; never reuse it.
work_dir=/var/tmp/pg-oauth-rpm-build
mkdir -m 0755 "$work_dir"
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

# The container network namespace enforces offline building. Check it here so
# forgetting --network=none cannot silently weaken this regression gate.
test -d /sys/class/net/lo
for interface in /sys/class/net/*; do
	test -f "$interface/flags" || continue
	test "$interface" != /sys/class/net/lo || continue
	flags=$(cat "$interface/flags")
	test "$((flags & 1))" -eq 0 || {
		echo 'error: a non-loopback network interface is up; use --network=none' >&2
		exit 1
	}
done
build_package() (
	# A subshell keeps each build's paths and metadata independent.
	trap - EXIT HUP INT TERM
	inputs=$1
	work_dir=$2
	mkdir -p "$work_dir"
	(cd "$inputs" && sha256sum --check INPUTS.sha256)
	if rpmspec --parse --define 'fedora 42' --define 'rhel 9' \
		"$inputs/SPECS/pg_oauth_validator.spec" >"$work_dir/unsupported.out" 2>&1; then
		echo 'error: spec accepted an unsupported distribution' >&2
		exit 1
	fi
	grep -q 'Only Fedora 43/44 and Enterprise Linux 10' "$work_dir/unsupported.out"
	mkdir -p "$work_dir/rpmbuild" "$work_dir/tmp"
	cp -R "$inputs/SOURCES" "$inputs/SPECS" "$work_dir/rpmbuild/"
	source_epoch=$(sed -n 's/^%global source_epoch \([0-9][0-9]*\)$/\1/p' \
		"$work_dir/rpmbuild/SPECS/pg_oauth_validator.spec")
	test -n "$source_epoch"
	chown -R nobody "$work_dir"
	chmod 0755 "$work_dir"
	runuser -u nobody -- env SOURCE_DATE_EPOCH="$source_epoch" \
		rpmbuild -ba \
		--define "_topdir $work_dir/rpmbuild" \
		--define "_tmppath $work_dir/tmp" \
		--define '_buildhost pg-oauth-rpm-builder.invalid' \
		--define 'use_source_date_epoch_as_buildtime 1' \
		--define 'clamp_mtime_to_source_date_epoch 1' \
		"$work_dir/rpmbuild/SPECS/pg_oauth_validator.spec"

	package_name=postgresql18-pg_oauth_validator
	package=$(find "$work_dir/rpmbuild/RPMS" -type f -name "$package_name-[0-9]*.rpm")
	test -n "$package" && test "$(printf '%s\n' "$package" | wc -l)" -eq 1
	test "$(rpm -qp --qf '%{NAME}' "$package")" = "$package_name"
	test "$(rpm -qp --qf '%{ARCH}' "$package")" = "$(rpm --eval '%{_arch}')"
	test -z "$(rpm -qp --scripts "$package")"
	requires=$work_dir/requires
	rpm -qp --requires "$package" >"$requires"
	case "$PG_CONFIG_PATH" in
		/usr/bin/pg_server_config)
			server=postgresql-server
			grep -Fx 'postgresql-server(:MODULE_COMPAT_18)' "$requires"
			;;
		/usr/pgsql-18/bin/pg_config) server=postgresql18-server ;;
		*) echo 'error: unexpected PostgreSQL selector' >&2; exit 1 ;;
	esac
	grep -Fx "$server$(rpm --eval '%{?_isa}') >= 18.6" "$requires"
	grep -Fx "$server$(rpm --eval '%{?_isa}') < 19" "$requires"
	rpm -qp --provides "$package" >"$work_dir/provides"
	grep -Fx 'bundled(jansson) = 2.15.1' "$work_dir/provides"
	grep -Fx 'bundled(libjwt) = 3.3.3' "$work_dir/provides"
	if grep -E 'lib(jwt|jansson)' "$requires"; then
		echo 'error: embedded dependencies became runtime requirements' >&2
		exit 1
	fi

	# The PAM subpackage is optional here: retained older releases do not have it.
	if grep -q '^%global with_pam 1$' "$work_dir/rpmbuild/SPECS/pg_oauth_validator.spec"; then
		pam_name=postgresql18-pg_oauth_validator-pam
		pam_package=$(find "$work_dir/rpmbuild/RPMS" -type f -name "$pam_name-[0-9]*.rpm")
		test -n "$pam_package" && test "$(printf '%s\n' "$pam_package" | wc -l)" -eq 1
		test "$(rpm -qp --qf '%{NAME}' "$pam_package")" = "$pam_name"
		test "$(rpm -qp --qf '%{ARCH}' "$pam_package")" = "$(rpm --eval '%{_arch}')"
		test -z "$(rpm -qp --scripts "$pam_package")"
		pam_requires=$work_dir/pam-requires
		rpm -qp --requires "$pam_package" >"$pam_requires"
		grep -Fx "$server$(rpm --eval '%{?_isa}') >= 18.6" "$pam_requires"
		grep -Fx "$server$(rpm --eval '%{?_isa}') < 19" "$pam_requires"
		# Independent artifacts: neither package requires the other.
		if grep -E 'pg_oauth_validator|lib(jwt|jansson)\b' "$pam_requires"; then
			echo 'error: PAM package has an unexpected package requirement' >&2
			exit 1
		fi
		if grep -E 'pg_oauth_validator-pam' "$requires"; then
			echo 'error: validator package requires the PAM package' >&2
			exit 1
		fi
		rpm -qp --provides "$pam_package" >"$work_dir/pam-provides"
		grep -Fx 'bundled(jansson) = 2.15.1' "$work_dir/pam-provides"
		grep -Fx 'bundled(libjwt) = 3.3.3' "$work_dir/pam-provides"
		printf '%s\n' "$pam_package" >"$work_dir/pam-package-path"
	fi

	# The SRPM must carry all three actual source archives, not only download URLs.
	srpm=$(find "$work_dir/rpmbuild/SRPMS" -type f -name '*.src.rpm')
	test -n "$srpm" && test "$(printf '%s\n' "$srpm" | wc -l)" -eq 1
	mkdir "$work_dir/srpm"
	rpm2cpio "$srpm" >"$work_dir/source.cpio"
	(cd "$work_dir/srpm" && cpio --extract --quiet <"$work_dir/source.cpio")
	(cd "$work_dir/srpm" && sha256sum --check SHA256SUMS)
	cmp "$inputs/SPECS/pg_oauth_validator.spec" "$work_dir/srpm/pg_oauth_validator.spec"

	printf '%s\n' "$package" >"$work_dir/package-path"
)

chmod 0755 "$work_dir"
build_package "$inputs" "$work_dir/baseline"
package=$(cat "$work_dir/baseline/package-path")
package_name=postgresql18-pg_oauth_validator
candidate_package=
if test "$#" -eq 2; then
	candidate_inputs=$(CDPATH= cd -- "$2" && pwd)
	build_package "$candidate_inputs" "$work_dir/candidate"
	candidate_package=$(cat "$work_dir/candidate/package-path")
fi

# Install with normal dependency/conflict checking; never use --nodeps.
library="$($PG_CONFIG_PATH --pkglibdir)/pg_oauth_validator.so"
test ! -e "$library"
rpm --install "$package"
rpm --verify "$package_name"
test -f "$library"
test -f "/usr/share/licenses/$package_name/LICENSE"
test -f "/usr/share/licenses/$package_name/THIRD-PARTY-LICENSES/JANSSON"
test -f "/usr/share/licenses/$package_name/THIRD-PARTY-LICENSES/LIBJWT-MPL-2.0"
test -f "/usr/share/doc/$package_name/BUILD-SOURCE"
nm -D "$library" | grep '_PG_oauth_validator_module_init'
readelf --dynamic "$library" >"$work_dir/dynamic"
if grep -E '\((RPATH|RUNPATH)\)' "$work_dir/dynamic"; then
	echo 'error: packaged module has a private runtime search path' >&2
	exit 1
fi
ldd "$library" >"$work_dir/ldd"
if grep -E 'not found|lib(jwt|jansson)' "$work_dir/ldd"; then
	echo 'error: invalid runtime linkage' >&2
	exit 1
fi
if find "/usr/share/doc/$package_name" "/usr/share/licenses/$package_name" \
	"$library" -type f -perm /022 | grep -q .; then
	echo 'error: writable installed package files' >&2
	exit 1
fi

# Use the versioned security suite to test the RPM's library; do not overwrite it
# with `make install` or build-tree module bytes.
if test "${RPM_RELEASE_BASELINE:-0}" = 1; then
	# Older releases have a different documented type/configuration contract.
	# Only the checked-in exact source/version baseline may select its own suite.
	python3 "$repo_root/scripts/ci/rpm-release.py" baseline-suite "$inputs" /source
	# The current harness handles distribution socket/logging defaults. Keep
	# the release's assertions while using the same isolated transport fixture.
	cp "$repo_root/tests/integration/integration_support.py" /source/tests/integration/
else
	cp -a "$repo_root/." /source/
fi
make -C /source clean PG_CONFIG="$PG_CONFIG_PATH" >/dev/null
make -C /source integrationcheck PG_CONFIG="$PG_CONFIG_PATH" \
	VALIDATOR_LIBRARY="$library"
rpm --verify "$package_name"
if test -n "$candidate_package"; then
	PG_CONFIG="$PG_CONFIG_PATH" VALIDATOR_LIBRARY="$library" \
		OAUTH_TEST_CLIENT=/source/tests/integration/oauth_test_client \
		PYTHONPYCACHEPREFIX=/source/.pycache \
		python3 /source/tests/integration/rpm_upgrade.py "$package" "$candidate_package"
fi
rpm --verify "$package_name"
# A VM may consume this exact tested artifact for the separate confinement gate.
if test -n "${RPM_TEST_EXPORT_DIR:-}"; then
	test -d "$RPM_TEST_EXPORT_DIR"
	cp "$package" "$RPM_TEST_EXPORT_DIR/validator.rpm"
fi
rpm --erase "$package_name"
test ! -e "$library"
test ! -e "/usr/share/doc/$package_name"
test ! -e "/usr/share/licenses/$package_name"
if rpm -q "$package_name"; then
	echo 'error: package remains installed after removal' >&2
	exit 1
fi
# The PAM subpackage must install, work and remove on its own, with the validator
# package absent (ADR 0008). Older retained baselines do not build it.
if test -f "$work_dir/baseline/pam-package-path"; then
	pam_package=$(cat "$work_dir/baseline/pam-package-path")
	pam_name=postgresql18-pg_oauth_validator-pam
	pam_library="$(rpm --eval '%{_libdir}')/security/pg_oauth_pam.so"
	test ! -e "$pam_library"
	rpm --install "$pam_package"
	rpm --verify "$pam_name"
	test -f "$pam_library"
	test -f "/usr/share/licenses/$pam_name/LICENSE"
	test -f "/usr/share/doc/$pam_name/pam.md"
	if rpm -q "$package_name"; then
		echo 'error: the PAM package pulled in the validator package' >&2
		exit 1
	fi
	exports=$(nm -D --defined-only "$pam_library" | awk '{print $3}' | LC_ALL=C sort | tr '\n' ' ')
	test "$exports" = 'pam_sm_acct_mgmt pam_sm_authenticate pam_sm_setcred ' || {
		echo "error: unexpected PAM module exports: $exports" >&2
		exit 1
	}
	readelf --dynamic "$pam_library" >"$work_dir/pam-dynamic"
	if grep -E '\((RPATH|RUNPATH)\)' "$work_dir/pam-dynamic"; then
		echo 'error: packaged PAM module has a private runtime search path' >&2
		exit 1
	fi
	ldd "$pam_library" >"$work_dir/pam-ldd"
	if grep -E 'not found|lib(jwt|jansson)' "$work_dir/pam-ldd"; then
		echo 'error: invalid PAM module runtime linkage' >&2
		exit 1
	fi
	if find "/usr/share/doc/$pam_name" "/usr/share/licenses/$pam_name" \
		"$pam_library" -type f -perm /022 | grep -q .; then
		echo 'error: writable installed PAM package files' >&2
		exit 1
	fi
	# The real-connection suite needs a disposable container. The SELinux VM
	# gate runs a separate, focused confinement check against this package.
	if test -f /.dockerenv; then
		PG_CONFIG="$PG_CONFIG_PATH" PAM_MODULE="$pam_library" \
			OAUTH_TEST_PAM_DISPOSABLE=1 PYTHONPYCACHEPREFIX=/source/.pycache \
			python3 -m pytest -q -o cache_dir=/source/.pytest_cache /source/tests/pam
	fi
	rpm --verify "$pam_name"
	# The confinement gate consumes this exact tested artifact as well.
	if test -n "${RPM_TEST_EXPORT_DIR:-}"; then
		test -d "$RPM_TEST_EXPORT_DIR"
		cp "$pam_package" "$RPM_TEST_EXPORT_DIR/pam.rpm"
	fi
	rpm --erase "$pam_name"
	test ! -e "$pam_library"
	test ! -e "/usr/share/doc/$pam_name"
	test ! -e "/usr/share/licenses/$pam_name"
	if rpm -q "$pam_name"; then
		echo 'error: PAM package remains installed after removal' >&2
		exit 1
	fi
fi
echo 'RPM offline build, source integrity, install, OAuth, PAM and removal checks passed'
# Candidate export happens only after every install/runtime/removal check passed.
# This is separate from the single-artifact handoff used by the SELinux VM.
if test -n "${RPM_CANDIDATE_EXPORT_DIR:-}"; then
	test "$#" -eq 1
	test -d "$RPM_CANDIDATE_EXPORT_DIR"
	test -z "$(ls -A "$RPM_CANDIDATE_EXPORT_DIR")"
	cp -R "$work_dir/baseline/rpmbuild/RPMS" "$work_dir/baseline/rpmbuild/SRPMS" "$RPM_CANDIDATE_EXPORT_DIR/"
	mkdir "$RPM_CANDIDATE_EXPORT_DIR/inputs"
	cp -R "$inputs/." "$RPM_CANDIDATE_EXPORT_DIR/inputs/"
	cmp "$inputs/INPUTS.sha256" "$RPM_CANDIDATE_EXPORT_DIR/inputs/INPUTS.sha256"
	{
		echo 'Experimental unsigned RPM candidate; not release approval.'
		echo 'Passed: offline unprivileged build, SRPM integrity, versioned installed OAuth suite, RPM verification, removal.'
		echo 'Not covered: SELinux confinement, cross-release upgrade/rollback, signing, vulnerability approval.'
		"$PG_CONFIG_PATH" --version
		gcc --version | head -n 1
		rpm --version
		echo 'Installed build environment:'
		rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort
	} >"$RPM_CANDIDATE_EXPORT_DIR/BUILD-ENVIRONMENT.txt"
fi
