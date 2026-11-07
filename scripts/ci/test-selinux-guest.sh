#!/bin/sh
# Root-only entry point for a disposable Fedora 44 VM, never a production host.
set -eu
test "$(id -u)" -eq 0
test "$(getenforce)" = Enforcing
. /etc/os-release
test "$ID" = fedora && test "$VERSION_ID" = 44
cd /opt/pg-oauth-validator
sh scripts/ci/install-rpm-dependencies.sh fedora44
dnf install -y rpm-build cpio elfutils policycoreutils-python-utils audit iproute setools-console
systemctl start auditd
# Cloud images may boot with auditing disabled. Enable records explicitly in
# this disposable guest; keep SELinux enforcing and reveal dontaudit denials.
auditctl -e 1
auditctl -s
auditctl -l >/tmp/pg-oauth-audit-rules
cat /tmp/pg-oauth-audit-rules
# auditctl(8), DISABLED BY DEFAULT: this rule suppresses every new task's
# audit processing even when the global enabled flag is 1.
if grep -Fxq -- '-a never,task' /tmp/pg-oauth-audit-rules; then
	auditctl -d never,task
fi
cat /proc/cmdline
# Verify the whole producer/consumer path before spending time on a build.
# CI stdin is not a terminal: --input-logs explicitly selects auditd's files.
grep -E '^(write_logs|local_events|log_file|log_format)[[:space:]]*=' /etc/audit/auditd.conf || true
auditctl -m pg_oauth_audit_probe
audit_ready=false
for attempt in $(seq 1 30); do
	if ausearch --input-logs -m USER --raw 2>/dev/null | grep -Fq pg_oauth_audit_probe; then
		audit_ready=true
		break
	fi
	sleep 0.1
done
if test "$audit_ready" != true; then
	journalctl -u auditd --no-pager -n 40
	ls -l /var/log/audit
	echo 'error: audit write/read preflight failed' >&2
	exit 1
fi
semodule -DB
trap 'getenforce; semanage permissive -l; ausearch --input-logs -m AVC,USER_AVC -i || true; journalctl -k --grep=avc: --no-pager -n 80 || true; auditctl -s; semodule -B' EXIT
export PG_CONFIG_PATH=/usr/bin/pg_server_config
export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig
export LD_LIBRARY_PATH=/usr/local/lib
python3 scripts/ci/prepare-rpm-sources.py fetch /opt/rpm-dependencies
JANSSON_SOURCE_ARCHIVE=/opt/rpm-dependencies/jansson.tar.gz sh scripts/ci/install-jansson.sh
LIBJWT_SOURCE_ARCHIVE=/opt/rpm-dependencies/libjwt.tar.gz sh scripts/ci/install-libjwt.sh
python3 scripts/ci/prepare-rpm-sources.py prepare 0.0.0 "$(git -c safe.directory=/opt/pg-oauth-validator rev-parse HEAD)" /opt/rpm-dependencies /opt/rpm-inputs
mkdir /source /opt/tested-rpm
export RPM_TEST_EXPORT_DIR=/opt/tested-rpm
# sysfs is tied to its mount's network namespace. Remount it privately so
# the existing offline gate observes this namespace, not the VM's NIC.
unshare --mount --net --fork --propagation private /bin/sh -eu -c \
	'mount -t sysfs sysfs /sys; ip link set lo up; exec sh scripts/ci/test-rpm-package.sh /opt/rpm-inputs'
rpm --install /opt/tested-rpm/validator.rpm
library="$($PG_CONFIG_PATH --pkglibdir)/pg_oauth_validator.so"
restorecon -v "$library"
# The shared-cache probe is test instrumentation, distinct from the RPM module.
install -m 0755 /source/tests/integration/cache_probe.so "$($PG_CONFIG_PATH --pkglibdir)/oauth_test_cache_probe.so"
restorecon -v "$($PG_CONFIG_PATH --pkglibdir)/oauth_test_cache_probe.so"
export PG_CONFIG="$PG_CONFIG_PATH" VALIDATOR_LIBRARY="$library"
export OAUTH_TEST_CLIENT=/source/tests/integration/oauth_test_client
export CACHE_PROBE="$($PG_CONFIG_PATH --pkglibdir)/oauth_test_cache_probe.so"
export OAUTH_TEST_SELINUX=1 PYTHONPYCACHEPREFIX=/source/.pycache
# Keep policy evidence even when the suite fails. Never upload provider keys,
# token files, raw PostgreSQL logs, or pytest locals.
uname -r
rpm -q selinux-policy selinux-policy-targeted policycoreutils postgresql-server
sesearch -A -s postgresql_t -t http_port_t -c tcp_socket -p name_connect
# A new valid token must be denied with a fresh, exact HTTPS AVC before
# permission is added. Never infer a policy grant from a generic HTTP error.
python3 tests/integration/selinux_denial.py
policy=/usr/share/doc/postgresql18-pg_oauth_validator/docs/selinux/pg_oauth_https.cil
cmp docs/selinux/pg_oauth_https.cil "$policy"
semodule -i "$policy"
python3 -m pytest -q --maxfail=1 --capture=tee-sys -p no:cacheprovider tests/integration
# A fresh cluster prevents cached keys from masking the effect of removal.
semodule -r pg_oauth_https
python3 tests/integration/selinux_denial.py
# The PAM module is a separate package. Install the tested artifact as an
# operator would, then repeat the denial/allowance/denial cycle with a fresh
# cluster each time. The module runs inside the confined PostgreSQL backend.
rpm --install /opt/tested-rpm/pam.rpm
pam_library="$(rpm --eval '%{_libdir}')/security/pg_oauth_pam.so"
restorecon -v "$pam_library"
ls -Z "$pam_library"
export PAM_MODULE="$pam_library"
python3 tests/pam/selinux_check.py denied
semodule -i "$policy"
python3 tests/pam/selinux_check.py allowed
semodule -r pg_oauth_https
python3 tests/pam/selinux_check.py denied
rpm --verify postgresql18-pg_oauth_validator postgresql18-pg_oauth_validator-pam
auditctl -s >/tmp/pg-oauth-audit-status
cat /tmp/pg-oauth-audit-status
grep -Fx 'lost 0' /tmp/pg-oauth-audit-status
test "$(getenforce)" = Enforcing
