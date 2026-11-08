# RPM dependency review, 2026-10-22

Historical review: dependency/security and license review was reported complete
by the deployment owner on 2026-10-24. Subsequent validation, signing and
prerelease approval are recorded in the [published 0.1.3 release](releases/0.1.3-prerelease.md).
This dependency review is not itself a signed release approval and does not
resolve vendor security findings. The scoped Rocky exception and production
retention requirements below still apply.

## Reviewed inputs and evidence

The complete six-target inventory is retained as `packages.tsv`, `tools.txt`
and `image.json` with each builder archive. Verify their SHA-256 and sizes
against [`builders.lock.json`](../packaging/rpm/builders.lock.json) before
review. Inventory fields include exact epoch/version/release/architecture,
license, source RPM and vendor; do not compare only upstream version numbers.
Both architectures are required for Fedora 43, Fedora 44 and Rocky Linux 10.

The initial capture was workflow run
[39734560246](https://github.com/proddata/pg_oauth_validator/actions/runs/39734560246).
All six inventory hashes were independently checked against that lock. The
initial environment had these runtime package releases (architecture suffixes
are recorded separately in the inventories):

| Distribution | libcurl package | OpenSSL libraries | PostgreSQL server |
| --- | --- | --- | --- |
| Fedora 43 | `libcurl-8.15.0-12.fc43` | `1:3.5.9-1.fc43` | `18.6-1.fc43` |
| Fedora 44 | `libcurl-8.18.0-14.fc44` | `1:3.5.9-1.fc44` | `18.6-1.fc44` |
| Rocky 10 | `libcurl-minimal-8.12.1-4.el10_2.7` | `1:3.5.8-2.el10_2` | `18.6-4PGDG.rhel10.2` |

The initial capture is rejected for production. Installing build dependencies
left other inherited base packages behind available vendor security updates.
Online queries in separate disposable native ARM containers used
`dnf --refresh updateinfo list --security --updates`; no source, release files,
credentials or provider tokens were mounted. Fedora reported updates including
`FEDORA-2026-56e14eb520` (CA certificates, critical in vendor metadata),
`FEDORA-2026-72d10c874d` (libevent), tar, sudo and the curl command-line package.
Rocky reported available glibc, libevent and other inherited-package fixes.
These queries do not prove absence of vulnerabilities without published fixes.

The capture installer now applies `dnf upgrade --assumeyes --security` after
installing dependencies, with normal repository signature verification. This
happens before archiving the complete image. Offline consumers never execute
that installer or resolve mutable repositories. The refreshed capture
[39846491722](https://github.com/proddata/pg_oauth_validator/actions/runs/39846491722)
succeeded on all six native targets. All three small records for each target
were independently checked against the new lock's digests and sizes. Applying
updates to a running release builder is prohibited.

The refreshed lock SHA-256 is
`bd60616d04472bc2ab292efc4a75ce13f7c6c4c63d893ebab89e7a99233f1ad7`.
Both CPU inventories now record these corrected inherited dependencies:

| Distribution | CA certificates | glibc | libevent |
| --- | --- | --- | --- |
| Fedora 43 | `2026.2.92_v9.0.319-2.fc43` | `2.42-17.fc43` | `2.1.13-1.fc43` |
| Fedora 44 | `2026.2.92_v9.0.319-1.fc44` | `2.43-9.fc44` | `2.1.13-1.fc44` |
| Rocky 10 | `2025.2.80_v9.0.305-102.el10` | `2.39-145.el10_2` | `2.1.13-1.el10_2` |

The direct libcurl, OpenSSL and PostgreSQL releases remain as listed above.
The lock is accepted for reproducibility/lifecycle testing, **not production
approval**. Rocky's OpenSSL finding has the scoped deployment exception below.

## Builder recapture for the PAM subpackage, 2026-11-07

The optional PAM subpackage needs `pam-devel` at build time, which the frozen
builders above do not contain, and offline builds cannot install it. All six
builders were therefore captured again, unchanged except for that dependency, by
workflow run
[42306639206](https://github.com/proddata/pg_oauth_validator/actions/runs/42306639206).
The capture installer, scripts and workflow are byte-identical to the checked-in
versions at the pull request head that was captured. The lock SHA-256 is
`46ef0d5abcb83a68432e89e46f1afd550fab7a1b9d6b4e3dfac424b24181a106`. The
`packages.tsv`, `tools.txt` and `image.json` records of all six targets were
downloaded and checked against that lock's digests, and the six base images are
unchanged.

Compared with the lock above:

- `pam-devel` is added on all six targets, at the same release as the installed
  `pam-libs` on each (Fedora 43 `1.7.1-5`, Fedora 44 `1.7.2-2`, Rocky 10
  `1.6.1-9.el10_2.1`).
- The direct runtime packages in the tables above are **unchanged** on every
  target: libcurl (or libcurl-minimal), OpenSSL, PostgreSQL, glibc and libevent.
  The scope of the Rocky OpenSSL exception below is therefore unchanged: the same
  `1:3.5.8-2.el10_2` packages and the same expiry.
- Because a fresh capture installs current repository content, other inherited
  packages moved to newer releases, about 20 to 40 per target. They include
  `ca-certificates` (Fedora 44 `-1` to `-2`; Rocky `2025.2.80_v9.0.305-102.el10`
  to `2026.2.92_v9.0.319-100.3.el10_2`), the Fedora 44 and Rocky compiler
  toolchains, `python3` on Fedora 44, `openssh`, `util-linux` and `brotli`. The
  per-target lists are in the retained review records of that run.

Only the package inventories were compared. The advisories and changelogs of the
updated packages were **not** reviewed, and the full-closure disposition above has
not been repeated for this inventory. The maintainer approved the lock for
reproducibility and lifecycle testing in the repository work session; this is not
independent review and not production approval. The previous captures stay
available through the earlier run and Git history. The RPM subpackage itself is
introduced separately and is not qualified under SELinux enforcing mode.

## Embedded libraries and licensing

The source pins are unchanged from v0.1.2:

| Library | Exact source commit | Archive SHA-256 | License |
| --- | --- | --- | --- |
| Jansson 2.15.1 | `dbb5fb3636e155fccfce4cd215de752779bd6971` | `65084e4e43de9840d66a0604c8d9d9c499b2fc0db52c05730e3b6ac3c11ed66f` | MIT, including dtoa notice |
| libjwt 3.3.3 | `602118d99d46ca5df71bda60d3df642135417f29` | `47e3d5d00fd60141dbacbcb9a0c2e1b277740364ac1d15b50728dccb7afdf23c` | MPL-2.0 |

The RPM gate checks complete license texts, the absence of private runtime
search paths and dynamic libjwt/Jansson dependencies, and complete corresponding
source archives in the SRPM. The package carries the existing third-party
notices and source locations. See
[`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md). System shared libraries and
compiler/test tools are not incorporated into the validator RPM. Redistribution
of complete builder images also requires preserving the vendor license and
source-availability obligations recorded by the full package inventory; a
successful application-package license check is not approval of that separate
redistribution.

The two published libjwt advisories were checked: the pinned 3.3.3 includes the
fixes for [algorithm confusion](https://github.com/benmcollins/libjwt/security/advisories/GHSA-q843-6q5f-w55g)
and [JWK NULL/bounds parsing](https://github.com/benmcollins/libjwt/security/advisories/GHSA-ph96-hqpc-9f66).
Project envelope tests additionally reject HMAC algorithms. Jansson's
[maintainer advisory list](https://github.com/akheron/jansson/security/advisories)
had no published entries at query time; that is not a guarantee of safety.

## Runtime advisory dispositions

- PostgreSQL is 18.6 on every initial target. The upstream
  [18.6 security announcement](https://www.postgresql.org/about/news/postgresql-186-1711-1615-1519-1424-and-19-beta-3-released-3365/)
  and [major-18 security list](https://www.postgresql.org/support/security/18/)
  remain the authority for supported server/client updates.
- Fedora OpenSSL 3.5.9 includes the upstream
  [September security fixes](https://openssl-library.org/news/openssl-3.5-notes/).
  Rocky 3.5.8-2 backports `CVE-2026-84782`, according to its installed RPM
  changelog, but does not record the `CVE-2026-35189` fix. The
  [upstream advisory](https://openssl-library.org/news/vulnerabilities-3.5/)
  describes certificate-processing memory exhaustion before 3.5.9; the
  [RHEL 10 tracker](https://access.redhat.com/security/cve/cve-2026-35189)
  lists OpenSSL as affected. The fresh Rocky security-update query offered no
  OpenSSL fix. The package remains affected; the controlled-endpoint deployment
  has the scoped exception below. Successful JWT or TLS tests do not establish
  that certificate processing is unaffected.
- curl upstream version matching alone overstates some findings because Fedora
  and Rocky backport fixes. For example, Fedora's
  [8.18.0-14 changelog](https://packages.fedoraproject.org/pkgs/curl/curl/fedora-44-updates.html)
  records OpenSSL-provider, pinning and HTTP/2 dependency fixes; the actual
  archived Fedora 43 and Rocky RPM changelogs were also inspected. Pending
  upstream reports still require explicit applicability review against the
  complete runtime closure before approval.
- In particular, [CVE-2026-92392](https://curl.se/docs/CVE-2026-92392.html)
  requires an HTTP/2 upload. The validator uses bounded GET requests without
  uploads. [CVE-2026-92387](https://curl.se/docs/CVE-2026-92387.html) concerns
  FTP/IMAP/POP3/SMTP control responses; the validator permits HTTP(S) only.
  These are application-path assessments, not assertions that the installed
  libcurl package is globally patched. Other software using the system library
  needs its own assessment.

The module's actual `ldd` closure was inspected locally. It includes libcurl,
OpenSSL, libc/libgcc and vendor transitive libraries; Fedora also loads HTTP/2,
HTTP/3, LDAP, SSH, Kerberos, compression and related dependencies. Linked does not
mean every protocol is enabled by this application. The full closure and all
remaining upstream/vendor advisories need final disposition against the
refreshed lock; there is no blanket waiver for unused features.

GitHub dependency, code-scanning and secret-scanning alert APIs returned no open
alerts on 2026-10-22. Secret values were not requested. New CI results and alert
status must be checked for the final candidate source revision.

## Controlled-endpoint exception: CVE-2026-35189

Decision date: **2026-10-23**. Reviewer/accepting owner: **proddata**, by explicit
instruction in the repository work session. This is owner review, not independent
review. Scope: the intended Rocky Linux 10 deployment on x86-64 and ARM64 using
the reviewed `1:3.5.8-2.el10_2` OpenSSL packages.

The owner controls the discovery/JWKS servers and their TLS certificates and
considers this CVE not relevant to that intended deployment. Treat it as a
**scoped risk acceptance**, removing this finding as a release blocker for that
deployment while the exception is valid. This is not a global not-affected
assessment or a claim that the vendor package contains a fix.

The rationale is the restricted TLS peer set: discovery and JWKS destinations
are administrator-controlled and host-allowlisted, redirects and implicit proxies
are disabled, and peer/hostname verification remains enabled
(`src/http_transport.c`). Ordinary login clients cannot choose a TLS endpoint
through token claims. These controls reduce exposure; they do not eliminate the
vulnerable certificate-processing path. A compromised endpoint or an attacker
able to intercept its TLS connection can still supply certificate bytes before
trust validation completes. The owner's decision accepts that residual
availability risk. HTTP body limits and request timeouts are not a proven bound
on certificate-processing memory. No exploit regression or deployment-specific
non-exploitability proof has been produced.

Expiry/review deadline: **2026-11-22**, or earlier if endpoint ownership,
certificates/trust configuration, or the deployment threat model changes. The
exception does not automatically apply to other installations, additional
providers, or other software using system OpenSSL. If it expires, this finding
blocks promotion until a fix is verified or a new explicit review is recorded.
Follow-up: [issue #28](https://github.com/proddata/pg_oauth_validator/issues/28).
Recheck signed Rocky packages and vendor/source patch evidence; when a fix is
available, capture and review fresh builders for both architectures and rerun
the affected release gates. Retain the old inputs and evidence.

### Exception re-review, 2026-11-07

The owner (`proddata`) reported in the repository work session that the exception
was re-reviewed on 2026-11-07 ahead of the 0.2.0 prerelease and continues
unchanged: same scope, rationale and **2026-11-22** expiry. This is owner review,
not independent review, and no new evidence, vendor patch confirmation or
reproduced analysis was supplied with that statement. The 2026-11-22 deadline
still applies: after it, promotion is blocked until a fix is verified or a new
explicit review is recorded.

## Owner review completion, 2026-10-24

The deployment owner (`proddata`) reported completion of the remaining
dependency/security and license review in the repository work session. This
records the owner's completion statement for the reviewed inputs above; it is
not an independently reproduced audit or an assertion that all dependencies
are free of vulnerabilities. No additional itemized findings, license evidence,
or review artifacts were supplied with that statement. The controlled-endpoint
Rocky exception remains scoped and time-limited as recorded above.

## Requirements recorded before publication

For the 0.1.3 prerelease, the owner accepts existing CI retention instead of
additional durable storage; see the limited prerelease decision in
[release readiness](release-readiness.md#limited-prerelease-retention-decision-2026-10-24).
Durable retention and a verified restore remain requirements before production
promotion. Local ignored `dist/` copies alone do not establish backup or durable
retention.

The following preparation requirements were subsequently completed for the
published 0.1.3 prerelease; future releases need their own evidence and approval.

Select the final release source revision and rerun the affected release gates
on that exact revision and reviewed builder lock. Honor the scope and expiry of
the Rocky OpenSSL exception. Obtain final release approval, sign and verify the
release artifacts, and follow the publication procedure. The owner's review
completion does not authorize tagging or publication by the agent. No RPM is
tagged, signed or published by this work.
