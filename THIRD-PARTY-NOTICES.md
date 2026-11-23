# Third-party notices

`pg_oauth_validator` itself is released under the PostgreSQL License; see
[`LICENSE`](LICENSE). This file records the separate third-party components the
module incorporates, links against, or uses only to build and test itself, and
their own terms.

The generated release archive carries the project license as `LICENSE`, this
file as `THIRD-PARTY-NOTICES.md`, and the exact upstream license texts of the
statically incorporated components under `THIRD-PARTY-LICENSES/`:

| Archive path | Component | License |
| --- | --- | --- |
| `LICENSE` | `pg_oauth_validator` | PostgreSQL License |
| `THIRD-PARTY-LICENSES/LIBJWT-MPL-2.0` | libjwt | Mozilla Public License 2.0 |
| `THIRD-PARTY-LICENSES/JANSSON` | Jansson | MIT (with the `dtoa.c` notice) |

Dynamically linked libraries are not redistributed in the archive, so their
license texts come from the operating system packages that provide them. They
are identified under "Dynamically linked libraries" below.

## libjwt

The module statically incorporates libjwt 3.3.3 from commit
`602118d99d46ca5df71bda60d3df642135417f29`, licensed under the Mozilla Public
License 2.0.

The corresponding covered source is available from:

`https://github.com/benmcollins/libjwt/tree/602118d99d46ca5df71bda60d3df642135417f29`

The source archive used by the build is:

`https://codeload.github.com/benmcollins/libjwt/tar.gz/602118d99d46ca5df71bda60d3df642135417f29`

Its SHA-256 digest is
`47e3d5d00fd60141dbacbcb9a0c2e1b277740364ac1d15b50728dccb7afdf23c`.
That commit is upstream tag `v3.3.3`.
The project's modifications, if any, are represented by the build scripts and
patches in the corresponding `pg_oauth_validator` source revision recorded in
`BUILD-MANIFEST`.

Because MPL-2.0 covered code is distributed in the module's binary form, each
release archive must keep the complete upstream license text as
`THIRD-PARTY-LICENSES/LIBJWT-MPL-2.0` and the source location and digest above,
so that the covered source remains obtainable for the exact linked revision. The
module links libjwt with GnuTLS, mbedTLS, json-c, and libcurl support disabled,
so no further libjwt-side dependency is incorporated.

## Jansson

The module statically incorporates Jansson 2.15.1 from commit
`dbb5fb3636e155fccfce4cd215de752779bd6971`, licensed under the MIT license.
Its exact version is also recorded in `BUILD-MANIFEST`.

The corresponding source is available from:

`https://github.com/akheron/jansson/tree/dbb5fb3636e155fccfce4cd215de752779bd6971`

The source archive used by the build is:

`https://codeload.github.com/akheron/jansson/tar.gz/dbb5fb3636e155fccfce4cd215de752779bd6971`

Its SHA-256 digest is
`65084e4e43de9840d66a0604c8d9d9c499b2fc0db52c05730e3b6ac3c11ed66f`.
That commit is upstream tag `v2.15.1`.
Jansson contains `src/dtoa.c`, whose additional notice is part of the upstream
`LICENSE` file. The generated archive copies that complete file as
`THIRD-PARTY-LICENSES/JANSSON`.

## Dynamically linked libraries

The module dynamically links the deployment environment's libcurl, OpenSSL, the
PostgreSQL server it is built against, and the C runtime. None of these are
redistributed in the release archive, so their license texts remain those of the
operating system packages that provide them:

| Component | Use | License |
| --- | --- | --- |
| libcurl | HTTPS GET transport for metadata and JWKS | curl license (MIT/X derivative) |
| OpenSSL 3.x | TLS, and RS256/ES256/EdDSA (Ed25519) signature verification | Apache License 2.0 |
| PostgreSQL | Server module API (PGXS, validator callbacks) | PostgreSQL License |
| C runtime and system libraries | Platform | Per operating system distribution |

libcurl must be built against the OpenSSL backend so that the module does not
load a second TLS implementation into a PostgreSQL backend process. Exact
versions are recorded from the build environment in `BUILD-MANIFEST`; operators
must use supported, security-maintained runtime packages and rebuild after
relevant security updates.

## Build- and test-only components

These components are used to build, format, or test the module. None is linked
into it or included in a release archive, so none contributes a redistribution
obligation. They are recorded here so a license audit can see they were
considered.

| Component | Use | License |
| --- | --- | --- |
| `pgindent` and `pg_bsd_indent` from the PostgreSQL 19.0 source tarball, fetched with a pinned SHA-256 by [`scripts/ci/install-pgindent.sh`](scripts/ci/install-pgindent.sh) | C formatting checks | PostgreSQL License |
| CMake, GCC/Clang, and the Debian build toolchain | Building the module and its pinned static archives | Per operating system distribution |
| `postgres` container images, pinned by digest in the CI workflows and in the `POSTGRES_IMAGE` base of [`tools/dev/Containerfile`](tools/dev/Containerfile) and [`demo/Containerfile`](demo/Containerfile) | Development, integration tests, and local demo | PostgreSQL License, on a Debian base |
| Keycloak 26.5.0, pinned by digest in [`tests/interop/keycloak/compose.yml`](tests/interop/keycloak/compose.yml) and [`compose.yml`](compose.yml) | Optional provider interoperability suite and local demo | Apache License 2.0 |

`tools/pgindent/project.typedefs` is a project-authored list of type names used
by the formatter and contains no third-party code.
