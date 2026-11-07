# ADR 0004: Access-token type allowlist and missing-type compatibility

## Context

RFC 9068 permits `at+jwt` and `application/at+jwt` as the `typ` of a JWT
access token. Some OIDC issuers produce JWT access tokens without `typ`.
Requiring one exact spelling excludes the other standards spelling and these
issuers. Accepting all JWT types would allow ID or session token substitution.

## Decision

`allowed_token_types` is a nonempty, duplicate-free allowlist restricted to the
two RFC 9068 spellings. Both are allowed by default. A separate
`allow_missing_token_type` boolean defaults to `off`. When it is `on`, only an
*absent* `typ` is additionally allowed; a present wrong-type or malformed
`typ` is always denied. Signature, exact issuer, configured resource audience,
expiry, required database scope, identity, and role authorization remain
mandatory. The exception does not claim RFC 9068 conformance.

An operator enabling this exception must establish mutually exclusive token
validation rules for all JWT kinds the issuer produces. In particular, ID and
session tokens must be unable to satisfy the configured resource audience and
database scope together. This is an issuer and deployment contract; token
claims alone cannot prove that another token kind could never carry them.

The `typ` value is compared ignoring ASCII case, because media type names are
case-insensitive (RFC 7515 section 4.1.9) and RFC 9068's own example is
`at+JWT`. Spelling is not equated across forms: an operator who lists only
`at+jwt` still rejects `application/at+jwt`, because the allowlist is an
explicit administrator choice. Case folding is ASCII-only so the result does
not depend on the database locale.

The previous singular `required_token_type` GUC is removed before the first
stable release. An existing configuration must migrate to
`allowed_token_types` and the module rejects the old setting at startup.
Rollback requires restoring the former setting with the former module.

## Evidence

- [RFC 9068, Sections 2.1 and 4](https://www.rfc-editor.org/rfc/rfc9068)
  defines the two accepted spellings and strict resource-server validation.
- [RFC 8725, Section 3.12](https://www.rfc-editor.org/rfc/rfc8725)
  requires mutually exclusive validation rules when an issuer produces more
  than one kind of JWT.
