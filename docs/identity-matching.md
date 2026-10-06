# Identities and identity matching

This document describes how signer identities are represented and how a
policy's expected identity is matched against the identities surfaced by
verification.

All types live in the `api/v1` package
(`proto/carabiner/signer/v1/identity.proto` and
`proto/carabiner/signer/v1/matcher.proto`).

## Overview

After a signature is verified, the result carries one or more *signer
identities* — records describing **who** produced the signature. A
policy declares an *expected identity*: the same `Identity` proto, but
populated with constraints (exact literals or matchers). Matching
answers: did any verified signer satisfy the policy's expectation?

```go
sv.MatchesIdentity(expected *Identity) bool
```

An `Identity` carries exactly one variant:

| Variant    | Go type             | Used when                                                                              |
| ---------- | ------------------- | -------------------------------------------------------------------------------------- |
| `Sigstore` | `*IdentitySigstore` | Signer is a Fulcio-issued cert (OIDC-backed).                                          |
| `Key`      | `*IdentityKey`      | Signer is a raw public key (RSA / ECDSA / Ed25519 / GPG).                              |
| `Spiffe`   | `*IdentitySpiffe`   | Signer is an X.509-SVID from a SPIFFE/SPIRE trust domain.                              |
| `Ref`      | `*IdentityRef`      | Placeholder pointing to an identity defined elsewhere (e.g., at a policy-set level).   |

Plus — new — a top-level `matchers` slice carrying arbitrary predicates:

```
message Identity {
    // ... variant oneof ...
    repeated Matcher matchers = 10;
}
```

Variant + `matchers` are AND'd. A signer is accepted when its variant
passes the variant-specific check **and** every outer matcher passes
against a field of that same signer.

## Principal — the canonical identity string

Every identity has a stable string form, its **principal**, that names
who signed without carrying match semantics:

| Variant    | Principal format                                  |
| ---------- | ------------------------------------------------- |
| `Sigstore` | `sigstore::<issuer>::<identity>`                  |
| `Key`      | `key::<type>::<id>`                               |
| `Ref`      | `ref:<id>`                                        |
| `Spiffe`   | `<svid>` — the SPIFFE URI itself                  |

`Identity.Principal()` emits it; `NewIdentityFromPrincipal(s)` parses
strictly (matcher annotations rejected). When you need the rich form
that also encodes matcher semantics, use `Identity.Spec()` /
`NewIdentityFromSpec` — see [principals.md](principals.md) for the
full grammar.

The deprecated names `Slug()` / `NewIdentityFromSlug` are compat
aliases for `Spec` / `NewIdentityFromSpec` and still work; prefer the
explicit names going forward.

## The matcher layer (new, canonical)

The matcher layer separates "who the signer is" (variant fields) from
"how the policy matches" (matchers). Two places to place matchers,
both serialized via `Matcher` / `StringMatcher` from `matcher.proto`:

1. **Per-variant convenience fields** (`*_match`) — embedded on each
   identity variant. Ergonomic for single-field constraints; read at
   match time alongside legacy fields.
2. **Outer `matchers` slice** on `Identity` — the canonical, fully
   expressive form. Each entry targets a dotted field path.

Both are AND'd; an empty outer slice is trivially satisfied.

### `StringMatcher`

```proto
message StringMatcher {
    oneof kind {
        string exact  = 1;
        string regex  = 2;
        string prefix = 3;
        string glob   = 4;
    }
    bool case_insensitive = 5;
}
```

Semantics:

| Kind     | Semantics                                                                                |
| -------- | ---------------------------------------------------------------------------------------- |
| `exact`  | Byte-exact equality.                                                                     |
| `regex`  | Go regular expression, **anchored to the full input** (`^(?:pattern)$` applied internally). Prefix-collision attacks via unanchored patterns are not possible. |
| `prefix` | `strings.HasPrefix`.                                                                     |
| `glob`   | `path.Match` — shell-style glob (`*`, `?`, `[...]`). **`*` does not cross `/`** (path-component granularity). |

`case_insensitive` applies to all kinds. For `regex` it prepends `(?i)`
to the compiled pattern; for other kinds both sides are lowercased
before comparison.

### `Matcher` — outer form

```proto
message Matcher {
    string field = 1;
    oneof kind {
        StringMatcher string = 2;
        // More kinds coming: Int, Bool, Duration, Time, List.
    }
}
```

`field` is a dotted path. `"principal"` is a universal field valid
against any variant. Other paths are variant-qualified:

| Field                   | Resolves to                                                               |
| ----------------------- | ------------------------------------------------------------------------- |
| `principal`             | `Identity.Principal()` — works for any variant                            |
| `sigstore.issuer`       | `Sigstore.Issuer` (signer must be sigstore)                               |
| `sigstore.identity`     | `Sigstore.Identity`                                                       |
| `sigstore.source_repository_uri` | `Sigstore.SourceRepositoryUri`                                   |
| `sigstore.build_config_uri` | `Sigstore.BuildConfigUri`                                             |
| `sigstore.build_trigger` | `Sigstore.BuildTrigger`                                                  |
| `sigstore.source_repository_ref` | `Sigstore.SourceRepositoryRef`                                   |
| `key.id`                | `Key.Id`                                                                  |
| `key.type`              | `Key.Type`                                                                |
| `key.signing_fingerprint` | `Key.SigningFingerprint`                                                |
| `spiffe.svid`           | `Spiffe.Svid` (the full `spiffe://…` URI)                                 |
| `spiffe.trust_domain`   | **virtual**: parsed from the signer's `Spiffe.Svid` at eval time          |
| `spiffe.path`           | **virtual**: parsed from the signer's `Spiffe.Svid` at eval time          |

When a matcher's field isn't applicable to the signer's variant
(e.g. `spiffe.path` on a sigstore signer), or names an unknown field,
the matcher **fails closed** for that signer.

## Sigstore identities

### Fields

| Field           | Meaning                                                                   |
| --------------- | ------------------------------------------------------------------------- |
| `Issuer`        | OIDC issuer (legacy — prefer `IssuerMatch`).                              |
| `Identity`      | Subject claim (legacy — prefer `IdentityMatch`).                          |
| `Mode`          | `exact` (default) or `regexp` — applies to legacy `Issuer`/`Identity`.    |
| `IssuerMatch`   | `StringMatcher` applied to the signer's issuer.                           |
| `IdentityMatch` | `StringMatcher` applied to the signer's identity.                         |
| `SourceRepositoryUriMatch` | `StringMatcher` applied to the signer's source repository URI. |
| `BuildConfigUriMatch` | `StringMatcher` applied to the workflow the certificate was issued for (for a reusable workflow, the calling workflow). |
| `BuildTriggerMatch` | `StringMatcher` applied to the event that triggered the run, for example `release` or `push`. |
| `SourceRepositoryRefMatch` | `StringMatcher` applied to the ref the run was for, for example `refs/tags/v1.2.3`. |

### Matching rules (new + legacy combined)

When **only the legacy fields are set**, the historical contract
applies: both `Issuer` and `Identity` must be non-empty. `Mode` chooses
literal-equality or anchored-regex semantics for the pair. A
half-specified legacy policy (only Issuer or only Identity, no
matchers) is treated as malformed and matches nothing.

When **matchers are used** (with or without legacy fields), each set
matcher must pass independently. Matcher-only policies can pin just
one axis (e.g. issuer_match without any identity constraint) — a
new capability over the legacy shape.

`BuildTriggerMatch` and `SourceRepositoryRefMatch` are the exception: an
event like `release` or a ref like `refs/tags/v1.2.3` exists in every
repository, so on their own they would match a run of anyone's
workflow. They only refine an identity and need an identity, source
repository URI or build config URI constraint next to them. An issuer
alone doesn't count, it names a whole platform like GitHub Actions. A
policy without one is invalid and matches nothing.

Legacy and matchers combine with AND semantics: all set constraints
must pass.

### Example — new form

```go
policy := &Identity{
    Sigstore: &IdentitySigstore{
        IssuerMatch:   &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"}},
        IdentityMatch: &StringMatcher{Kind: &StringMatcher_Regex{Regex: `https://github\.com/myorg/repo/.+@refs/tags/v.+`}},
    },
}
```

### Example — legacy (still works)

```go
mode := SigstoreModeRegexp
policy := &Identity{
    Sigstore: &IdentitySigstore{
        Mode:     &mode,
        Issuer:   `https://token\.actions\.githubusercontent\.com`,
        Identity: `https://github\.com/myorg/repo/.+@refs/tags/v.+`,
    },
}
```

Both policies behave identically — regex is anchored in both cases.

### Deprecation plan for sigstore legacy fields

The `Mode` + regex-in-string shape predates the matcher layer and
conflates identity facts with match semantics. The plan:

1. **Now**: both forms coexist. `Mode`/`Issuer`/`Identity` are not
   yet marked `deprecated = true` in the proto to keep codegen
   warnings quiet while ampel and other consumers migrate.
2. **Next release**: add `[deprecated = true]` on `Mode` (and possibly
   `Issuer`/`Identity` as string-shaped regex carriers) once
   downstream policy schemas support the matcher form.
3. **Major version**: remove the deprecated fields.

In the meantime, prefer `IssuerMatch` / `IdentityMatch` for new
policies.

## Key identities

### Fields

| Field                       | Meaning                                                                                        |
| --------------------------- | ---------------------------------------------------------------------------------------------- |
| `Id`                        | Primary identifier (hash-derived hex id, or GPG primary fingerprint).                          |
| `Type`                      | Scheme string (e.g. `rsa`, `ecdsa-sha2-nistp256`, `ed25519`). Optional.                        |
| `Data`                      | PEM public key / OpenPGP armored block — used for normalization, never matched directly.      |
| `SigningFingerprint`        | GPG subkey fingerprint that produced the signature. Optional on policy; populated on signers. |
| `IdMatch`                   | `StringMatcher` applied to `Id` **OR** `SigningFingerprint` (disjunction preserved).          |
| `TypeMatch`                 | `StringMatcher` applied to `Type` — strict (always evaluated when set).                       |
| `SigningFingerprintMatch`   | `StringMatcher` applied to `SigningFingerprint` — strict when set.                            |

`Data` has no matcher — PEM blobs aren't pattern-matched. Pin via
`IdMatch` on the derived fingerprint.

### Normalization

When a policy has `Data` but no `Id`, the matcher clones it and calls
`Normalize()`, which parses the key material and fills in `Id` and
`Type`. The caller's policy object isn't mutated.

A policy with neither `Id` nor `IdMatch` nor `Data` can't match
anything.

### Matching rules

String comparisons on legacy `Id` and `SigningFingerprint` are
**case-insensitive** (hex fingerprints appear in both cases).
`StringMatcher` case-insensitivity is opt-in via the
`case_insensitive` flag.

For each signer:

1. **Id dimension** (required via `Id` or `IdMatch`):
   - Legacy `Id`: must equal `signer.Id` or `signer.SigningFingerprint`
     (case-insensitive).
   - `IdMatch`: applied against `signer.Id` or `signer.SigningFingerprint`;
     accepts if either passes (preserves the disjunction semantic).
2. **Type** (optional):
   - Legacy `Type`: narrows only when **both** sides are non-empty.
   - `TypeMatch`: strict — when set, the signer's type must satisfy
     it regardless of whether the signer has a type at all.
3. **Signing fingerprint pin** (optional):
   - Legacy `SigningFingerprint`: case-insensitive exact pin.
   - `SigningFingerprintMatch`: strict when set.

### GPG: the three policy shapes

For GPG keys a verified signer carries both a primary fingerprint (`Id`)
and — when the signature was made by a subkey — a subkey fingerprint
(`SigningFingerprint`). Three useful policy shapes:

| Intent                                        | `policy.Id`  | `policy.SigningFingerprint` | Matches                                                             |
| --------------------------------------------- | ------------ | --------------------------- | ------------------------------------------------------------------- |
| Trust this key, any subkey                    | primary FP   | *empty*                     | Any signature by this key.                                          |
| Trust only a specific subkey                  | subkey FP    | *empty*                     | Only signatures made by that subkey.                                |
| Strict: this primary + this exact subkey      | primary FP   | subkey FP                   | Primary matches AND the exact subkey was used.                      |

All three work identically with `IdMatch` and `SigningFingerprintMatch`
if you want pattern semantics (e.g. any fingerprint with a given
prefix).

## SPIFFE identities

### Fields

| Field                | Meaning                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------ |
| `Svid`               | Canonical SPIFFE ID URI (e.g. `spiffe://prod.example.org/workload/api`).                         |
| `TrustRoots`         | PEM-encoded SPIRE upstream CA root(s) used by the verifier. **Not consulted during matching** — it's trust material, not a match predicate. |
| `SvidMatch`          | `StringMatcher` applied to the full signer SVID URI.                                             |
| `TrustDomainMatch`   | `StringMatcher` applied to the trust-domain component **parsed from the signer's svid** at eval time. |
| `PathMatch`          | `StringMatcher` applied to the path component parsed from the signer's svid at eval time.       |

### Matching rules

`Svid`, `SvidMatch`, `TrustDomainMatch`, and `PathMatch` all AND
together. At least one must be set; a policy with none of them is
rejected (to avoid a policy that says "accept any SPIFFE signer
regardless of identity").

- `Svid` (if set): exact URI match against `signer.Svid`.
- `SvidMatch`: `StringMatcher` against the full URI.
- `TrustDomainMatch` / `PathMatch`: parse the signer's `Svid` via
  `spiffeid.FromString`; if it doesn't parse, these matchers fail
  closed for that signer.

### Examples

```go
// Pin the whole SVID URI.
policy := &Identity{Spiffe: &IdentitySpiffe{Svid: "spiffe://prod.example.org/workload/api"}}

// Accept any workload in a trust domain.
policy := &Identity{Spiffe: &IdentitySpiffe{
    TrustDomainMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "prod.example.org"}},
}}

// Trust domain + path glob.
policy := &Identity{Spiffe: &IdentitySpiffe{
    TrustDomainMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "prod.example.org"}},
    PathMatch:        &StringMatcher{Kind: &StringMatcher_Prefix{Prefix: "/workload/"}},
}}
```

## Outer matchers

The canonical place to express matcher constraints, usable against any
variant. Each entry targets a field path and carries a `StringMatcher`
(the only kind today; more coming).

```go
policy := &Identity{
    Sigstore: &IdentitySigstore{ /* variant selection */ },
    Matchers: []*Matcher{{
        Field: "sigstore.issuer",
        Kind: &Matcher_String_{String_: &StringMatcher{
            Kind: &StringMatcher_Exact{Exact: "https://accounts.google.com"},
        }},
    }, {
        Field: "principal",
        Kind: &Matcher_String_{String_: &StringMatcher{
            Kind: &StringMatcher_Regex{Regex: `sigstore::.*@example\.com$`},
        }},
    }},
}
```

**Semantics**: every outer matcher must pass, on the same signer that
passed the variant check. A matcher targeting a field that doesn't
apply to the signer's variant fails closed.

## Validation

`Identity.Validate()` checks:

- Exactly one variant is set.
- The selected variant's required fields are present (issuer+identity
  for sigstore legacy, id-or-data-or-id_match for key, at least one
  constraint for spiffe).
- SPIFFE `Svid` parses as a valid SPIFFE ID.
- All `StringMatcher` regex patterns compile (anchored, with optional
  `(?i)`).
- All `StringMatcher` glob patterns are well-formed per
  `path.Match`.
- Outer matchers have a non-empty `field`.

Catching these at policy-load time rather than match time lets ampel
surface authoring errors immediately.

## References

`IdentityRef` holds a single `Id` pointing at an identity defined
outside the policy (typically in a shared policy-set definition). It
has no matching logic here — the calling layer must resolve the
reference to a concrete variant before calling `MatchesIdentity`. An
unresolved `Ref` falls through `MatchesIdentity`'s dispatcher and
returns `false`.

Principal form: `ref:<id>`.

## Quick reference

| You want to match…                                           | Set on `*Identity`                                                                 |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Any signer from an OIDC issuer + subject (exact)             | `Sigstore{IssuerMatch: exact, IdentityMatch: exact}`                               |
| Sigstore with wildcard on subject                            | `Sigstore{IssuerMatch: exact, IdentityMatch: regex}`                               |
| Sigstore: accept any identity from one issuer                | `Sigstore{IssuerMatch: exact}`                                                     |
| A raw key by its id                                          | `Key{Id}`                                                                          |
| A key by a matcher (prefix, regex)                           | `Key{IdMatch: …}`                                                                  |
| A GPG primary, any subkey                                    | `Key{Id: <primary FP>}`                                                            |
| A specific GPG subkey                                        | `Key{Id: <subkey FP>}`                                                             |
| A GPG primary *and* a specific subkey                        | `Key{Id: <primary FP>, SigningFingerprint: <subkey FP>}`                           |
| A specific SPIFFE workload                                   | `Spiffe{Svid: "spiffe://td/path"}`                                                 |
| Any workload in a SPIFFE trust domain                        | `Spiffe{TrustDomainMatch: exact}`                                                  |
| A reference defined elsewhere                                | `Ref{Id}` (caller must resolve)                                                    |
| Cross-cutting: principal regex on any variant                | `Matchers: [{Field: "principal", String: {Regex: …}}]`                             |
| Variant pinned, additional constraint on a non-primary field | variant + `Matchers: [{Field: "sigstore.issuer", …}]` (etc.)                       |
