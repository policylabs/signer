# Principals and specs

This document describes the two canonical string forms of an `Identity`:

- **Principal** — a pure identifier naming **who** signed.
- **Spec** — a richer string that also carries **how** to match.

Specs are most useful for CLI flags (`--identity=…`) and config files
where you need to express both the signer and the matching semantics in
a single value. Principals are useful for logs, audit records, error
messages, and any place where you want a stable name without policy
semantics leaking in.

For the matcher layer itself (per-variant `*_match` fields and the outer
`Matchers` slice), see [identity-matching.md](identity-matching.md).

All types live in the `api/v1` package
(`proto/carabiner/signer/v1/identity.proto` and `matcher.proto`).

## Principal — the identity, nothing else

The principal is a **pure identifier**. It names the signer; it does
not say how to match against the signer. Two identities with the same
principal name the same security-domain entity, regardless of how a
policy chose to verify them.

| Variant    | Principal format                                  | Example                                       |
| ---------- | ------------------------------------------------- | --------------------------------------------- |
| `Sigstore` | `sigstore::<issuer>::<identity>`                  | `sigstore::https://accounts.google.com::user@example.com` |
| `Key`      | `key::<type>::<id>`                               | `key::rsa::1234abcdef…`                       |
| `Ref`      | `ref:<id>`                                        | `ref:shared-prod-signer`                      |
| `Spiffe`   | `<svid>` — the SPIFFE URI itself                  | `spiffe://prod.example.org/workload/api`      |

```go
id, err := api.NewIdentityFromPrincipal("sigstore::https://accounts.google.com::user@example.com")
fmt.Println(id.Principal()) // → same string, byte-for-byte
```

### Round-trip guarantee

`NewIdentityFromPrincipal(p).Principal() == p` for every well-formed
principal string. The parser is **strict**: any parenthetical
annotation (legacy `sigstore(regexp)::…` or rich `sigstore(issuerMatch=…)::…`)
is rejected with a clear error pointing the caller at
`NewIdentityFromSpec`.

```go
_, err := api.NewIdentityFromPrincipal("sigstore(regexp)::https://.*::.*@example.com")
// err: principal does not accept matcher annotations; use NewIdentityFromSpec for "..."
```

### Per-variant notes

- **Sigstore.** Two `::` separators, three slots: prefix, issuer,
  identity. Both issuer and identity are required when constructing
  via the principal form. The principal does not carry
  `Mode` — that's matcher state, expressed in `Spec`.

- **Key.** Two `::` separators, three slots: prefix, type, id. The
  parsed identity has only `Id` and `Type` populated; `Data` is *not*
  encoded in a principal. `IdentityKey.Normalize()` is **not** called
  automatically — if a caller wants `Id`/`Type` derived from `Data`,
  they invoke it explicitly. For SSH keys the id is the fingerprint of
  the key (`key::ed25519::SHA256:nzPv/9uw…`); its case is significant
  and is kept as written.

- **Ref.** A single colon (`ref:<id>`), not the double `::`. References
  are placeholders — the calling layer must resolve them to a concrete
  variant before matching. An unresolved `Ref` matches nothing.

- **Spiffe.** No prefix; the SPIFFE URI itself is the principal.
  Round-trips through `NewIdentityFromPrincipal` because `spiffe://`
  is dispatch-able by prefix. The trust roots
  (`IdentitySpiffe.TrustRoots`) are verifier configuration, not part of
  the signer's identity, so they are never encoded.

## Spec — principal + matcher semantics

A spec is the canonical string form when matcher fields are populated.
It extends the principal grammar with a parenthetical annotation block
that names which fields are matchers and what kind each matcher is:

```
<type>(<field>=<kind>[/i][, …])::<slot>::<slot>
```

When no matchers are set, **`Spec()` returns the same string as
`Principal()`**. The annotations only appear when needed.

```go
fmt.Println(id.Spec())  // pure form: sigstore::issuer::identity
                        // rich form: sigstore(identityMatch=regex)::issuer::pattern
```

`NewIdentityFromSpec` is the **lenient** parser. It accepts:

1. Every form `NewIdentityFromPrincipal` accepts.
2. The legacy single-token form `sigstore(regexp)::issuer::identity`
   (sets `Mode=regexp` on the resulting `IdentitySigstore`).
3. The rich form with field-level annotations.

### The annotation grammar

Inside the parens, comma-separated entries name a field and bind it to
a `StringMatcher` kind. The matcher's value comes from the slot at the
same position as the legacy field that the annotation displaces.

| Token                  | Meaning                                        |
| ---------------------- | ---------------------------------------------- |
| `<field>=<kind>`       | This field becomes a `StringMatcher` of kind.  |
| `<field>=<kind>/i`     | …with `case_insensitive = true`.               |
| `regexp`               | Legacy single-token marker (sigstore only).    |

`<kind>` is one of `exact`, `regex`, `prefix`, `glob` — the four
`StringMatcher` kinds.

### Slot semantics

Each variant has a fixed positional slot layout. Every annotation
binds to a specific slot; unannotated slots fall through to the
legacy field at that position.

| Variant    | Slot 1                | Slot 2          |
| ---------- | --------------------- | --------------- |
| `sigstore` | issuer / `issuerMatch`  | identity / `identityMatch` |
| `key`      | type / `typeMatch`      | id / `idMatch`             |
| `spiffe`   | trust-domain / `trustDomainMatch` (or whole URI / `svidMatch` in single-slot form) | path / `pathMatch` |

So `sigstore(issuerMatch=regex)::https://.*::user@example.com` produces:

```go
&Identity{Sigstore: &IdentitySigstore{
    IssuerMatch: &StringMatcher{Kind: &StringMatcher_Regex{Regex: "https://.*"}},
    Identity:    "user@example.com",   // unannotated → legacy field
}}
```

Mixing annotated and unannotated slots is supported and combines with
AND semantics at match time (see identity-matching.md).

### Per-type examples

#### Sigstore

```text
# pure
sigstore::https://accounts.google.com::user@example.com

# legacy (regexp marker)
sigstore(regexp)::https://.*::.*@example\.com

# single matcher, other slot is legacy
sigstore(identityMatch=regex)::https://accounts.google.com::.*@example\.com

# both slots as matchers
sigstore(issuerMatch=exact,identityMatch=regex)::https://accounts.google.com::.*@example\.com

# case-insensitive
sigstore(identityMatch=regex/i)::https://accounts.google.com::USER@example\.com
```

#### Key

```text
# pure
key::rsa::1234abcdef

# matcher on id (e.g. fingerprint prefix)
key(idMatch=prefix)::rsa::1234

# matcher on both
key(typeMatch=exact,idMatch=glob)::rsa::ab*
```

The `signing_fingerprint` field and `SigningFingerprintMatch` matcher
are intentionally **not** encoded in `Spec` — they are rarely set on
CLI-authored policies. Use the proto directly when you need them.

#### SPIFFE

SPIFFE has two annotated forms because the bare principal is already a
URI (one slot, not two):

```text
# pure — no annotations
spiffe://prod.example.org/workload/api

# single-slot: match the whole URI as a regex
spiffe(svidMatch=regex)::^spiffe://prod\..*/workload$

# two-slot: match the components separately
spiffe(trustDomainMatch=exact,pathMatch=glob)::prod.example.org::/api/*
```

The single- and two-slot forms are mutually exclusive; mixing
`svidMatch` with `trustDomainMatch`/`pathMatch` in a single spec is
not supported (use the proto directly).

#### Ref

References carry no matcher semantics; their `Spec` and `Principal`
are identical: `ref:<id>`.

### Round-trip guarantee

`NewIdentityFromSpec(s).Spec() == s` for every well-formed spec the
emitter would produce. This includes:

- pure forms (where `Spec` collapses to `Principal`),
- legacy `sigstore(regexp)::…`,
- the rich form with any combination of annotations and slot fallbacks.

Forms not produced by `Spec` (e.g. mixed `svidMatch`+`trustDomainMatch`,
or `signingFingerprintMatch`) are not guaranteed to round-trip — the
proto is always the source of truth.

### What `Spec` does NOT encode

Spec is scoped to the dominant CLI use case: per-variant principal-slot
matchers. It does **not** encode:

| Field / feature                          | Where it lives instead                            |
| ---------------------------------------- | ------------------------------------------------- |
| `Identity.Matchers` (outer slice)        | Use the proto / config file directly.             |
| `IdentityKey.SigningFingerprint(_match)` | Set on the proto; rarely useful in a CLI flag.    |
| `IdentitySpiffe.TrustRoots`              | Verifier configuration, not signer identity.      |
| Mixed sigstore legacy `Mode` + matchers  | Use the proto (Spec emits one form or the other). |

If you need full fidelity, serialize the proto — Spec is a string
ergonomic, not a wire format.

## Slug — compatibility alias

`Slug()` and `NewIdentityFromSlug` are deprecated aliases for `Spec`
and `NewIdentityFromSpec`, retained because earlier callers depended
on the rich form (`sigstore(regexp)::…`) being emitted from a
"canonical name" function. New code should use `Spec` (rich) or
`Principal` (pure) based on intent.

## Choosing between Principal and Spec

| Use case                                                | Use      |
| ------------------------------------------------------- | -------- |
| Logs, audit, error messages, telemetry IDs              | `Principal` |
| Comparing two signers for identity equality             | `Principal` |
| Storing a policy in a config file as a one-line string  | `Spec`      |
| `--identity=…` CLI flags                                | `Spec`      |
| Round-tripping a verified identity back to a fixture    | `Principal` (no matcher state to encode) |
| Authoring a regex-based sigstore policy                 | `Spec` (or the proto)                    |

## Quick reference

```text
Principal      Spec
─────────      ────
sigstore::…    sigstore::…                         (no matchers)
sigstore::…    sigstore(regexp)::…                 (legacy Mode=regexp)
sigstore::…    sigstore(identityMatch=regex)::…    (rich, one matcher)
key::…         key(idMatch=glob)::…                (rich)
ref:id         ref:id                              (no matchers possible)
spiffe://…     spiffe://…                          (no matchers)
spiffe://…     spiffe(svidMatch=regex)::pattern    (rich, single-slot)
spiffe://…     spiffe(trustDomainMatch=exact,pathMatch=glob)::td::path  (rich, two-slot)
```

```go
// Constructors
api.NewIdentityFromPrincipal(s)  // strict — pure forms only
api.NewIdentityFromSpec(s)       // lenient — pure + legacy + rich
api.NewIdentityFromSlug(s)       // deprecated alias for NewIdentityFromSpec

// Emitters
id.Principal()  // pure identifier
id.Spec()       // rich form (== Principal when no matchers set)
id.Slug()       // deprecated alias for Spec
```
