# Command-line flags

This package ships ready-made `command.OptionsSet` implementations so a
CLI tool built on `github.com/carabiner-dev/command` can wire signer
and verifier configuration onto a cobra command without re-deriving
the flag surface.

All sets live in the `options` package. Each set conforms to
`command.OptionsSet` (`Config`, `AddFlags`, `Validate`) and exposes a
`Build*` method that materializes the resolved configuration into the
runtime types in the top-level `signer` package.

## Two layers

**Per-backend sets** carry the flags for one signing path:

| Set | Sign / Verify | Backend |
| --- | --- | --- |
| `KeysSign`           | sign   | raw private keys → bare DSSE     |
| `KeysVerify`         | verify | raw public keys → DSSE signature |
| `SigstoreSignSet`    | sign   | Fulcio + Rekor + sigstore bundle |
| `SigstoreVerifySet`  | verify | sigstore bundle                  |
| `SpiffeSignSet`      | sign   | X.509-SVID + sigstore bundle     |
| `SpiffeVerifySet`    | verify | X.509-SVID-signed bundle         |

**Bundled sets** compose every per-backend set behind one cobra command:

| Set | Selects vs. composes | Notes |
| --- | --- | --- |
| `SignerSet`   | selects via `--signing-backend=key\|sigstore\|spiffe` | exactly one backend signs at a time |
| `VerifierSet` | composes Active children                       | a bundle may have been signed any way; the verifier wants trust material for every accepted path |

`Active()` — only the verify side has it — returns true when the user
has supplied enough configuration that the child should run. Inactive
children are skipped during `Validate` and `ApplyToVerifier` so a
sigstore-only verify call doesn't error on missing SPIFFE flags.

## Per-backend flag reference

Each set takes an optional flag-prefix at construction so two sets of
the same backend can share a cobra command without colliding (only
relevant when you wire children directly; the bundled sets pre-pick
prefixes).

### `KeysSign` — `options.DefaultKeysSign()`

Used standalone (rare) or via `SignerSet` when `--signing-backend=key`.

| Flag | Short | Repeatable | Description |
| --- | --- | --- | --- |
| `--signing-key`                | `-K` | yes | path to a private signing key file (PEM PKCS#8/PKCS#1/SEC1, OpenPGP or OpenSSH) |
| `--signing-key-passphrase-env` |      | no  | envvar name to read the signing-key passphrase from (default: `SIGNING_KEY_PASSPHRASE`) |
| `--signing-ssh-namespace`      |      | no  | namespace of the signatures made with SSH signing keys, read from a file or held by an SSH agent (default: `file`) |
| `--signing-ssh-agent-key`      |      | yes | signing key held by the SSH agent at `SSH_AUTH_SOCK`: path to its public key file or its `SHA256:` fingerprint |

`BuildSigner()` parses each path and produces an `*options.Signer`
with `Backend = BackendKey` and `Keys` populated.

Private keys in the OpenSSH format sign in the SSH signature format, and
`--signing-ssh-agent-key` signs with a key held by an SSH agent without
reading the private key; see [ssh-keys.md](ssh-keys.md).

### `KeysVerify` — `options.DefaultKeysVerify()`

Embeds the upstream `github.com/carabiner-dev/command/keys.Options`,
so the flag matches every other carabiner-dev tool.

| Flag | Short | Repeatable | Description |
| --- | --- | --- | --- |
| `--key` | `-k` | yes | path to a public key file |

`BuildVerifier()` parses each path and writes the providers onto
`Verifier.Verification.PubKeys`. `VerifyParsedDSSE` consults that
slice as a fallback when the per-call `keys` argument is empty, so a
CLI can wire `--key` once and call `VerifyDSSE` without re-passing.

`KeysVerify.Active()` is true when at least one `--key` is supplied.

### `SigstoreSignSet` — `options.DefaultSigstoreSignSet("sigstore")`

The default constructor namespaces every flag under `sigstore-`. Pass
`""` for bare names.

| Flag | Description |
| --- | --- |
| `--sigstore-roots`              | path to a custom `sigstore-roots.json` (overrides the embedded defaults) |
| `--sigstore-instance`           | instance ID from the roots file (default: first in file order) |
| `--sigstore-oidc-client-id`     | OIDC client ID for the token exchange |
| `--sigstore-oidc-redirect-url`  | OIDC redirect URL for the interactive flow |
| `--sigstore-oidc-client-secret` | OIDC client secret (for confidential clients) |
| `--sigstore-oidc-token-file`    | path to a pre-issued OIDC ID token (CI/non-interactive) |
| `--sigstore-rekor-append`       | record the signature in the Rekor transparency log |
| `--sigstore-timestamp`          | attach a TSA-signed timestamp |
| `--sigstore-disable-sts`        | skip the STS token exchange |
| `--sigstore-sts-providers`      | STS providers to get ambient credentials from, in the order to try them (`actions`, `gitlab`, `gcp`; default: all, in that order). No other provider is consulted. Cannot be combined with `--sigstore-disable-sts` |

The OIDC flags are hidden by default (the embedded defaults work for
the public sigstore instance); flip `HideOIDCOptions` to surface them.

`BuildSigner()` resolves the chosen instance from the roots file and
returns an `*options.Signer` ready for `Backend = BackendSigstore`.

### `SigstoreVerifySet` — `options.DefaultSigstoreVerifySet("sigstore")`

| Flag | Description |
| --- | --- |
| `--sigstore-roots` | path to a custom `sigstore-roots.json` (shared with the sign-side `SigstoreCommon` when both are wired against the same `*SigstoreCommon`) |

The per-instance verification policy (require CT log / Rekor /
timestamp) is read from the roots file at verification time and is
not exposed as a CLI flag — it's per-instance configuration, not a
user-tunable knob.

`SigstoreVerifySet.Active()` is always true when the set is
constructed: the embedded `sigstore.DefaultRoots` make sigstore the
always-on baseline verifier.

### `SpiffeSignSet` — `options.DefaultSpiffeSignSet("spiffe")`

| Flag | Description | Env-var fallback |
| --- | --- | --- |
| `--spiffe-trust-domain` | expected SPIFFE trust domain (e.g. `prod.example.org`) |  |
| `--spiffe-socket`       | Workload API socket (`unix:///run/spire/sockets/api.sock`) | `SPIFFE_ENDPOINT_SOCKET` |
| `--spiffe-timestamp`    | attach an RFC 3161 TSA-signed timestamp to the bundle (default `true`); suppressed and replaced by `--signing-timestamp` when bundled via `SignerSet`. See [SPIFFE timestamping](spiffe-timestamping.md) for the full flow. |  |

`BuildSigner()` returns an `*options.Signer` with
`Backend = BackendSpiffe`. The SPIFFE backend can't lazy-build its
credentials from `Options` alone, so callers must additionally call
`BuildCredentialProvider()` and assign the result to
`signer.Signer.Credentials` — or, simpler, use
`signer.NewSignerFromSet` (below) which wires both in one call.

### `SpiffeVerifySet` — `options.DefaultSpiffeVerifySet("spiffe")`

| Flag | Description | Env-var fallback |
| --- | --- | --- |
| `--spiffe-trust-domain` | expected SPIFFE trust domain |  |
| `--spiffe-trust-bundle` | path to a PEM-encoded SPIRE upstream trust bundle | `SPIFFE_TRUST_BUNDLE` |
| `--spiffe-path`         | exact SVID path the leaf must carry (mutually exclusive with `--spiffe-path-regex`) |  |
| `--spiffe-path-regex`   | regex the SVID path must match (mutually exclusive with `--spiffe-path`) |  |

`SpiffeVerifySet.Active()` is true when any trust-bundle source is
configured: the flag, the env var, or programmatic `TrustBundlePEM`.

## Bundled sets

### `SignerSet` — `options.DefaultSignerSet()`

Registers `--signing-backend` plus every per-backend sign set's flags
so the full CLI surface shows up in `--help`. `Validate` and
`BuildSigner` dispatch on the resolved backend; non-selected children
contribute their flags to help text but are otherwise inert.

| Flag | Description | Default |
| --- | --- | --- |
| `--signing-backend`   | signing backend (`key`, `sigstore`, `spiffe`) | auto-detect (see below) |
| `--signing-timestamp` | attach an RFC 3161 TSA-signed timestamp to the bundle (applies to sigstore and SPIFFE; ignored by the key backend). When bundled here, this replaces the per-backend `--sigstore-timestamp` and `--spiffe-timestamp` flags. See [SPIFFE timestamping](spiffe-timestamping.md). | `true` |

**Auto-detection.** When `--signing-backend` is unset, the resolved
backend is inferred from the populated child *flags*:

- `--signing-key` or `--signing-ssh-agent-key` provided → `key`
- `--spiffe-socket` provided → `spiffe`
- otherwise → `sigstore`

Only flags trigger auto-detect. Env-var fallbacks (notably
`SPIFFE_ENDPOINT_SOCKET`, which `--spiffe-socket` falls back to once
SPIFFE is selected) intentionally do **not** trigger it: a user
running on a host that happens to have SPIRE installed shouldn't
silently produce SPIFFE-signed bundles. Set `--signing-backend=spiffe`
explicitly to opt into env-driven SPIFFE configuration.

If both a signing key and `--spiffe-socket` are set without an
explicit `--signing-backend`, resolution fails — pass
`--signing-backend` to disambiguate.

### `VerifierSet` — `options.DefaultVerifierSet()`

Has no own flags — it just registers every per-backend verify set's
flags. `Validate` and `ApplyToVerifier` consult only the children
that are `Active()`. A user verifying a sigstore-only bundle leaves
`--key` and `--spiffe-trust-bundle` unset and gets no errors.

## Example

A minimal cobra command that signs and verifies through the bundled
sets — works against any backend:

```go
package main

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"

    "github.com/policylabs/signer"
    "github.com/policylabs/signer/options"
)

func main() {
    signSet := options.DefaultSignerSet()      // backend auto-detected from flags; falls back to sigstore
    verifySet := options.DefaultVerifierSet()

    cmd := &cobra.Command{
        Use: "mytool",
        RunE: func(cmd *cobra.Command, args []string) error {
            if err := signSet.Validate(); err != nil {
                return err
            }
            if err := verifySet.Validate(); err != nil {
                return err
            }

            // Sign.
            s, err := signer.NewSignerFromSet(signSet)
            if err != nil {
                return err
            }
            defer s.Close() // releases the SPIFFE Workload API stream when applicable

            bundle, err := s.SignStatementBundle([]byte(`{"_type":"..."}`))
            if err != nil {
                return err
            }

            // Verify.
            v, err := signer.NewVerifierFromSet(verifySet)
            if err != nil {
                return err
            }
            if _, err := v.VerifyParsedBundle(bundle); err != nil {
                return err
            }
            fmt.Println("verified")
            return nil
        },
    }

    signSet.AddFlags(cmd)
    verifySet.AddFlags(cmd)

    if err := cmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

Run with any of:

```sh
# sigstore — no flags at all (auto-detect → sigstore fallback)
mytool

# key — auto-detected from --signing-key
mytool --signing-key=priv.pem --key=pub.pem

# key — held by the SSH agent, auto-detected from --signing-ssh-agent-key
mytool --signing-ssh-agent-key ~/.ssh/id_ed25519.pub --key ~/.ssh/id_ed25519.pub

# spiffe — auto-detected from --spiffe-socket
mytool --spiffe-socket=unix:///run/spire/sockets/api.sock \
       --spiffe-trust-bundle=/etc/spire/bundle.pem

# explicit override (useful when env vars carry the configuration)
export SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/api.sock
export SPIFFE_TRUST_BUNDLE=/etc/spire/bundle.pem
mytool --signing-backend=spiffe
```

A complete working example lives at
[`_examples/spiffe/main.go`](../_examples/spiffe/main.go).

## Bypassing the bundled sets

If `--signing-backend` is overkill (e.g. a tool that only ever signs through
SPIFFE), wire the per-backend set directly:

```go
signSet := options.DefaultSpiffeSignSet("spiffe")
signSet.AddFlags(cmd)

// later:
opts, _   := signSet.BuildSigner()
creds, _  := signSet.BuildCredentialProvider()
s := signer.NewSigner()
s.Options = *opts
s.Credentials = creds
defer s.Close()
```

The two-call pattern (`BuildSigner` + `BuildCredentialProvider`)
exists because `options/` cannot import the runtime `signer` /
`bundle` packages without an import cycle. `signer.NewSignerFromSet`
collapses it back to one call when the bundled `SignerSet` is used.
