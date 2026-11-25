# Carabiner Signer Library

Easy digital signing library with support for [sigstore](https://www.sigstore.dev/)
bundles, [DSSE](https://github.com/secure-systems-lab/dsse) envelopes and
support for easy signing with key pairs. The library handles ECDSA, RSA,
ed25519, GPG/OpenPGP and SSH keys.

## Signing and Creating Sigstore Bundles

Signing data with sigstore and bundling it is super easy. The library takes
care of producing the signing key pair and fulcio certificate for you. Once
the signing operation is done, the Carabiner signer registers it in the
Rekor transparency log.

### Sigstore Example

```golang
package main

import (
	"fmt"
	"os"

	"github.com/policylabs/signer"
)

func main() {
    // Create a signer:
    s := signer.NewSigner()

	// Sign a string as a sigstore bundle.
    //
    // This call triggers the sigstore flow if ambient
    // credentials are not available.
	bundle, err := s.SignMessage([]byte("My signed data"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Output the bundle to STDOUT
	if err := s.WriteBundle(bundle, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
```

### Ambient Credentials

When no identity token is set, the signer looks for one in the ambient
credentials of the environment: GitHub Actions, GitLab CI and Google Cloud
(service account keys or the metadata server) are supported out of the box,
falling back to an interactive OIDC flow. On Google Cloud the signer can also
impersonate a dedicated signing service account instead of signing as the
workload's own identity, see [docs/gcp-identity.md](docs/gcp-identity.md).

The providers are tried one after the other, always in the same order, and
the first one with a token wins:

| Order | Name      | Looks for |
| ----- | --------- | --------- |
| 1     | `actions` | the ID token of a GitHub Actions job |
| 2     | `gitlab`  | the ID token of a GitLab CI job |
| 3     | `gcp`     | a Google Cloud service account key or the metadata server |

Providers added with `sts.RegisterProvider` come after these, in the order
they were registered. A provider whose environment is there but broken fails
the signing: the signer does not move on to sign with another identity.

More than one provider can have credentials, a GitHub Actions job on a
self-hosted runner in Google Cloud for example. To sign only with the
identity you expect, name the providers to use. No other provider is
consulted, and they are tried in the order you give:

```golang
s := signer.NewSigner()
s.Options.STSProviders = []string{"actions"}
```

Command line tools built on the options sets take the same list in
`--sigstore-sts-providers=actions`.

## Dead Simple Signing Envelope (DSSE)

Initial support for DSSE has been implemented since v0.2.0. The library can sign
and verify envelopes signed with arbitrary keys.

Envelopes signed keyless with a Sigstore certificate — the pre-bundle
flow of cosign and the slsa-github-generator — can be verified against
the Rekor transparency log. The lookup is off by default because it goes
over the network; see [docs/keyless-dsse.md](docs/keyless-dsse.md).

### DSSE Example

```golang
package main

import (
	"fmt"
	"os"

	"github.com/policylabs/signer"
	"github.com/policylabs/signer/options"
	"github.com/policylabs/signer/key"
)

func main() {
	// Start with a message
	myMessage := []byte("Hello world")

	// Generate a Key Pair to sign
	privateKey, err := key.NewGenerator().GenerateKeyPair()

	// Create a new signer
	s := signer.NewSigner()

	// Wrap the message in a new envelope and sign it with the key:
	envelope, err := s.SignMessageToDSSE(
		myMessage,
		options.WithKey(privateKey),
		options.WithPayloadType("text/plain"),
	)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// DSEE Envelope Verification
	v := signer.NewVerifier()
	res, err := v.VerifyParsedDSSE(envelope, []key.PublicKeyProvider{
		privateKey, // Private keys are public key providers
	})
	if err != nil {
		fmt.Printf("Error verifying: %v\n", err)
		os.Exit(1)
	}

	if res.Verified {
		fmt.Println("DSSE envelope verified!")
	} else {
		fmt.Println("DSSE envelope failed verification.")
	}
}
```

## Key Pair Handling

The `key` package will handle all aspects with keys. The package provides
a key Generator and a key Parser. It also defines the public and private
key abstractions used throughout the package.

Most verifying operations take a `key.PublicKeyProvider`. This interface
masks any object that can provide a public key object for use in cryptographic
operations. The `key.Public` object is the most basic `PublicKeyProvider` but
we may implement more complex providers such as cache interfaces and key
management systems clients. For GPG/OpenPGP keys, the `key.GPGPublic` provider
preserves full key metadata (key IDs, subkeys, and fingerprints) required for
PGP signature verification. For SSH keys, the `key.SSHPublic` provider verifies
signatures in the SSH signature format.

Signing operations take a `key.PrivateKeyProvider`. This abstraction handles
key pairs. You can generate keys using the `key.Generator` object. The library
supports ECDSA, RSA, ed25519, GPG/OpenPGP and SSH key formats.

SSH keys sign and verify in the SSH signature format, the one `ssh-keygen -Y
sign` produces. The private key can be read from a file or stay in an SSH
agent. See [docs/ssh-keys.md](docs/ssh-keys.md).

## Status

The library has simple signing functions to sign and verify attestations and
arbitrary data into sigstore bundles. The current functionality is considered
stable but the library is still under active feature development.

Full [DSSE](https://github.com/secure-systems-lab/dsse) signature verification
is now implemented in the signer module. The main verifier exposes functions to
sign and verify DSSE envelopes and their payloads.

The library also includes a `key` package that handles public key parsing and
signature verification. GPG/OpenPGP key blocks and SSH keys are supported for
both parsing and DSSE envelope verification.

Key identity matching (via `MatchesKeyIdentity`) compares identities using
their key ID and type. Identities defined with only raw key material (including
GPG key blocks and SSH public keys) are automatically normalized — the key data is parsed to
extract the ID and type before matching.

### Upcoming Features

Some of the features we are working on that will soon show up in this module
include:

- ~Support for signing with supplied plain key pairs.~
- ~DSSE (non bundle) output~
- More keypair providers
- Certificate/identity cache ([gitsign](https://github.com/sigstore/gitsign)
credential cache style).

## Code Examples

We have examples that demonstrate features of the library:

- [Sign and verify an in-toto attestation to a Sigstore bundle](_examples/attestation)
- [Sign and verify a random data message to a Sigstore bundle](_examples/message)
- [Sign a random message in a DSSE envelope](_examples/dsse-sign)
- [Verify data packed in a DSSE envelope](_examples/dsse-verify)

## Copyright and License

This library is made with <3 and Copyright by Carabiner Systems, Inc and released
under the Apache-2.0 license. Feel free to send patches and open issues or just
tell us if you are using it. We love feedback on all our projects.
