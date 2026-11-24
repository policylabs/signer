# Signing with SSH keys

The key backend signs and verifies DSSE envelopes with SSH keys, the
ones in `~/.ssh` that many developers already use to sign their git
commits.

SSH keys sign in the SSH signature format, the one
`ssh-keygen -Y sign` produces and git uses for commits. It is not a bare
cryptographic signature: the signature carries the signer's public key
and a [namespace](#namespaces), and other SSH tooling can read it.

## Keys

| | Format | Example |
| --- | --- | --- |
| Private key | The OpenSSH format `ssh-keygen` writes, encrypted or not | `~/.ssh/id_ed25519` |
| Public key | A line in the `authorized_keys` format | `~/.ssh/id_ed25519.pub` |

Ed25519, ECDSA (P-256, P-384 and P-521) and RSA keys are supported. RSA
keys sign with SHA-512 (`rsa-sha2-512`); RSA signatures made with SHA-1
are rejected.

The key parser recognizes both formats, so SSH keys go wherever other
keys go: `key.NewParser()`, the `--signing-key` flag and the `--key`
flag. Encrypted private keys take their passphrase the way other keys
do, through `key.WithPassphrase` or the variable named by
`--signing-key-passphrase-env`.

Only private keys in the OpenSSH format are handled as SSH keys. A
private key in another PEM format (PKCS #8, PKCS #1, SEC 1) is a plain
key and signs with a bare signature, even if SSH can use that file too.

SSH certificates are not supported: a signature made with a
certificate does not verify, and a certificate is refused as a key.

## Signing and verifying

```golang
package main

import (
	"fmt"
	"os"

	"github.com/policylabs/signer"
	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
)

func main() {
	parser := key.NewParser()

	// Read the private key. Add key.WithPassphrase if it is encrypted.
	privateData, err := os.ReadFile("id_ed25519")
	if err != nil {
		panic(err)
	}
	privateKey, err := parser.ParsePrivateKeyProvider(privateData)
	if err != nil {
		panic(err)
	}

	// Sign a message into a DSSE envelope
	envelope, err := signer.NewSigner().SignMessageToDSSE(
		[]byte("Hello world"),
		options.WithKey(privateKey),
		options.WithPayloadType("text/plain"),
	)
	if err != nil {
		panic(err)
	}

	// Verify the envelope with the public key
	publicData, err := os.ReadFile("id_ed25519.pub")
	if err != nil {
		panic(err)
	}
	publicKey, err := parser.ParsePublicKeyProvider(publicData)
	if err != nil {
		panic(err)
	}

	res, err := signer.NewVerifier().VerifyParsedDSSE(envelope, []key.PublicKeyProvider{publicKey})
	if err != nil {
		panic(err)
	}
	for _, k := range res.Keys {
		// SHA256:nzPv/9uwC5nI... signed under "file"
		fmt.Printf("%s signed under %q\n", k.ID(), k.SignatureNamespace)
	}
}
```

The signature in the envelope is an SSH signature of the DSSE
pre-authentication encoding (PAE) of the payload, in its binary form.

A signature only verifies against the kind of key that made it. An SSH
signature does not verify against the same key material loaded as a
plain key, and a bare signature does not verify against an SSH public
key.

## Keys held by an SSH agent

The private key does not have to be in a file. An SSH agent
(`ssh-agent`, or the one of a password manager) holds keys and signs
with them for other programs, so the key never leaves it. Signing asks
the agent, and the envelope that comes out is the same one a key read
from a file produces: verification and the identity of the signer do
not change.

Name the key by the path to its public key or by its fingerprint, as
`ssh-add -l` prints it:

```sh
mytool --signing-ssh-agent-key ~/.ssh/id_ed25519.pub
mytool --signing-ssh-agent-key SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU
```

The flag is repeatable and selects the key backend, as `--signing-key`
does. The agent is the one `SSH_AUTH_SOCK` points to.

In code, `key.SSHAgentKey` takes the path of the agent's socket and the
fingerprint of the key:

```golang
privateKey, err := key.SSHAgentKey(
	os.Getenv(key.SSHAgentSocketEnv),
	"SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU",
)
if err != nil {
	panic(err)
}
envelope, err := signer.NewSigner().SignMessageToDSSE(
	[]byte("Hello world"),
	options.WithKey(privateKey),
	options.WithPayloadType("text/plain"),
)
```

`key.SSHAgentKeys` lists the keys an agent holds.

What to expect:

- **A key has to be named.** There is no "use whatever the agent
  holds".
- **A missing key fails early.** The agent is asked for the key when
  the signing keys are loaded, and the error lists the keys it does
  hold.
- **Signing can wait for you.** If the agent asks to confirm each use
  of the key, signing blocks until you answer. There is no timeout.
- **The agent is contacted for each signature**, so a restarted agent
  keeps working as long as it listens on the same socket.
- **Unix sockets only.** Agents are not supported on Windows.
- **Hardware keys are untested.** Keys on a security token (the `sk-`
  types) should work, as the agent does the signing, but they have not
  been tried.

## Namespaces

Every SSH signature is made under a namespace, a label the signer
chooses to say what the signature is for. `ssh-keygen` takes it in its
`-n` flag; git signs commits under `git`, and people signing files by
hand use `file`. The namespace is part of what the key signs, so it
cannot be changed afterwards.

- **Signing** uses `file` unless told otherwise: with
  `key.WithSSHNamespace` when parsing the key, with the `Namespace`
  field of a `key.SSHPrivate`, or with the
  `--signing-key-ssh-namespace` flag, which also applies to the keys
  held by an SSH agent.
- **Verifying** accepts any namespace. The signature is verified under
  the namespace it declares, which is never compared to an expected
  value.
- **The namespace of a verified signature is reported** in the
  `SignatureNamespace` field of the keys in a `key.VerificationResult`.
  It is information: it is not part of the identity of the signer.

The namespace does not need to tell attestations apart from other
signed data. What an SSH key signs here is the DSSE PAE, which opens
with `DSSEv1` and the payload type, so a signature of an envelope
cannot be mistaken for a signature of anything else.

## Identity

A signer that used an SSH key is reported as a key identity. Its id is
the SHA-256 fingerprint of the key, written the way OpenSSH prints it,
and its type is the scheme of the underlying key:

```
$ ssh-keygen -lf id_ed25519.pub
256 SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU test@example.com (ED25519)
```

```
key::ed25519::SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU
```

A policy names an SSH key by its fingerprint or carries the key itself,
as the line of the `.pub` file:

```golang
// By fingerprint
&api.Identity{Key: &api.IdentityKey{
	Id: "SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU",
}}

// By key
&api.Identity{Key: &api.IdentityKey{
	Data: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICHIc/Qxgy2hOWMpP4qUdEZpc11c1KpEda8EVnXiRQJg",
}}
```

Two things to keep in mind:

- **The fingerprint is case-sensitive.** It is base64, not hex, so it
  is compared exactly, `SHA256:` prefix included. See
  [identity-matching.md](identity-matching.md#matching-rules).
- **The comment is not an identity.** The name or email address at the
  end of a `.pub` line is not part of the key and nothing vouches for
  it. It is kept (`SSHPublic.Comment`) but never used to identify a
  signer.

## Envelopes signed by other tools

Nothing in the envelope is specific to this library, so envelopes signed
with SSH keys elsewhere verify here too:

- **By hand.** Sign the PAE of the payload with
  `ssh-keygen -Y sign -n file -f key pae.bin` and store the resulting
  signature in the envelope. The armored form `ssh-keygen` writes is
  accepted as it is.
- **[gittuf](https://gittuf.dev).** gittuf signs its attestations with
  SSH keys under the `git` namespace.
