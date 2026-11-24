// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/policylabs/signer/internal/sshsig"
)

// sshAgentSocketPath returns a path for an agent socket. Socket paths
// are limited to about a hundred bytes, which t.TempDir can exceed.
func sshAgentSocketPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("SSH agents are not supported on Windows")
	}
	dir, err := os.MkdirTemp("", "agent") //nolint:usetesting // t.TempDir is too long for a socket
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) }) //nolint:errcheck,gosec // best effort
	return filepath.Join(dir, "s")
}

// serveSSHAgent serves a on a socket and returns its path.
func serveSSHAgent(t *testing.T, a agent.Agent) string {
	t.Helper()
	socket := sshAgentSocketPath(t)

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck,gosec // best effort

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()        //nolint:errcheck // best effort
				agent.ServeAgent(a, conn) //nolint:errcheck,gosec // ends when the client hangs up
			}()
		}
	}()
	return socket
}

// sshAgentWithFixtures serves an in-memory agent that holds the given
// private key fixtures.
func sshAgentWithFixtures(t *testing.T, files ...string) string {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, file := range files {
		raw, err := ssh.ParseRawPrivateKey(readTestdata(t, file))
		require.NoError(t, err)
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: raw, Comment: file}))
	}
	return serveSSHAgent(t, keyring)
}

// sshFixtureFingerprint returns the fingerprint of a public key fixture.
func sshFixtureFingerprint(t *testing.T, file string) string {
	t.Helper()
	pub, err := ParseSSHPublicKey(readTestdata(t, file))
	require.NoError(t, err)
	return pub.Fingerprint()
}

func TestSSHAgentKeys(t *testing.T) {
	t.Parallel()

	t.Run("lists-keys", func(t *testing.T) {
		t.Parallel()
		socket := sshAgentWithFixtures(t, "ssh-ed25519", "ssh-ecdsa", "ssh-rsa")

		keys, err := SSHAgentKeys(socket)
		require.NoError(t, err)

		got := map[string]string{}
		for _, k := range keys {
			got[k.Fingerprint()] = k.Comment()
		}
		require.Equal(t, map[string]string{
			sshFixtureFingerprint(t, "ssh-ed25519.pub"): "ssh-ed25519",
			sshFixtureFingerprint(t, "ssh-ecdsa.pub"):   "ssh-ecdsa",
			sshFixtureFingerprint(t, "ssh-rsa.pub"):     "ssh-rsa",
		}, got)
	})

	t.Run("empty-agent", func(t *testing.T) {
		t.Parallel()
		keys, err := SSHAgentKeys(serveSSHAgent(t, agent.NewKeyring()))
		require.NoError(t, err)
		require.Empty(t, keys)
	})

	t.Run("no-socket", func(t *testing.T) {
		t.Parallel()
		_, err := SSHAgentKeys("")
		require.ErrorContains(t, err, "no SSH agent socket")
	})

	t.Run("nothing-listening", func(t *testing.T) {
		t.Parallel()
		_, err := SSHAgentKeys(sshAgentSocketPath(t))
		require.ErrorContains(t, err, "connecting to the SSH agent")
	})
}

func TestSSHAgentKey(t *testing.T) {
	t.Parallel()
	socket := sshAgentWithFixtures(t, "ssh-ed25519", "ssh-ecdsa", "ssh-rsa")
	message := []byte("signed by an agent")

	for _, tc := range []struct {
		file   string
		format string
	}{
		{"ssh-ed25519", ssh.KeyAlgoED25519},
		{"ssh-ecdsa", ssh.KeyAlgoECDSA256},
		{"ssh-rsa", ssh.KeyAlgoRSASHA512},
	} {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			pub, err := ParseSSHPublicKey(readTestdata(t, tc.file+".pub"))
			require.NoError(t, err)

			k, err := SSHAgentKey(socket, pub.Fingerprint())
			require.NoError(t, err)
			require.Equal(t, pub.Fingerprint(), k.Fingerprint())

			// The public half is all there, the private one is not.
			fromAgent, err := k.PublicKey()
			require.NoError(t, err)
			fromFile, err := pub.PublicKey()
			require.NoError(t, err)
			require.Equal(t, fromFile.ID(), fromAgent.ID())
			require.Equal(t, fromFile.Scheme, fromAgent.Scheme)
			require.Equal(t, fromFile.Data, fromAgent.Data)

			_, err = k.PrivateKey()
			require.Error(t, err)
			require.Empty(t, k.GetData())

			// It signs like a key read from a file does.
			k.Namespace = "custom@example.com"
			sig, err := NewSigner().SignMessage(k, message)
			require.NoError(t, err)

			ok, err := pub.VerifyMessage(message, sig)
			require.NoError(t, err)
			require.True(t, ok)

			ok, err = pub.VerifyMessage([]byte("another message"), sig)
			require.NoError(t, err)
			require.False(t, ok)

			ns, err := pub.SignatureNamespace(sig)
			require.NoError(t, err)
			require.Equal(t, "custom@example.com", ns)

			// RSA keys sign with SHA-2.
			raw, ok := k.signer.(ssh.AlgorithmSigner)
			require.True(t, ok)
			bare, err := raw.SignWithAlgorithm(nil, message, tc.format)
			require.NoError(t, err)
			require.Equal(t, tc.format, bare.Format)
		})
	}

	t.Run("default-namespace", func(t *testing.T) {
		t.Parallel()
		pub, err := ParseSSHPublicKey(readTestdata(t, "ssh-ed25519.pub"))
		require.NoError(t, err)
		k, err := SSHAgentKey(socket, sshEd25519Fingerprint)
		require.NoError(t, err)

		sig, err := k.SignMessage(message)
		require.NoError(t, err)
		ns, err := pub.SignatureNamespace(sig)
		require.NoError(t, err)
		require.Equal(t, DefaultSSHNamespace, ns)
	})

	t.Run("key-not-held", func(t *testing.T) {
		t.Parallel()
		other := sshAgentWithFixtures(t, "ssh-ecdsa")
		_, err := SSHAgentKey(other, sshEd25519Fingerprint)
		require.ErrorIs(t, err, ErrSSHAgentKeyNotFound)
		require.ErrorContains(t, err, sshEd25519Fingerprint)
		// The error tells which keys the agent does hold.
		require.ErrorContains(t, err, sshFixtureFingerprint(t, "ssh-ecdsa.pub"))
	})

	t.Run("empty-agent", func(t *testing.T) {
		t.Parallel()
		_, err := SSHAgentKey(serveSSHAgent(t, agent.NewKeyring()), sshEd25519Fingerprint)
		require.ErrorIs(t, err, ErrSSHAgentKeyNotFound)
		require.ErrorContains(t, err, "no usable keys")
	})

	t.Run("no-fingerprint", func(t *testing.T) {
		t.Parallel()
		_, err := SSHAgentKey(socket, "")
		require.Error(t, err)
	})

	t.Run("fingerprint-is-case-sensitive", func(t *testing.T) {
		t.Parallel()
		_, err := SSHAgentKey(socket, "SHA256:"+strings.ToLower(strings.TrimPrefix(sshEd25519Fingerprint, "SHA256:")))
		require.ErrorIs(t, err, ErrSSHAgentKeyNotFound)
	})
}

// TestSSHAgentKeyGone checks that a key that leaves the agent after it
// was looked up fails to sign, and signs again once it is back.
func TestSSHAgentKeyGone(t *testing.T) {
	t.Parallel()
	raw, err := ssh.ParseRawPrivateKey(readTestdata(t, "ssh-ed25519"))
	require.NoError(t, err)

	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: raw}))
	socket := serveSSHAgent(t, keyring)

	k, err := SSHAgentKey(socket, sshEd25519Fingerprint)
	require.NoError(t, err)
	_, err = k.SignMessage([]byte("message"))
	require.NoError(t, err)

	require.NoError(t, keyring.RemoveAll())
	_, err = k.SignMessage([]byte("message"))
	require.ErrorContains(t, err, "signing with the SSH agent")

	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: raw}))
	_, err = k.SignMessage([]byte("message"))
	require.NoError(t, err)
}

// misbehavingAgent answers signature requests with whatever sign returns.
type misbehavingAgent struct {
	agent.Agent
	sign func(key ssh.PublicKey, data []byte) (*ssh.Signature, error)
}

func (m *misbehavingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return m.sign(key, data)
}

// TestSSHAgentBadSignatures checks that what the agent answers is not
// taken on trust.
func TestSSHAgentBadSignatures(t *testing.T) {
	t.Parallel()

	newAgent := func(t *testing.T, file string) (keyring agent.Agent, signer ssh.Signer) {
		t.Helper()
		raw, err := ssh.ParseRawPrivateKey(readTestdata(t, file))
		require.NoError(t, err)
		signer, err = ssh.NewSignerFromKey(raw)
		require.NoError(t, err)
		keyring = agent.NewKeyring()
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: raw}))
		return keyring, signer
	}

	t.Run("rsa-sha1", func(t *testing.T) {
		t.Parallel()
		// Old agents ignore the request to sign with SHA-2 and answer
		// with a SHA-1 signature.
		keyring, signer := newAgent(t, "ssh-rsa")
		socket := serveSSHAgent(t, &misbehavingAgent{
			Agent: keyring,
			sign: func(_ ssh.PublicKey, data []byte) (*ssh.Signature, error) {
				as, ok := signer.(ssh.AlgorithmSigner)
				if !ok {
					return nil, errors.New("not an algorithm signer")
				}
				return as.SignWithAlgorithm(nil, data, ssh.KeyAlgoRSA)
			},
		})

		k, err := SSHAgentKey(socket, ssh.FingerprintSHA256(signer.PublicKey()))
		require.NoError(t, err)
		_, err = k.SignMessage([]byte("message"))
		require.ErrorContains(t, err, `signed with "ssh-rsa"`)
	})

	t.Run("signature-of-something-else", func(t *testing.T) {
		t.Parallel()
		keyring, signer := newAgent(t, "ssh-ed25519")
		socket := serveSSHAgent(t, &misbehavingAgent{
			Agent: keyring,
			sign: func(_ ssh.PublicKey, _ []byte) (*ssh.Signature, error) {
				return signer.Sign(nil, []byte("not what was asked"))
			},
		})

		k, err := SSHAgentKey(socket, sshEd25519Fingerprint)
		require.NoError(t, err)
		_, err = k.SignMessage([]byte("message"))
		require.ErrorContains(t, err, "does not verify")
	})
}

// TestSSHAgentOpenSSH signs with keys held by a real ssh-agent, and
// checks the signatures with ssh-keygen.
func TestSSHAgentOpenSSH(t *testing.T) {
	t.Parallel()
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not installed", bin)
		}
	}

	socket := sshAgentSocketPath(t)
	dir := filepath.Dir(socket)

	// -D keeps the agent in the foreground, so it dies with the test.
	ctx, cancel := context.WithCancel(t.Context())
	agentCmd := exec.CommandContext(ctx, "ssh-agent", "-D", "-a", socket) //nolint:gosec // test paths
	require.NoError(t, agentCmd.Start())
	t.Cleanup(func() {
		cancel()
		agentCmd.Wait() //nolint:errcheck,gosec // killed on purpose
	})
	require.Eventually(t, func() bool {
		_, err := os.Stat(socket)
		return err == nil
	}, 10*time.Second, 20*time.Millisecond, "ssh-agent did not start")

	message := readTestdata(t, "ssh-message.sig") // any bytes will do
	messagePath := filepath.Join(dir, "message")
	require.NoError(t, os.WriteFile(messagePath, message, 0o600))

	for _, file := range []string{"ssh-ed25519", "ssh-ecdsa", "ssh-rsa"} {
		// ssh-add refuses private keys others can read.
		keyPath := filepath.Join(dir, file)
		require.NoError(t, os.WriteFile(keyPath, readTestdata(t, file), 0o600))

		add := exec.CommandContext(t.Context(), "ssh-add", keyPath) //nolint:gosec // test paths
		add.Env = append(os.Environ(), SSHAgentSocketEnv+"="+socket)
		out, err := add.CombinedOutput()
		require.NoError(t, err, string(out))
	}

	for _, file := range []string{"ssh-ed25519", "ssh-ecdsa", "ssh-rsa"} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			pubData := readTestdata(t, file+".pub")
			pub, err := ParseSSHPublicKey(pubData)
			require.NoError(t, err)

			k, err := SSHAgentKey(socket, pub.Fingerprint())
			require.NoError(t, err)

			sig, err := k.SignMessage(message)
			require.NoError(t, err)

			ok, err := pub.VerifyMessage(message, sig)
			require.NoError(t, err)
			require.True(t, ok)

			// ssh-keygen reads the armored form.
			parsed, err := sshsig.Parse(sig)
			require.NoError(t, err)
			sigPath := filepath.Join(dir, file+".sig")
			require.NoError(t, os.WriteFile(sigPath, parsed.Armor(), 0o600))

			signers := filepath.Join(dir, file+".allowed")
			line := "signer@example.com " + string(ssh.MarshalAuthorizedKey(pub.SSHPublicKey()))
			require.NoError(t, os.WriteFile(signers, []byte(line), 0o600))

			in, err := os.Open(messagePath)
			require.NoError(t, err)
			defer in.Close() //nolint:errcheck // read only

			verify := exec.CommandContext(t.Context(), "ssh-keygen", "-Y", "verify", //nolint:gosec // fixed arguments
				"-f", signers, "-I", "signer@example.com", "-n", DefaultSSHNamespace, "-s", sigPath)
			verify.Stdin = in
			out, err := verify.CombinedOutput()
			require.NoError(t, err, string(out))
		})
	}
}
