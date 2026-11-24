// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/policylabs/signer/key"
)

// testSSHAgent is an in-memory SSH agent listening on a socket.
type testSSHAgent struct {
	socket  string
	keyring agent.Agent
}

// newTestSSHAgent serves an empty SSH agent.
func newTestSSHAgent(t *testing.T) *testSSHAgent {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("SSH agents are not supported on Windows")
	}

	// Socket paths are limited to about a hundred bytes, which t.TempDir
	// can exceed.
	dir, err := os.MkdirTemp("", "agent") //nolint:usetesting // t.TempDir is too long for a socket
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) }) //nolint:errcheck,gosec // best effort

	a := &testSSHAgent{socket: filepath.Join(dir, "s"), keyring: agent.NewKeyring()}
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", a.socket)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck,gosec // best effort

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()                //nolint:errcheck // best effort
				agent.ServeAgent(a.keyring, conn) //nolint:errcheck,gosec // ends when the client hangs up
			}()
		}
	}()
	return a
}

// addKey puts a new key in the agent. It returns the fingerprint of the
// key and the path of a file holding its public half.
func (a *testSSHAgent) addKey(t *testing.T) (fingerprint, pubPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, a.keyring.Add(agent.AddedKey{PrivateKey: priv}))

	pubPath, fingerprint = writeSSHPublicKey(t, pub)
	return fingerprint, pubPath
}

// writeSSHPublicKey writes pub the way ssh-keygen writes .pub files. It
// returns the path of the file and the fingerprint of the key.
func writeSSHPublicKey(t *testing.T, pub ed25519.PublicKey) (path, fingerprint string) {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	path = filepath.Join(t.TempDir(), "id_ed25519.pub")
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " user@example.com\n"
	require.NoError(t, os.WriteFile(path, []byte(line), 0o600))
	return path, ssh.FingerprintSHA256(sshPub)
}

// fingerprints returns the fingerprints of the SSH keys among providers.
func fingerprints(t *testing.T, providers []key.PrivateKeyProvider) []string {
	t.Helper()
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		sshKey, ok := p.(*key.SSHPrivate)
		require.True(t, ok)
		out = append(out, sshKey.Fingerprint())
	}
	return out
}

func TestKeysSignSSHAgent(t *testing.T) {
	t.Parallel()

	t.Run("by-fingerprint-and-by-file", func(t *testing.T) {
		t.Parallel()
		a := newTestSSHAgent(t)
		first, _ := a.addKey(t)
		second, secondPath := a.addKey(t)
		a.addKey(t) // held by the agent, not asked for

		k := DefaultKeysSign()
		k.SSHAgentSocket = a.socket
		cmd := &cobra.Command{Use: "test"}
		k.AddFlags(cmd)
		require.NoError(t, cmd.PersistentFlags().Parse([]string{
			"--signing-ssh-agent-key=" + first,
			"--signing-ssh-agent-key=" + secondPath,
		}))
		require.NoError(t, k.Validate())

		providers, err := k.ParseSigningKeys()
		require.NoError(t, err)
		require.Equal(t, []string{first, second}, fingerprints(t, providers))

		// The keys sign, and no private key material is at hand.
		for _, p := range providers {
			sig, err := key.NewSigner().SignMessage(p, []byte("message"))
			require.NoError(t, err)
			require.NotEmpty(t, sig)
			_, err = p.PrivateKey()
			require.Error(t, err)
		}
	})

	t.Run("after-file-keys", func(t *testing.T) {
		t.Parallel()
		a := newTestSSHAgent(t)
		fingerprint, _ := a.addKey(t)

		k := DefaultKeysSign()
		k.SSHAgentSocket = a.socket
		k.SSHAgentKeys = []string{fingerprint}
		k.PrivateKeyPaths = []string{writeSSHPrivateKey(t)}

		providers, err := k.ParseSigningKeys()
		require.NoError(t, err)
		require.Len(t, providers, 2)
		require.Equal(t, fingerprint, fingerprints(t, providers)[1])
	})

	t.Run("namespace", func(t *testing.T) {
		t.Parallel()
		a := newTestSSHAgent(t)
		fingerprint, pubPath := a.addKey(t)

		for _, tc := range []struct{ set, expect string }{
			{"", key.DefaultSSHNamespace},
			{"git", "git"},
		} {
			k := DefaultKeysSign()
			k.SSHAgentSocket = a.socket
			k.SSHAgentKeys = []string{fingerprint}
			if tc.set != "" {
				k.SSHNamespace = tc.set
			}
			providers, err := k.ParseSigningKeys()
			require.NoError(t, err)
			require.Len(t, providers, 1)
			sig, err := key.NewSigner().SignMessage(providers[0], []byte("message"))
			require.NoError(t, err)

			pubData, err := os.ReadFile(pubPath)
			require.NoError(t, err)
			pub, err := key.ParseSSHPublicKey(pubData)
			require.NoError(t, err)
			ok, err := pub.VerifyMessage([]byte("message"), sig)
			require.NoError(t, err)
			require.True(t, ok)
			namespace, err := pub.SignatureNamespace(sig)
			require.NoError(t, err)
			require.Equal(t, tc.expect, namespace)
		}
	})

	t.Run("build-signer", func(t *testing.T) {
		t.Parallel()
		a := newTestSSHAgent(t)
		fingerprint, _ := a.addKey(t)

		k := DefaultKeysSign()
		k.SSHAgentSocket = a.socket
		k.SSHAgentKeys = []string{fingerprint}
		opts, err := k.BuildSigner()
		require.NoError(t, err)
		require.Equal(t, BackendKey, opts.Backend)
		require.Len(t, opts.Keys, 1)
	})

	t.Run("key-not-in-agent", func(t *testing.T) {
		t.Parallel()
		a := newTestSSHAgent(t)
		a.addKey(t)
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pubPath, fingerprint := writeSSHPublicKey(t, pub)

		for _, name := range []string{fingerprint, pubPath} {
			k := DefaultKeysSign()
			k.SSHAgentSocket = a.socket
			k.SSHAgentKeys = []string{name}
			_, err = k.ParseSigningKeys()
			require.ErrorIs(t, err, key.ErrSSHAgentKeyNotFound)
			require.ErrorContains(t, err, name)
		}
	})

	t.Run("not-a-public-key-file", func(t *testing.T) {
		t.Parallel()
		a := newTestSSHAgent(t)
		k := DefaultKeysSign()
		k.SSHAgentSocket = a.socket
		// A private key is not what the flag takes.
		k.SSHAgentKeys = []string{writeSSHPrivateKey(t)}
		require.NoError(t, k.Validate())
		_, err := k.ParseSigningKeys()
		require.ErrorContains(t, err, "reading SSH public key file")
	})

	t.Run("validate-missing-file", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysSign()
		k.SSHAgentSocket = "/nonexistent/agent.sock"
		k.SSHAgentKeys = []string{filepath.Join(t.TempDir(), "nope.pub")}
		require.ErrorContains(t, k.Validate(), "checking SSH agent key")
	})

	t.Run("agent-not-running", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("SSH agents are not supported on Windows")
		}
		k := DefaultKeysSign()
		k.SSHAgentSocket = filepath.Join(t.TempDir(), "nothing-here")
		k.SSHAgentKeys = []string{"SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU"}
		// Validate does not contact the agent.
		require.NoError(t, k.Validate())
		_, err := k.ParseSigningKeys()
		require.ErrorContains(t, err, "connecting to the SSH agent")
	})
}

// Without a socket of its own, KeysSign reaches the agent named by
// SSH_AUTH_SOCK.
func TestKeysSignSSHAgentEnv(t *testing.T) {
	a := newTestSSHAgent(t)
	fingerprint, _ := a.addKey(t)

	k := DefaultKeysSign()
	k.SSHAgentKeys = []string{fingerprint}

	t.Setenv(key.SSHAgentSocketEnv, "")
	require.ErrorContains(t, k.Validate(), "SSH_AUTH_SOCK is not set")
	_, err := k.ParseSigningKeys()
	require.ErrorContains(t, err, "no SSH agent socket")

	t.Setenv(key.SSHAgentSocketEnv, a.socket)
	require.NoError(t, k.Validate())
	providers, err := k.ParseSigningKeys()
	require.NoError(t, err)
	require.Equal(t, []string{fingerprint}, fingerprints(t, providers))

	// No agent keys asked for: no agent needed.
	t.Setenv(key.SSHAgentSocketEnv, "")
	require.NoError(t, DefaultKeysSign().Validate())
}
