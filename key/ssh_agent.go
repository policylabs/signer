// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// An SSH agent is a process that holds private keys and signs with them
// on behalf of other programs, which talk to it over a local socket. The
// keys never leave the agent: they can live in its memory, in a
// password manager or on a hardware token.
//
// Agents are reached over Unix sockets only, which leaves Windows out.

// SSHAgentSocketEnv is the environment variable that holds the path of
// the socket of the user's SSH agent.
const SSHAgentSocketEnv = "SSH_AUTH_SOCK"

// sshAgentDialTimeout bounds connecting to the agent. Signing itself is
// not bounded: the agent may be waiting for the user to confirm the use
// of the key or to touch a hardware token.
const sshAgentDialTimeout = 10 * time.Second

// ErrSSHAgentKeyNotFound is returned when the agent does not hold the
// key it was asked for.
var ErrSSHAgentKeyNotFound = errors.New("the SSH agent does not hold the key")

// SSHAgentKeys lists the public keys held by the SSH agent listening on
// socket. Keys of kinds that cannot sign here, such as certificates, are
// left out.
func SSHAgentKeys(socket string) ([]*SSHPublic, error) {
	conn, err := dialSSHAgent(socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck // nothing to do about it

	held, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, fmt.Errorf("listing the keys of the SSH agent: %w", err)
	}

	keys := make([]*SSHPublic, 0, len(held))
	for _, k := range held {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		sshPub, err := newSSHPublic(pub, k.Comment)
		if err != nil {
			continue
		}
		keys = append(keys, sshPub)
	}
	return keys, nil
}

// SSHAgentKey returns the key with the given fingerprint held by the SSH
// agent listening on socket. The fingerprint is the SHA-256 one OpenSSH
// prints ("SHA256:..."), as `ssh-add -l` shows it.
//
// The key signs by asking the agent, which is contacted again for every
// signature. Its private key material is not available: PrivateKey
// returns an error.
//
// When the agent does not hold the key, the error wraps
// ErrSSHAgentKeyNotFound.
func SSHAgentKey(socket, fingerprint string) (*SSHPrivate, error) {
	if fingerprint == "" {
		return nil, errors.New("no fingerprint of the SSH agent key to use")
	}

	keys, err := SSHAgentKeys(socket)
	if err != nil {
		return nil, err
	}

	held := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.Fingerprint() == fingerprint {
			return &SSHPrivate{
				signer: &sshAgentSigner{socket: socket, key: k.key},
			}, nil
		}
		held = append(held, k.Fingerprint())
	}

	if len(held) == 0 {
		return nil, fmt.Errorf("%w %s: it holds no usable keys", ErrSSHAgentKeyNotFound, fingerprint)
	}
	return nil, fmt.Errorf(
		"%w %s: it holds %s", ErrSSHAgentKeyNotFound, fingerprint, strings.Join(held, ", "),
	)
}

// dialSSHAgent connects to the SSH agent listening on socket.
func dialSSHAgent(socket string) (net.Conn, error) {
	if socket == "" {
		return nil, errors.New("no SSH agent socket")
	}
	if runtime.GOOS == "windows" {
		return nil, errors.New("SSH agents are not supported on Windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), sshAgentDialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connecting to the SSH agent: %w", err)
	}
	return conn, nil
}

// sshAgentSigner signs with a key held by an SSH agent. It connects to
// the agent for each signature, so it holds nothing to close and does
// not go stale when the agent restarts on the same socket.
type sshAgentSigner struct {
	socket string
	key    ssh.PublicKey
}

// PublicKey returns the public half of the key.
func (s *sshAgentSigner) PublicKey() ssh.PublicKey { return s.key }

// Sign signs data with the default algorithm of the key.
func (s *sshAgentSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, s.key.Type())
}

// SignWithAlgorithm signs data with the given signature algorithm. Only
// RSA keys have more than one. It implements ssh.AlgorithmSigner.
//
// The signature that comes back is verified: an agent that answers with
// another algorithm (older ones ignore the request for RSA with SHA-2)
// or with a bad signature is caught here and not by whoever verifies the
// signature later.
func (s *sshAgentSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var flags agent.SignatureFlags
	switch {
	case algorithm == s.key.Type():
	case s.key.Type() == ssh.KeyAlgoRSA && algorithm == ssh.KeyAlgoRSASHA256:
		flags = agent.SignatureFlagRsaSha256
	case s.key.Type() == ssh.KeyAlgoRSA && algorithm == ssh.KeyAlgoRSASHA512:
		flags = agent.SignatureFlagRsaSha512
	default:
		return nil, fmt.Errorf("%s keys cannot sign with %q", s.key.Type(), algorithm)
	}

	conn, err := dialSSHAgent(s.socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck // nothing to do about it

	sig, err := agent.NewClient(conn).SignWithFlags(s.key, data, flags)
	if err != nil {
		return nil, fmt.Errorf("signing with the SSH agent: %w", err)
	}

	if sig.Format != algorithm {
		return nil, fmt.Errorf(
			"the SSH agent signed with %q, not with %q as asked", sig.Format, algorithm,
		)
	}
	if err := s.key.Verify(data, sig); err != nil {
		return nil, fmt.Errorf("the signature of the SSH agent does not verify: %w", err)
	}
	return sig, nil
}

var _ ssh.AlgorithmSigner = (*sshAgentSigner)(nil)
