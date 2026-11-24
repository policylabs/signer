// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// pemTypeOpenSSHPrivateKey is the PEM block type of private keys in the
// OpenSSH format, the one ssh-keygen writes.
const pemTypeOpenSSHPrivateKey = "OPENSSH PRIVATE KEY"

// ParseSSHPublicKey reads an SSH public key in the authorized_keys
// format, the one of the .pub files ssh-keygen writes:
//
//	ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... comment
//
// When the data holds more than one key the first one is returned.
func ParseSSHPublicKey(data []byte) (*SSHPublic, error) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH public key: %w", err)
	}
	return newSSHPublic(pub, comment)
}

// ParseSSHPrivateKey reads a private key in the OpenSSH format, the one
// ssh-keygen writes, decrypting it with the passphrase if it is
// encrypted.
//
// Private keys in other PEM formats are not read here, even though SSH
// can use them: they are handled as plain keys by the rest of the
// package.
func ParseSSHPrivateKey(data, passphrase []byte) (*SSHPrivate, error) {
	if !isOpenSSHPrivateKey(data) {
		return nil, errors.New("not a private key in the OpenSSH format")
	}

	var (
		raw any
		err error
	)
	if len(passphrase) > 0 {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	} else {
		raw, err = ssh.ParseRawPrivateKey(data)
	}
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("the SSH private key is encrypted, a passphrase is required")
		}
		return nil, fmt.Errorf("parsing SSH private key: %w", err)
	}
	return newSSHPrivate(raw)
}

// isOpenSSHPrivateKey reports whether data is a PEM block holding a
// private key in the OpenSSH format.
func isOpenSSHPrivateKey(data []byte) bool {
	block, _ := pem.Decode(data)
	return block != nil && block.Type == pemTypeOpenSSHPrivateKey
}
