// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/key"
)

const (
	// The ed25519 SSH key fixture of the key package.
	sshTestKey         = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICHIc/Qxgy2hOWMpP4qUdEZpc11c1KpEda8EVnXiRQJg test@example.com"
	sshTestFingerprint = "SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU"
)

// sshTestFingerprintOtherCase is the test fingerprint with the case of
// every letter of the hash inverted: another fingerprint that only
// differs from it in case.
var sshTestFingerprintOtherCase = sshFingerprintPrefix + strings.Map(func(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z':
		return r - 'a' + 'A'
	case r >= 'A' && r <= 'Z':
		return r - 'A' + 'a'
	}
	return r
}, strings.TrimPrefix(sshTestFingerprint, sshFingerprintPrefix))

// sshSigner is the identity a verification reports for a signature made
// with the SSH test key.
func sshSigner(t *testing.T) *Identity {
	t.Helper()
	prov, err := key.NewParser().ParsePublicKeyProvider([]byte(sshTestKey))
	require.NoError(t, err)
	pub, err := prov.PublicKey()
	require.NoError(t, err)
	return &Identity{Key: IdentityKeyFromPublic(pub)}
}

// An SSH signer is identified by the fingerprint of the key and typed by
// its underlying algorithm.
func TestSSHKeyIdentity(t *testing.T) {
	t.Parallel()
	signer := sshSigner(t)
	require.Equal(t, sshTestFingerprint, signer.GetKey().GetId())
	require.Equal(t, "ed25519", signer.GetKey().GetType())
	require.Empty(t, signer.GetKey().GetSigningFingerprint())

	// The principal round-trips, keeping the case of the fingerprint.
	principal := signer.Principal()
	require.Equal(t, "key::ed25519::"+sshTestFingerprint, principal)
	parsed, err := NewIdentityFromPrincipal(principal)
	require.NoError(t, err)
	require.Equal(t, sshTestFingerprint, parsed.GetKey().GetId())
	require.Equal(t, principal, parsed.Principal())

	spec, err := NewIdentityFromSpec(principal)
	require.NoError(t, err)
	require.Equal(t, principal, spec.Spec())
}

// A policy can name an SSH key by its fingerprint or carry the key
// itself, as the line of an authorized_keys file.
func TestMatchesKeyIdentitySSH(t *testing.T) {
	t.Parallel()
	sv := &SignatureVerification{Identities: []*Identity{sshSigner(t)}}

	for name, tc := range map[string]struct {
		id      *IdentityKey
		matches bool
	}{
		"fingerprint":                 {&IdentityKey{Id: sshTestFingerprint}, true},
		"fingerprint and type":        {&IdentityKey{Id: sshTestFingerprint, Type: "ed25519"}, true},
		"fingerprint, wrong type":     {&IdentityKey{Id: sshTestFingerprint, Type: "rsassa-pkcs1v15"}, false},
		"key data":                    {&IdentityKey{Data: sshTestKey}, true},
		"key data without comment":    {&IdentityKey{Data: strings.Join(strings.Fields(sshTestKey)[:2], " ")}, true},
		"fingerprint in another case": {&IdentityKey{Id: sshTestFingerprintOtherCase}, false},
		"lowercase prefix":            {&IdentityKey{Id: "sha256:" + strings.TrimPrefix(sshTestFingerprint, sshFingerprintPrefix)}, false},
		"all lowercase":               {&IdentityKey{Id: strings.ToLower(sshTestFingerprint)}, false},
		"fingerprint without prefix":  {&IdentityKey{Id: strings.TrimPrefix(sshTestFingerprint, sshFingerprintPrefix)}, false},
		"another fingerprint":         {&IdentityKey{Id: "SHA256:KTrCAHHGUSCkNjanR0t4ojOiHQ4qZIQM6mkwX64b2KY"}, false},
		"id matcher": {&IdentityKey{
			IdMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: sshTestFingerprint}},
		}, true},
		"id matcher in another case": {&IdentityKey{
			IdMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: sshTestFingerprintOtherCase}},
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.matches, sv.MatchesKeyIdentity(tc.id))
		})
	}
}

func TestKeyIDsEqual(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b  string
		equal bool
	}{
		// Hex ids ignore case, as they always did.
		{"1234abcd", "1234ABCD", true},
		{"04B44C056663906446B77A6D89F11DC191AA7042", "04b44c056663906446b77a6d89f11dc191aa7042", true},
		{"1234abcd", "1234abce", false},
		{"", "", true},

		// SSH fingerprints are exact, whichever side carries one.
		{sshTestFingerprint, sshTestFingerprint, true},
		{sshTestFingerprint, sshTestFingerprintOtherCase, false},
		{sshTestFingerprintOtherCase, sshTestFingerprint, false},
		{"SHA256:abc", "SHA256:ABC", false},
		{"SHA256:abc", "sha256:abc", false},
		{"sha256:abc", "sha256:ABC", false},
		{"SHA256:abc", "sha256:ABC", false},
		{"SHA256:", "sha256:", false},

		// The signing fingerprint of a GPG key is no SSH fingerprint.
		{"SHA256", "sha256", true},
	} {
		require.Equal(t, tc.equal, keyIDsEqual(tc.a, tc.b), "%q vs %q", tc.a, tc.b)
	}
}

// The signing fingerprint pin compares the way the id does.
func TestMatchesKeyIdentitySSHSigningFingerprint(t *testing.T) {
	t.Parallel()
	sv := &SignatureVerification{Identities: []*Identity{{Key: &IdentityKey{
		Id: "1234abcd", SigningFingerprint: sshTestFingerprint,
	}}}}

	require.True(t, sv.MatchesKeyIdentity(&IdentityKey{Id: "1234ABCD", SigningFingerprint: sshTestFingerprint}))
	require.False(t, sv.MatchesKeyIdentity(&IdentityKey{Id: "1234abcd", SigningFingerprint: sshTestFingerprintOtherCase}))
	// The id also names a signer by its signing fingerprint.
	require.True(t, sv.MatchesKeyIdentity(&IdentityKey{Id: sshTestFingerprint}))
	require.False(t, sv.MatchesKeyIdentity(&IdentityKey{Id: sshTestFingerprintOtherCase}))
}
