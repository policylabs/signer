// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/key"
)

// mintSpiffeLeafForTest mints a self-signed cert whose URI SAN is the given
// spiffe:// ID. Good enough for IdentitySpiffeFromCert unit tests.
func mintSpiffeLeafForTest(t *testing.T, spiffeURI string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	uri, err := url.Parse(spiffeURI)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svid"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if uri != nil && uri.Scheme != "" {
		tpl.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestVerifyIdentity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		mustFail bool
		sut      *Identity
	}{
		{"sigstore", false, &Identity{
			Id: "sut",
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "test@example.com",
			},
		}},
		{"key", false, &Identity{
			Id: "sut",
			Key: &IdentityKey{
				Id:   "key-id",
				Type: "rsa",
				Data: "kjshdidy82387y387",
			},
		}},
		{"ref", false, &Identity{
			Ref: &IdentityRef{
				Id: "abcde",
			},
		}},
		{"no-ids", true, &Identity{}},
		{"two-ids", true, &Identity{
			Ref: &IdentityRef{
				Id: "abcde",
			},
			Key: &IdentityKey{
				Id:   "key-id",
				Type: "rsa",
				Data: "kjshdidy82387y387",
			},
		}},
		{"key-no-data-or-id", true, &Identity{
			Id: "sut",
			Key: &IdentityKey{
				Id: "", Type: "rsa", Data: "",
			},
		}},
		{"spiffe-valid-svid", false, &Identity{
			Spiffe: &IdentitySpiffe{Svid: "spiffe://example.org/workload"},
		}},
		{"spiffe-valid-matcher-only", false, &Identity{
			Spiffe: &IdentitySpiffe{
				TrustDomainMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "example.org"},
				},
			},
		}},
		{"spiffe-no-constraint", true, &Identity{
			Spiffe: &IdentitySpiffe{},
		}},
		{"spiffe-invalid-svid", true, &Identity{
			Spiffe: &IdentitySpiffe{Svid: "not-a-spiffe-uri"},
		}},
		{"spiffe-bad-regex-in-path-match", true, &Identity{
			Spiffe: &IdentitySpiffe{
				PathMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"spiffe-bad-glob-in-svid-match", true, &Identity{
			Spiffe: &IdentitySpiffe{
				SvidMatch: &StringMatcher{
					Kind: &StringMatcher_Glob{Glob: "[malformed"},
				},
			},
		}},
		{"sigstore-legacy-regex-bad", true, func() *Identity {
			mode := SigstoreModeRegexp
			return &Identity{
				Sigstore: &IdentitySigstore{
					Mode:     &mode,
					Issuer:   "https://accounts.google.com",
					Identity: "[unclosed",
				},
			}
		}()},
		{"sigstore-legacy-half-specified", true, &Identity{
			Sigstore: &IdentitySigstore{Issuer: "https://accounts.google.com"},
		}},
		{"sigstore-matcher-only-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://accounts.google.com"},
				},
			},
		}},
		{"sigstore-identity-match-bad-regex", true, &Identity{
			Sigstore: &IdentitySigstore{
				IdentityMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"sigstore-source-repo-match-only-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"},
				},
			},
		}},
		{"sigstore-source-repo-match-bad-regex", true, &Identity{
			Sigstore: &IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"sigstore-source-repo-data-on-expectation-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				IdentityMatch:       &StringMatcher{Kind: &StringMatcher_Exact{Exact: "user@example.com"}},
				SourceRepositoryUri: "https://github.com/myorg/repo",
			},
		}},
		{"sigstore-build-config-match-only-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				BuildConfigUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3"},
				},
			},
		}},
		{"sigstore-build-config-match-bad-regex", true, &Identity{
			Sigstore: &IdentitySigstore{
				BuildConfigUriMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"sigstore-build-config-data-on-expectation-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				IdentityMatch:  &StringMatcher{Kind: &StringMatcher_Exact{Exact: "user@example.com"}},
				BuildConfigUri: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
			},
		}},
		{"sigstore-build-trigger-match-only-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				BuildTriggerMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
			},
		}},
		{"sigstore-build-trigger-match-anchored-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"}},
				BuildTriggerMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
			},
		}},
		{"sigstore-build-trigger-data-on-expectation-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				IdentityMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "user@example.com"}},
				BuildTrigger:  "release",
			},
		}},
		{"sigstore-source-ref-match-only-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Glob{Glob: "refs/tags/v*"}},
			},
		}},
		{"sigstore-refinements-only-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				BuildTriggerMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Glob{Glob: "refs/tags/v*"}},
			},
		}},
		{"sigstore-source-ref-match-anchored-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				IdentityMatch:            &StringMatcher{Kind: &StringMatcher_Prefix{Prefix: "https://github.com/myorg/repo/"}},
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Glob{Glob: "refs/tags/v*"}},
			},
		}},
		{"sigstore-refinements-with-issuer-only-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				IssuerMatch:              &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"}},
				BuildTriggerMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Glob{Glob: "refs/tags/v*"}},
			},
		}},
		{"sigstore-source-ref-data-on-expectation-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				IdentityMatch:       &StringMatcher{Kind: &StringMatcher_Exact{Exact: "user@example.com"}},
				SourceRepositoryRef: "refs/tags/v1.2.3",
			},
		}},
		{"sigstore-source-repo-from-context-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{FromContext: "source_repo"},
			},
		}},
		{"sigstore-from-context-with-kind-invalid", true, &Identity{
			Sigstore: &IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{
					FromContext: "source_repo",
					Kind:        &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"},
				},
			},
		}},
		{"key-id-match-valid", false, &Identity{
			Key: &IdentityKey{
				IdMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "abc123"},
				},
			},
		}},
		{"key-type-match-bad-regex", true, &Identity{
			Key: &IdentityKey{
				Id: "abc123",
				TypeMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"outer-matcher-missing-field", true, &Identity{
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "u@example.com",
			},
			Matchers: []*Matcher{{
				Kind: &Matcher_String_{String_: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "foo"},
				}},
			}},
		}},
		{"outer-matcher-bad-regex", true, &Identity{
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "u@example.com",
			},
			Matchers: []*Matcher{{
				Field: "sigstore.issuer",
				Kind: &Matcher_String_{String_: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				}},
			}},
		}},
		{"outer-matcher-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "u@example.com",
			},
			Matchers: []*Matcher{{
				Field: "sigstore.issuer",
				Kind: &Matcher_String_{String_: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://accounts.google.com"},
				}},
			}},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.sut.Validate()
			if tt.mustFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestIdentityPrincipalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		principal string
	}{
		{"sigstore", "sigstore::https://accounts.google.com::user@example.com"},
		{"sigstore-regex-pattern", "sigstore::https://.*::.*@example\\.com"},
		{"key", "key::rsa::1234abcdef"},
		{"ref", "ref:shared-identity"},
		{"spiffe", "spiffe://prod.example.org/workload/api"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, err := NewIdentityFromPrincipal(tt.principal)
			require.NoError(t, err)
			require.Equal(t, tt.principal, id.Principal())
		})
	}
}

// TestNewIdentityFromPrincipalRejectsAnnotations confirms Principal is
// strict: parenthetical matcher annotations belong to Spec, not Principal.
func TestNewIdentityFromPrincipalRejectsAnnotations(t *testing.T) {
	t.Parallel()
	for _, tt := range []string{
		"sigstore(regexp)::https://.*::.*@example.com",
		"sigstore(issuerMatch=exact)::https://accounts.google.com::user@example.com",
		"key(idMatch=glob)::rsa::abc*",
	} {
		t.Run(tt, func(t *testing.T) {
			t.Parallel()
			_, err := NewIdentityFromPrincipal(tt)
			require.Error(t, err)
			require.Contains(t, err.Error(), "matcher annotations")
		})
	}
}

func TestIdentitySpecRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		spec string
	}{
		// Pure forms — Spec degrades to Principal.
		{"sigstore-pure", "sigstore::https://accounts.google.com::user@example.com"},
		{"key-pure", "key::rsa::1234abcdef"},
		{"ref-pure", "ref:shared-identity"},
		{"spiffe-pure", "spiffe://prod.example.org/workload/api"},

		// Legacy sigstore(regexp).
		{"sigstore-regexp-legacy", "sigstore(regexp)::https://.*::.*@example\\.com"},

		// Rich form — sigstore.
		{"sigstore-issuer-match", "sigstore(issuerMatch=exact)::https://accounts.google.com::user@example.com"},
		{"sigstore-identity-match-regex", "sigstore(identityMatch=regex)::https://accounts.google.com::.*@example\\.com"},
		{"sigstore-both-match", "sigstore(issuerMatch=exact,identityMatch=regex)::https://accounts.google.com::.*@example\\.com"},
		{"sigstore-case-insensitive", "sigstore(identityMatch=regex/i)::https://accounts.google.com::user@EXAMPLE\\.com"},

		// Rich form — key.
		{"key-id-match-glob", "key(idMatch=glob)::rsa::abc*"},
		{"key-type-match-prefix", "key(typeMatch=prefix)::ed::1234abcdef"},

		// Rich form — spiffe.
		{"spiffe-svid-match-regex", "spiffe(svidMatch=regex)::^spiffe://prod\\..*/workload$"},
		{"spiffe-trust-domain-match", "spiffe(trustDomainMatch=exact)::prod.example.org::"},
		{"spiffe-both-components", "spiffe(trustDomainMatch=exact,pathMatch=glob)::prod.example.org::/api/*"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, err := NewIdentityFromSpec(tt.spec)
			require.NoError(t, err, "parsing")
			require.Equal(t, tt.spec, id.Spec(), "round-trip")
		})
	}
}

func TestNewIdentityFromSpecPopulatesMatcherFields(t *testing.T) {
	t.Parallel()
	id, err := NewIdentityFromSpec("sigstore(issuerMatch=exact,identityMatch=regex/i)::https://accounts.google.com::.*@example\\.com")
	require.NoError(t, err)
	sig := id.GetSigstore()
	require.NotNil(t, sig)

	require.NotNil(t, sig.GetIssuerMatch())
	require.IsType(t, &StringMatcher_Exact{}, sig.GetIssuerMatch().GetKind())
	require.Equal(t, "https://accounts.google.com", sig.GetIssuerMatch().GetExact())
	require.False(t, sig.GetIssuerMatch().GetCaseInsensitive())

	require.NotNil(t, sig.GetIdentityMatch())
	require.IsType(t, &StringMatcher_Regex{}, sig.GetIdentityMatch().GetKind())
	require.Equal(t, ".*@example\\.com", sig.GetIdentityMatch().GetRegex())
	require.True(t, sig.GetIdentityMatch().GetCaseInsensitive())

	// Slot values flow into the matcher pattern, NOT into the legacy fields.
	require.Empty(t, sig.GetIssuer(), "legacy issuer must stay empty when issuerMatch is set")
	require.Empty(t, sig.GetIdentity(), "legacy identity must stay empty when identityMatch is set")
}

func TestNewIdentityFromSpecMixedLegacyAndMatcher(t *testing.T) {
	t.Parallel()
	// One slot annotated, the other inherits the legacy field.
	id, err := NewIdentityFromSpec("sigstore(issuerMatch=regex)::https://.*::user@example.com")
	require.NoError(t, err)
	sig := id.GetSigstore()
	require.NotNil(t, sig)
	require.NotNil(t, sig.GetIssuerMatch())
	require.Equal(t, "https://.*", sig.GetIssuerMatch().GetRegex())
	require.Empty(t, sig.GetIssuer())
	require.Equal(t, "user@example.com", sig.GetIdentity(), "identity slot populates legacy field when not annotated")
	require.Nil(t, sig.GetIdentityMatch())
}

func TestNewIdentityFromSpecErrors(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		spec    string
		wantSub string
	}{
		{"unclosed-paren", "sigstore(issuerMatch=exact::a::b", "unclosed"},
		{"unknown-kind", "sigstore(issuerMatch=fuzzy)::a::b", "unknown matcher kind"},
		{"unknown-field", "sigstore(weirdMatch=exact)::a::b", "unknown sigstore matcher field"},
		{"bad-options", "sigstore(issuerMatch=exact/x)::a::b", "unknown matcher options"},
		{"sigstore-wrong-slots", "sigstore(issuerMatch=exact)::only-one-slot", "requires 2 slots"},
		{"unknown-type", "weirdtype(field=exact)::a::b", "unknown identity type"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewIdentityFromSpec(tt.spec)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantSub)
		})
	}
}

func TestIdentitySlugAliasesSpec(t *testing.T) {
	t.Parallel()
	// Old callers used Slug, which carried the rich form (e.g. (regexp)).
	// The new alias must preserve that behavior.
	rich := "sigstore(regexp)::https://.*::.*@example\\.com"
	id, err := NewIdentityFromSlug(rich)
	require.NoError(t, err)
	require.Equal(t, rich, id.Slug(), "Slug round-trips rich form")
	require.Equal(t, id.Spec(), id.Slug(), "Slug aliases Spec")

	// And NewIdentityFromSlug must still accept pure forms.
	pure := "sigstore::https://accounts.google.com::user@example.com"
	id2, err := NewIdentityFromSlug(pure)
	require.NoError(t, err)
	require.Equal(t, pure, id2.Spec())
	require.Equal(t, pure, id2.Principal(), "pure form: Spec == Principal")
}

func TestIdentitySpiffeFromString(t *testing.T) {
	t.Parallel()

	t.Run("success-with-path", func(t *testing.T) {
		t.Parallel()
		id, err := IdentitySpiffeFromString("spiffe://prod.example.org/workload/api")
		require.NoError(t, err)
		require.Equal(t, "spiffe://prod.example.org/workload/api", id.GetSvid())
		require.Empty(t, id.GetTrustRoots())
	})

	t.Run("success-no-path", func(t *testing.T) {
		t.Parallel()
		id, err := IdentitySpiffeFromString("spiffe://example.org")
		require.NoError(t, err)
		require.Equal(t, "spiffe://example.org", id.GetSvid())
	})

	t.Run("invalid-scheme", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromString("https://example.org/workload")
		require.Error(t, err)
	})

	t.Run("empty-string", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromString("")
		require.Error(t, err)
	})

	t.Run("missing-trust-domain", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromString("spiffe:///workload")
		require.Error(t, err)
	})
}

func TestIdentitySpiffeFromCert(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		leaf := mintSpiffeLeafForTest(t, "spiffe://prod.example.org/workload/api")
		id, err := IdentitySpiffeFromCert(leaf)
		require.NoError(t, err)
		require.Equal(t, "spiffe://prod.example.org/workload/api", id.GetSvid())
		require.Empty(t, id.GetTrustRoots(), "TrustRoots must not be populated on the verified-side identity")
	})

	t.Run("nil-cert", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromCert(nil)
		require.Error(t, err)
	})

	t.Run("cert-with-no-uri-san", func(t *testing.T) {
		t.Parallel()
		leaf := mintSpiffeLeafForTest(t, "")
		_, err := IdentitySpiffeFromCert(leaf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "spiffe://")
	})

	t.Run("cert-with-non-spiffe-uri-san", func(t *testing.T) {
		t.Parallel()
		leaf := mintSpiffeLeafForTest(t, "https://example.com/workload")
		_, err := IdentitySpiffeFromCert(leaf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "spiffe://")
	})

	t.Run("cert-with-malformed-spiffe-uri", func(t *testing.T) {
		t.Parallel()
		// Valid URI scheme but not a valid SPIFFE ID (empty trust domain).
		leaf := mintSpiffeLeafForTest(t, "spiffe:///workload")
		_, err := IdentitySpiffeFromCert(leaf)
		require.Error(t, err)
	})
}

func TestIdentityKeyFromPublic(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, IdentityKeyFromPublic(nil))
	})

	t.Run("carries-signing-fingerprint", func(t *testing.T) {
		t.Parallel()
		// A *key.Public standing in for a post-verification entry whose
		// signature was made by a subkey: ID() reports the primary,
		// SigningKeyFingerprint reports the subkey.
		pub := &key.Public{
			Scheme:                key.Ed25519,
			SigningKeyFingerprint: "04B44C056663906446B77A6D89F11DC191AA7042",
		}
		// Force ID() to return the primary fingerprint via the same
		// mechanism Public uses for GPG-derived keys.
		pub.Data = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPRILHF2NfPlV9xTQkLTM5aWCQfY9bF4cHRPm8a9Uc2o=\n-----END PUBLIC KEY-----\n"

		ik := IdentityKeyFromPublic(pub)
		require.NotNil(t, ik)
		require.Equal(t, "04B44C056663906446B77A6D89F11DC191AA7042", ik.GetSigningFingerprint())
		require.Equal(t, string(key.Ed25519), ik.GetType())
	})
}

func TestValidateSigstoreRefinementErrors(t *testing.T) {
	t.Parallel()
	repo := &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"}}
	badRegex := &StringMatcher{Kind: &StringMatcher_Regex{Regex: "[unclosed"}}
	for _, tt := range []struct {
		name    string
		sut     *IdentitySigstore
		wantErr string
	}{
		{
			"build-trigger-bad-regex",
			&IdentitySigstore{SourceRepositoryUriMatch: repo, BuildTriggerMatch: badRegex},
			"build_trigger_match: ",
		},
		{
			"source-ref-bad-regex",
			&IdentitySigstore{SourceRepositoryUriMatch: repo, SourceRepositoryRefMatch: badRegex},
			"source_repository_ref_match: ",
		},
		{
			"unanchored-names-only-the-set-refinement",
			&IdentitySigstore{BuildTriggerMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}}},
			"sigstore build_trigger_match only refines an identity and needs identity, identity_match, source_repository_uri_match, or build_config_uri_match next to them",
		},
		{
			"empty-names-no-refinement-as-sufficient",
			&IdentitySigstore{},
			"sigstore identity requires issuer, identity, issuer_match, identity_match, source_repository_uri_match, or build_config_uri_match",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := (&Identity{Sigstore: tt.sut}).Validate()
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
