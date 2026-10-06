// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"
)

func TestMatchesKeyIdentity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		matches bool
		sut     *SignatureVerification
		id      *IdentityKey
	}{
		{
			"id-match", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}}},
			}, &IdentityKey{Id: "1234abc"},
		},
		{
			"id-and-type-match", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}}},
			}, &IdentityKey{Id: "1234abc", Type: "rsa"},
		},
		{
			"id-match-type-ignored-when-empty", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc"}}},
			}, &IdentityKey{Id: "1234abc", Type: "rsa"},
		},
		{
			"id-match-data-ignored", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}}},
			}, &IdentityKey{Id: "1234abc", Data: "different-data"},
		},
		{
			"no-id-no-match", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc"}}},
			}, &IdentityKey{Data: "keydata"},
		},
		{
			"wrong-id", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc"}}},
			}, &IdentityKey{Id: "wrong"},
		},
		{
			"type-mismatch", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}}},
			}, &IdentityKey{Id: "1234abc", Type: "ecdsa"},
		},
		{
			"two-signers-first-matches", true,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}},
					{Key: &IdentityKey{Id: "5678def", Type: "ecdsa"}},
				},
			}, &IdentityKey{Id: "1234abc", Type: "rsa"},
		},
		{
			"two-signers-second-matches", true,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}},
					{Key: &IdentityKey{Id: "5678def", Type: "ecdsa"}},
				},
			}, &IdentityKey{Id: "5678def", Type: "ecdsa"},
		},
		{
			"two-signers-none-match", false,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}},
					{Key: &IdentityKey{Id: "5678def", Type: "ecdsa"}},
				},
			}, &IdentityKey{Id: "aaaaaaa"},
		},
		{
			"nil-signer-key", false,
			&SignatureVerification{
				Identities: []*Identity{{Sigstore: &IdentitySigstore{Issuer: "x"}}},
			}, &IdentityKey{Id: "1234abc"},
		},
		{
			"empty-identities", false,
			&SignatureVerification{
				Identities: []*Identity{},
			}, &IdentityKey{Id: "1234abc"},
		},
		{
			// Identity has only Data (PEM key), Id/Type should be
			// auto-populated via Normalize before matching.
			"data-only-auto-normalize", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id:   "5be34774cae03891",
					Type: "ecdsa-sha2-nistp256",
				}}},
			}, &IdentityKey{
				Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			},
		},
		{
			// Same as above but signer has a different key — should not match.
			"data-only-auto-normalize-no-match", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id:   "aaaaaaaaaaaaaaaa",
					Type: "ecdsa-sha2-nistp256",
				}}},
			}, &IdentityKey{
				Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			},
		},
		{
			// Expectation pins the signing subkey and the verified identity matches it.
			"signing-fingerprint-pin-match", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP"},
		},
		{
			// Case-insensitive so upper/lower-hex fingerprints don't matter.
			"signing-fingerprint-pin-case-insensitive", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "subkeyfp",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP"},
		},
		{
			// Expectation pins a different subkey than the one that signed.
			"signing-fingerprint-pin-mismatch", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_A",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_B"},
		},
		{
			// Expectation omits the signing fingerprint — pin is not enforced
			// even if the verified identity has one.
			"signing-fingerprint-unpinned-permissive", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_A",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP"},
		},
		{
			// Expectation uses only the subkey fingerprint as Id — matches
			// against the signer's SigningFingerprint field.
			"id-matches-signer-subkey", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP",
				}}},
			}, &IdentityKey{Id: "SUBKEYFP"},
		},
		{
			// Expected Id is a subkey fingerprint that doesn't match either
			// the primary or the signer's actual subkey.
			"id-matches-neither-primary-nor-subkey", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_A",
				}}},
			}, &IdentityKey{Id: "SUBKEY_B"},
		},
		{
			// Fingerprint comparisons are case-insensitive, including the
			// primary Id match (hex fingerprints show up in either case).
			"id-case-insensitive", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP",
				}}},
			}, &IdentityKey{Id: "primaryfp"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, tt.sut.MatchesKeyIdentity(tt.id))
		})
	}
}

// sigRegexp builds an IdentitySigstore with Mode=regexp pinned at the
// GitHub Actions OIDC issuer for tests.
func sigRegexp(identity string) *IdentitySigstore {
	mode := SigstoreModeRegexp
	return &IdentitySigstore{
		Mode:     &mode,
		Issuer:   `https://token\.actions\.githubusercontent\.com`,
		Identity: identity,
	}
}

func TestMatchesSigstoreIdentityConvenienceMatchers(t *testing.T) {
	t.Parallel()
	signer := &SignatureVerification{
		Identities: []*Identity{{Sigstore: &IdentitySigstore{
			Issuer:              "https://token.actions.githubusercontent.com",
			Identity:            "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
			SourceRepositoryUri: "https://github.com/myorg/repo",
			BuildConfigUri:      "https://github.com/myorg/repo/.github/workflows/caller.yml@refs/tags/v1.2.3",
			BuildTrigger:        "release",
			SourceRepositoryRef: "refs/tags/v1.2.3",
		}}},
	}
	for _, tt := range []struct {
		name     string
		expected *IdentitySigstore
		matches  bool
	}{
		{
			"both-matchers-set",
			&IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"},
				},
				IdentityMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: `https://github\.com/myorg/repo/.+@refs/tags/v.+`},
				},
			},
			true,
		},
		{
			"issuer-match-glob",
			&IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Glob{Glob: "https://token.actions.githubusercontent.com"},
				},
				IdentityMatch: &StringMatcher{
					Kind: &StringMatcher_Prefix{Prefix: "https://github.com/myorg/"},
				},
			},
			true,
		},
		{
			"identity-match-prefix-collision-rejected",
			&IdentitySigstore{
				IdentityMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: `https://github\.com/myorg`},
				},
			},
			false,
		},
		{
			"legacy-plus-matcher-both-must-pass",
			&IdentitySigstore{
				Issuer:   "https://token.actions.githubusercontent.com",
				Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				IdentityMatch: &StringMatcher{
					Kind: &StringMatcher_Prefix{Prefix: "https://github.com/OTHER/"},
				},
			},
			false, // legacy passes, matcher fails → reject
		},
		{
			"matcher-only-issuer-accepts-any-identity",
			&IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"},
				},
			},
			true,
		},
		{
			"source-repo-match-only-positive",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"},
				},
			},
			true,
		},
		{
			"source-repo-match-prefix-positive",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{
					Kind: &StringMatcher_Prefix{Prefix: "https://github.com/myorg/"},
				},
			},
			true,
		},
		{
			"source-repo-match-only-wrong-value",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/other/repo"},
				},
			},
			false,
		},
		{
			"source-repo-from-context-unresolved-fails-closed",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{FromContext: "source_repo"},
			},
			false,
		},
		{
			"build-config-match-only-positive",
			&IdentitySigstore{
				BuildConfigUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo/.github/workflows/caller.yml@refs/tags/v1.2.3"},
				},
			},
			true,
		},
		{
			"build-config-match-only-wrong-value",
			&IdentitySigstore{
				BuildConfigUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/other/repo/.github/workflows/caller.yml@refs/tags/v1.2.3"},
				},
			},
			false,
		},
		{
			"build-config-match-combined-with-issuer-and",
			&IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"},
				},
				BuildConfigUriMatch: &StringMatcher{
					Kind: &StringMatcher_Prefix{Prefix: "https://github.com/myorg/repo/"},
				},
			},
			true,
		},
		{
			"source-repo-match-combined-with-issuer-and",
			&IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"},
				},
				SourceRepositoryUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"},
				},
			},
			true,
		},
		{
			"source-repo-match-combined-issuer-ok-repo-wrong",
			&IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"},
				},
				SourceRepositoryUriMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://github.com/other/repo"},
				},
			},
			false,
		},
		{
			"build-trigger-match-anchored-positive",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"}},
				BuildTriggerMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
			},
			true,
		},
		{
			"build-trigger-match-anchored-wrong-value",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"}},
				BuildTriggerMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "pull_request"}},
			},
			false,
		},
		{
			"build-trigger-match-only-rejected",
			&IdentitySigstore{
				BuildTriggerMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
			},
			false,
		},
		{
			"source-ref-match-glob-anchored-positive",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"}},
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Glob{Glob: "refs/tags/v*"}},
			},
			true,
		},
		{
			"source-ref-match-anchored-wrong-value",
			&IdentitySigstore{
				SourceRepositoryUriMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://github.com/myorg/repo"}},
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "refs/heads/main"}},
			},
			false,
		},
		{
			"build-trigger-with-issuer-only-rejected",
			&IdentitySigstore{
				IssuerMatch:       &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"}},
				BuildTriggerMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
			},
			false,
		},
		{
			"issuer-match-only-still-matches",
			&IdentitySigstore{
				IssuerMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"}},
			},
			true,
		},
		{
			"refinements-only-rejected",
			&IdentitySigstore{
				BuildTriggerMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Glob{Glob: "refs/tags/v*"}},
			},
			false,
		},
		{
			"build-trigger-and-source-ref-combined-with-identity-and",
			&IdentitySigstore{
				IdentityMatch: &StringMatcher{
					Kind: &StringMatcher_Prefix{Prefix: "https://github.com/myorg/repo/"},
				},
				BuildTriggerMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "release"}},
				SourceRepositoryRefMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "refs/heads/main"}},
			},
			false,
		},
		{
			"no-constraint-at-all-rejected",
			&IdentitySigstore{},
			false,
		},
		{
			"legacy-half-specified-rejected",
			&IdentitySigstore{Issuer: "https://token.actions.githubusercontent.com"},
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, signer.MatchesSigstoreIdentity(tt.expected))
		})
	}
}

func TestMatchesKeyIdentityConvenienceMatchers(t *testing.T) {
	t.Parallel()
	signer := &SignatureVerification{
		Identities: []*Identity{{Key: &IdentityKey{
			Id:                 "PRIMARYFP01",
			Type:               "ecdsa-sha2-nistp256",
			SigningFingerprint: "SUBKEYFP02",
		}}},
	}
	for _, tt := range []struct {
		name     string
		expected *IdentityKey
		matches  bool
	}{
		{
			"id-match-against-primary",
			&IdentityKey{IdMatch: &StringMatcher{
				Kind: &StringMatcher_Exact{Exact: "PRIMARYFP01"},
			}},
			true,
		},
		{
			"id-match-against-subkey",
			&IdentityKey{IdMatch: &StringMatcher{
				Kind: &StringMatcher_Exact{Exact: "SUBKEYFP02"},
			}},
			true,
		},
		{
			"id-match-case-insensitive",
			&IdentityKey{IdMatch: &StringMatcher{
				Kind:            &StringMatcher_Exact{Exact: "primaryfp01"},
				CaseInsensitive: true,
			}},
			true,
		},
		{
			"type-match-glob",
			&IdentityKey{
				IdMatch:   &StringMatcher{Kind: &StringMatcher_Exact{Exact: "PRIMARYFP01"}},
				TypeMatch: &StringMatcher{Kind: &StringMatcher_Glob{Glob: "ecdsa-*"}},
			},
			true,
		},
		{
			"type-match-strict-mismatch",
			&IdentityKey{
				IdMatch:   &StringMatcher{Kind: &StringMatcher_Exact{Exact: "PRIMARYFP01"}},
				TypeMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "rsa"}},
			},
			false,
		},
		{
			"signing-fp-match-strict",
			&IdentityKey{
				IdMatch:                 &StringMatcher{Kind: &StringMatcher_Exact{Exact: "PRIMARYFP01"}},
				SigningFingerprintMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "SUBKEYFP02"}},
			},
			true,
		},
		{
			"signing-fp-match-mismatch",
			&IdentityKey{
				IdMatch:                 &StringMatcher{Kind: &StringMatcher_Exact{Exact: "PRIMARYFP01"}},
				SigningFingerprintMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "OTHER"}},
			},
			false,
		},
		{
			"legacy-plus-matcher-both-must-pass",
			&IdentityKey{
				Id:                      "PRIMARYFP01",
				SigningFingerprintMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "OTHER"}},
			},
			false,
		},
		{
			"no-id-dimension-rejected",
			&IdentityKey{},
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, signer.MatchesKeyIdentity(tt.expected))
		})
	}
}

// TestMatchesIdentityOuterMatchers exercises the outer matchers slice —
// the canonical expectation-side check layer that lives on Identity.matchers.
// Each matcher targets a dotted field path on the signer; the special
// "principal" field matches the whole principal string regardless of
// variant. All set constraints AND together with the variant check.
func TestMatchesIdentityOuterMatchers(t *testing.T) {
	t.Parallel()

	sigstoreSigner := &SignatureVerification{
		Identities: []*Identity{{Sigstore: &IdentitySigstore{
			Issuer:              "https://token.actions.githubusercontent.com",
			Identity:            "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
			SourceRepositoryUri: "https://github.com/myorg/repo",
			BuildConfigUri:      "https://github.com/myorg/repo/.github/workflows/caller.yml@refs/tags/v1.2.3",
			BuildTrigger:        "release",
			SourceRepositoryRef: "refs/tags/v1.2.3",
		}}},
	}
	spiffeSigner := &SignatureVerification{
		Identities: []*Identity{{Spiffe: &IdentitySpiffe{Svid: "spiffe://prod.example.org/workload/api"}}},
	}

	stringMatch := func(field, exact string) *Matcher {
		return &Matcher{
			Field: field,
			Kind: &Matcher_String_{String_: &StringMatcher{
				Kind: &StringMatcher_Exact{Exact: exact},
			}},
		}
	}
	stringPrefix := func(field, prefix string) *Matcher {
		return &Matcher{
			Field: field,
			Kind: &Matcher_String_{String_: &StringMatcher{
				Kind: &StringMatcher_Prefix{Prefix: prefix},
			}},
		}
	}
	stringRegex := func(field, re string) *Matcher {
		return &Matcher{
			Field: field,
			Kind: &Matcher_String_{String_: &StringMatcher{
				Kind: &StringMatcher_Regex{Regex: re},
			}},
		}
	}

	for _, tt := range []struct {
		name     string
		sv       *SignatureVerification
		expected *Identity
		matches  bool
	}{
		{
			"sigstore-variant-only-no-outer",
			sigstoreSigner,
			&Identity{Sigstore: &IdentitySigstore{
				Issuer:   "https://token.actions.githubusercontent.com",
				Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
			}},
			true,
		},
		{
			"outer-matcher-passes-alongside-variant",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringPrefix("sigstore.identity", "https://github.com/myorg/"),
				},
			},
			true,
		},
		{
			"outer-matcher-fails-rejects-whole-identity",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					// Variant passes; outer forces a different issuer. Overall reject.
					stringMatch("sigstore.issuer", "https://accounts.google.com"),
				},
			},
			false,
		},
		{
			"principal-field-matches-any-variant",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringRegex("principal", `sigstore::.*myorg.*`),
				},
			},
			true,
		},
		{
			"spiffe-trust-domain-virtual-field",
			spiffeSigner,
			&Identity{
				Spiffe: &IdentitySpiffe{Svid: "spiffe://prod.example.org/workload/api"},
				Matchers: []*Matcher{
					stringMatch("spiffe.trust_domain", "prod.example.org"),
				},
			},
			true,
		},
		{
			"spiffe-path-virtual-field-mismatch",
			spiffeSigner,
			&Identity{
				Spiffe: &IdentitySpiffe{Svid: "spiffe://prod.example.org/workload/api"},
				Matchers: []*Matcher{
					stringMatch("spiffe.path", "/other"),
				},
			},
			false,
		},
		{
			"principal-on-spiffe-signer",
			spiffeSigner,
			&Identity{
				Spiffe: &IdentitySpiffe{Svid: "spiffe://prod.example.org/workload/api"},
				Matchers: []*Matcher{
					stringMatch("principal", "spiffe://prod.example.org/workload/api"),
				},
			},
			true,
		},
		{
			"outer-field-inapplicable-to-signer-variant",
			sigstoreSigner,
			// Expectation selects sigstore variant but an outer matcher
			// targets spiffe.path — doesn't apply to this signer's
			// variant; fail closed.
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringMatch("spiffe.path", "/anything"),
				},
			},
			false,
		},
		{
			"multiple-outer-matchers-all-must-pass",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringPrefix("sigstore.identity", "https://github.com/myorg/"),
					stringMatch("sigstore.issuer", "https://token.actions.githubusercontent.com"),
				},
			},
			true,
		},
		{
			"outer-source-repo-matches",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringMatch("sigstore.source_repository_uri", "https://github.com/myorg/repo"),
				},
			},
			true,
		},
		{
			"outer-source-repo-mismatch",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringMatch("sigstore.source_repository_uri", "https://github.com/other/repo"),
				},
			},
			false,
		},
		{
			"outer-build-trigger-and-source-ref-match",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringMatch("sigstore.build_trigger", "release"),
					stringPrefix("sigstore.source_repository_ref", "refs/tags/"),
				},
			},
			true,
		},
		{
			"outer-build-trigger-mismatch",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringMatch("sigstore.build_trigger", "pull_request_target"),
				},
			},
			false,
		},
		{
			"unknown-field-fails-closed",
			sigstoreSigner,
			&Identity{
				Sigstore: &IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Matchers: []*Matcher{
					stringMatch("sigstore.unknown", "x"),
				},
			},
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, tt.sv.MatchesIdentity(tt.expected))
		})
	}
}

func TestMatchesSigstoreIdentityRegexAnchored(t *testing.T) {
	t.Parallel()
	// Signer fixture — simulates a verified signature from myorg's CI.
	sv := &SignatureVerification{
		Identities: []*Identity{{Sigstore: &IdentitySigstore{
			Issuer:   "https://token.actions.githubusercontent.com",
			Identity: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/heads/main",
		}}},
	}

	for _, tt := range []struct {
		name     string
		expected *IdentitySigstore
		matches  bool
	}{
		{
			"exact-full-match",
			sigRegexp(`https://github\.com/myorg/repo/.*`),
			true,
		},
		{
			// Prefix-collision attack: the signer's SAN starts with
			// `https://github.com/myorg` — under unanchored matching an
			// expectation meant to pin "myorg" would also match
			// "myorg-evil". Anchoring forces the pattern to cover the
			// entire SAN.
			"prefix-rejects-longer-signer",
			sigRegexp(`https://github\.com/myorg`),
			false,
		},
		{
			// Substring-in-the-middle attack: the expected pattern
			// appears as a substring of the SAN but isn't the whole
			// thing.
			"substring-rejected",
			sigRegexp(`myorg/repo`),
			false,
		},
		{
			// Anchored pattern users may write explicitly — still works.
			"user-anchored-pattern",
			sigRegexp(`^https://github\.com/myorg/repo/.+@refs/heads/main$`),
			true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, sv.MatchesSigstoreIdentity(tt.expected))
		})
	}
}

func TestMatchesSpiffeIdentity(t *testing.T) {
	t.Parallel()
	// Shorthand: build a signer with the given svid.
	signer := func(svid string) *SignatureVerification {
		return &SignatureVerification{
			Identities: []*Identity{{Spiffe: &IdentitySpiffe{Svid: svid}}},
		}
	}
	for _, tt := range []struct {
		name    string
		matches bool
		sut     *SignatureVerification
		id      *IdentitySpiffe
	}{
		{
			"svid-exact-match", true,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{Svid: "spiffe://example.org/workload"},
		},
		{
			"svid-exact-mismatch", false,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{Svid: "spiffe://example.org/other"},
		},
		{
			"svid-match-regex", true,
			signer("spiffe://example.org/workload/api"),
			&IdentitySpiffe{SvidMatch: &StringMatcher{
				Kind: &StringMatcher_Regex{Regex: `spiffe://example\.org/workload/.+`},
			}},
		},
		{
			"svid-match-prefix", true,
			signer("spiffe://example.org/workload/api"),
			&IdentitySpiffe{SvidMatch: &StringMatcher{
				Kind: &StringMatcher_Prefix{Prefix: "spiffe://example.org/workload/"},
			}},
		},
		{
			"svid-match-glob", true,
			signer("spiffe://example.org/workload/api"),
			&IdentitySpiffe{SvidMatch: &StringMatcher{
				Kind: &StringMatcher_Glob{Glob: "spiffe://example.org/workload/*"},
			}},
		},
		{
			"trust-domain-match-exact", true,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{TrustDomainMatch: &StringMatcher{
				Kind: &StringMatcher_Exact{Exact: "example.org"},
			}},
		},
		{
			"trust-domain-match-mismatch", false,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{TrustDomainMatch: &StringMatcher{
				Kind: &StringMatcher_Exact{Exact: "other.example"},
			}},
		},
		{
			// Regex matchers are anchored — pattern /work must NOT match
			// /workload-stealer via prefix collision.
			"path-match-regex-anchored", false,
			signer("spiffe://example.org/workload-stealer"),
			&IdentitySpiffe{PathMatch: &StringMatcher{
				Kind: &StringMatcher_Regex{Regex: `/work`},
			}},
		},
		{
			"path-match-glob", true,
			signer("spiffe://example.org/workload/api/v1"),
			&IdentitySpiffe{PathMatch: &StringMatcher{
				Kind: &StringMatcher_Glob{Glob: "/workload/*/*"},
			}},
		},
		{
			"td-and-path-matchers-both-required", true,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{
				TrustDomainMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "example.org"}},
				PathMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "/workload"}},
			},
		},
		{
			"td-and-path-matchers-one-fails", false,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{
				TrustDomainMatch: &StringMatcher{Kind: &StringMatcher_Exact{Exact: "example.org"}},
				PathMatch:        &StringMatcher{Kind: &StringMatcher_Exact{Exact: "/other"}},
			},
		},
		{
			"no-constraint-rejected", false,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{},
		},
		{
			"non-spiffe-signer-ignored", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc"}}},
			},
			&IdentitySpiffe{Svid: "spiffe://example.org/workload"},
		},
		{
			"two-signers-second-matches", true,
			&SignatureVerification{
				Identities: []*Identity{
					{Spiffe: &IdentitySpiffe{Svid: "spiffe://other.example/a"}},
					{Spiffe: &IdentitySpiffe{Svid: "spiffe://example.org/b"}},
				},
			},
			&IdentitySpiffe{Svid: "spiffe://example.org/b"},
		},
		{
			// trust_roots on the expectation side is ignored for matching
			// — it's verifier config, not a signer attribute.
			"trust-roots-ignored-for-matching", true,
			signer("spiffe://example.org/workload"),
			&IdentitySpiffe{
				Svid:       "spiffe://example.org/workload",
				TrustRoots: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
			},
		},
		{
			"empty-identities", false,
			&SignatureVerification{Identities: []*Identity{}},
			&IdentitySpiffe{Svid: "spiffe://example.org/workload"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, tt.sut.MatchesSpiffeIdentity(tt.id))
		})
	}
}

func TestSignatureVerificationFromResult(t *testing.T) {
	t.Parallel()

	t.Run("nil-result-unverified", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(nil)
		require.False(t, sv.GetVerified())
		require.Empty(t, sv.GetIdentities())
	})

	t.Run("spiffe-san-produces-spiffe-identity", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			VerifiedIdentity: &verify.CertificateIdentity{
				SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{
					SubjectAlternativeName: "spiffe://example.org/workload",
				},
			},
		})
		require.True(t, sv.GetVerified())
		require.Len(t, sv.GetIdentities(), 1)
		spiffe := sv.GetIdentities()[0].GetSpiffe()
		require.NotNil(t, spiffe)
		require.Equal(t, "spiffe://example.org/workload", spiffe.GetSvid())
	})

	t.Run("fulcio-identity-produces-sigstore-identity", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			VerifiedIdentity: &verify.CertificateIdentity{
				SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{
					SubjectAlternativeName: "user@example.com",
				},
				Issuer: verify.IssuerMatcher{Issuer: "https://accounts.google.com"},
			},
		})
		require.True(t, sv.GetVerified())
		require.Len(t, sv.GetIdentities(), 1)
		ss := sv.GetIdentities()[0].GetSigstore()
		require.NotNil(t, ss)
		require.Equal(t, "https://accounts.google.com", ss.GetIssuer())
		require.Equal(t, "user@example.com", ss.GetIdentity())
	})

	t.Run("fulcio-captures-source-repository-uri", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			VerifiedIdentity: &verify.CertificateIdentity{
				SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{
					SubjectAlternativeName: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				},
				Issuer: verify.IssuerMatcher{Issuer: "https://token.actions.githubusercontent.com"},
			},
			Signature: &verify.SignatureVerificationResult{
				Certificate: &certificate.Summary{
					Extensions: certificate.Extensions{
						SourceRepositoryURI: "https://github.com/myorg/repo",
						BuildConfigURI:      "https://github.com/myorg/repo/.github/workflows/caller.yml@refs/tags/v1.2.3",
						BuildTrigger:        "release",
						SourceRepositoryRef: "refs/tags/v1.2.3",
					},
				},
			},
		})
		require.True(t, sv.GetVerified())
		require.Len(t, sv.GetIdentities(), 1)
		ss := sv.GetIdentities()[0].GetSigstore()
		require.NotNil(t, ss)
		require.Equal(t, "https://github.com/myorg/repo", ss.GetSourceRepositoryUri())
		require.Equal(t, "https://github.com/myorg/repo/.github/workflows/caller.yml@refs/tags/v1.2.3", ss.GetBuildConfigUri())
		require.Equal(t, "release", ss.GetBuildTrigger())
		require.Equal(t, "refs/tags/v1.2.3", ss.GetSourceRepositoryRef())
	})

	t.Run("identity-check-skipped-reads-certificate-summary", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			Signature: &verify.SignatureVerificationResult{
				Certificate: &certificate.Summary{
					SubjectAlternativeName: "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
					Extensions: certificate.Extensions{
						Issuer:              "https://token.actions.githubusercontent.com",
						SourceRepositoryURI: "https://github.com/myorg/repo",
					},
				},
			},
		})
		require.True(t, sv.GetVerified())
		require.Len(t, sv.GetIdentities(), 1)
		ss := sv.GetIdentities()[0].GetSigstore()
		require.NotNil(t, ss)
		require.Equal(t, "https://token.actions.githubusercontent.com", ss.GetIssuer())
		require.Equal(t, "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3", ss.GetIdentity())
		require.Equal(t, "https://github.com/myorg/repo", ss.GetSourceRepositoryUri())
	})

	t.Run("identity-check-skipped-spiffe-certificate-summary", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			Signature: &verify.SignatureVerificationResult{
				Certificate: &certificate.Summary{SubjectAlternativeName: "spiffe://example.org/workload"},
			},
		})
		require.True(t, sv.GetVerified())
		require.Len(t, sv.GetIdentities(), 1)
		require.Equal(t, "spiffe://example.org/workload", sv.GetIdentities()[0].GetSpiffe().GetSvid())
	})

	t.Run("verified-identity-takes-precedence-over-summary", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			VerifiedIdentity: &verify.CertificateIdentity{
				SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{SubjectAlternativeName: "policy@example.com"},
				Issuer:                 verify.IssuerMatcher{Issuer: "https://policy.example.com"},
			},
			Signature: &verify.SignatureVerificationResult{
				Certificate: &certificate.Summary{
					SubjectAlternativeName: "summary@example.com",
					Extensions:             certificate.Extensions{Issuer: "https://summary.example.com"},
				},
			},
		})
		require.Len(t, sv.GetIdentities(), 1)
		require.Equal(t, "policy@example.com", sv.GetIdentities()[0].GetSigstore().GetIdentity())
	})

	t.Run("no-identity-and-no-certificate-is-verified-without-signers", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{})
		require.True(t, sv.GetVerified())
		require.Empty(t, sv.GetIdentities())
	})

	t.Run("fulcio-no-signature-empty-source-repo", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			VerifiedIdentity: &verify.CertificateIdentity{
				SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{
					SubjectAlternativeName: "user@example.com",
				},
				Issuer: verify.IssuerMatcher{Issuer: "https://accounts.google.com"},
			},
		})
		require.True(t, sv.GetVerified())
		require.Len(t, sv.GetIdentities(), 1)
		ss := sv.GetIdentities()[0].GetSigstore()
		require.NotNil(t, ss)
		require.Empty(t, ss.GetSourceRepositoryUri())
	})

	t.Run("spiffe-san-with-cert-does-not-capture-source-repo", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			VerifiedIdentity: &verify.CertificateIdentity{
				SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{
					SubjectAlternativeName: "spiffe://example.org/workload",
				},
			},
			Signature: &verify.SignatureVerificationResult{
				Certificate: &certificate.Summary{
					Extensions: certificate.Extensions{
						SourceRepositoryURI: "https://github.com/myorg/repo",
					},
				},
			},
		})
		require.True(t, sv.GetVerified())
		require.Len(t, sv.GetIdentities(), 1)
		require.NotNil(t, sv.GetIdentities()[0].GetSpiffe())
		require.Nil(t, sv.GetIdentities()[0].GetSigstore())
	})

	t.Run("result-without-verified-identity", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{})
		require.True(t, sv.GetVerified())
		require.Empty(t, sv.GetIdentities())
	})

	t.Run("malformed-spiffe-san-falls-through-to-empty", func(t *testing.T) {
		t.Parallel()
		sv := SignatureVerificationFromResult(&verify.VerificationResult{
			VerifiedIdentity: &verify.CertificateIdentity{
				SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{
					SubjectAlternativeName: "spiffe:///workload", // missing trust domain
				},
			},
		})
		// Verified stays true (the cryptographic verification succeeded)
		// but no identity was extractable.
		require.True(t, sv.GetVerified())
		require.Empty(t, sv.GetIdentities())
	})
}

// TestMatchesIdentityDispatchesSpiffe confirms the top-level dispatcher
// routes SPIFFE-shaped identities to MatchesSpiffeIdentity.
func TestMatchesIdentityDispatchesSpiffe(t *testing.T) {
	t.Parallel()
	sv := &SignatureVerification{
		Identities: []*Identity{{Spiffe: &IdentitySpiffe{Svid: "spiffe://example.org/workload"}}},
	}
	require.True(t, sv.MatchesIdentity(&Identity{
		Spiffe: &IdentitySpiffe{Svid: "spiffe://example.org/workload"},
	}))
	require.False(t, sv.MatchesIdentity(&Identity{
		Spiffe: &IdentitySpiffe{Svid: "spiffe://other.example/workload"},
	}))
}

func TestMatchesKeyIdentityDoesNotMutate(t *testing.T) {
	t.Parallel()
	keyData := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n"

	identity := &IdentityKey{Data: keyData}
	sv := &SignatureVerification{
		Identities: []*Identity{{Key: &IdentityKey{Id: "5be34774cae03891"}}},
	}

	require.True(t, sv.MatchesKeyIdentity(identity))

	// The original identity must not be mutated.
	require.Empty(t, identity.GetId())
	require.Empty(t, identity.GetType())
	require.Equal(t, keyData, identity.GetData())
}

func TestIdentitySigstoreFromCertificate(t *testing.T) {
	t.Parallel()
	const (
		issuer = "https://token.actions.githubusercontent.com"
		san    = "https://github.com/myorg/repo/.github/workflows/provenance.yml@refs/tags/v1.2.3"
	)
	for _, tt := range []struct {
		name        string
		cert        *certificate.Summary
		wantTrigger string
		wantRef     string
	}{
		{"no-certificate", nil, "", ""},
		{
			"current-extensions",
			&certificate.Summary{Extensions: certificate.Extensions{
				SourceRepositoryURI: "https://github.com/myorg/repo",
				BuildConfigURI:      "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
				BuildTrigger:        "release",
				SourceRepositoryRef: "refs/tags/v1.2.3",
			}},
			"release", "refs/tags/v1.2.3",
		},
		{
			"deprecated-github-extensions",
			&certificate.Summary{Extensions: certificate.Extensions{
				GithubWorkflowTrigger: "release",
				GithubWorkflowRef:     "refs/tags/v1.2.3",
			}},
			"release", "refs/tags/v1.2.3",
		},
		{
			"current-extensions-win",
			&certificate.Summary{Extensions: certificate.Extensions{
				BuildTrigger:          "release",
				SourceRepositoryRef:   "refs/tags/v1.2.3",
				GithubWorkflowTrigger: "push",
				GithubWorkflowRef:     "refs/heads/main",
			}},
			"release", "refs/tags/v1.2.3",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ss := IdentitySigstoreFromCertificate(issuer, san, tt.cert)
			require.Equal(t, issuer, ss.GetIssuer())
			require.Equal(t, san, ss.GetIdentity())
			require.Equal(t, tt.wantTrigger, ss.GetBuildTrigger())
			require.Equal(t, tt.wantRef, ss.GetSourceRepositoryRef())
			if tt.cert != nil {
				require.Equal(t, tt.cert.SourceRepositoryURI, ss.GetSourceRepositoryUri())
				require.Equal(t, tt.cert.BuildConfigURI, ss.GetBuildConfigUri())
			}
		})
	}
}
