// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/policylabs/attestation"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/protobuf/proto"
)

// Ensure we are implementing the framworks verification
var _ attestation.Verification = (*Verification)(nil) //nolint:errcheck

// SignatureVerificationFromResult translates sigstore-go's
// *verify.VerificationResult into the api/v1 SignatureVerification used for
// identity matching. Handles both sigstore and SPIFFE flows: a spiffe://
// SAN produces an IdentitySpiffe; any other SAN/Issuer pair produces an
// IdentitySigstore.
//
// The signer is read from VerifiedIdentity when an identity policy was
// evaluated. When verification ran without one (WithoutIdentitiesUnsafe,
// as set by options.WithSkipIdentityCheck) sigstore-go leaves
// VerifiedIdentity nil, and the signer is read from the verified
// certificate's summary instead: the chain and signature were checked,
// only the match against an expectation was skipped, so the certificate's
// identity is still the verified signer.
//
// Pass a nil result (e.g. when verification failed) to get back an empty,
// unverified SignatureVerification. Callers typically invoke this after a
// successful Verify call:
//
//	result, err := verifier.Verify(nil, bndl)
//	if err != nil {
//	    return err
//	}
//	sv := api.SignatureVerificationFromResult(result)
//	if !sv.MatchesIdentity(expected) {
//	    return errors.New("signer did not match expected identity")
//	}
func SignatureVerificationFromResult(r *verify.VerificationResult) *SignatureVerification {
	if r == nil {
		return &SignatureVerification{}
	}
	sv := &SignatureVerification{Verified: true}

	var san, issuer string
	switch {
	case r.VerifiedIdentity != nil:
		san = r.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
		issuer = r.VerifiedIdentity.Issuer.Issuer
	case r.Signature != nil && r.Signature.Certificate != nil:
		san = r.Signature.Certificate.SubjectAlternativeName
		issuer = r.Signature.Certificate.Issuer
	default:
		return sv
	}

	switch {
	case strings.HasPrefix(san, "spiffe://"):
		id, err := IdentitySpiffeFromString(san)
		if err != nil {
			return sv
		}
		sv.Identities = append(sv.Identities, &Identity{Spiffe: id})
	case san != "" || issuer != "":
		ss := &IdentitySigstore{Issuer: issuer, Identity: san}
		if r.Signature != nil && r.Signature.Certificate != nil {
			ss.SourceRepositoryUri = r.Signature.Certificate.SourceRepositoryURI
			ss.BuildConfigUri = r.Signature.Certificate.BuildConfigURI
		}
		sv.Identities = append(sv.Identities, &Identity{Sigstore: ss})
	}
	return sv
}

// anchoredRegex wraps a user-supplied pattern so it must match the full
// input end-to-end. Without anchoring, Go's regexp.MatchString returns
// true on any substring match — a caller authoring an identity regex
// would reasonably expect full-string semantics (same convention as
// sigstore-go's cert-identity verification and cosign), and an
// unanchored pattern enables prefix/substring collision attacks.
func anchoredRegex(pattern string) string {
	return "^(?:" + pattern + ")$"
}

// Error implements the Go error interface when verification fails
func (v *Verification) Error() string {
	if !v.GetVerified() && v.GetSignature() != nil {
		return v.GetSignature().GetError()
	}
	return ""
}

// MatchesIdentity returns true if one of the verified signatures matches
// the identity.
func (v *Verification) MatchesIdentity(rawID any) bool {
	id, ok := rawID.(*Identity)
	if !ok {
		return false
	}
	if v.GetSignature() == nil {
		return false
	}

	return v.GetSignature().MatchesIdentity(id)
}

// GetVerified returns true if verification passed
func (v *Verification) GetVerified() bool {
	if v.GetSignature() == nil {
		return false
	}
	return v.GetSignature().GetVerified()
}

// MatchesIdentity returns true when at least one verified signer satisfies
// the variant-specific check AND every outer matcher in id.GetMatchers()
// passes for that same signer. AND semantics — all set constraints must
// pass for a signer to be accepted.
func (sv *SignatureVerification) MatchesIdentity(id *Identity) bool {
	variant, ok := variantCheck(id)
	if !ok {
		return false
	}
	outer := id.GetMatchers()
	for _, signer := range sv.GetIdentities() {
		if !variant(signer) {
			continue
		}
		if !outerMatchersPass(signer, outer) {
			continue
		}
		return true
	}
	return false
}

// variantCheck returns a per-signer check capturing the variant-
// specific preconditions + precomputed state (regex compiles, key
// normalization). Returns (nil, false) when the expected identity has
// no variant selected or its preconditions fail.
func variantCheck(id *Identity) (func(*Identity) bool, bool) {
	switch {
	case id.GetSigstore() != nil:
		return sigstoreCheck(id.GetSigstore())
	case id.GetKey() != nil:
		return keyCheck(id.GetKey())
	case id.GetSpiffe() != nil:
		return spiffeCheck(id.GetSpiffe())
	}
	return nil, false
}

// MatchesSigstoreIdentity returns true if one of the verified signatures
// matches the supplied sigstore identity. Matching rules:
//
//   - Legacy fields (Issuer + Identity + Mode): when used, BOTH Issuer
//     and Identity must be set. Mode chooses literal-equality or
//     (anchored) regex semantics for the pair. Both must match.
//   - Convenience matchers (IssuerMatch / IdentityMatch): independent
//     StringMatchers layered on top. Each, when set, must pass.
//   - Legacy and convenience forms may be combined — all constraints
//     that are set must match the signer (AND semantics).
//
// An expectation that sets NO constraint across either path matches
// nothing. An expectation that sets exactly one legacy field (Issuer
// OR Identity but not both) is treated as malformed and matches nothing,
// preserving the previous "both required" contract for legacy-only
// expectations.
func (sv *SignatureVerification) MatchesSigstoreIdentity(id *IdentitySigstore) bool {
	check, ok := sigstoreCheck(id)
	if !ok {
		return false
	}
	return slices.ContainsFunc(sv.GetIdentities(), check)
}

// sigstoreCheck builds a per-signer check from an expected sigstore
// identity. Returns (nil, false) when the expectation is malformed or
// sets no constraint: captures the legacy "both required" rule and
// precompiles any regex patterns so failures surface before the signer
// loop.
func sigstoreCheck(id *IdentitySigstore) (func(*Identity) bool, bool) {
	issuerLegacy := id.GetIssuer()
	identityLegacy := id.GetIdentity()
	issuerMatch := id.GetIssuerMatch()
	identityMatch := id.GetIdentityMatch()
	sourceRepoMatch := id.GetSourceRepositoryUriMatch()
	buildConfigMatch := id.GetBuildConfigUriMatch()

	useLegacy := issuerLegacy != "" || identityLegacy != ""
	useMatchers := issuerMatch != nil || identityMatch != nil || sourceRepoMatch != nil || buildConfigMatch != nil
	if !useLegacy && !useMatchers {
		return nil, false
	}
	if useLegacy && (issuerLegacy == "" || identityLegacy == "") && !useMatchers {
		return nil, false
	}

	var regIssuer, regIdentity *regexp.Regexp
	if id.GetMode() == SigstoreModeRegexp {
		if issuerLegacy != "" {
			re, err := regexp.Compile(anchoredRegex(issuerLegacy))
			if err != nil {
				return nil, false
			}
			regIssuer = re
		}
		if identityLegacy != "" {
			re, err := regexp.Compile(anchoredRegex(identityLegacy))
			if err != nil {
				return nil, false
			}
			regIdentity = re
		}
	}
	regexpMode := id.GetMode() == SigstoreModeRegexp

	return func(signer *Identity) bool {
		ss := signer.GetSigstore()
		if ss == nil {
			return false
		}
		signerIssuer := ss.GetIssuer()
		signerIdentity := ss.GetIdentity()

		if issuerLegacy != "" {
			if regexpMode {
				if !regIssuer.MatchString(signerIssuer) {
					return false
				}
			} else if signerIssuer != issuerLegacy {
				return false
			}
		}
		if identityLegacy != "" {
			if regexpMode {
				if !regIdentity.MatchString(signerIdentity) {
					return false
				}
			} else if signerIdentity != identityLegacy {
				return false
			}
		}
		if issuerMatch != nil && !matchString(issuerMatch, signerIssuer) {
			return false
		}
		if identityMatch != nil && !matchString(identityMatch, signerIdentity) {
			return false
		}
		if sourceRepoMatch != nil && !matchString(sourceRepoMatch, ss.GetSourceRepositoryUri()) {
			return false
		}
		if buildConfigMatch != nil && !matchString(buildConfigMatch, ss.GetBuildConfigUri()) {
			return false
		}
		return true
	}, true
}

// MatchesSpiffeIdentity returns true if one of the verified signatures was
// produced by a SPIFFE workload matching the supplied identity. Matching
// rules:
//
//   - Svid (optional, exact): when set, the signer's svid must match this
//     URI exactly.
//   - SvidMatch (optional): StringMatcher applied to the full signer
//     svid URI.
//   - TrustDomainMatch / PathMatch (optional): StringMatchers applied to
//     the trust-domain / path components parsed from the signer's svid
//     at eval time. If the signer's svid doesn't parse as a valid SPIFFE
//     ID, these matchers fail closed.
//   - TrustRoots is not consulted here — it is verifier configuration
//     used to validate the chain, not an attribute of the signer.
//
// All conditions that are set must pass (AND semantics). At least one
// constraint must be specified; an identity with none of svid, svid_match,
// trust_domain_match, or path_match set matches nothing.
func (sv *SignatureVerification) MatchesSpiffeIdentity(id *IdentitySpiffe) bool {
	check, ok := spiffeCheck(id)
	if !ok {
		return false
	}
	return slices.ContainsFunc(sv.GetIdentities(), check)
}

// spiffeCheck builds a per-signer check from an expected SPIFFE
// identity. trust_domain_match and path_match parse the signer's svid
// at eval time via spiffeid.FromString; unparseable SVIDs fail closed.
func spiffeCheck(id *IdentitySpiffe) (func(*Identity) bool, bool) {
	svid := id.GetSvid()
	svidMatch := id.GetSvidMatch()
	tdMatch := id.GetTrustDomainMatch()
	pathMatch := id.GetPathMatch()

	if svid == "" && svidMatch == nil && tdMatch == nil && pathMatch == nil {
		return nil, false
	}
	needsParsed := tdMatch != nil || pathMatch != nil

	return func(signer *Identity) bool {
		sp := signer.GetSpiffe()
		if sp == nil {
			return false
		}
		sSvid := sp.GetSvid()

		if svid != "" && sSvid != svid {
			return false
		}
		if svidMatch != nil && !matchString(svidMatch, sSvid) {
			return false
		}
		if needsParsed {
			parsed, err := spiffeid.FromString(sSvid)
			if err != nil {
				return false
			}
			if tdMatch != nil && !matchString(tdMatch, parsed.TrustDomain().Name()) {
				return false
			}
			if pathMatch != nil && !matchString(pathMatch, parsed.Path()) {
				return false
			}
		}
		return true
	}, true
}

// outerMatchersPass evaluates the Identity.matchers slice against a
// signer. All entries must pass (AND). A matcher whose field isn't
// applicable to the signer's variant fails closed for that signer.
// An empty slice is trivially satisfied.
func outerMatchersPass(signer *Identity, matchers []*Matcher) bool {
	for _, m := range matchers {
		value, ok := resolveIdentityField(signer, m.GetField())
		if !ok {
			return false
		}
		switch kind := m.GetKind().(type) {
		case *Matcher_String_:
			if kind.String_ == nil || !matchString(kind.String_, value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// resolveIdentityField returns the value of a dotted field path on a
// signer Identity. The special field "principal" maps to Identity.Principal()
// regardless of variant. Variant-qualified paths ("sigstore.issuer",
// "key.id", "spiffe.trust_domain", ...) return ok=false when the signer
// is a different variant or the requested sub-field is unknown. SPIFFE's
// trust_domain and path are virtual — derived by parsing the signer's svid.
func resolveIdentityField(signer *Identity, field string) (string, bool) {
	if field == "principal" {
		return signer.Principal(), true
	}
	variant, name, ok := strings.Cut(field, ".")
	if !ok {
		return "", false
	}
	switch variant {
	case identityTypeSigstore:
		ss := signer.GetSigstore()
		if ss == nil {
			return "", false
		}
		switch name {
		case "issuer":
			return ss.GetIssuer(), true
		case "identity":
			return ss.GetIdentity(), true
		case "source_repository_uri":
			return ss.GetSourceRepositoryUri(), true
		case "build_config_uri":
			return ss.GetBuildConfigUri(), true
		}
	case identityTypeKey:
		k := signer.GetKey()
		if k == nil {
			return "", false
		}
		switch name {
		case "id":
			return k.GetId(), true
		case "type":
			return k.GetType(), true
		case "signing_fingerprint":
			return k.GetSigningFingerprint(), true
		}
	case identityTypeSpiffe:
		sp := signer.GetSpiffe()
		if sp == nil {
			return "", false
		}
		switch name {
		case "svid":
			return sp.GetSvid(), true
		case "trust_domain":
			id, err := spiffeid.FromString(sp.GetSvid())
			if err != nil {
				return "", false
			}
			return id.TrustDomain().Name(), true
		case "path":
			id, err := spiffeid.FromString(sp.GetSvid())
			if err != nil {
				return "", false
			}
			return id.Path(), true
		}
	}
	return "", false
}

// matchString evaluates a StringMatcher against value. An unset matcher
// matches any value (caller-controlled guard).
func matchString(m *StringMatcher, value string) bool {
	if m == nil {
		return true
	}
	// An unresolved from_context binding must be filled in by the caller (e.g.
	// ampel resolves it from the verification context) before matching. If it
	// reaches here unresolved, fail closed rather than silently ignoring it.
	if m.GetFromContext() != "" {
		return false
	}
	switch kind := m.GetKind().(type) {
	case *StringMatcher_Exact:
		if m.GetCaseInsensitive() {
			return strings.EqualFold(kind.Exact, value)
		}
		return kind.Exact == value
	case *StringMatcher_Regex:
		pattern := anchoredRegex(kind.Regex)
		if m.GetCaseInsensitive() {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	case *StringMatcher_Prefix:
		if m.GetCaseInsensitive() {
			return strings.HasPrefix(strings.ToLower(value), strings.ToLower(kind.Prefix))
		}
		return strings.HasPrefix(value, kind.Prefix)
	case *StringMatcher_Glob:
		target := value
		pattern := kind.Glob
		if m.GetCaseInsensitive() {
			target = strings.ToLower(target)
			pattern = strings.ToLower(pattern)
		}
		ok, err := path.Match(pattern, target)
		return err == nil && ok
	default:
		return false
	}
}

// MatchesKeyIdentity returns true if one of the verified signatures was
// performed with the specified key. Matching rules:
//
//   - Id (required via legacy field OR IdMatch): compared against both
//     the signer's primary key Id and its signing subkey fingerprint —
//     an expected identity can name a GPG signer by either. Legacy Id
//     is case-insensitive; IdMatch follows its StringMatcher
//     configuration.
//   - Type (optional, legacy): narrows the match when both sides set it.
//     An unset signer type skips the check. TypeMatch (new) is strict:
//     when set, the signer's type must satisfy it.
//   - SigningFingerprint (optional, legacy): case-insensitive exact pin.
//     SigningFingerprintMatch (new) is strict when set.
//
// If the identity has Data but no Id, Normalize is called first.
func (sv *SignatureVerification) MatchesKeyIdentity(keyIdentity *IdentityKey) bool {
	check, ok := keyCheck(keyIdentity)
	if !ok {
		return false
	}
	return slices.ContainsFunc(sv.GetIdentities(), check)
}

// keyCheck builds a per-signer check from an expected key identity.
// Normalize (legacy Data → Id derivation) runs once up front on a clone.
func keyCheck(keyIdentity *IdentityKey) (func(*Identity) bool, bool) {
	ki := keyIdentity
	if ki.GetId() == "" && ki.GetData() != "" {
		cloned, ok := proto.Clone(keyIdentity).(*IdentityKey)
		if ok {
			_ = cloned.Normalize() //nolint:errcheck // best effort
			ki = cloned
		}
	}

	id := strings.TrimSpace(ki.GetId())
	keyType := strings.TrimSpace(ki.GetType())
	signingFP := strings.TrimSpace(ki.GetSigningFingerprint())
	idMatch := ki.GetIdMatch()
	typeMatch := ki.GetTypeMatch()
	sfpMatch := ki.GetSigningFingerprintMatch()

	if id == "" && idMatch == nil {
		return nil, false
	}

	return func(signer *Identity) bool {
		signerKeyData := signer.GetKey()
		if signerKeyData == nil {
			return false
		}

		signerID := strings.TrimSpace(signerKeyData.GetId())
		signerSubFP := strings.TrimSpace(signerKeyData.GetSigningFingerprint())
		signerType := strings.TrimSpace(signerKeyData.GetType())

		if id != "" {
			if !strings.EqualFold(id, signerID) && !strings.EqualFold(id, signerSubFP) {
				return false
			}
		}
		if idMatch != nil && !matchString(idMatch, signerID) && !matchString(idMatch, signerSubFP) {
			return false
		}
		if keyType != "" && signerType != "" && signerType != keyType {
			return false
		}
		if typeMatch != nil && !matchString(typeMatch, signerType) {
			return false
		}
		if signingFP != "" && !strings.EqualFold(signerSubFP, signingFP) {
			return false
		}
		if sfpMatch != nil && !matchString(sfpMatch, signerSubFP) {
			return false
		}
		return true
	}, true
}
