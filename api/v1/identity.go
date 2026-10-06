// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/x509"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/policylabs/signer/key"
)

// Identity-type prefixes used in Principal/Spec strings.
const (
	identityTypeSigstore = "sigstore"
	identityTypeKey      = "key"
	identityTypeSpiffe   = "spiffe"
)

// NewIdentityFromPrincipal parses an Identity from its canonical principal
// string — a pure, matcher-free identifier. Supported forms:
//
//	sigstore::<issuer>::<identity>
//	key::<type>::<id>
//	ref:<id>
//	spiffe://<trust-domain><path>
//
// Strict: parenthetical annotations like "sigstore(regexp)::..." or
// "sigstore(issuerMatch=exact)::..." are rejected — those carry matcher
// semantics and belong to NewIdentityFromSpec. Round-trips with
// (*Identity).Principal.
func NewIdentityFromPrincipal(principal string) (*Identity, error) {
	if strings.HasPrefix(principal, "spiffe://") {
		spiffeID, err := IdentitySpiffeFromString(principal)
		if err != nil {
			return nil, fmt.Errorf("parsing spiffe principal: %w", err)
		}
		return &Identity{Spiffe: spiffeID}, nil
	}

	itype, identityString, ok := strings.Cut(principal, "::")
	if !ok {
		refId, isRef := strings.CutPrefix(principal, "ref:")
		if isRef {
			return &Identity{Ref: &IdentityRef{Id: refId}}, nil
		}
		return nil, fmt.Errorf("unable to parse identity from principal string %q", principal)
	}

	if strings.ContainsAny(itype, "()") {
		return nil, fmt.Errorf("principal does not accept matcher annotations; use NewIdentityFromSpec for %q", principal)
	}

	switch itype {
	case identityTypeSigstore:
		issuer, ident, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse sigstore identity from principal string")
		}
		return &Identity{
			Sigstore: &IdentitySigstore{
				Issuer:   issuer,
				Identity: ident,
			},
		}, nil
	case identityTypeKey:
		keyType, keyId, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse key details from principal string")
		}
		return &Identity{
			Key: &IdentityKey{
				Id:   keyId,
				Type: keyType,
			},
		}, nil
	}
	return nil, fmt.Errorf("unable to parse identity from principal string %q", principal)
}

// NewIdentityFromSpec parses an Identity from its rich canonical form.
// The spec carries both the principal AND its matcher semantics.
//
// Accepts:
//
//   - all forms supported by NewIdentityFromPrincipal (pure identifiers)
//
//   - the legacy single-token form "sigstore(regexp)::<issuer>::<identity>"
//     (sets Mode=regexp on the resulting IdentitySigstore)
//
//   - the rich form with per-field StringMatcher annotations:
//
//     sigstore(issuerMatch=exact,identityMatch=regex)::<issuer>::<identity>
//     key(idMatch=glob,typeMatch=exact)::<type>::<id>
//     spiffe(svidMatch=regex)::<pattern>
//     spiffe(trustDomainMatch=exact,pathMatch=glob)::<trust-domain>::<path>
//
// Matcher kinds: exact | regex | prefix | glob. The /i suffix on a kind
// (e.g. "identityMatch=regex/i") sets case_insensitive on that matcher.
//
// Slot semantics: each annotated field consumes a positional slot; slots
// not annotated populate the legacy field at that position
// (e.g. "sigstore(issuerMatch=regex)::https://.*::user@x" becomes
// IssuerMatch=regex, Identity="user@x"). Round-trips with (*Identity).Spec.
func NewIdentityFromSpec(spec string) (*Identity, error) {
	// Pure forms with no matcher annotations dispatch to Principal.
	if strings.HasPrefix(spec, "spiffe://") || strings.HasPrefix(spec, "ref:") {
		return NewIdentityFromPrincipal(spec)
	}

	itype, paramStr, rest, err := splitSpecHead(spec)
	if err != nil {
		return nil, err
	}

	// No annotations: the spec is a Principal string.
	if paramStr == "" {
		return NewIdentityFromPrincipal(spec)
	}

	params, err := parseSpecParams(paramStr)
	if err != nil {
		return nil, fmt.Errorf("parsing spec annotations in %q: %w", spec, err)
	}

	slots := strings.Split(rest, "::")

	switch itype {
	case identityTypeSigstore:
		return parseSigstoreSpec(params, slots)
	case identityTypeKey:
		return parseKeySpec(params, slots)
	case identityTypeSpiffe:
		return parseSpiffeSpec(params, slots)
	default:
		return nil, fmt.Errorf("unknown identity type %q in spec %q", itype, spec)
	}
}

// NewIdentityFromSlug is a compatibility alias for NewIdentityFromSpec.
// Retained because legacy callers depended on the rich form (e.g. the
// "sigstore(regexp)::..." marker that Principal no longer emits).
//
// Deprecated: prefer NewIdentityFromSpec; or NewIdentityFromPrincipal for
// the pure form.
func NewIdentityFromSlug(slug string) (*Identity, error) {
	return NewIdentityFromSpec(slug)
}

// Principal returns the canonical string naming this identity — the
// security-domain "principal" that uniquely identifies who signed.
// Matcher semantics (e.g. sigstore Mode=regexp) are NOT encoded in the
// principal: it is a pure identifier. Round-trips with
// NewIdentityFromPrincipal.
func (i *Identity) Principal() string {
	switch {
	case i.GetSigstore() != nil:
		return fmt.Sprintf("sigstore::%s::%s", i.GetSigstore().GetIssuer(), i.GetSigstore().GetIdentity())
	case i.GetKey() != nil:
		return fmt.Sprintf("key::%s::%s", i.GetKey().GetType(), i.GetKey().GetId())
	case i.GetRef() != nil:
		return fmt.Sprintf("ref:%s", i.GetRef().GetId())
	case i.GetSpiffe() != nil:
		return i.GetSpiffe().GetSvid()
	default:
		return ""
	}
}

// Spec returns the rich canonical string carrying both the principal and
// its matcher semantics. Suitable for CLI flag values like
//
//	--identity=sigstore(identityMatch=regex)::https://accounts.google.com::user@.*\.example\.com
//
// When no matchers are set, Spec returns the same string as Principal
// (with the legacy "(regexp)" marker reintroduced when Mode=regexp on
// IdentitySigstore). Round-trips with NewIdentityFromSpec.
//
// Spec covers the per-variant *_match conveniences and the dominant
// principal-slot fields. It does NOT encode the outer Matchers slice,
// IdentityKey.signing_fingerprint(_match), IdentitySpiffe.trust_roots, or
// the certificate extension fields of IdentitySigstore (source_repository_uri,
// build_config_uri, build_trigger and source_repository_ref, and their
// _match forms). Callers that need full fidelity should use the proto
// directly.
func (i *Identity) Spec() string {
	switch {
	case i.GetSigstore() != nil:
		return sigstoreSpec(i.GetSigstore())
	case i.GetKey() != nil:
		return keySpec(i.GetKey())
	case i.GetSpiffe() != nil:
		return spiffeSpec(i.GetSpiffe())
	case i.GetRef() != nil:
		return fmt.Sprintf("ref:%s", i.GetRef().GetId())
	default:
		return ""
	}
}

// Slug returns the rich form (alias of Spec).
//
// Deprecated: prefer Spec for the rich form, Principal for the pure
// identifier. Retained for existing callers.
func (i *Identity) Slug() string {
	return i.Spec()
}

// splitSpecHead extracts the type prefix, the parenthetical annotation
// body (without parens), and the remaining slot string (without leading
// "::") from a spec. Returns ("", "", spec, nil) when neither annotation
// nor "::" is present so that callers can fall through to Principal
// parsing.
func splitSpecHead(spec string) (itype, paramStr, rest string, err error) {
	openParen := strings.Index(spec, "(")
	doubleColon := strings.Index(spec, "::")

	switch {
	case openParen >= 0 && (doubleColon < 0 || openParen < doubleColon):
		closeParen := strings.Index(spec[openParen:], ")")
		if closeParen < 0 {
			return "", "", "", fmt.Errorf("unclosed matcher annotation in spec %q", spec)
		}
		closeParen += openParen
		itype = spec[:openParen]
		paramStr = spec[openParen+1 : closeParen]
		afterAnnot := spec[closeParen+1:]
		if !strings.HasPrefix(afterAnnot, "::") {
			return "", "", "", fmt.Errorf("expected :: after matcher annotation in spec %q", spec)
		}
		rest = strings.TrimPrefix(afterAnnot, "::")
		return itype, paramStr, rest, nil
	case doubleColon >= 0:
		itype = spec[:doubleColon]
		rest = spec[doubleColon+2:]
		return itype, "", rest, nil
	default:
		return "", "", spec, nil
	}
}

// parseSpecParams turns "issuerMatch=regex/i,identityMatch=exact" into a
// map of field-name → kind-annotation. The single-token legacy form
// "regexp" becomes a key with empty value.
func parseSpecParams(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range strings.Split(s, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return nil, errors.New("empty matcher annotation")
		}
		name, val, hasEq := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if !hasEq {
			out[name] = ""
			continue
		}
		out[name] = strings.TrimSpace(val)
	}
	return out, nil
}

// matcherFromAnnotation builds a StringMatcher from a "<kind>[/i]"
// annotation paired with the slot value to be matched.
func matcherFromAnnotation(annotation, value string) (*StringMatcher, error) {
	kind, opts, _ := strings.Cut(annotation, "/")
	caseInsensitive := false
	switch opts {
	case "":
	case "i":
		caseInsensitive = true
	default:
		return nil, fmt.Errorf("unknown matcher options %q (expected /i)", opts)
	}

	m := &StringMatcher{CaseInsensitive: caseInsensitive}
	switch kind {
	case "exact":
		m.Kind = &StringMatcher_Exact{Exact: value}
	case "regex":
		m.Kind = &StringMatcher_Regex{Regex: value}
	case "prefix":
		m.Kind = &StringMatcher_Prefix{Prefix: value}
	case "glob":
		m.Kind = &StringMatcher_Glob{Glob: value}
	default:
		return nil, fmt.Errorf("unknown matcher kind %q", kind)
	}
	return m, nil
}

func parseSigstoreSpec(params map[string]string, slots []string) (*Identity, error) {
	if len(slots) != 2 {
		return nil, fmt.Errorf("sigstore spec requires 2 slots (issuer::identity), got %d", len(slots))
	}
	sig := &IdentitySigstore{}
	for name, kind := range params {
		switch name {
		case "regexp":
			if kind != "" {
				return nil, fmt.Errorf("legacy sigstore(regexp) marker takes no value, got %q", kind)
			}
			mode := SigstoreModeRegexp
			sig.Mode = &mode
		case "issuerMatch":
			m, err := matcherFromAnnotation(kind, slots[0])
			if err != nil {
				return nil, fmt.Errorf("issuerMatch: %w", err)
			}
			sig.IssuerMatch = m
		case "identityMatch":
			m, err := matcherFromAnnotation(kind, slots[1])
			if err != nil {
				return nil, fmt.Errorf("identityMatch: %w", err)
			}
			sig.IdentityMatch = m
		default:
			return nil, fmt.Errorf("unknown sigstore matcher field %q", name)
		}
	}
	if _, ok := params["issuerMatch"]; !ok {
		sig.Issuer = slots[0]
	}
	if _, ok := params["identityMatch"]; !ok {
		sig.Identity = slots[1]
	}
	return &Identity{Sigstore: sig}, nil
}

func parseKeySpec(params map[string]string, slots []string) (*Identity, error) {
	if len(slots) != 2 {
		return nil, fmt.Errorf("key spec requires 2 slots (type::id), got %d", len(slots))
	}
	k := &IdentityKey{}
	for name, kind := range params {
		switch name {
		case "typeMatch":
			m, err := matcherFromAnnotation(kind, slots[0])
			if err != nil {
				return nil, fmt.Errorf("typeMatch: %w", err)
			}
			k.TypeMatch = m
		case "idMatch":
			m, err := matcherFromAnnotation(kind, slots[1])
			if err != nil {
				return nil, fmt.Errorf("idMatch: %w", err)
			}
			k.IdMatch = m
		default:
			return nil, fmt.Errorf("unknown key matcher field %q", name)
		}
	}
	if _, ok := params["typeMatch"]; !ok {
		k.Type = slots[0]
	}
	if _, ok := params["idMatch"]; !ok {
		k.Id = slots[1]
	}
	return &Identity{Key: k}, nil
}

func parseSpiffeSpec(params map[string]string, slots []string) (*Identity, error) {
	s := &IdentitySpiffe{}
	// Single-slot form: spiffe(svidMatch=...)::pattern
	if len(slots) == 1 {
		kind, ok := params["svidMatch"]
		if !ok || len(params) != 1 {
			return nil, fmt.Errorf("spiffe spec with one slot requires svidMatch annotation only")
		}
		m, err := matcherFromAnnotation(kind, slots[0])
		if err != nil {
			return nil, fmt.Errorf("svidMatch: %w", err)
		}
		s.SvidMatch = m
		return &Identity{Spiffe: s}, nil
	}
	if len(slots) != 2 {
		return nil, fmt.Errorf("spiffe spec requires 1 or 2 slots, got %d", len(slots))
	}
	for name, kind := range params {
		switch name {
		case "trustDomainMatch":
			m, err := matcherFromAnnotation(kind, slots[0])
			if err != nil {
				return nil, fmt.Errorf("trustDomainMatch: %w", err)
			}
			s.TrustDomainMatch = m
		case "pathMatch":
			m, err := matcherFromAnnotation(kind, slots[1])
			if err != nil {
				return nil, fmt.Errorf("pathMatch: %w", err)
			}
			s.PathMatch = m
		default:
			return nil, fmt.Errorf("unknown spiffe matcher field %q in two-slot form", name)
		}
	}
	if s.GetTrustDomainMatch() == nil && s.GetPathMatch() == nil {
		return nil, errors.New("spiffe spec with two slots requires trustDomainMatch and/or pathMatch")
	}
	return &Identity{Spiffe: s}, nil
}

func sigstoreSpec(s *IdentitySigstore) string {
	issuerMatch := s.GetIssuerMatch()
	identityMatch := s.GetIdentityMatch()

	if issuerMatch == nil && identityMatch == nil {
		if s.GetMode() == SigstoreModeRegexp {
			return fmt.Sprintf("sigstore(regexp)::%s::%s", s.GetIssuer(), s.GetIdentity())
		}
		return fmt.Sprintf("sigstore::%s::%s", s.GetIssuer(), s.GetIdentity())
	}

	var params []string
	issuerSlot := s.GetIssuer()
	if issuerMatch != nil {
		params = append(params, "issuerMatch="+stringMatcherAnnotation(issuerMatch))
		issuerSlot = stringMatcherPattern(issuerMatch)
	}
	identitySlot := s.GetIdentity()
	if identityMatch != nil {
		params = append(params, "identityMatch="+stringMatcherAnnotation(identityMatch))
		identitySlot = stringMatcherPattern(identityMatch)
	}
	return fmt.Sprintf("sigstore(%s)::%s::%s", strings.Join(params, ","), issuerSlot, identitySlot)
}

func keySpec(k *IdentityKey) string {
	typeMatch := k.GetTypeMatch()
	idMatch := k.GetIdMatch()
	if typeMatch == nil && idMatch == nil {
		return fmt.Sprintf("key::%s::%s", k.GetType(), k.GetId())
	}

	var params []string
	typeSlot := k.GetType()
	if typeMatch != nil {
		params = append(params, "typeMatch="+stringMatcherAnnotation(typeMatch))
		typeSlot = stringMatcherPattern(typeMatch)
	}
	idSlot := k.GetId()
	if idMatch != nil {
		params = append(params, "idMatch="+stringMatcherAnnotation(idMatch))
		idSlot = stringMatcherPattern(idMatch)
	}
	return fmt.Sprintf("key(%s)::%s::%s", strings.Join(params, ","), typeSlot, idSlot)
}

func spiffeSpec(s *IdentitySpiffe) string {
	svidMatch := s.GetSvidMatch()
	tdMatch := s.GetTrustDomainMatch()
	pathMatch := s.GetPathMatch()

	if svidMatch == nil && tdMatch == nil && pathMatch == nil {
		return s.GetSvid()
	}
	if svidMatch != nil && tdMatch == nil && pathMatch == nil {
		return fmt.Sprintf("spiffe(svidMatch=%s)::%s",
			stringMatcherAnnotation(svidMatch), stringMatcherPattern(svidMatch))
	}
	var params []string
	tdSlot := ""
	if tdMatch != nil {
		params = append(params, "trustDomainMatch="+stringMatcherAnnotation(tdMatch))
		tdSlot = stringMatcherPattern(tdMatch)
	}
	pathSlot := ""
	if pathMatch != nil {
		params = append(params, "pathMatch="+stringMatcherAnnotation(pathMatch))
		pathSlot = stringMatcherPattern(pathMatch)
	}
	return fmt.Sprintf("spiffe(%s)::%s::%s", strings.Join(params, ","), tdSlot, pathSlot)
}

// stringMatcherAnnotation returns the "<kind>[/i]" annotation string for a
// StringMatcher, or "" if the matcher is nil or has no kind set.
func stringMatcherAnnotation(m *StringMatcher) string {
	if m == nil {
		return ""
	}
	var kind string
	switch m.GetKind().(type) {
	case *StringMatcher_Exact:
		kind = "exact"
	case *StringMatcher_Regex:
		kind = "regex"
	case *StringMatcher_Prefix:
		kind = "prefix"
	case *StringMatcher_Glob:
		kind = "glob"
	default:
		return ""
	}
	if m.GetCaseInsensitive() {
		kind += "/i"
	}
	return kind
}

func stringMatcherPattern(m *StringMatcher) string {
	if m == nil {
		return ""
	}
	switch v := m.GetKind().(type) {
	case *StringMatcher_Exact:
		return v.Exact
	case *StringMatcher_Regex:
		return v.Regex
	case *StringMatcher_Prefix:
		return v.Prefix
	case *StringMatcher_Glob:
		return v.Glob
	default:
		return ""
	}
}

// Validate checks the integrity of the identity and returns an error if
// fields are missing or invalid. Validates each variant's required fields,
// compiles regex patterns on legacy sigstore fields (when Mode=regexp)
// and on any StringMatcher regex/glob kinds, and checks spiffe svid parses
// as a valid SPIFFE ID — surfacing authoring errors at validation time
// rather than at match time.
func (i *Identity) Validate() error {
	errs := []error{}
	typesDefined := []string{}

	if i.GetSigstore() != nil {
		typesDefined = append(typesDefined, "sigstore")
		errs = append(errs, validateSigstore(i.GetSigstore())...)
	}

	if i.GetKey() != nil {
		typesDefined = append(typesDefined, "key")
		errs = append(errs, validateKey(i.GetKey())...)
	}

	if i.GetRef() != nil {
		typesDefined = append(typesDefined, "ref")
	}

	if i.GetSpiffe() != nil {
		typesDefined = append(typesDefined, "spiffe")
		errs = append(errs, validateSpiffe(i.GetSpiffe())...)
	}

	for idx, m := range i.GetMatchers() {
		if err := validateMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("matchers[%d]: %w", idx, err))
		}
	}

	if len(typesDefined) == 0 {
		errs = append(errs, errors.New("at least one type of identity must be set (sigstore, key, ref or spiffe)"))
	}

	if len(typesDefined) > 1 {
		errs = append(errs, fmt.Errorf("only one type of identity can be set at a time (got %v)", typesDefined))
	}
	return errors.Join(errs...)
}

// validateSigstore checks a sigstore identity's legacy fields + convenience
// matchers. Legacy Issuer/Identity as regex (Mode=regexp) are compiled up
// front so bad patterns surface at validation time.
func validateSigstore(s *IdentitySigstore) []error {
	var errs []error

	useLegacy := s.GetIssuer() != "" || s.GetIdentity() != ""
	useMatchers := s.GetIssuerMatch() != nil || s.GetIdentityMatch() != nil || hasExtensionMatcher(s, false)
	var refinements, anchors []string
	for _, ext := range sigstoreExtensions {
		switch {
		case !ext.refinement:
			anchors = append(anchors, ext.name+"_match")
		case ext.getMatcher(s) != nil:
			refinements = append(refinements, ext.name+"_match")
		}
	}
	if !useLegacy && !useMatchers {
		errs = append(errs, fmt.Errorf("sigstore identity requires %s",
			joinOr(append([]string{"issuer", sigstoreFieldIdentity, "issuer_match", "identity_match"}, anchors...))))
	} else if len(refinements) > 0 && !anchoredSigstore(s) {
		verbs := "refine an identity and need"
		if len(refinements) == 1 {
			verbs = "refines an identity and needs"
		}
		errs = append(errs, fmt.Errorf("sigstore %s only %s %s next to them",
			strings.Join(refinements, " and "), verbs, joinOr(append([]string{sigstoreFieldIdentity, "identity_match"}, anchors...))))
	}
	if useLegacy && !useMatchers && (s.GetIssuer() == "" || s.GetIdentity() == "") {
		errs = append(errs, errors.New("sigstore legacy form requires both issuer and identity when matchers are not used"))
	}

	if s.GetMode() == SigstoreModeRegexp {
		if v := s.GetIssuer(); v != "" {
			if _, err := regexp.Compile(anchoredRegex(v)); err != nil {
				errs = append(errs, fmt.Errorf("sigstore issuer regex: %w", err))
			}
		}
		if v := s.GetIdentity(); v != "" {
			if _, err := regexp.Compile(anchoredRegex(v)); err != nil {
				errs = append(errs, fmt.Errorf("sigstore identity regex: %w", err))
			}
		}
	}

	if m := s.GetIssuerMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("issuer_match: %w", err))
		}
	}
	if m := s.GetIdentityMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("identity_match: %w", err))
		}
	}
	// The certificate extensions aren't supported by legacy mode, so anyone
	// setting their raw fields won't get what they expect. They must use
	// the matchers instead.
	for _, ext := range sigstoreExtensions {
		if m := ext.getMatcher(s); m != nil {
			if err := validateStringMatcher(m); err != nil {
				errs = append(errs, fmt.Errorf("%s_match: %w", ext.name, err))
			}
		}
		if ext.value(s) != "" {
			errs = append(errs, fmt.Errorf("%s cannot be set on a policy identity; use %s_match", ext.name, ext.name))
		}
	}
	return errs
}

// sigstoreFieldIdentity names the identity field of sigstore identities,
// in error messages and outer matchers.
const sigstoreFieldIdentity = "identity"

// joinOr lists the names as alternatives: "a, b, or c".
func joinOr(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + ", or " + names[len(names)-1]
}

func validateKey(k *IdentityKey) []error {
	var errs []error
	if k.GetId() == "" && k.GetData() == "" && k.GetIdMatch() == nil {
		errs = append(errs, errors.New("key identity requires id, data, or id_match"))
	}
	if m := k.GetIdMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("id_match: %w", err))
		}
	}
	if m := k.GetTypeMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("type_match: %w", err))
		}
	}
	if m := k.GetSigningFingerprintMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("signing_fingerprint_match: %w", err))
		}
	}
	return errs
}

func validateSpiffe(s *IdentitySpiffe) []error {
	var errs []error
	if s.GetSvid() == "" &&
		s.GetSvidMatch() == nil &&
		s.GetTrustDomainMatch() == nil &&
		s.GetPathMatch() == nil {
		errs = append(errs, errors.New("spiffe identity requires svid, svid_match, trust_domain_match, or path_match"))
	}
	if v := s.GetSvid(); v != "" {
		if _, err := spiffeid.FromString(v); err != nil {
			errs = append(errs, fmt.Errorf("spiffe svid: %w", err))
		}
	}
	if m := s.GetSvidMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("svid_match: %w", err))
		}
	}
	if m := s.GetTrustDomainMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("trust_domain_match: %w", err))
		}
	}
	if m := s.GetPathMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("path_match: %w", err))
		}
	}
	return errs
}

// validateMatcher checks an outer Matcher entry: field is required, the
// embedded kind is validated by its concrete type.
func validateMatcher(m *Matcher) error {
	if m.GetField() == "" {
		return errors.New("field is required")
	}
	switch kind := m.GetKind().(type) {
	case *Matcher_String_:
		if kind.String_ == nil {
			return errors.New("string matcher is nil")
		}
		return validateStringMatcher(kind.String_)
	case nil:
		return errors.New("matcher kind is not set")
	default:
		return fmt.Errorf("unsupported matcher kind %T", kind)
	}
}

// validateStringMatcher ensures regex patterns compile and glob patterns
// are well-formed. Exact/Prefix kinds have no format requirements. A
// from_context binding is valid on its own (the caller resolves it) but cannot
// be combined with a match kind.
func validateStringMatcher(m *StringMatcher) error {
	if m.GetFromContext() != "" {
		if m.GetKind() != nil {
			return errors.New("from_context cannot be combined with a match kind")
		}
		return nil
	}
	switch kind := m.GetKind().(type) {
	case *StringMatcher_Regex:
		pattern := anchoredRegex(kind.Regex)
		if m.GetCaseInsensitive() {
			pattern = "(?i)" + pattern
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("regex %q: %w", kind.Regex, err)
		}
	case *StringMatcher_Glob:
		if _, err := path.Match(kind.Glob, ""); err != nil {
			return fmt.Errorf("glob %q: %w", kind.Glob, err)
		}
	case *StringMatcher_Exact, *StringMatcher_Prefix:
		// no format to validate
	case nil:
		return errors.New("matcher kind is not set")
	default:
		return fmt.Errorf("unsupported string matcher kind %T", kind)
	}
	return nil
}

// IdentitySpiffeFromString parses a SPIFFE ID string (e.g.
// "spiffe://example.org/workload") into an IdentitySpiffe.
//
// TrustRoots is intentionally NOT populated — it is a verifier configuration
// (which root(s) the chain was validated against), not an attribute of the
// signer. Expectation-side IdentitySpiffe values carry TrustRoots to tell
// the verifier what to trust; verified-side IdentitySpiffe values
// describe who signed.
func IdentitySpiffeFromString(spiffeID string) (*IdentitySpiffe, error) {
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("parsing spiffe id: %w", err)
	}
	return &IdentitySpiffe{
		Svid: id.String(),
	}, nil
}

// IdentitySpiffeFromCert builds an IdentitySpiffe from a leaf certificate by
// extracting the SPIFFE ID from its URI SAN and then delegating to
// IdentitySpiffeFromString once the SAN is found. Useful when a caller has
// only the leaf (e.g. test fixtures or standalone cert inspection); when a
// VerificationResult is available, read the SAN from VerifiedIdentity and
// call IdentitySpiffeFromString directly.
func IdentitySpiffeFromCert(leaf *x509.Certificate) (*IdentitySpiffe, error) {
	if leaf == nil {
		return nil, errors.New("leaf certificate is nil")
	}
	for _, uri := range leaf.URIs {
		if uri.Scheme != identityTypeSpiffe {
			continue
		}
		return IdentitySpiffeFromString(uri.String())
	}
	return nil, errors.New("certificate has no spiffe:// URI SAN")
}

// IdentityKeyFromPublic builds an IdentityKey from a verified *key.Public.
// It copies the key Id, Scheme (as Type) and — critically for GPG — the
// SigningKeyFingerprint populated during verification, so the resulting
// IdentityKey names the actual signing (sub)key rather than just the
// primary/identity key.
func IdentityKeyFromPublic(pub *key.Public) *IdentityKey {
	if pub == nil {
		return nil
	}
	return &IdentityKey{
		Id:                 pub.ID(),
		Type:               string(pub.Scheme),
		SigningFingerprint: pub.SigningKeyFingerprint,
	}
}

// Normalize populates empty Type and Id fields by parsing the key Data.
// This ensures identities defined with only key material (e.g. a GPG
// key block) have their Id and Type resolved before matching.
func (ik *IdentityKey) Normalize() error {
	if ik.GetData() == "" {
		return nil
	}

	provider, err := key.NewParser().ParsePublicKeyProvider([]byte(ik.GetData()))
	if err != nil {
		return fmt.Errorf("parsing key data: %w", err)
	}

	pub, err := provider.PublicKey()
	if err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}

	if ik.GetType() == "" {
		ik.Type = string(pub.Scheme)
	}

	if ik.GetId() == "" {
		ik.Id = pub.ID()
	}

	return nil
}

// PublicKey returns the identity public key by parsing the data if set.
// It uses ParsePublicKeyProvider to preserve full key metadata (e.g. GPG
// key IDs and subkeys) required for PGP signature verification.
func (i *Identity) PublicKey() (key.PublicKeyProvider, error) {
	var data string
	if data = i.GetKey().GetData(); data == "" {
		return nil, nil
	}
	k, err := key.NewParser().ParsePublicKeyProvider([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	return k, nil
}
