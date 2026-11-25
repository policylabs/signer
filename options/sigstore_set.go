// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/policylabs/signer/sigstore"
	"github.com/policylabs/signer/sts"
)

// SigstoreCommon holds the flag-bound sigstore roots configuration shared
// between SigstoreSign and SigstoreVerify. Tools that expose both
// operations should construct one *SigstoreCommon, share it via pointer
// in their SigstoreSign and SigstoreVerify, and call
// SigstoreCommon.AddFlags(cmd) once so --sigstore-roots is registered
// exactly once.
type SigstoreCommon struct {
	// RootsPath is the filesystem path to a sigstore-roots.json file.
	// Empty means use RootsData if set, otherwise sigstore.DefaultRoots.
	RootsPath string

	// RootsData is the raw JSON of a sigstore-roots file when callers
	// want to inject it programmatically. Empty falls back to RootsPath
	// (then to sigstore.DefaultRoots).
	RootsData []byte

	loaded *sigstore.SigstoreRoots
	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SigstoreCommon)(nil)

// DefaultSigstoreCommon returns a SigstoreCommon configured to use the
// embedded sigstore.DefaultRoots until the caller overrides it.
func DefaultSigstoreCommon() *SigstoreCommon {
	return &SigstoreCommon{}
}

// Config returns the flag configuration for SigstoreCommon.
func (c *SigstoreCommon) Config() *command.OptionsSetConfig {
	if c.config == nil {
		c.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"roots": {
					Long: "roots",
					Help: "path to a sigstore-roots.json file (overrides the embedded defaults)",
				},
			},
		}
	}
	return c.config
}

// AddFlags registers the SigstoreCommon flags on cmd.
func (c *SigstoreCommon) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&c.RootsPath,
		c.Config().LongFlag("roots"),
		c.RootsPath,
		c.Config().HelpText("roots"),
	)
}

// Validate parses the roots data (if not already parsed) and confirms
// at least one instance is defined.
func (c *SigstoreCommon) Validate() error {
	return c.LoadRoots()
}

// LoadRoots reads and parses the roots data into a SigstoreRoots struct.
// Subsequent calls are no-ops. Resolution order:
//  1. RootsPath (file)
//  2. RootsData (inline JSON)
//  3. sigstore.DefaultRoots (embedded)
func (c *SigstoreCommon) LoadRoots() error {
	if c.loaded != nil {
		return nil
	}

	var data []byte
	switch {
	case c.RootsPath != "":
		b, err := os.ReadFile(c.RootsPath)
		if err != nil {
			return fmt.Errorf("reading sigstore roots file %q: %w", c.RootsPath, err)
		}
		data = b
	case len(c.RootsData) > 0:
		data = c.RootsData
	default:
		data = sigstore.DefaultRoots
	}

	parsed, err := sigstore.ParseRoots(data)
	if err != nil {
		return fmt.Errorf("parsing sigstore roots: %w", err)
	}
	if len(parsed.Roots) == 0 {
		return errors.New("no sigstore instances in roots configuration")
	}
	c.loaded = parsed
	return nil
}

// Instance returns the InstanceConfig whose ID matches name. When name
// is empty, returns the first instance in file order (Roots[0]).
func (c *SigstoreCommon) Instance(name string) (*sigstore.InstanceConfig, error) {
	if err := c.LoadRoots(); err != nil {
		return nil, err
	}
	if name == "" {
		return &c.loaded.Roots[0], nil
	}
	for i := range c.loaded.Roots {
		if c.loaded.Roots[i].ID == name {
			return &c.loaded.Roots[i], nil
		}
	}
	return nil, fmt.Errorf("sigstore instance %q not found in roots configuration", name)
}

// Instances returns every parsed instance configuration, in file order.
// Returns nil if LoadRoots failed.
func (c *SigstoreCommon) Instances() []sigstore.InstanceConfig {
	if err := c.LoadRoots(); err != nil {
		return nil
	}
	return c.loaded.Roots
}

// SigstoreSign is the OptionsSet for the signing side of a sigstore
// workflow. It pinpoints a specific instance from SigstoreCommon, holds
// the client-side OIDC overrides, and the sign-time toggles.
type SigstoreSign struct {
	*SigstoreCommon

	// InstanceName selects which instance from the roots file to sign
	// against. Empty resolves to Roots[0].
	InstanceName string

	// OIDC overrides — applied on top of the selected instance's
	// OIDCConfig at ResolveInstance time. Empty fields leave the roots
	// file's value in place.
	OIDCClientID     string
	OIDCRedirectURL  string
	OIDCClientSecret string

	// OIDCTokenFile is an optional path to a pre-issued OIDC ID token,
	// for non-interactive (CI) flows. Read at ResolveInstance time.
	OIDCTokenFile string

	// Sign-time toggles.
	RekorAppend bool
	Timestamp   bool
	DisableSTS  bool

	// STSProviders names the STS providers to look for ambient
	// credentials in, in the order they are tried. No other provider is
	// consulted. Bound to --<prefix>-sts-providers. When empty, all the
	// registered providers are tried in their default order (see
	// sts.Ordered).
	STSProviders []string

	// HideOIDCOptions marks the --oidc-* flags as hidden on the CLI.
	HideOIDCOptions bool

	// ManagedTimestamp, when true, suppresses registration of the
	// --<prefix>-timestamp flag in AddFlags. Set by SignerSet so the
	// bundled --signing-timestamp can be the single user-facing knob;
	// standalone callers leave this false (default) and get
	// --sigstore-timestamp under the standard prefix.
	ManagedTimestamp bool

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SigstoreSign)(nil)

// defaultOIDCClientID is the public client ID used by the sigstore
// public-good instance for the interactive auth flow. Public clients
// have no secret; this constant is named separately so gosec doesn't
// flag the literal as a hardcoded credential.
const defaultOIDCClientID = "sigstore"

const (
	flagInstance         = "instance"
	flagOIDCClientID     = "oidc-client-id"
	flagOIDCRedirectURL  = "oidc-redirect-url"  //nolint:gosec // G101: flag name, not a credential
	flagOIDCClientSecret = "oidc-client-secret" //nolint:gosec // G101: flag name, not a credential
	flagOIDCTokenFile    = "oidc-token-file"    //nolint:gosec // G101: flag name, not a credential
	flagRekorAppend      = "rekor-append"
	flagTimestamp        = "timestamp"
	flagDisableSTS       = "disable-sts"
	flagSTSProviders     = "sts-providers"
)

// DefaultSigstoreSign builds a SigstoreSign with sensible defaults
// (OIDC ClientID "sigstore", localhost callback, Rekor and TSA enabled,
// OIDC flags hidden). Pass nil for common to allocate a fresh one.
func DefaultSigstoreSign(common *SigstoreCommon) *SigstoreSign {
	if common == nil {
		common = DefaultSigstoreCommon()
	}
	return &SigstoreSign{ //nolint:gosec // G101 false-positive: defaultOIDCClientID is a public OAuth client identifier, not a credential.
		SigstoreCommon:  common,
		OIDCClientID:    defaultOIDCClientID,
		OIDCRedirectURL: "http://localhost:0/auth/callback",
		RekorAppend:     true,
		Timestamp:       true,
		HideOIDCOptions: true,
	}
}

// Config returns the flag configuration for SigstoreSign.
func (s *SigstoreSign) Config() *command.OptionsSetConfig {
	if s.config == nil {
		s.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagInstance:         {Long: flagInstance, Help: "sigstore instance ID to sign against"},
				flagOIDCClientID:     {Long: flagOIDCClientID, Help: "OIDC client ID to use when exchanging tokens"},
				flagOIDCRedirectURL:  {Long: flagOIDCRedirectURL, Help: "OIDC redirect URL for the interactive flow"},
				flagOIDCClientSecret: {Long: flagOIDCClientSecret, Help: "OIDC client secret (for confidential clients)"},
				flagOIDCTokenFile:    {Long: flagOIDCTokenFile, Help: "path to a pre-issued OIDC ID token (non-interactive / CI)"},
				flagRekorAppend:      {Long: flagRekorAppend, Help: "record the signature in the Rekor transparency log"},
				flagTimestamp:        {Long: flagTimestamp, Help: "attach a TSA-signed timestamp to the signature"},
				flagDisableSTS:       {Long: flagDisableSTS, Help: "skip the STS token exchange"},
				flagSTSProviders:     {Long: flagSTSProviders, Help: "STS providers to get ambient credentials from, in the order to try them (default: all)"},
			},
		}
	}
	return s.config
}

// AddFlags registers SigstoreSign flags on cmd. Assumes the caller
// registers SigstoreCommon's flags separately so --sigstore-roots is
// not registered twice.
func (s *SigstoreSign) AddFlags(cmd *cobra.Command) {
	cfg := s.Config()
	pf := cmd.PersistentFlags()

	pf.StringVar(&s.InstanceName, cfg.LongFlag(flagInstance), s.InstanceName, s.instanceHelpText(cfg.HelpText(flagInstance)))
	pf.StringVar(&s.OIDCClientID, cfg.LongFlag(flagOIDCClientID), s.OIDCClientID, cfg.HelpText(flagOIDCClientID))
	pf.StringVar(&s.OIDCRedirectURL, cfg.LongFlag(flagOIDCRedirectURL), s.OIDCRedirectURL, cfg.HelpText(flagOIDCRedirectURL))
	pf.StringVar(&s.OIDCClientSecret, cfg.LongFlag(flagOIDCClientSecret), s.OIDCClientSecret, cfg.HelpText(flagOIDCClientSecret))
	pf.StringVar(&s.OIDCTokenFile, cfg.LongFlag(flagOIDCTokenFile), s.OIDCTokenFile, cfg.HelpText(flagOIDCTokenFile))
	pf.BoolVar(&s.RekorAppend, cfg.LongFlag(flagRekorAppend), s.RekorAppend, cfg.HelpText(flagRekorAppend))
	if !s.ManagedTimestamp {
		pf.BoolVar(&s.Timestamp, cfg.LongFlag(flagTimestamp), s.Timestamp, cfg.HelpText(flagTimestamp))
	}
	pf.BoolVar(&s.DisableSTS, cfg.LongFlag(flagDisableSTS), s.DisableSTS, cfg.HelpText(flagDisableSTS))
	pf.StringSliceVar(&s.STSProviders, cfg.LongFlag(flagSTSProviders), s.STSProviders, cfg.HelpText(flagSTSProviders))

	if s.HideOIDCOptions {
		for _, id := range []string{flagOIDCClientID, flagOIDCRedirectURL, flagOIDCClientSecret, flagOIDCTokenFile} {
			_ = pf.MarkHidden(cfg.LongFlag(id)) //nolint:errcheck // safe: flag was just registered above
		}
	}
}

// Validate ensures the embedded SigstoreCommon is populated, the roots
// file loads cleanly, and the selected instance exists.
func (s *SigstoreSign) Validate() error {
	if s.SigstoreCommon == nil {
		return errors.New("SigstoreSign: SigstoreCommon is nil")
	}
	if err := s.SigstoreCommon.Validate(); err != nil {
		return err
	}
	if _, err := s.Instance(s.InstanceName); err != nil {
		return err
	}
	if len(s.STSProviders) > 0 {
		if s.DisableSTS {
			cfg := s.Config()
			return fmt.Errorf(
				"--%s and --%s cannot be used together",
				cfg.LongFlag(flagSTSProviders), cfg.LongFlag(flagDisableSTS),
			)
		}
		if _, err := sts.Select(s.STSProviders...); err != nil {
			return err
		}
	}
	return nil
}

// instanceHelpText augments the static help with the default instance
// and the list of available IDs, read from the roots loadable at
// flag-registration time. Falls back to the static help if the common
// embed is missing or the roots can't be parsed (rare — the embedded
// defaults always parse).
//
// Caveat: if the caller later passes --sigstore-roots to load a
// different file, the rendered --help still reflects the IDs from the
// roots resolved at registration time. For the dominant case (embedded
// defaults), this is exactly right.
func (s *SigstoreSign) instanceHelpText(fallback string) string {
	if s.SigstoreCommon == nil {
		return fallback
	}
	instances := s.Instances()
	if len(instances) == 0 {
		return fallback
	}
	ids := make([]string, len(instances))
	for i := range instances {
		ids[i] = instances[i].ID
	}
	if len(ids) == 1 {
		return fmt.Sprintf("%s (default %q)", fallback, ids[0])
	}
	return fmt.Sprintf("%s (default %q; available: %s)", fallback, ids[0], strings.Join(ids, ", "))
}

// ResolveInstance returns a fresh sigstore.Instance populated from the
// selected roots entry overlaid with the OIDC + toggle overrides held
// on this SigstoreSign. Empty OIDC override fields leave the roots
// file value unchanged. Returns an error if the selected instance
// can't be resolved.
func (s *SigstoreSign) ResolveInstance() (*sigstore.Instance, error) {
	entry, err := s.Instance(s.InstanceName)
	if err != nil {
		return nil, err
	}
	inst := entry.Instance
	inst.AppendToRekor = s.RekorAppend
	inst.Timestamp = s.Timestamp
	inst.DisableSTS = s.DisableSTS
	inst.STSProviders = slices.Clone(s.STSProviders)
	inst.HideOIDCOptions = s.HideOIDCOptions
	if s.OIDCClientID != "" {
		inst.OIDCConfig.ClientID = s.OIDCClientID
	}
	if s.OIDCRedirectURL != "" {
		inst.OIDCConfig.RedirectURL = s.OIDCRedirectURL
	}
	if s.OIDCClientSecret != "" {
		inst.OIDCConfig.ClientSecret = s.OIDCClientSecret
	}
	return &inst, nil
}

// ApplyToSigner populates the legacy *options.Signer with the resolved
// sigstore.Instance held on this SigstoreSign. Tools migrating to the
// new OptionsSet layer call this immediately before handing the legacy
// Signer to signer.NewSigner. Marks the target's roots as already
// parsed so the runtime ParseRoots is a no-op and doesn't overwrite
// the resolved instance.
//
// OIDC token-file loading is the caller's responsibility — they
// should read s.OIDCTokenFile, decode the wrapper into an
// *oauthflow.OIDCIDToken, and set target.Token before signing.
func (s *SigstoreSign) ApplyToSigner(target *Signer) error {
	if target == nil {
		return errors.New("ApplyToSigner: target is nil")
	}
	inst, err := s.ResolveInstance()
	if err != nil {
		return err
	}
	target.Instance = *inst
	target.parsedRoots = true
	return nil
}

// SigstoreSignSet bundles a SigstoreCommon and a SigstoreSign sharing
// the same flag prefix — the typical shape needed by a CLI signing
// tool. AddFlags registers the common flags (--<prefix>-roots) and the
// sign flags (--<prefix>-instance, --<prefix>-oidc-*, etc.) in one
// call. Validate runs the signing-side validation. BuildSigner
// produces a populated *Signer ready to hand to signer.NewSigner.
type SigstoreSignSet struct {
	Common *SigstoreCommon
	Sign   *SigstoreSign
}

// DefaultSigstoreSignSet builds a SigstoreSignSet with the default
// embedded sigstore roots and signing toggles, and the supplied
// flag prefix applied to both the Common and Sign Config(). Empty
// prefix produces bare flag names (e.g. --roots, --instance).
func DefaultSigstoreSignSet(flagPrefix string) *SigstoreSignSet {
	common := DefaultSigstoreCommon()
	common.Config().FlagPrefix = flagPrefix
	sign := DefaultSigstoreSign(common)
	sign.Config().FlagPrefix = flagPrefix
	return &SigstoreSignSet{Common: common, Sign: sign}
}

var _ command.OptionsSet = (*SigstoreSignSet)(nil)

// Config returns the SigstoreSign Config — the bundle's primary
// flag-namespace identity. Common's Config() is registered separately
// via the embedded *SigstoreCommon when AddFlags runs.
func (s *SigstoreSignSet) Config() *command.OptionsSetConfig {
	return s.Sign.Config()
}

// AddFlags registers both Common and Sign flags. Common goes first so
// the shared --<prefix>-roots flag is registered exactly once.
func (s *SigstoreSignSet) AddFlags(cmd *cobra.Command) {
	s.Common.AddFlags(cmd)
	s.Sign.AddFlags(cmd)
}

// Validate runs the signing-side validation. Returns an error if the
// set was zero-valued (nil receiver or nil Sign) rather than panicking,
// so callers can detect "constructed" vs "zero" reliably.
func (s *SigstoreSignSet) Validate() error {
	if s == nil || s.Sign == nil {
		return errors.New("SigstoreSignSet: nil; construct via DefaultSigstoreSignSet")
	}
	return s.Sign.Validate()
}

// BuildSigner returns a *Signer populated by the resolved
// sigstore.Instance held on this set, ready to assign to
// signer.Signer.Options. Nil-safe.
func (s *SigstoreSignSet) BuildSigner() (*Signer, error) {
	if s == nil || s.Sign == nil {
		return nil, errors.New("SigstoreSignSet: nil; construct via DefaultSigstoreSignSet")
	}
	target := DefaultSigner
	if err := s.Sign.ApplyToSigner(&target); err != nil {
		return nil, err
	}
	return &target, nil
}

// SigstoreVerify is the OptionsSet for the verification side of a
// sigstore workflow. The require-CTlog/Tlog/observer-timestamp/
// signed-timestamps policy is per-instance configuration that lives
// in sigstore-roots.json and is read by the bundle verifier directly
// — it's not a user-tunable knob, so this set carries no toggle
// flags. It exists primarily so SigstoreVerifySet has a verify-side
// counterpart to SigstoreSign and so SigstoreCommon's --roots flag
// flows through to the runtime.
type SigstoreVerify struct {
	*SigstoreCommon

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SigstoreVerify)(nil)

// DefaultSigstoreVerify builds a SigstoreVerify sharing the supplied
// common. Pass nil for common to allocate a fresh one.
func DefaultSigstoreVerify(common *SigstoreCommon) *SigstoreVerify {
	if common == nil {
		common = DefaultSigstoreCommon()
	}
	return &SigstoreVerify{SigstoreCommon: common}
}

// Config returns the flag configuration for SigstoreVerify. Currently
// empty — SigstoreCommon owns the only verify-side flag (--roots).
// Kept so SigstoreVerify implements command.OptionsSet uniformly with
// the rest of the family.
func (v *SigstoreVerify) Config() *command.OptionsSetConfig {
	if v.config == nil {
		v.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{},
		}
	}
	return v.config
}

// AddFlags is a no-op. SigstoreCommon registers --roots; SigstoreVerify
// has no flags of its own.
func (v *SigstoreVerify) AddFlags(cmd *cobra.Command) {
	_ = v.Config()
}

// Validate ensures the embedded SigstoreCommon is populated and the
// roots configuration loads cleanly.
func (v *SigstoreVerify) Validate() error {
	if v.SigstoreCommon == nil {
		return errors.New("SigstoreVerify: SigstoreCommon is nil")
	}
	return v.SigstoreCommon.Validate()
}

// ApplyToVerifier writes the sigstore-roots configuration onto target
// so signer.NewVerifier(...) consumes it.
func (v *SigstoreVerify) ApplyToVerifier(target *Verifier) error {
	if target == nil {
		return errors.New("SigstoreVerify.ApplyToVerifier: target is nil")
	}
	if v.SigstoreCommon == nil {
		return errors.New("SigstoreVerify: SigstoreCommon is nil")
	}
	target.SigstoreRootsPath = v.RootsPath
	if len(v.RootsData) > 0 {
		target.SigstoreRootsData = v.RootsData
	}
	return nil
}

// SigstoreVerifySet bundles a SigstoreCommon and a SigstoreVerify
// sharing the same flag prefix. Mirror of SigstoreSignSet for the
// verify side.
type SigstoreVerifySet struct {
	Common *SigstoreCommon
	Verify *SigstoreVerify
}

// DefaultSigstoreVerifySet builds a SigstoreVerifySet with the default
// embedded sigstore roots and verifier toggles, applying flagPrefix to
// both Common and Verify Config(). Empty prefix produces bare flag
// names (e.g. --roots, --require-ctlog).
func DefaultSigstoreVerifySet(flagPrefix string) *SigstoreVerifySet {
	common := DefaultSigstoreCommon()
	common.Config().FlagPrefix = flagPrefix
	verify := DefaultSigstoreVerify(common)
	verify.Config().FlagPrefix = flagPrefix
	return &SigstoreVerifySet{Common: common, Verify: verify}
}

var _ command.OptionsSet = (*SigstoreVerifySet)(nil)

// Config returns the SigstoreVerify Config — the bundle's primary
// flag-namespace identity.
func (s *SigstoreVerifySet) Config() *command.OptionsSetConfig {
	return s.Verify.Config()
}

// AddFlags registers both Common and Verify flags. Common first so
// the shared --<prefix>-roots flag is registered exactly once.
func (s *SigstoreVerifySet) AddFlags(cmd *cobra.Command) {
	s.Common.AddFlags(cmd)
	s.Verify.AddFlags(cmd)
}

// Validate runs the verify-side validation. Nil-safe so callers can
// detect a zero-value receiver without panicking.
func (s *SigstoreVerifySet) Validate() error {
	if s == nil || s.Verify == nil {
		return errors.New("SigstoreVerifySet: nil; construct via DefaultSigstoreVerifySet")
	}
	return s.Verify.Validate()
}

// ApplyToVerifier delegates to SigstoreVerify.ApplyToVerifier. Nil-safe.
func (s *SigstoreVerifySet) ApplyToVerifier(target *Verifier) error {
	if s == nil || s.Verify == nil {
		return errors.New("SigstoreVerifySet: nil; construct via DefaultSigstoreVerifySet")
	}
	return s.Verify.ApplyToVerifier(target)
}

// Active reports whether the bundled VerifierSet should consult this
// child. Sigstore is the always-on verification baseline — even with
// no user flags, the embedded sigstore.DefaultRoots make
// SigstoreVerifySet ready to verify, so Active is true whenever the
// set is non-nil. Returning false here would suppress sigstore
// verification entirely, which is rarely what callers want.
func (s *SigstoreVerifySet) Active() bool {
	return s != nil && s.Verify != nil && s.Common != nil
}

// BuildVerifier returns a *Verifier populated from the resolved
// sigstore-roots configuration. Mirrors SigstoreSignSet.BuildSigner
// on the verify side.
func (s *SigstoreVerifySet) BuildVerifier() (*Verifier, error) {
	target := DefaultVerifier
	if err := s.ApplyToVerifier(&target); err != nil {
		return nil, err
	}
	return &target, nil
}
