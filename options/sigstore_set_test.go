// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/sigstore"
)

func TestSigstoreCommonLoadRoots(t *testing.T) {
	t.Parallel()

	t.Run("embedded-default-when-empty", func(t *testing.T) {
		t.Parallel()
		c := DefaultSigstoreCommon()
		require.NoError(t, c.LoadRoots())
		require.NotEmpty(t, c.Instances())
		require.Equal(t, "sigstore", c.Instances()[0].ID, "first embedded instance should be 'sigstore'")
	})

	t.Run("inline-data", func(t *testing.T) {
		t.Parallel()
		c := &SigstoreCommon{RootsData: sigstore.DefaultRoots}
		require.NoError(t, c.LoadRoots())
		require.NotEmpty(t, c.Instances())
	})

	t.Run("file-path", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "roots.json")
		require.NoError(t, os.WriteFile(path, sigstore.DefaultRoots, 0o600))
		c := &SigstoreCommon{RootsPath: path}
		require.NoError(t, c.LoadRoots())
		require.NotEmpty(t, c.Instances())
	})

	t.Run("missing-file", func(t *testing.T) {
		t.Parallel()
		c := &SigstoreCommon{RootsPath: filepath.Join(t.TempDir(), "nope.json")}
		err := c.LoadRoots()
		require.Error(t, err)
		require.Contains(t, err.Error(), "reading sigstore roots")
	})

	t.Run("invalid-json", func(t *testing.T) {
		t.Parallel()
		c := &SigstoreCommon{RootsData: []byte("not json")}
		err := c.LoadRoots()
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing sigstore roots")
	})

	t.Run("empty-roots-list", func(t *testing.T) {
		t.Parallel()
		c := &SigstoreCommon{RootsData: []byte(`{"roots":[]}`)}
		err := c.LoadRoots()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no sigstore instances")
	})

	t.Run("idempotent", func(t *testing.T) {
		t.Parallel()
		c := DefaultSigstoreCommon()
		require.NoError(t, c.LoadRoots())
		require.NoError(t, c.LoadRoots(), "second LoadRoots must be a no-op")
	})

	t.Run("path-takes-precedence-over-data", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "roots.json")
		require.NoError(t, os.WriteFile(path, sigstore.DefaultRoots, 0o600))
		// RootsData would parse but RootsPath should win.
		c := &SigstoreCommon{
			RootsPath: path,
			RootsData: []byte(`{"roots":[]}`),
		}
		require.NoError(t, c.LoadRoots())
		require.NotEmpty(t, c.Instances())
	})
}

func TestSigstoreCommonInstance(t *testing.T) {
	t.Parallel()

	t.Run("empty-name-returns-first", func(t *testing.T) {
		t.Parallel()
		c := DefaultSigstoreCommon()
		inst, err := c.Instance("")
		require.NoError(t, err)
		require.Equal(t, "sigstore", inst.ID, "empty name must default to Roots[0]")
	})

	t.Run("by-id", func(t *testing.T) {
		t.Parallel()
		c := DefaultSigstoreCommon()
		inst, err := c.Instance("github")
		require.NoError(t, err)
		require.Equal(t, "github", inst.ID)
	})

	t.Run("not-found", func(t *testing.T) {
		t.Parallel()
		c := DefaultSigstoreCommon()
		_, err := c.Instance("does-not-exist")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("propagates-load-error", func(t *testing.T) {
		t.Parallel()
		c := &SigstoreCommon{RootsData: []byte("not json")}
		_, err := c.Instance("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing sigstore roots")
	})
}

func TestSigstoreSignAddFlags(t *testing.T) {
	t.Parallel()

	t.Run("registers-all-flags-bare", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.HideOIDCOptions = false // so we can find the flags by name
		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)

		for _, name := range []string{
			"instance",
			"oidc-client-id",
			"oidc-redirect-url",
			"oidc-client-secret",
			"oidc-token-file",
			"rekor-append",
			"timestamp",
			"disable-sts",
			"sts-providers",
		} {
			require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %s must be registered", name)
		}
	})

	t.Run("registers-with-sigstore-prefix", func(t *testing.T) {
		t.Parallel()
		// Typical CLI usage: prefix all sigstore flags with "sigstore-"
		// to avoid collisions in the larger command surface.
		s := DefaultSigstoreSign(nil)
		s.HideOIDCOptions = false
		s.Config().FlagPrefix = "sigstore"
		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)

		for _, name := range []string{
			"sigstore-instance",
			"sigstore-oidc-client-id",
			"sigstore-rekor-append",
			"sigstore-timestamp",
		} {
			require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %s must be registered", name)
		}
	})

	t.Run("hides-oidc-when-configured", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		require.True(t, s.HideOIDCOptions, "default should hide OIDC")
		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)

		f := cmd.PersistentFlags().Lookup("oidc-client-id")
		require.NotNil(t, f)
		require.True(t, f.Hidden, "OIDC flag should be hidden")
	})

	t.Run("flag-prefix-applies-to-all", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.HideOIDCOptions = false
		s.Config().FlagPrefix = "alt"
		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)
		require.NotNil(t, cmd.PersistentFlags().Lookup("alt-rekor-append"))
		require.NotNil(t, cmd.PersistentFlags().Lookup("alt-oidc-client-id"))
		require.NotNil(t, cmd.PersistentFlags().Lookup("alt-instance"))
	})
}

func TestSigstoreSignInstanceHelpText(t *testing.T) {
	t.Parallel()

	t.Run("multi-instance-lists-available", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.HideOIDCOptions = false
		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)

		f := cmd.PersistentFlags().Lookup("instance")
		require.NotNil(t, f)
		// The embedded default roots have at least sigstore + github.
		require.Contains(t, f.Usage, `default "sigstore"`)
		require.Contains(t, f.Usage, "available:")
		require.Contains(t, f.Usage, "sigstore")
		require.Contains(t, f.Usage, "github")
	})

	t.Run("falls-back-when-common-nil", func(t *testing.T) {
		t.Parallel()
		s := &SigstoreSign{} // no SigstoreCommon
		got := s.instanceHelpText("BASE")
		require.Equal(t, "BASE", got, "must fall back when no common is set")
	})

	t.Run("falls-back-when-roots-fail-to-load", func(t *testing.T) {
		t.Parallel()
		c := &SigstoreCommon{RootsData: []byte("not json")}
		s := DefaultSigstoreSign(c)
		got := s.instanceHelpText("BASE")
		require.Equal(t, "BASE", got, "must fall back when LoadRoots fails")
	})
}

func TestSigstoreSignResolveInstance(t *testing.T) {
	t.Parallel()

	t.Run("default-resolves-first-instance", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		inst, err := s.ResolveInstance()
		require.NoError(t, err)
		require.NotNil(t, inst)
		require.True(t, inst.AppendToRekor, "default should enable Rekor")
		require.True(t, inst.Timestamp, "default should enable TSA")
		require.False(t, inst.DisableSTS)
	})

	t.Run("oidc-overrides-applied", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.OIDCClientID = "my-client"
		s.OIDCRedirectURL = "http://localhost:9999/callback"
		s.OIDCClientSecret = "shh"

		inst, err := s.ResolveInstance()
		require.NoError(t, err)
		require.Equal(t, "my-client", inst.OIDCConfig.ClientID)
		require.Equal(t, "http://localhost:9999/callback", inst.OIDCConfig.RedirectURL)
		require.Equal(t, "shh", inst.OIDCConfig.ClientSecret)
	})

	t.Run("empty-overrides-leave-roots-values", func(t *testing.T) {
		t.Parallel()
		s := &SigstoreSign{
			SigstoreCommon: DefaultSigstoreCommon(),
			// leave OIDC fields empty
		}
		inst, err := s.ResolveInstance()
		require.NoError(t, err)
		// Roots file may be empty for these fields too — just confirm we
		// didn't blank out existing data: the instance's OIDCConfig must
		// be the same as the loaded roots' OIDCConfig.
		entry, err := s.Instance("")
		require.NoError(t, err)
		require.Equal(t, entry.OIDCConfig.ClientID, inst.OIDCConfig.ClientID)
	})

	t.Run("toggles-applied", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.RekorAppend = false
		s.Timestamp = false
		s.DisableSTS = true
		inst, err := s.ResolveInstance()
		require.NoError(t, err)
		require.False(t, inst.AppendToRekor)
		require.False(t, inst.Timestamp)
		require.True(t, inst.DisableSTS)
	})

	t.Run("sts-providers", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		inst, err := s.ResolveInstance()
		require.NoError(t, err)
		require.Empty(t, inst.STSProviders, "no provider is named by default")

		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)
		require.NoError(t, cmd.PersistentFlags().Parse([]string{"--sts-providers=gcp,actions"}))
		require.NoError(t, s.Validate())

		inst, err = s.ResolveInstance()
		require.NoError(t, err)
		require.Equal(t, []string{"gcp", "actions"}, inst.STSProviders)

		// The names reach the credential provider the signer builds.
		target := &Signer{}
		require.NoError(t, s.ApplyToSigner(target))
		require.Equal(t, []string{"gcp", "actions"}, target.BuildSigstoreCredentials().STSProviders)
	})

	t.Run("explicit-instance-name", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.InstanceName = "github"
		inst, err := s.ResolveInstance()
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("unknown-instance-name-errors", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.InstanceName = "does-not-exist"
		_, err := s.ResolveInstance()
		require.Error(t, err)
	})

	t.Run("returns-fresh-struct", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		first, err := s.ResolveInstance()
		require.NoError(t, err)
		first.OIDCConfig.ClientID = "mutated"
		second, err := s.ResolveInstance()
		require.NoError(t, err)
		require.NotEqual(t, "mutated", second.OIDCConfig.ClientID,
			"ResolveInstance must return a fresh instance each call")
	})
}

func TestSigstoreSignValidate(t *testing.T) {
	t.Parallel()

	t.Run("default-passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DefaultSigstoreSign(nil).Validate())
	})

	t.Run("nil-common-fails", func(t *testing.T) {
		t.Parallel()
		s := &SigstoreSign{}
		err := s.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SigstoreCommon is nil")
	})

	t.Run("unknown-instance-fails", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.InstanceName = "does-not-exist"
		err := s.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})
}

func TestSigstoreSignValidateSTSProviders(t *testing.T) {
	t.Parallel()

	t.Run("known", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.STSProviders = []string{"actions"}
		require.NoError(t, s.Validate())
	})

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.STSProviders = []string{"actions", "nope"}
		require.ErrorContains(t, s.Validate(), `unknown STS provider "nope"`)
	})

	t.Run("twice", func(t *testing.T) {
		t.Parallel()
		s := DefaultSigstoreSign(nil)
		s.STSProviders = []string{"gcp", "gcp"}
		require.ErrorContains(t, s.Validate(), "more than once")
	})

	t.Run("with-disable-sts", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreSignSet("sigstore")
		set.Sign.STSProviders = []string{"actions"}
		set.Sign.DisableSTS = true
		require.ErrorContains(t, set.Validate(),
			"--sigstore-sts-providers and --sigstore-disable-sts cannot be used together")
	})
}

func TestSigstoreVerifyValidate(t *testing.T) {
	t.Parallel()

	t.Run("default-passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DefaultSigstoreVerify(nil).Validate())
	})

	t.Run("nil-common-fails", func(t *testing.T) {
		t.Parallel()
		v := &SigstoreVerify{}
		err := v.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SigstoreCommon is nil")
	})
}

// TestSigstoreCommonSharedBetweenSignAndVerify documents the recommended
// usage pattern: one *SigstoreCommon shared by pointer between the sign
// and verify sets, and only the common's flags registered (once) for
// --sigstore-roots.
func TestSigstoreCommonSharedBetweenSignAndVerify(t *testing.T) {
	t.Parallel()
	common := DefaultSigstoreCommon()
	sign := DefaultSigstoreSign(common)
	verify := DefaultSigstoreVerify(common)

	require.Same(t, common, sign.SigstoreCommon)
	require.Same(t, common, verify.SigstoreCommon)

	// Mutating the shared instance is observed by both sets.
	common.RootsPath = "/tmp/somewhere.json"
	require.Equal(t, "/tmp/somewhere.json", sign.RootsPath)
	require.Equal(t, "/tmp/somewhere.json", verify.RootsPath)
}

func TestSigstoreSignSet(t *testing.T) {
	t.Parallel()

	t.Run("default-prefixed-flags", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreSignSet("sigstore")
		set.Sign.HideOIDCOptions = false
		cmd := &cobra.Command{Use: "test"}
		set.AddFlags(cmd)

		for _, name := range []string{
			"sigstore-roots",
			"sigstore-instance",
			"sigstore-oidc-client-id",
			"sigstore-rekor-append",
			"sigstore-timestamp",
			"sigstore-disable-sts",
			"sigstore-sts-providers",
		} {
			require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %s must be registered", name)
		}
	})

	t.Run("validate-default-passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DefaultSigstoreSignSet("").Validate())
	})

	t.Run("validate-zero-value-fails", func(t *testing.T) {
		t.Parallel()
		require.Error(t, (&SigstoreSignSet{}).Validate())
	})

	t.Run("build-signer-populates-instance", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreSignSet("sigstore")
		signer, err := set.BuildSigner()
		require.NoError(t, err)
		require.NotEmpty(t, signer.OidcIssuerURL())
		require.NotEmpty(t, signer.FulcioURL())
		require.NotNil(t, signer.SigningConfig)
	})

	t.Run("build-signer-zero-value-fails", func(t *testing.T) {
		t.Parallel()
		_, err := (&SigstoreSignSet{}).BuildSigner()
		require.Error(t, err)
	})

	t.Run("empty-prefix-bare-flags", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreSignSet("")
		set.Sign.HideOIDCOptions = false
		cmd := &cobra.Command{Use: "test"}
		set.AddFlags(cmd)
		require.NotNil(t, cmd.PersistentFlags().Lookup("roots"))
		require.NotNil(t, cmd.PersistentFlags().Lookup("instance"))
	})
}

func TestSigstoreVerifySet(t *testing.T) {
	t.Parallel()

	t.Run("default-prefixed-flags", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreVerifySet("sigstore")
		cmd := &cobra.Command{Use: "test"}
		set.AddFlags(cmd)

		require.NotNil(t, cmd.PersistentFlags().Lookup("sigstore-roots"), "flag sigstore-roots must be registered")
	})

	t.Run("validate-default-passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DefaultSigstoreVerifySet("").Validate())
	})

	t.Run("validate-zero-value-fails", func(t *testing.T) {
		t.Parallel()
		require.Error(t, (&SigstoreVerifySet{}).Validate())
	})
}
