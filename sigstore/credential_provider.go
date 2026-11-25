// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"

	"github.com/policylabs/signer/internal/httpretry"
	"github.com/policylabs/signer/sts"
)

// CredentialProvider implements bundle.CredentialProvider and binds a sigstore
// instance (OIDC provider + Fulcio) to a signer.
type CredentialProvider struct {
	// Instance holds the sigstore configuration (TUF options, signing config,
	// OIDC client config, verifier config).
	Instance *Instance

	// DisableSTS skips the ambient credential providers.
	DisableSTS bool

	// STSProviders names the ambient credential providers to try, in
	// order. No other provider is consulted. When empty, all the
	// registered providers are tried in their default order (see
	// sts.Ordered).
	STSProviders []string

	// Token is an optional pre-provided OIDC ID token. When set, Prepare skips
	// the ambient STS providers; the token still flows through OIDConnect so
	// that it is parsed/validated the same way as a freshly issued one.
	// Treated as read-only input: Prepare stores the parsed result in the
	// private token field instead of writing back here.
	Token *oauthflow.OIDCIDToken

	// mu guards the lazy preparation state below. Prepare errors are not
	// cached: prepared is only set on success, so later calls retry after
	// a transient failure.
	mu          sync.Mutex
	token       *oauthflow.OIDCIDToken
	keypair     *sign.EphemeralKeypair
	cp          sign.CertificateProvider
	trustedRoot *root.TrustedRoot
	prepared    bool
}

// NewCredentialProvider creates a sigstore CredentialProvider for the given Instance.
func NewCredentialProvider(instance *Instance) *CredentialProvider {
	return &CredentialProvider{Instance: instance}
}

// Prepare runs the OIDC flow, ensures TUF roots are on disk, generates an
// ephemeral keypair, and builds the Fulcio certificate provider. Subsequent
// calls are no-ops. Safe for concurrent use.
func (p *CredentialProvider) Prepare(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.prepared {
		return nil
	}
	if p.Instance == nil {
		return errors.New("sigstore instance not set")
	}

	// Resolve the trusted root through the new single sigstore resolver (embedded
	// when fresh or TUF). Keep it so CertifiedKey can reconstruct the Fulcio
	// intermediate chain (sigstore-go's Fulcio provider returns onlythe leaf).
	trustedRoot, err := p.Instance.TrustedRoot()
	if err != nil {
		return fmt.Errorf("fetching trusted root: %w", err)
	}
	p.trustedRoot = trustedRoot

	// Generate the ephemeral keypair that will be bound to the Fulcio cert.
	kp, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	if _, err := kp.GetPublicKeyPem(); err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}
	p.keypair = kp

	// Try ambient STS providers before falling back to an interactive flow.
	seed := p.Token
	if !p.DisableSTS && seed == nil {
		ambient, err := p.runAmbientSTS(ctx)
		if err != nil {
			return fmt.Errorf("fetching ambient credentials: %w", err)
		}
		seed = ambient
	}

	tok, err := p.runOIDCFlow(seed)
	if err != nil {
		return fmt.Errorf("getting ID token: %w", err)
	}
	p.token = tok

	fulcioURL := p.Instance.FulcioURL()
	if fulcioURL == "" {
		return errors.New("no fulcio URL configured in signing config")
	}

	// Wrap Fulcio with a validity-window cache so repeated signs with the
	// same identity reuse the certificate until it expires.
	p.cp = &cachingCertProvider{inner: newFulcio(fulcioURL)}

	p.prepared = true
	return nil
}

// Keypair returns the ephemeral keypair bound to the Fulcio certificate.
func (p *CredentialProvider) Keypair() sign.Keypair {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keypair
}

// CertificateProvider returns the Fulcio provider and the OIDC ID token that
// authenticates the signing cert request. The token parsed during Prepare
// wins; the public Token field is the fallback for providers assembled by
// hand that never went through Prepare.
func (p *CredentialProvider) CertificateProvider() (sign.CertificateProvider, *sign.CertificateProviderOptions) {
	p.mu.Lock()
	defer p.mu.Unlock()

	tok := p.token
	if tok == nil {
		tok = p.Token
	}

	var opts *sign.CertificateProviderOptions
	if tok != nil {
		opts = &sign.CertificateProviderOptions{IDToken: tok.RawString}
	}
	return p.cp, opts
}

// Intermediates returns nil. The Fulcio chain is reconstructed at verify
// time from the sigstore TUF root, so no intermediates are embedded in the
// bundle's VerificationMaterial.
func (p *CredentialProvider) Intermediates() []*x509.Certificate { return nil }

// CertifiedKey runs the keyless (Fulcio) flow with a freshly generated key and
// returns the leaf certificate with its intermediate chain (leaf-adjacent first,
// root excluded), and the private key. The material is suitable for building a
// detached CMS/PKCS7 signature. We built this to emulate the gitsign signer but
// it can be used to sign anything with the same ambient identity the sigstore
// bundle backend signs with.
//
// Unlike the bundle path, the returned key is available to the caller as a
// crypto.Signer,. this function generates its own key and drives the Fulcio
// certificate request with it but ( as opposed to sigstore-go's that hides its
// its key in EphemeralKeypair), the issued certificate binds to a key the caller
// gets to keep.
//
// The ambient OIDC token and Fulcio provider are obtained through Prepare, so an
// injected Token / DisableSTS is honored exactly like the signing path.
func (p *CredentialProvider) CertifiedKey(ctx context.Context) (
	leaf *x509.Certificate, chain []*x509.Certificate, key crypto.Signer, err error,
) {
	if err := p.Prepare(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("preparing credentials: %w", err)
	}

	// Generate our own key so we can hand the crypto.Signer back to the caller.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating signing key: %w", err)
	}
	kp, err := NewSignerKeypair(priv, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building keypair: %w", err)
	}

	cp, opts := p.CertificateProvider()
	if cp == nil {
		return nil, nil, nil, errors.New("no certificate provider available after Prepare")
	}
	// Bypass the validity-window cache: it is keyed only by time, not by
	// keypair, so it may hold a certificate bound to the bundle path's ephemeral
	// key. We need one freshly bound to the key we just generated.
	if cc, ok := cp.(*cachingCertProvider); ok {
		cp = cc.inner
	}

	// When the provider can return a full chain (leaf + intermediates), use it.
	// The real Fulcio provider only returns the leaf, so fall back to
	// reconstructing the intermediates from the sigstore trusted root.
	if ccp, ok := cp.(sign.CertificateChainProvider); ok {
		chainDER, cerr := ccp.GetCertificateChain(ctx, kp, opts)
		if cerr != nil {
			return nil, nil, nil, fmt.Errorf("requesting certificate chain: %w", cerr)
		}
		leaf, chain, err = parseLeafAndChain(chainDER)
		if err != nil {
			return nil, nil, nil, err
		}
		return leaf, chain, priv, nil
	}

	leafDER, cerr := cp.GetCertificate(ctx, kp, opts)
	if cerr != nil {
		return nil, nil, nil, fmt.Errorf("requesting certificate: %w", cerr)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	return leaf, p.fulcioIntermediates(leaf), priv, nil
}

// fulcioIntermediates reconstructs the intermediate chain for a Fulcio-issued
// leaf from the sigstore trusted root. sigstore-go's Fulcio provider returns
// only the leaf, so the intermediates — which a detached CMS signature needs to
// chain to the Fulcio root — come from the trust root fetched during Prepare.
// Returns nil when no matching authority is found: the leaf alone is still
// usable and the caller can supply intermediates from its own trust root.
func (p *CredentialProvider) fulcioIntermediates(leaf *x509.Certificate) []*x509.Certificate {
	if p.trustedRoot == nil || leaf == nil {
		return nil
	}
	for _, ca := range p.trustedRoot.FulcioCertificateAuthorities() {
		chains, err := ca.Verify(leaf, leaf.NotBefore)
		if err != nil || len(chains) == 0 {
			continue
		}
		// Each chain is [leaf, intermediate(s)..., root]; drop leaf and root.
		chain := chains[0]
		if len(chain) <= 2 {
			return nil
		}
		intermediates := chain[1 : len(chain)-1]
		out := make([]*x509.Certificate, len(intermediates))
		copy(out, intermediates)
		return out
	}
	return nil
}

// parseLeafAndChain parses a DER chain (leaf first) into the leaf certificate
// and its intermediates, dropping a trailing self-signed root if the provider
// included one (CMS callers supply the trust anchor out of band).
func parseLeafAndChain(chainDER [][]byte) (leaf *x509.Certificate, chain []*x509.Certificate, err error) {
	if len(chainDER) == 0 {
		return nil, nil, errors.New("certificate provider returned an empty chain")
	}
	certs := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			return nil, nil, fmt.Errorf("parsing certificate %d in chain: %w", i, perr)
		}
		certs = append(certs, c)
	}

	leaf = certs[0]
	intermediates := certs[1:]
	if n := len(intermediates); n > 0 && isSelfSigned(intermediates[n-1]) {
		intermediates = intermediates[:n-1]
	}
	if len(intermediates) == 0 {
		return leaf, nil, nil
	}
	out := make([]*x509.Certificate, len(intermediates))
	copy(out, intermediates)
	return leaf, out, nil
}

// isSelfSigned reports whether a certificate's issuer equals its subject, the
// hallmark of a trust-anchor root.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// newFulcio returns a client of the Fulcio instance at baseURL that rides out
// its passing failures: answers that say to try again (5xx and 429) are
// retried by the client itself, connections that fail by the transport.
func newFulcio(baseURL string) *sign.Fulcio {
	return sign.NewFulcio(&sign.FulcioOptions{
		BaseURL:   baseURL,
		Timeout:   30 * time.Second,
		Retries:   httpretry.Retries,
		Transport: httpretry.NewTransport(),
	})
}

// runAmbientSTS tries the STS providers and returns the first token one of
// them yields, or nil when no provider has credentials. The providers are
// the ones named in STSProviders, in that order, or all the registered ones
// in their default order (see sts.Ordered) when none is named.
func (p *CredentialProvider) runAmbientSTS(ctx context.Context) (*oauthflow.OIDCIDToken, error) {
	providers, err := sts.Select(p.STSProviders...)
	if err != nil {
		return nil, err
	}
	return firstAmbientToken(ctx, providers, p.Instance.OIDCConfig.ClientID)
}

// firstAmbientToken tries providers one after the other and returns the
// first token one of them yields, or nil when none has credentials.
//
// A provider that fails ends the search: its environment is there but
// broken, and signing with the identity of another provider instead would
// hide that. Providers after the one that yields a token are not tried.
//
// The name of the provider that yields the token is logged at the debug
// level. The token is not.
func firstAmbientToken(ctx context.Context, providers []sts.Named, audience string) (*oauthflow.OIDCIDToken, error) {
	for _, named := range providers {
		token, err := named.Provider.Provide(ctx, audience)
		if err != nil {
			return nil, fmt.Errorf("trying ambient credentials from %s: %w", named.Name, err)
		}
		if token != nil {
			logrus.Debugf("using ambient credentials from the %s STS provider", named.Name)
			return token, nil
		}
	}
	logrus.Debugf("no ambient credentials found (%d STS providers tried)", len(providers))
	return nil, nil
}

// runOIDCFlow does the OIDC exchange to get the token.
// If a seed token is provided it goes through the static flow which just
// parses and returns it unchanged. Otherwise the flow is chosen based on the
// environment (browser, device flow, or fail-fast in CI).
func (p *CredentialProvider) runOIDCFlow(seed *oauthflow.OIDCIDToken) (*oauthflow.OIDCIDToken, error) {
	issuer := p.Instance.OidcIssuerURL()

	var flow oauthflow.TokenGetter
	switch {
	case seed != nil:
		flow = &oauthflow.StaticTokenGetter{RawToken: seed.RawString}
	case !term.IsTerminal(0):
		if os.Getenv("CI") != "" {
			return nil, fmt.Errorf(
				"no OIDC ambient credentials found in CI environment, " +
					"ensure the workflow has 'id-token: write' permission",
			)
		}
		flow = oauthflow.NewDeviceFlowTokenGetterForIssuer(issuer)
	default:
		flow = oauthflow.DefaultIDTokenGetter
	}

	return oauthflow.OIDConnect(
		issuer,
		p.Instance.OIDCConfig.ClientID,
		p.Instance.OIDCConfig.ClientSecret,
		randomizePort(p.Instance.OIDCConfig.RedirectURL),
		flow,
	)
}

func randomizePort(redirectURL string) string {
	p, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}

	rond, err := rand.Int(rand.Reader, big.NewInt(64511))
	if err != nil {
		return ""
	}
	return strings.Replace(
		redirectURL,
		fmt.Sprintf("%s:0/", p.Hostname()),
		fmt.Sprintf("%s:%d/", p.Hostname(), rond.Int64()+1025),
		1,
	)
}

// cachingCertProvider wraps a CertificateProvider and caches the certificate
// within its validity window. This avoids issuing multiple Fulcio certificate
// requests when the same keypair is used to sign several artifacts.
//
// The mutex spans the whole check-fetch-store sequence, which doubles as
// singleflight: when the cached certificate expires mid-run, one caller
// refreshes it while concurrent signs wait instead of stampeding Fulcio.
type cachingCertProvider struct {
	mu        sync.Mutex
	inner     sign.CertificateProvider
	cert      []byte
	notBefore time.Time
	notAfter  time.Time
}

func (c *cachingCertProvider) GetCertificate(ctx context.Context, kp sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if c.cert != nil && now.After(c.notBefore) && now.Before(c.notAfter) {
		return c.cert, nil
	}

	cert, err := c.inner.GetCertificate(ctx, kp, opts)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("parsing cached certificate: %w", err)
	}

	c.cert = cert
	c.notBefore = x509Cert.NotBefore
	c.notAfter = x509Cert.NotAfter
	return cert, nil
}
