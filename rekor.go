// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	rverify "github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	api "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
	"github.com/policylabs/signer/sigstore"
)

// verifyKeylessDSSE verifies a DSSE envelope signed with a short lived
// Sigstore cert (the pre-bundle keyless flow of cosign and the
// slsa-github-generator) against the Rekor transparency log:
//
//  1. the log must hold an entry for the envelope's signature
//  2. the entry's signed timestamp must verify against the log's key,
//     and its inclusion proof when the entry carries one
//  3. the entry's integration time must fall inside the certificate's
//     validity (10m), standing in as the trusted signing time
//  4. the certificate must chain to a trusted Fulcio root at that time
//  5. the envelope signature must verify against the certificate's key
//
// A refuted step is a conclusion (FAILED), not an error. A log that
// cannot be reached or trust material that cannot be assembled is
// UNVERIFIABLE.
func (v *Verifier) verifyKeylessDSSE(art *EnvelopeArtifact, certPEM []byte, opts *options.Verification) (*api.Verification, error) {
	ctx := context.Background()
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		return conclude(api.VerificationStatus_UNVERIFIABLE,
			fmt.Sprintf("the signature's certificate cannot be parsed: %v", err)), nil
	}
	raw := art.Raw
	if raw == nil {
		// A programmatically built artifact has no original bytes in thiscase
		// the log is keyed by the uploaded serialization, so marshal what
		// there is and try with that.
		raw, err = protojson.Marshal(art.Envelope)
		if err != nil {
			return nil, fmt.Errorf("marshaling envelope: %w", err)
		}
	}

	// The envelope signature must verify against the certificate's key.
	// This is local and decisive: a mismatch refutes the envelope before
	// any transparency log is consulted.
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling certificate public key: %w", err)
	}
	pub, err := key.NewParser().ParsePublicKey(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("loading certificate public key: %w", err)
	}
	res, err := v.VerifyParsedDSSE(art.Envelope, []key.PublicKeyProvider{pub})
	if err != nil {
		return nil, fmt.Errorf("verifying envelope signature: %w", err)
	}
	if !res.Verified {
		return conclude(api.VerificationStatus_FAILED,
			"the envelope signature does not verify against the certificate's key"), nil
	}

	roots, err := v.sigstoreTrustedRoots()
	if err != nil {
		return conclude(api.VerificationStatus_UNVERIFIABLE,
			fmt.Sprintf("no sigstore trust material available: %v", err)), nil
	}

	entry, err := searchRekorEntry(ctx, opts.Rekor.GetURL(), raw, certPEM)
	if err != nil {
		return conclude(api.VerificationStatus_UNVERIFIABLE,
			fmt.Sprintf("querying the transparency log at %s: %v", opts.Rekor.GetURL(), err)), nil
	}
	if entry == nil {
		return conclude(api.VerificationStatus_FAILED,
			"the transparency log has no entry matching the envelope signature"), nil
	}

	// Verify the log's countersignature (and inclusion proof, when the
	// entry has one) with the log key the trusted root records for the
	// entry's log ID.
	logID := ""
	if entry.LogID != nil {
		logID = *entry.LogID
	}
	logVerifier, err := rekorLogVerifier(roots, logID)
	if err != nil {
		return conclude(api.VerificationStatus_UNVERIFIABLE, err.Error()), nil
	}
	if entry.Verification != nil && entry.Verification.InclusionProof != nil {
		err = rverify.VerifyLogEntry(ctx, entry, logVerifier)
	} else {
		err = rverify.VerifySignedEntryTimestamp(ctx, entry, logVerifier)
	}
	if err != nil {
		return conclude(api.VerificationStatus_FAILED,
			fmt.Sprintf("the transparency log entry did not verify: %v", err)), nil
	}

	// The verified integration time vouches for when the signature was
	// made: it must fall within the short-lived certificate's validity.
	var integratedUnix int64
	if entry.IntegratedTime != nil {
		integratedUnix = *entry.IntegratedTime
	}
	integrated := time.Unix(integratedUnix, 0)
	if integrated.Before(leaf.NotBefore) || integrated.After(leaf.NotAfter) {
		return conclude(api.VerificationStatus_FAILED, fmt.Sprintf(
			"the envelope was logged at %s, outside the signing certificate's validity (%s to %s)",
			integrated.UTC().Format(time.RFC3339), leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339),
		)), nil
	}

	if err := verifyFulcioChain(roots, leaf, integrated); err != nil {
		return conclude(api.VerificationStatus_FAILED, err.Error()), nil
	}

	summary, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		return conclude(api.VerificationStatus_UNVERIFIABLE,
			fmt.Sprintf("reading the certificate identity: %v", err)), nil
	}
	return verified([]*api.Identity{{
		Sigstore: api.IdentitySigstoreFromCertificate(summary.Issuer, summary.SubjectAlternativeName, &summary),
	}}), nil
}

// searchRekorEntry looks the envelope's signature up in the log by
// proposing the two entry kinds keyless DSSE envelopes were uploaded
// as: intoto v0.0.1 and dsse v0.0.1, both built from the envelope's original
// bytes and its certificate. Returns nil when the log has no entry.
func searchRekorEntry(ctx context.Context, url string, envelope, certPEM []byte) (*models.LogEntryAnon, error) {
	client, err := rekorclient.GetRekorClient(url)
	if err != nil {
		return nil, fmt.Errorf("building transparency log client: %w", err)
	}
	// The intoto v0.0.1 proposed entry is built by hand: its type
	// package drags rekor's server logging (and an HTTP router) into
	// the module graph, and the model is three fields.
	envelopeHash := sha256.Sum256(envelope)
	publicKey := strfmt.Base64(certPEM)
	intotoProposed := &models.Intoto{
		APIVersion: conv.Pointer("0.0.1"),
		Spec: models.IntotoV001Schema{
			Content: &models.IntotoV001SchemaContent{
				Envelope: string(envelope),
				Hash: &models.IntotoV001SchemaContentHash{
					Algorithm: conv.Pointer(models.IntotoV001SchemaContentHashAlgorithmSha256),
					Value:     conv.Pointer(hex.EncodeToString(envelopeHash[:])),
				},
			},
			PublicKey: &publicKey,
		},
	}
	dsseProposed, err := types.NewProposedEntry(ctx, rekordsse.KIND, dsse_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  envelope,
		PublicKeyBytes: [][]byte{certPEM},
	})
	if err != nil {
		return nil, fmt.Errorf("building proposed dsse entry: %w", err)
	}
	proposed := []models.ProposedEntry{intotoProposed, dsseProposed}
	params := entries.NewSearchLogQueryParams()
	query := models.SearchLogQuery{}
	query.SetEntries(proposed)
	params.SetEntry(&query)
	resp, err := client.Entries.SearchLogQueryContext(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("searching the log: %w", err)
	}
	for _, logEntry := range resp.GetPayload() {
		for _, anon := range logEntry {
			return &anon, nil
		}
	}
	return nil, nil
}

// sigstoreTrustedRoots resolves the trusted roots of every configured
// sigstore instance: the ones the verifier options name, or the
// embedded defaults.
func (v *Verifier) sigstoreTrustedRoots() ([]*root.TrustedRoot, error) {
	data := v.Options.SigstoreRootsData
	if v.Options.SigstoreRootsPath != "" {
		loaded, err := os.ReadFile(v.Options.SigstoreRootsPath)
		if err != nil {
			return nil, fmt.Errorf("reading sigstore roots: %w", err)
		}
		data = loaded
	}
	if len(data) == 0 {
		data = sigstore.DefaultRoots
	}
	parsed, err := sigstore.ParseRoots(data)
	if err != nil {
		return nil, fmt.Errorf("parsing sigstore roots: %w", err)
	}
	roots := make([]*root.TrustedRoot, 0, len(parsed.Roots))
	var errs []error
	for i := range parsed.Roots {
		tr, err := parsed.Roots[i].TrustedRoot()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		roots = append(roots, tr)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("resolving trusted roots: %w", errors.Join(errs...))
	}
	return roots, nil
}

// rekorLogVerifier returns a signature verifier for the log key the
// trusted roots record under logID.
func rekorLogVerifier(roots []*root.TrustedRoot, logID string) (signature.Verifier, error) {
	for _, tr := range roots {
		for id, tlog := range tr.RekorLogs() {
			if id != logID && hex.EncodeToString(tlog.ID) != logID {
				continue
			}
			verifier, err := signature.LoadVerifier(tlog.PublicKey, crypto.SHA256)
			if err != nil {
				return nil, fmt.Errorf("loading transparency log key: %w", err)
			}
			return verifier, nil
		}
	}
	return nil, fmt.Errorf("no trusted transparency log key for log id %s", logID)
}

// verifyFulcioChain checks the leaf chains to a trusted Fulcio root at
// the given time.
func verifyFulcioChain(roots []*root.TrustedRoot, leaf *x509.Certificate, at time.Time) error {
	for _, tr := range roots {
		for _, ca := range tr.FulcioCertificateAuthorities() {
			fca, ok := ca.(*root.FulcioCertificateAuthority)
			if !ok {
				continue
			}
			rootPool := x509.NewCertPool()
			rootPool.AddCert(fca.Root)
			intermediates := x509.NewCertPool()
			for _, ic := range fca.Intermediates {
				intermediates.AddCert(ic)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:         rootPool,
				Intermediates: intermediates,
				CurrentTime:   at,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			}); err == nil {
				return nil
			}
		}
	}
	return errors.New("the signing certificate does not chain to a trusted Fulcio root")
}

// firstSignatureCert returns the first certificate attached to the
// artifact's signatures, if any.
func firstSignatureCert(art *EnvelopeArtifact) []byte {
	for _, cert := range art.SignatureCerts {
		if len(cert) > 0 {
			return cert
		}
	}
	return nil
}

// certIdentityHint names the certificate's identity for messages, so an
// UNVERIFIABLE conclusion says who claims to have signed.
func certIdentityHint(certPEM []byte) string {
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		return "unreadable certificate"
	}
	summary, err := certificate.SummarizeCertificate(leaf)
	if err != nil || summary.SubjectAlternativeName == "" {
		return "unknown identity"
	}
	return fmt.Sprintf("identity %s issued by %s", summary.SubjectAlternativeName, summary.Issuer)
}

// parseCertPEM parses the first PEM block as an x509 certificate.
func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block in certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
