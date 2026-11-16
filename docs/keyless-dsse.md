# Verifying keyless DSSE envelopes

Before Sigstore bundles existed, keyless signers wrapped their payloads
in plain DSSE envelopes: cosign's early flow, and most notably the
[slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator),
whose `*.intoto.jsonl` provenance attests much of the existing SLSA
ecosystem. These envelopes carry the signature and, in a non-standard
`cert` field on each signature, the short-lived Fulcio certificate that
made it:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "…",
  "signatures": [
    {"keyid": "", "sig": "…", "cert": "-----BEGIN CERTIFICATE-----\n…"}
  ]
}
```

What they do **not** carry is any proof the signature was made while the
certificate was valid — Fulcio certificates expire about ten minutes
after issuance. That proof lives in the
[Rekor](https://docs.sigstore.dev/logging/overview/) transparency log:
the entry uploaded at signing time holds a countersigned timestamp and
an inclusion proof. A bundle inlines that entry; a legacy envelope needs
it fetched. This is the same verification a bundle gets, with the log
consulted over the network instead of read from the document.

## The gate: off by default

Because verifying one of these envelopes means calling out to a
transparency log, the feature is gated and **disabled by default**.
Without it, a keyless envelope is a conclusion, not an error:
`UNVERIFIABLE`, with the reason naming the certificate identity and the
option that would verify it:

```
the envelope is signed with a Sigstore certificate (identity
https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/heads/main
issued by https://token.actions.githubusercontent.com); verifying it
needs a transparency log lookup, which is disabled — enable it with
options.WithRekorVerification
```

Enable it per verification:

```go
v := signer.NewVerifier()
res, err := v.VerifyStatementBytes(envelopeBytes,
    options.WithRekorVerification(true),
    // options.WithRekorURL("https://rekor.example.com"), // default: rekor.sigstore.dev
)
```

The log is queried with a client that dials its own connections and
retries failed requests. To send the query through an HTTP client of
your own (a proxy, custom timeouts, or a platform where connections
cannot be dialed, such as js/wasm in a browser, where a client on
`http.DefaultTransport` goes through the Fetch API) pass it with
`options.WithRekorHTTPClient`. Timeouts and retries are then that
client's to handle:

```go
res, err := v.VerifyStatementBytes(envelopeBytes,
    options.WithRekorVerification(true),
    options.WithRekorHTTPClient(&http.Client{Timeout: 30 * time.Second}),
)
```

Public keys always win: when keys are configured
(`options.WithPublicKeys`), the envelope is verified against them and
the transparency log is never consulted.

## What is verified

With the lookup enabled, `VerifyStatement` runs these steps in order.
Every refuted step is a `FAILED` conclusion; a step that cannot run — the
log unreachable, no trust material — is `UNVERIFIABLE`.

1. **Signature against the certificate key.** The envelope's PAE is
   verified against the public key of the attached certificate. Local
   and decisive: a tampered envelope is refuted before any network
   traffic.
2. **The log has an entry.** The envelope is looked up by proposing the
   two entry kinds these envelopes were uploaded as (`intoto v0.0.1`
   and `dsse v0.0.1`), built from the envelope's original bytes and its
   certificate. No entry means nothing vouches for the signature.
3. **The entry verifies.** Its signed timestamp is checked against the
   log key the sigstore trusted root records for the entry's log ID,
   and its inclusion proof when it carries one.
4. **The time fits.** The entry's integration time must fall inside the
   certificate's validity window — the log's countersignature is what
   makes a ten-minute certificate verifiable years later.
5. **The certificate chains.** The leaf must chain to a trusted Fulcio
   root *at the integration time*.

On success the verification is `VERIFIED` and carries the Fulcio
identity — issuer, SAN and source repository — as a regular
`IdentitySigstore`, so [identity matching](identity-matching.md) and
everything built on it treat these envelopes exactly like bundles.

## Limits

- **A certificate is required.** Envelopes signed keyless but without
  the `cert` extension exist (the log entry holds their certificate);
  searching the log by payload hash to recover it is not implemented,
  and such envelopes stay `UNVERIFIABLE`.
- **No SCT verification.** The certificate's signed certificate
  timestamps are not checked against the CT log, matching the original
  slsa-verifier's behavior for this flow.
- **The envelope's original bytes matter.** The log is keyed by the
  serialization that was uploaded, so `ParseArtifact` keeps the raw
  bytes on the artifact. Programmatically built envelopes fall back to
  a re-marshal, which may not match the log.

## Trust material

The log keys and Fulcio roots come from the same sigstore trusted roots
the bundle path uses: the verifier's configured roots
(`SigstoreRootsData` / `SigstoreRootsPath`) or the embedded defaults,
refreshed via TUF when stale.
