# Google Cloud identities

The `gcp` STS provider (`sts/providers/gcp`) mints Google-issued OIDC
identity tokens that Fulcio accepts as the signing identity. Fulcio
certificates issued from these tokens carry the service account email
as the SAN and `https://accounts.google.com` as the issuer, which is
what verification policies match on.

The provider is part of the default ambient credential providers, so
any signer running on Google Cloud (a GCE VM, GKE, Cloud Build, Cloud
Run...) signs as the service account attached to the workload without
any configuration. It is implemented on the standard library only, so
it lives in this repository rather than in signer-extras.

## Credential resolution

The provider looks for a credential in application-default order:

1. A service account key configured explicitly with
   `gcp.WithServiceAccountJSON` or `gcp.WithServiceAccountFile`.
2. The key file named by `$GOOGLE_APPLICATION_CREDENTIALS`, when it is
   a service account key (`"type": "service_account"`). Other
   application default credential types (`authorized_user`,
   `external_account`) cannot mint identity tokens for arbitrary
   audiences and are skipped.
3. The metadata server of the host, which mints tokens for the service
   account attached to the workload.

With a key, the provider signs a JWT-bearer assertion with the key and
exchanges it at Google's token endpoint for an identity token. If the
key fails, it falls back to the metadata server unless
`gcp.WithAmbientCredentials(false)` disabled it. When no source yields a
token the provider reports no token.

The signer tries its ambient providers in a fixed order, and `gcp` comes
after GitHub Actions and GitLab CI: a CI job that has an ID token of its
own signs with it, even on a runner hosted in Google Cloud. To sign such
a job with the Google identity instead, name the provider:

```golang
s := signer.NewSigner()
s.Options.STSProviders = []string{"gcp"}
```

## Impersonation

Often the workload running the signer must not *be* the signing
identity: a CI job should sign as a dedicated signer service account
that it is allowed to act as, without holding that account's key. This
is what impersonation does. Instead of using the resolved credential as
the identity, the provider uses it to call the [IAM Credentials
API](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken)
and mint the identity token *for the impersonated account*. This is the
same mechanism as cosign's `google-impersonate` provider and
`gcloud --impersonate-service-account`.

### Enabling it

Impersonation is enabled by naming the target service account, either
in code:

```golang
provider, err := gcp.New(
    gcp.WithImpersonation("signer@my-project.iam.gserviceaccount.com"),
)
```

or through the environment, which the zero-value provider in the
default ambient providers honours:

```shell
export GOOGLE_SERVICE_ACCOUNT_NAME=signer@my-project.iam.gserviceaccount.com
```

`GOOGLE_SERVICE_ACCOUNT_NAME` is the variable cosign uses for the same
purpose, so environments already set up for keyless signing with cosign
work unchanged. An explicit `WithImpersonation` takes precedence over
the variable.

### How the token is minted

1. The provider resolves its own credential following the order above
   and obtains an OAuth2 *access* token for it (scope
   `https://www.googleapis.com/auth/cloud-platform`): from the key by
   exchanging a scoped assertion, or from the metadata server.
2. It calls `generateIdToken` on the target service account with the
   requested audience (the sigstore OIDC client ID), authenticated with
   that access token.
3. The identity token returned is the one handed to Fulcio. The
   resulting certificate carries the *target's* email as SAN; the
   caller's identity does not appear in the bundle.

### Required permissions

The caller's identity needs `roles/iam.serviceAccountTokenCreator` on
the target service account (a binding on the account, not on the
project):

```shell
gcloud iam service-accounts add-iam-policy-binding \
    signer@my-project.iam.gserviceaccount.com \
    --member="serviceAccount:caller@my-project.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator"
```

Nothing else is required: the target account does not need a key and
the caller does not need any project-level role. Removing the binding
immediately revokes the ability to sign as the target.

### Failure semantics

Impersonation is a pinned identity: when a target is configured the
provider **never falls back** to signing with a different identity. Any
of the following make the token request fail, and with it the signing
operation:

- The IAM Credentials API denies the request (the caller lacks the
  binding or the target does not exist).
- The caller's own credential cannot be obtained (the key exchange
  fails, or there is neither a key nor a metadata server).
- Ambient credentials are disabled and no key is configured.

This guarantees that a signer configured to sign as `signer@...` either
signs as that account or fails: it cannot silently produce a bundle
signed by the workload's own identity.

### Pinning the identity in a signer

Applications that must lock a signing session to the impersonated
identity can mint the token themselves and pin it, which also disables
the ambient discovery of the signer entirely:

```golang
provider, err := gcp.New(
    gcp.WithImpersonation("signer@my-project.iam.gserviceaccount.com"),
)
if err != nil {
    return err
}

s := signer.NewSigner()

// The token audience must be the OIDC client ID of the sigstore instance
token, err := provider.Provide(ctx, s.Options.OIDCConfig.ClientID)
if err != nil {
    return err
}

s.Options.Token = token
s.Options.DisableSTS = true

bundle, err := s.SignStatementBundle(statement)
```

Verifiers then match the identity in the bundle's certificate with a
policy such as:

```golang
res, err := v.VerifyParsedBundle(bundle,
    options.WithExpectedIdentity(
        "https://accounts.google.com",
        "signer@my-project.iam.gserviceaccount.com",
    ),
)
```
