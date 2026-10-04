# Security Token Services

This directory contains different drivers to obtain short lived tokens from
STS providers. These are meant to be exchanged with Sigstore's Fulcio when
obtaining a signing certificate. This readme is here mainly to answer the
following question:

__SHOULD I ADD PROVIDERS HERE?__

Short answer: It depends 🙃

## Where should I commit my new STS provider?

We are trying to keep the signer dependency list as short as we can. So if you
write an STS provider:

- If it adds very few dependencies (note "very" is __VERY__ few and lighweight), feel free to add it here.
- It it has a heaver dependency tree, add it to [policylabs/signer-extras](https://github.com/policylabs/signer-extras/).

Thanks!
