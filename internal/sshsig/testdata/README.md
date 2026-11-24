# SSH signature fixtures

None of the signatures here were made by this repository's code. They
exist to check that it reads what other tools write.

## ssh-keygen

Made with OpenSSH 10.2. The private keys were discarded.

| Signature                   | Key              | Namespace            | Hash   |
| --------------------------- | ---------------- | -------------------- | ------ |
| `ed25519.sig`               | `ed25519.pub`    | `file`               | sha512 |
| `ecdsa-p256.sig`            | `ecdsa-p256.pub` | `file`               | sha512 |
| `ecdsa-p384.sig`            | `ecdsa-p384.pub` | `file`               | sha512 |
| `rsa.sig`                   | `rsa.pub`        | `file`               | sha512 |
| `ed25519-sha256-custom.sig` | `ed25519.pub`    | `custom@example.com` | sha256 |

All of them sign `message.txt`:

```
ssh-keygen -t ed25519 -N '' -C '' -f ed25519
ssh-keygen -Y sign -n file -f ed25519 message.txt
ssh-keygen -Y sign -n custom@example.com -O hashalg=sha256 -f ed25519 message.txt
```

## gittuf

`gittuf-approval.dsse.json` is a DSSE envelope from the gittuf project's
own repository (https://github.com/gittuf/gittuf, Apache-2.0). It records
a pull request approval and was signed by the gittuf GitHub app with an
RSA SSH key, under the `git` namespace, over the DSSE PAE of the payload.
The signature is stored armored.

- Envelope: `refs/gittuf/attestations` at commit
  `88e8478e3e71750dcf6fd4916224ddf5087a24b6`, path
  `code-review-approvals/refs/heads/main/01e470a9917f2f03f95be10e73981262207d7457-a6b8d2d969f18b083768f467d774c561df491e43/github/aHR0cHM6Ly9naXR0dWYuZGV2L2dpdGh1Yi1hcHA=`
- Key: `gittuf-app.pub`, the principal
  `SHA256:KTrCAHHGUSCkNjanR0t4ojOiHQ4qZIQM6mkwX64b2KY` in the root
  metadata at `refs/gittuf/policy`.
