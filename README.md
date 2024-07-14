ssh-tpm-ca-authority
====================

An implementation of a CA authority that issues SSH certificates bound to TPMs
after EK attestation.


POC quality. WIP.


# Config

```yaml
---
hosts:
  - host: gibson.ellingson.com
    ca_file: id_ecdsa.tpm
    users:
      - user: zero_cool
        ek: 000ba1d6910d32dbafb47e1365e8a84606aaefc9bb2404f4f99082f6284a9b33415b
```
