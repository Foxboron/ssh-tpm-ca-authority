ssh-tpm-ca-authority
====================

An implementation of a CA authority that issues SSH certificates bound to TPMs
after EK attestation.


POC quality. Very much a work in progress.

# Setup

### Create a CA
```sh
authority$ ssh-tpm-keygen -f id_ecdsa
authority$ scp id_ecdsa.pub gibson.ellingson.com:/etc/ssh/ca_user_key.pub
```

Transfer `id_ecdsa.pub` to the remote servers that is suppose to trust this user
ca. Modify `/etc/ssh/sshd_config` to point at the certificate. In this case we
have it stored as `/etc/ssh/ca_user_key.pub` on the remote server.

```
gibson$ cat /etc/ssh/sshd_config | grep TrustedUserCAKeys
TrustedUserCAKeys /etc/ssh/ca_user_key.pub

gibson$ systemctl restart sshd
```

### Setup CA Authority

Create a configuration that lists the valid hosts, the correct `ca_file` and the
users with access.

```sh
authority$ cat config.yaml
---
hosts:
  - host: gibson.ellingson.com
    ca_file: id_ecdsa.tpm
    users:
      - user: zero_cool
        ek: 000ba1d6910d32dbafb47e1365e8a84606aaefc9bb2404f4f99082f6284a9b33415b
```

The Endorsment Key (EK) needs to be retrieved from the client machines. It's the
hex representation of the TPM2_Public Name. An example to retrieve it can be
found in `cmd/getek/main.go`.

```sh
client$ go run ./cmd/getek
000ba1d6910d32dbafb47e1365e8a84606aaefc9bb2404f4f99082f6284a9b33415b
```

Then run the CA authority.

Note: It will currently only listed to `http://127.0.0.1:8080`.

```sh
authority$ ssh-tpm-ca-authority --config ./config.yaml
```

Inside your `~/.ssh/config` include a line of the hosts you want to match on.
This ensures `ssh-tpm-add` will retrieve a signed key from the CA authority
before authenticating towards the host.

Note: This unreleased changes to `ssh-tpm-agent`

```ssh
Match host gibson.ellingson.com exec "ssh-tpm-add --ca 'http://127.0.0.1:8080' --host '%h' --user '%r'"
```

`ssh-tpm-ca-authority` will issue shortlived 5 minute signed certificates.

The end result should be a seamless connection to the remote host.

```sh
client$ ssh zero_cool@gibson.ellingson.com
Last login: Sun Jul 14 17:01:46 2024 from 192.168.1.1337
gibson%
```
