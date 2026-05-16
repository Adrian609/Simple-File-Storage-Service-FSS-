# Security Notes

## Certificate and Key Handling

The certificates and keys in this repository are for the class test environment
only. They are not production credentials.

Public certificates are included so clients can verify the server:

- `certs/ca_cert.pem`
- `certs/server_cert.pem`
- `client_root/home/client/ca_cert.pem`
- `server_root/home/server/ca_cert.pem`
- `server_root/home/server/server_cert.pem`
- `client_root/certs/*.crt`
- `server_root/certs/*.crt`
- `mitm_root/certs/*.crt`

Private keys are sensitive and should not be committed to a real public
repository. The server does require `server_root/home/server/server_key.pem` at
startup, so that file is retained only as a class/demo runtime key. Regenerate
it before any real deployment.

The CA private key should not be published or reused. `generate_certs.sh`
generates `certs/ca_key.pem` only long enough to sign the demo server
certificate, then removes it. The duplicate generated `certs/server_key.pem`
and OpenSSL serial file are also removed after the runtime demo files are
copied into place.

`server_root/home/server/users.json` contains bcrypt hashes for the fixed class
demo accounts listed in `README.md`. These are included so the submission runs
without an interactive setup step. They are not production credentials and must
be replaced or regenerated before any real deployment.

To regenerate all class demo certificate material:

```bash
./generate_certs.sh
```

Verify the server certificate has a real Subject Alternative Name:

```bash
openssl x509 -in certs/server_cert.pem -noout -ext subjectAltName
```

Expected output:

```text
X509v3 Subject Alternative Name:
    IP Address:10.0.8.2
```

## Sensitive Key Scan

Run:

```bash
bash scripts/check_sensitive_keys.sh
```

Expected class/demo result:

- `server_root/home/server/server_key.pem` is reported as the retained demo
  server private key.
- No CA private key is present.

Before pushing this project to a public GitHub repository, remove all private
keys from the published history or rotate/regenerate them. Treat the included
demo server key as already exposed.

## Environment Configuration

`.env.example` is a safe template containing class/demo host, port, certificate
filenames, storage directory, log filename, and protocol limit values. It does
not contain secrets. The class/demo server listens on port `9001`, and
`.env.example` matches that default. Change the port only if you also update
both the client and server configuration.

You may copy `.env.example` to `.env` for local wrappers or experiments, but the
current Python scripts do not load `.env` automatically. Real `.env` files are
ignored by `.gitignore` and should not be committed.

Public certificates may be committed for the class environment. Private keys,
production secrets, and real deployment configuration should not be committed.
Regenerate all demo keys before any real deployment.

## Known Limitations

- This implementation protects credentials, commands, tokens, and file contents in transit from a network MITM.
- Files are stored in plaintext on the server filesystem and are not encrypted at rest in this Stage 2 Part B implementation.
- The included server private key is demo-only for the class environment and must be regenerated before any real deployment.
