# FSS Secure Implementation

Network Security - University of Denver  
Stage 2 Part B

## Dependencies

Install the Python dependencies in the project environment:

```bash
pip install cryptography bcrypt
```

On the provided Linux/VM environment, the system also uses `ip netns` from
`iproute2` for the assignment network namespaces.

## First-Time Setup

The submitted package includes the CA certificate, server certificate, server
private key, and hashed `users.json` needed to run the system. To regenerate
them from scratch:

```bash
chmod +x generate_certs.sh
./generate_certs.sh
cd server_root/home/server/
python3 generate_users.py
```

After regenerating certificates, copy the generated files as the script
instructs.

## Running The System

Set up the assignment network namespaces after each VM restart:

```bash
sudo ./setup_net
```

Open two terminals.

Terminal 1 - server:

```bash
sudo ./enter server
cd ~/
python3 server.py
```

Terminal 2 - client:

```bash
sudo ./enter client
cd ~/
python3 client.py
```

The final system does not require any trusted code to run on the MITM machine.
`setup_net` still creates a middle namespace so traffic travels through the
assignment network path, but that namespace only routes packets. An evaluator
or another group may run their own attacker code there, but the client and
server do not depend on it.

## Test Accounts

- `alice` / `password123`
- `bob` / `password123`
- `charlie` / `password123`
- `mitm` / `mitm123`

## Request And Response Structure

After the initial certificate-authenticated ECDH handshake, all client/server
messages are AES-GCM encrypted and base64 encoded.

Every encrypted request includes:

- `nonce`: a unique UUID generated for this request.
- `ts`: a Unix timestamp used to reject stale requests.
- `req_id`: a UUID used to match the response to this request.

Every encrypted server response echoes the request's `req_id`. The client
rejects responses with a missing or mismatched `req_id`.

## Security Changes From Baseline

- Client/server traffic is encrypted using X25519 ECDH, HKDF, and AES-GCM.
- The server presents a CA-signed certificate, and the client verifies the CA
  signature, validity period, and expected server identity before accepting key
  material.
- The server signs its ECDH public key with the certificate private key.
- Passwords are stored as bcrypt hashes instead of plaintext.
- Nonces and timestamps are checked to reject replayed or stale requests.
- Session tokens are removed from memory on logout.
- File names are validated and resolved with `os.path.realpath()` to prevent
  path traversal.
- Oversized messages are dropped.
- AUTH and CREATE are rate limited by source IP.
- Security events are written to `server_security.log`.

## Environment Configuration

`.env.example` documents safe class-demo configuration values. The current
client, server, and MITM scripts keep these values as constants, so copying
`.env.example` to `.env` is optional unless you add a local wrapper that loads
environment variables. The assignment namespace code currently uses port `9001`
even though the template includes `SERVER_PORT=5000` as a safe demo placeholder.

`.env` and `.env.*` are ignored and should not be committed. Public
certificates may be committed for the assignment, but private keys, production
secrets, and real deployment credentials should not be committed. Any demo keys
included for the class environment must be regenerated before real deployment.

## Security Validation Tests

See `SECURITY_TESTS.md` for the certificate SAN verification command and the
standalone MITM ciphertext, path traversal, and logout-token reuse tests.

See `SECURITY_NOTES.md` for certificate/private-key handling guidance before
sharing the project or publishing it to GitHub.
