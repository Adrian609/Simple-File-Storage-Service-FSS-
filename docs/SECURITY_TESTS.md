# Security Validation Tests

These tests are standalone Python scripts. They do not require `pytest` or any
new dependencies.

## Certificate SAN Verification

Regenerate certificates:

```bash
./generate_certs.sh
```

Verify the server certificate contains a real Subject Alternative Name:

```bash
openssl x509 -in certs/server_cert.pem -noout -ext subjectAltName
```

Expected output:

```text
X509v3 Subject Alternative Name:
    IP Address:10.0.8.2
```

## Test Setup

Start the network and server first:

```bash
sudo ./setup_net
sudo ./enter server
cd ~/
python3 server.py
```

Run the pytest suite from the repository root in another terminal. The tests use
the client namespace so traffic follows the assignment network path:

```bash
sudo ip netns exec ns_client python3 -m pytest tests/
```

The individual test files can also be run directly with `python3` if pytest is
not available.

## T-01 MITM Sees Only Ciphertext After Handshake

Command:

```bash
sudo ip netns exec ns_client python3 -m pytest tests/test_mitm_ciphertext.py
```

Purpose:

The script records raw post-handshake socket messages while running AUTH, LIST,
DOWNLOAD, and LOGOUT over the real encrypted protocol. It verifies each captured
post-handshake message is base64-encoded AES-GCM data and does not contain
plaintext credentials, commands, filenames, path traversal strings, or file
contents.

Expected result:

```text
PASS T-01 MITM ciphertext: post-handshake capture contains no sensitive plaintext
```

It is acceptable for certificate and public-key handshake metadata to be visible.
The security claim is that application-layer requests and responses after the
secure channel is established are opaque to a network attacker.

## T-02 Path Traversal Attempt Is Rejected

Command:

```bash
sudo ip netns exec ns_client python3 -m pytest tests/test_path_traversal.py
```

Purpose:

The script logs in as Alice, attempts to download and upload using
`../bob/letter.txt`, and verifies Bob's `letter.txt` contents and SHA-256 digest
remain unchanged.

Expected result:

```text
PASS T-02 path traversal: ../bob/letter.txt rejected and Bob's file unchanged
```

## T-03 Logout Token Reuse Is Rejected

Command:

```bash
sudo ip netns exec ns_client python3 -m pytest tests/test_logout_token_reuse.py
```

Purpose:

The script logs in as Alice, stores the returned session token, logs out, and
then attempts to reuse the old token for LIST on the same encrypted connection.

Expected result:

```text
PASS T-03 logout token reuse: old token rejected after logout
```

## Compile Check

Run:

```bash
python3 -m py_compile \
  client_root/home/client/client.py \
  server_root/home/server/server.py \
  mitm_root/home/mitm/mitm.py \
  tests/fss_test_helpers.py \
  tests/test_mitm_ciphertext.py \
  tests/test_path_traversal.py \
  tests/test_logout_token_reuse.py
```
