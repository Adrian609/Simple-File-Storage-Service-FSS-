# Stage 2 Part B Review

## Executive Summary

Verdict: **mostly ready for Stage 2/Stage 3 review**.

The implementation package is coherent, runnable in the expected Linux
namespace environment, and the final design document substantially matches the
implemented client/server system. The strongest points are authenticated
client/server key exchange, AES-GCM protection for application messages,
server-certificate validation, bcrypt password storage, replay checks,
request/response binding, path validation, logout invalidation, and removal of
trusted MITM runtime requirements.

The main remaining submission task is packaging: create the final ZIP in the
baseline folder structure and include the files documented below. The current
repository state is ready to package, but the ZIP itself was not created during
this review.

## Assignment Compliance Checklist

| Requirement | Status | Evidence / Notes |
| --- | --- | --- |
| Final design document exists | PASS | `Stage2_PartB_Design_Table.md` is present. |
| Design describes implemented actions, not only plans | PASS | Design table maps implemented ECDH, cert validation, bcrypt, nonce/timestamp, logout, path validation, rate limiting, and logging to code. |
| Overview identifies major changes | PASS | `Stage2_PartB_Design_Table.md:3-17`. |
| Separate request/response changes section | PASS | `Stage2_PartB_Design_Table.md:21-39`. |
| Final `client.py` in correct baseline folder | PASS | `client_root/home/client/client.py`. |
| Final `server.py` in correct baseline folder | PASS | `server_root/home/server/server.py`. |
| Supporting files needed to run are present | PASS | `users.json`, storage fixtures, `server_cert.pem`, `server_key.pem`, `ca_cert.pem`, `requirements.txt`, scripts. |
| README or run instructions present | PASS | `README.md:33-63`. |
| System runnable for evaluator | PASS | Live namespace run succeeded in this review. |
| Does not require trusted MITM code | PASS | README starts only server/client; `setup_net` makes MITM a router only. See `README.md:59-63`, `setup_net:5-8`, `setup_net:56`. |
| Final ZIP package exists | PARTIAL | Repository is ready to zip, but no final ZIP was generated as part of this review. |

## Folder / Package Structure

Expected baseline-style roots are present:

- `client_root/home/client/client.py`
- `server_root/home/server/server.py`
- `mitm_root/home/mitm/mitm.py`
- `server_root/home/server/server_storage/...`
- `server_root/home/server/users.json`
- `client_root/home/client/ca_cert.pem`
- `server_root/home/server/server_cert.pem`
- `server_root/home/server/server_key.pem`
- `server_root/home/server/ca_cert.pem`
- `README.md`, `Stage2_PartB_Design_Table.md`, `requirements.txt`

Supporting validation/documentation files are also present:

- `docs/SECURITY_TESTS.md`
- `docs/SECURITY_NOTES.md`
- `tests/*.py`
- `scripts/check_sensitive_keys.sh`
- `.env.example`
- `.gitignore`

Files removed or absent as desired:

- No `.DS_Store`, `*.out`, `*.err`, or `*.srl` files were found by the final artifact scan.
- The CA private key is not present. The only private key marker outside `.git` is the retained class demo server key.

## Design Document Review

| Category | Status | Notes |
| --- | --- | --- |
| Coherence | PASS | The design is a coherent client/server security design: authenticated key exchange, encrypted application protocol, replay controls, token sessions, and filesystem validation. |
| Consistency with implementation | PASS | The main claims are implemented in `client.py` and `server.py`. Request `req_id` binding is implemented in `client.py:89-113` and response generation in `server.py:167-178`. |
| Clarity/completeness | PASS | The document includes overview, protocol changes, and an action/requirement table. |
| Honest limitations | PASS | README and `docs/SECURITY_NOTES.md` explicitly state that storage files remain plaintext on the server filesystem. |
| Format match to initial document | PARTIAL | The final document is a Markdown table. If the initial submission used an `.xlsx` or instructor-specific template, confirm the Markdown format is acceptable or export it to the required format before submission. |

## Implementation Review

| Item | Status | Evidence / Notes |
| --- | --- | --- |
| Authentication | PASS | `handle_auth` uses bcrypt checks and returns a UUID token: `server.py:433-467`. |
| Secure client/server communication | PASS | X25519 + HKDF + AES-GCM: `client.py:44-70`, `server.py:100-126`, handshake in `client.py:175-226`, `server.py:199-244`. |
| Server authentication / certificate verification | PASS | Client verifies CA signature, cert validity, and host identity: `client.py:116-172`. |
| Credential confidentiality in transit | PASS | AUTH happens after encrypted channel establishment via `send_recv`: `client.py:89-113`. |
| File-content confidentiality in transit | PASS | UPLOAD/DOWNLOAD are encrypted AES-GCM messages. |
| Command/response integrity | PASS | AES-GCM detects tampering. Client rejects mismatched `req_id`: `client.py:109-112`. |
| Replay protection | PASS | Server checks nonce and timestamp before dispatch: `server.py:247-288`, `server.py:598-605`. |
| Session/token handling | PASS | Tokens stored in memory and protected by locks: `server.py:354-378`. |
| Logout invalidation | PASS | Logout removes token: `server.py:569-587`. Live test passed. |
| File upload | PASS | `handle_upload`: `server.py:502-535`. |
| File download | PASS | `handle_download`: `server.py:538-566`. |
| File listing | PASS | `handle_list`: `server.py:470-499`. |
| Path traversal protection | PASS | Filename validation and `realpath` containment check: `server.py:327-351`. Live test passed. |
| Cross-user file access prevention | PASS | File paths are rooted under authenticated user's storage directory. |
| Input validation | PASS | Username, filename, content type, request metadata, and message size checks exist. |
| Error handling | PASS | Malformed encrypted requests are rejected/closed; handler exceptions are logged without returning raw exception text. |
| Socket disconnect handling | PASS | `recv_line` handles disconnect and accepted sockets use timeouts: `server.py:626-662`. |
| Message size limits | PASS | 10 MB cap in client and server receive loops: `client.py:38`, `client.py:73-85`, `server.py:45`, `server.py:129-146`. |
| Password storage | PASS | `users.json` contains bcrypt hashes, not plaintext. |
| Hardcoded production secrets | PASS | No production secrets found. Demo server private key remains because server startup requires it; documented in `docs/SECURITY_NOTES.md`. |
| MITM dependency | PASS | Security does not depend on `mitm.py`. |

## Request/Response Structure

Actual protocol:

1. TCP connection uses newline-delimited message framing. There is no length prefix; receive loops read until `\n` and enforce a 10 MB cap.
2. Handshake plaintext metadata:
   - Server -> client: JSON `{"type": "CERT", "cert": "<base64 PEM>"}`
   - Client -> server: JSON `{"type": "CLIENT_PUB", "pub": "<base64 raw X25519 public key>"}`
   - Server -> client: JSON `{"type": "SERVER_PUB", "pub": "<base64 raw X25519 public key>", "sig": "<base64 signature>"}`
3. Session key:
   - X25519 shared secret.
   - HKDF-SHA256 with info `fss-session-key`.
   - 32-byte AES-GCM key.
4. Encrypted messages:
   - JSON plaintext is AES-GCM encrypted.
   - Wire format is base64 of `12-byte AES-GCM nonce || ciphertext+tag`, followed by newline.
5. Encrypted request fields:
   - `action`: `AUTH`, `CREATE`, `LIST`, `UPLOAD`, `DOWNLOAD`, `LOGOUT`
   - `nonce`: UUID string
   - `ts`: Unix timestamp
   - `req_id`: UUID string
   - action-specific fields such as `username`, `password`, `token`, `filename`, `content`
6. Encrypted response fields:
   - `status`: `ok` or `error`
   - `req_id`: echoed from request
   - action-specific fields such as `token`, `files`, `content`, `sha256`, `message`
7. Replay/request binding:
   - Server rejects missing/stale/reused `nonce` and bad timestamps.
   - Client rejects responses whose `req_id` does not match the current request.

Design document comparison: PASS. The structure above matches `Stage2_PartB_Design_Table.md:21-39` and `README.md:72-84`.

## MITM Independence Check

Status: PASS.

- `setup_net` creates `ns_mitm`, but only as a forwarding/router namespace: `setup_net:37-56`.
- No TPROXY/iptables MITM interception is required.
- README instructs running only server and client terminals: `README.md:43-56`.
- README explicitly says no trusted MITM code is required: `README.md:59-63`.
- `mitm.py` remains in the baseline folder, but the system does not require it for security or operation.

## Runnability Check

Commands run:

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

Result: PASS.

Certificate SAN check:

```bash
openssl x509 -in certs/server_cert.pem -noout -ext subjectAltName
```

Result:

```text
X509v3 Subject Alternative Name:
    IP Address:10.0.8.2
```

Key scan:

```text
[key-scan] private key markers outside .git:
  server_root/home/server/server_key.pem
[key-scan] OK: no CA private key file found.
[key-scan] NOTE: class demo server key is present because server.py requires it at runtime.
```

Artifact scan:

```bash
find . -name ".DS_Store" -o -name "*.out" -o -name "*.err" -o -name "*.srl"
```

Result: no output.

Live namespace tests:

```bash
sudo ./setup_net
sudo ./enter server
cd ~/
python3 server.py
```

The review launched the server in `ns_server` and ran:

```bash
ip netns exec ns_client python3 tests/test_mitm_ciphertext.py
ip netns exec ns_client python3 tests/test_path_traversal.py
ip netns exec ns_client python3 tests/test_logout_token_reuse.py
```

Results:

```text
PASS T-01 MITM ciphertext: post-handshake capture contains no sensitive plaintext
PASS T-02 path traversal: ../bob/letter.txt rejected and Bob's file unchanged
PASS T-03 logout token reuse: old token rejected after logout
```

Pytest note: tests now expose pytest test functions and can be run with
`python3 -m pytest tests/` when pytest is installed. The direct `python3
tests/test_*.py` entrypoints are retained as a fallback.

## Certificate and Key Handling

Status: PASS with class-demo caveat.

- Public CA and server certs are present.
- Server cert has SAN `IP Address:10.0.8.2`.
- CA private key is not present after generation.
- `server_root/home/server/server_key.pem` remains because `server.py` loads it at startup (`server.py:50-51`, `server.py:91-94`).
- `.gitignore` excludes `.env`, private key patterns, `.srl`, runtime logs, `.DS_Store`, and Python caches.
- `docs/SECURITY_NOTES.md` documents the retained server key as demo-only.

Before public GitHub publication, treat the retained demo server private key as exposed and rotate/remove it from published history.

## Documentation Completeness

| Area | Status | Notes |
| --- | --- | --- |
| Dependencies | PASS | `requirements.txt` and README list `cryptography` and `bcrypt`. |
| Server startup | PASS | `README.md:43-49`. |
| Client startup | PASS | `README.md:51-56`. |
| MITM independence | PASS | `README.md:59-63`. |
| Demo credentials | PASS | `README.md:65-70`. |
| Request/response changes | PASS | `README.md:72-84`, design doc section. |
| Security guarantees | PASS | `README.md:86-100`, design table. |
| Cert regeneration/SAN | PASS | `docs/SECURITY_NOTES.md:30-47`, `docs/SECURITY_TESTS.md:6-25`. |
| Stage 3 testing | PASS | `docs/SECURITY_TESTS.md` gives exact commands. |
| Known limitations | PASS | README and `docs/SECURITY_NOTES.md` explicitly state that files are not encrypted at rest and document the class demo private key caveat. |

## Likely Stage 3 Attack Readiness

| Attack | Assessment | Evidence / Caveat |
| --- | --- | --- |
| MITM reads credentials | Likely resisted | AUTH is encrypted after handshake; T-01 passed. |
| MITM reads file content | Likely resisted | DOWNLOAD/UPLOAD content encrypted; T-01 passed. |
| MITM modifies command | Likely resisted | AES-GCM tamper detection should reject altered ciphertext. |
| MITM replays old request | Likely resisted | Nonce/timestamp check: `server.py:247-288`; duplicate nonce rejected. |
| MITM replays old response | Likely resisted | Client checks `req_id`: `client.py:109-112`. |
| MITM swaps responses between requests | Likely resisted | `req_id` mismatch rejected. |
| Path traversal `../bob/letter.txt` | Likely resisted | T-02 passed; slash and realpath checks. |
| Absolute path access | Likely resisted | Slash rejected and realpath containment check. |
| URL-encoded traversal | Likely resisted | `%2e%2e` is not decoded by server; treated as literal filename. |
| Weird filename traversal | Partially resisted | `/`, `\`, null, empty names, directories, and realpath escapes rejected. Additional fuzzing for unusual Unicode filenames is recommended. |
| Alice reads Bob's file | Likely resisted | User-rooted storage path and traversal test. |
| Logout token reuse | Likely resisted | T-03 passed. |
| Brute-force login | Partially resisted | Per-IP in-memory rate limit on AUTH/CREATE. Distributed attempts or server restart reset the limiter. |
| Oversized message/file upload | Likely resisted | 10 MB receive cap on client/server. |
| Malformed JSON | Likely resisted | `recv_json` catches decode/decrypt/JSON errors and drops connection. |
| Missing required fields | Likely resisted | Missing auth/token/metadata rejected by handlers and replay checks. |
| Duplicate nonce | Likely resisted | Nonces tracked in memory and rejected. |
| Duplicate `req_id` with fresh nonce | Partially resisted | Server requires `req_id` but does not enforce uniqueness. This is acceptable for response binding but not a replay primitive by itself. |
| Expired timestamp | Likely resisted | 60-second window enforced. |
| Server restart/session persistence edge case | Likely resisted for old tokens | Sessions are memory-only, so old tokens die on restart. Nonce cache also resets, but old encrypted requests are tied to old session keys/connections. |

## Required Fixes Before Submission

### Critical fixes before submission

1. Create the final ZIP package in the baseline folder structure. Include runtime certs, demo server key, `users.json`, storage fixtures, README, requirements, final design document, and supporting scripts/docs.
2. Confirm the final design document format matches the instructor's expected "same format as initial document." If the initial was an Excel/table template, export or submit the Markdown table in the accepted format.

### High-priority security fixes

No clear high-priority code fix is required based on this review. The live tests passed.

Recommended hardening if time allows:

1. Add a small fuzz/manual test for unusual filename inputs, including absolute paths, encoded traversal strings, null-byte-like input, and very long filenames.
2. Consider enforcing `req_id` uniqueness within a session. Current `req_id` validation is sufficient for response binding, while nonce is the replay control.

### Documentation fixes

1. Confirm the plaintext-at-rest limitation remains visible in README and `docs/SECURITY_NOTES.md`.
2. Clarify that `.env.example` is documentation only; code currently uses constants.
3. Keep the demo server private key warning prominent for GitHub/public sharing.

### Cleanup fixes

1. Do not include generated logs, `.DS_Store`, `*.out`, `*.err`, or `.srl` files in the final package.
2. Do not include a CA private key.
3. If a previous ZIP exists locally, regenerate it after final changes.

## Recommended Manual Tests

Run in the class Linux/VM environment:

```bash
pip install -r requirements.txt
sudo ./setup_net
```

Terminal 1:

```bash
sudo ./enter server
cd ~/
python3 server.py
```

Terminal 2:

```bash
sudo ./enter client
cd ~/
python3 client.py
```

Manual client workflows:

1. Login as `alice` / `password123`.
2. List files.
3. Download `test.txt`.
4. Upload a new harmless file under Alice.
5. Attempt `../bob/letter.txt`; expect failure.
6. Logout; old token should not work.

Automated security validation from repo root with server running:

```bash
sudo ip netns exec ns_client python3 -m pytest tests/
```

Certificate/key hygiene:

```bash
openssl x509 -in certs/server_cert.pem -noout -ext subjectAltName
bash scripts/check_sensitive_keys.sh
find . -name ".DS_Store" -o -name "*.out" -o -name "*.err" -o -name "*.srl"
```

Static validation:

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

## Final Submission Checklist

- [ ] Confirm final design document is in the required instructor format.
- [ ] Confirm README starts server/client only and does not require MITM code.
- [ ] Confirm `server_root/home/server/server_key.pem` is included only as class demo material.
- [ ] Confirm CA private key is absent.
- [ ] Confirm no `.DS_Store`, logs, `.out`, `.err`, `.srl`, `__pycache__`, or `.pyc` files are packaged.
- [ ] Run the three standalone security tests in the class VM.
- [ ] Create final ZIP after all checks pass.
