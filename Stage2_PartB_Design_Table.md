# Stage 2 Part B Final Design

## Overview

The final implementation is a client/server secure file storage service. The
MITM machine is not trusted and is not required to run any code for the system
to function. Traffic may pass through the MITM network path, but confidentiality,
integrity, freshness, and server authenticity are enforced by the client and
server themselves.

Major changes from the initial design are:

- The submitted runtime starts only the server and client. The MITM namespace is
  a router for testing, not a required system component.
- Responses now always echo the request `req_id`, and the client rejects missing
  or mismatched response IDs.
- The server now validates malformed request metadata more strictly, uses
  socket timeouts, avoids leaking raw exception text to clients, and protects
  shared user/session state with locks.

## Request/Response Structure Changes

After the initial handshake, every request and response is AES-GCM encrypted and
base64 encoded.

Every encrypted request includes:

- `nonce`: a client-generated unique value for replay detection. The current
  client generates UUID values.
- `ts`: a Unix timestamp used to reject stale requests.
- `req_id`: a UUID identifying the request.

Every encrypted response includes:

- `req_id`: the same request ID from the request.
- `status`: `ok` or `error`.
- action-specific fields such as `token`, `files`, `content`, `sha256`, or
  `message`.

The client treats a missing or mismatched response `req_id` as a security error.

## Final Design Table

| Implemented Action / Change | Requirement(s) Addressed | Explanation |
| --- | --- | --- |
| Added a server-authenticated ECDH handshake at the start of each session. The client and server exchange X25519 public keys, derive a shared AES-256 key with HKDF, and encrypt all later messages with AES-GCM. | R1, R2, R5, R12 | Baseline traffic was plaintext. The final design prevents a network attacker from reading or modifying file contents, credentials, tokens, or commands after the handshake. AES-GCM also detects tampering. |
| The server presents an X.509 certificate signed by the project CA. The client verifies the CA signature, certificate validity period, and expected server identity, including an exact IP SAN match for `10.0.8.2`. The server also signs its ECDH public key with the certificate private key. | R6, R12 | This prevents a MITM from impersonating the server during key exchange. The client only accepts key material that is tied to the genuine server certificate. |
| The system no longer requires any trusted program to run on the MITM machine. The middle namespace created by `setup_net` only routes packets. | R12 | Trust is established between the client and server, not by assuming the network path is cooperative. This matches the Stage 2 Part B rule that the MITM is not under our control. |
| Passwords are stored in `users.json` as bcrypt hashes with salts, and login uses `bcrypt.checkpw()`. | R1, R12 | Reading the user database no longer reveals plaintext passwords. |
| Every request carries a nonce and timestamp. The server rejects missing or invalid metadata, timestamps outside the freshness window, and previously seen nonces. | R4, R8, R9 | Captured requests cannot be replayed later or submitted twice within a session. Malformed metadata is rejected before command execution. |
| Every encrypted response echoes the request `req_id`, and the client rejects responses whose `req_id` is missing or different. | R3, R6 | The client can detect injected, replayed, or out-of-order responses that do not correspond to the current request. |
| Session tokens are removed from the server's session table on logout. Session access is protected with a lock. | R8, R10 | Tokens stop working immediately after logout, and concurrent clients cannot corrupt the session table. |
| Upload and download filenames are validated and resolved with `os.path.realpath()`. Empty names, path separators, null bytes, directory targets, and traversal attempts are rejected. | R7, R9 | Authenticated users can only access files inside their own storage directory. |
| Usernames in CREATE requests are restricted to letters, digits, dot, underscore, and hyphen, with length limits. | R9 | Account names cannot be used to manipulate filesystem paths or create unsafe directories. |
| Incoming messages are capped at 10 MB, and accepted sockets use timeouts. | R9, R10 | Oversized messages and slow or incomplete network reads cannot consume unbounded memory or hold server resources forever. |
| AUTH and CREATE are rate limited per source IP address. | R10 | Brute-force login attempts and account-creation spam are limited without blocking normal use. |
| Security-relevant events are logged to `server_security.log` with timestamps. | R11 | Authentication failures, replays, invalid paths, malformed requests, rate limits, file operations, and errors are available for later review. |
| Shared mutable state for users and sessions is protected with thread locks. | R10 | Concurrent clients cannot race account creation, session insertion, or logout in a way that corrupts server state. |

## Known Limitations

- This implementation protects credentials, commands, tokens, and file contents in transit from a network MITM.
- Files are stored in plaintext on the server filesystem and are not encrypted at rest in this Stage 2 Part B implementation.
- The included server private key is demo-only for the class environment and must be regenerated before any real deployment.
