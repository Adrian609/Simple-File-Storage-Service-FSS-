
## Initial Design Document

### Short Overview

The redesign will convert the baseline FSS into a protocol that assumes the network is hostile and explicitly trusts only authenticated endpoints and session-bound interactions. The plan centers on three complementary improvements: (1) protect confidentiality and integrity of client-server traffic with transport-layer authentication, (2) bind every request and response to a current authenticated session and transaction, and (3) enforce strict server-side authorization, input validation, and audit logging.

This means the client will authenticate the server before sending credentials or file operations, and the server will only accept operations that are correctly authorized, transaction-matched, and syntactically valid. Session tokens will become ephemeral, tied to a single login session, and invalidated on logout. File access will be limited through per-user storage directories plus filename sanitization so users cannot access or modify other users’ data. Finally, the system will log important security events and failures so later review can distinguish honest operations from attacks.

This strategy directly addresses the Stage 1 failures in the baseline system: plaintext JSON traffic, missing server authentication, unrestricted request replay and injection, session token reuse, absent input validation, and weak evidence generation. It does so without changing the MITM machine or network topology, because the defense is implemented entirely in the client/server protocol and runtime behavior.

---

### Design Action Table

| Proposed action / change | Requirement(s) addressed | Explanation |
| --- | --- | --- |
| Use TLS for all client-server connections and require the client to validate the server certificate before proceeding. | R1, R5, R6, R12 | Encrypts file contents and requests in transit so the MITM cannot read or silently modify them. Explicit server authentication establishes trust needed for correct behavior. |
| Add request/response transaction identifiers and bind each server response to the originating client request. | R3, R4, R5, R6, R8 | Ensures each completed operation corresponds to a current honest request and that responses cannot be replayed or substituted from older interactions. |
| Store session tokens server-side and invalidate them on logout; reject reused or expired session tokens. | R4, R6, R8, R10 | Prevents attacker reuse of old interaction state and keeps session-specific authorization tokens usable only within the intended session. |
| Enforce strict server-side authorization and file path validation for every file operation. | R1, R2, R7 | Ensures users can only list/download/upload files under their own directory, preventing unauthorized access or modification of other users’ files. |
| Validate all incoming protocol messages on the server, including JSON structure, action names, filename syntax, content length, and token presence. | R9, R10, R3 | Prevents malformed or unexpected input from causing unsafe or undefined server behavior, while preserving service availability for legitimate users. |
| Add server-side authenticated audit logging for login attempts, file operations, failed authorization, malformed requests, and logout events. | R11, R10 | Creates evidence of important events and failures for later review, and supports debugging when attacks or protocol misuse occur. |
| Have the client verify response integrity using server-supplied metadata tied to the transaction (e.g., signed digests or HMACs over response fields). | R5, R6, R3, R11 | Ensures the client accepts only genuine, unmodified responses that correctly reflect the requested operation. |
| Move credential storage from plaintext to a secure password hash and prevent account creation from bypassing authorization checks. | R2, R7, R12 | Reduces the risk that attacker-controlled accounts or leaked passwords can be used to subvert file authorization, while keeping trust relationships explicit in the system. |

