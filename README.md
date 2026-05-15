# FSS Secure Implementation
## Network Security — University of Denver
## Stage 2 Part B

## Dependencies

```
pip install cryptography bcrypt
```

## First time setup

### Step 1 — Generate certificates
```
chmod +x generate_certs.sh
./generate_certs.sh
```

Copy output files as the script instructs.

### Step 2 — Generate hashed user accounts
```
cd server_root/home/server/
python3 generate_users.py
```

## Running the system

Set up namespaces first (run after every VM restart):
```
sudo ./setup_net
```

Open three terminals:

**Terminal 1 — Server**
```
sudo ./enter server
cd ~/
python3 server.py
```

**Terminal 2 — MITM**
```
sudo ./enter mitm
cd ~/
python3 mitm.py
```

**Terminal 3 — Client**
```
sudo ./enter client
cd ~/
python3 client.py
```

## Changes to request/response structure

Every request now includes three additional fields:
- `nonce` — a unique UUID generated per request, used to prevent replay attacks
- `ts` — a Unix timestamp, used to reject stale requests
- `req_id` — a UUID used to match each response to its request

All messages after the initial handshake are AES-GCM encrypted and base64 encoded.
The MITM will only see ciphertext.

## Security changes from baseline

- All communication is encrypted using ECDH key exchange and AES-GCM
- Server presents a certificate signed by our own CA; client verifies it before proceeding
- Passwords are stored as bcrypt hashes instead of plaintext
- Each request carries a nonce and timestamp; server rejects replays and stale requests
- Session tokens are deleted from memory on logout
- File paths are validated using os.path.realpath to block path traversal
- Messages exceeding 10MB are dropped
- AUTH and CREATE are rate limited to 10 attempts per minute per IP
- Security events are logged to server_security.log with timestamps
- Usernames are validated to reject dangerous characters
