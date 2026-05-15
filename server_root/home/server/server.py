#!/usr/bin/env python3
"""
Network Security - University of Denver

server.py

This file holds the server code for a simple file storage service. The original
code was not secure for use in an adversarial network setting. This version has
been rewritten to address the security requirements of the project.

"""

import json
import os
import signal
import socket
import threading
import uuid
import sys
import hashlib
import logging
import time
import base64
import string

import bcrypt
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives import hashes as hsh
from cryptography.exceptions import InvalidSignature

HOST = "10.0.8.2"
PORT = 9001
STORAGE_DIR = "server_storage"

SESSIONS = {}
CLIENT_LIMIT = 512  # DO NOT CHANGE: only enough resources to allow 1024 clients

MAX_MESSAGE_BYTES = 10 * 1024 * 1024  # reject messages larger than 10MB
NONCE_WINDOW = 60                      # seconds before a nonce expires
RATE_WINDOW = 60                       # sliding window for rate limiting
RATE_MAX = 10                          # max attempts per window per IP

CERT_PATH = "server_cert.pem"
KEY_PATH  = "server_key.pem"

connection_semaphore = threading.Semaphore(CLIENT_LIMIT)

SEEN_NONCES = {}
SEEN_NONCES_LOCK = threading.Lock()

RATE_TRACKER = {}
RATE_TRACKER_LOCK = threading.Lock()

USERS_LOCK = threading.Lock()
SESSIONS_LOCK = threading.Lock()

# log security events to a file so they are not lost on restart
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("server_security.log"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("fss_server")

# You may decide to store the user and password data in a different manner, but
# whatever method you use, the account 'mitm' with password 'mitm123' must be
# present. Consider it an account that an attacker created on the system.
try:
    with open("users.json", "r") as f:
        USERS = json.load(f)
except Exception:
    log.exception("[SERVER] error reading user file")
    sys.exit(1)

if not os.path.isdir(STORAGE_DIR):
    log.error("[SERVER] storage directory not found")
    sys.exit(1)

# load server certificate and private key for the handshake
try:
    with open(CERT_PATH, "rb") as f:
        SERVER_CERT_PEM = f.read()
    with open(KEY_PATH, "rb") as f:
        SERVER_PRIVATE_KEY = load_pem_private_key(f.read(), password=None)
except Exception:
    log.exception("[SERVER] error loading certificate")
    sys.exit(1)


def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derive an AES key from the ECDH shared secret using HKDF.
    """
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"fss-session-key")
    return hkdf.derive(shared_secret)


def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a string using AES-GCM. Returns base64-encoded ciphertext with
    the nonce prepended.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct)


def decrypt_message(key: bytes, data: str) -> str:
    """
    Decrypt a base64-encoded AES-GCM message. Raises on tamper detection.
    """
    raw = base64.b64decode(data)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def recv_line(conn):
    """
    Receive data from a network connection until a newline.
    Drops connection if message exceeds MAX_MESSAGE_BYTES.

    :param conn: a network connection object
    :returns: read data (without the ending newline)
    """
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > MAX_MESSAGE_BYTES:
            log.warning("[SERVER] oversized message received, dropping connection")
            return None
    return data.decode("utf-8").strip()


def send_raw(conn, text: str):
    """
    Send a plain text line. Used only during the handshake before
    the session key is established.
    """
    conn.sendall((text + "\n").encode("utf-8"))


def send_json(conn, key: bytes, obj: dict):
    """
    Encrypt a dictionary as JSON and send it over the connection.

    :param conn: a network connection object
    :param key: the session encryption key
    :param obj: a dictionary object
    """
    conn.sendall(encrypt_message(key, json.dumps(obj)) + b"\n")


def make_response(req: dict, status: str, **fields) -> dict:
    """
    Build a response that always includes the request ID when one was supplied.
    """
    req_id = ""
    if isinstance(req, dict) and isinstance(req.get("req_id", ""), str):
        req_id = req.get("req_id", "")

    resp = {"status": status, "req_id": req_id}
    resp.update(fields)
    return resp


def recv_json(conn, key: bytes):
    """
    Receive an encrypted line and decrypt it to a dictionary.
    """
    try:
        line = recv_line(conn)
        if line is None:
            return None
        obj = json.loads(decrypt_message(key, line))
        if not isinstance(obj, dict):
            log.warning("[SERVER] rejected non-object request")
            return None
        return obj
    except Exception as e:
        log.warning(f"[SERVER] rejected malformed encrypted request: {e}")
        return None


def perform_handshake(conn):
    """
    Perform ECDH key exchange with the client to establish an encrypted
    session. The server sends its certificate so the client can verify
    its identity, then both sides derive the same session key.

    :param conn: a network connection object
    :returns: session key bytes, or None if the handshake fails
    """
    try:
        # send server certificate so client can verify who it is talking to
        cert_b64 = base64.b64encode(SERVER_CERT_PEM).decode("utf-8")
        send_raw(conn, json.dumps({"type": "CERT", "cert": cert_b64}))

        # receive client ECDH public key
        line = recv_line(conn)
        if not line:
            return None
        msg = json.loads(line)
        if msg.get("type") != "CLIENT_PUB":
            return None
        client_pub = X25519PublicKey.from_public_bytes(base64.b64decode(msg["pub"]))

        # generate a fresh server ECDH keypair for this session
        server_priv = X25519PrivateKey.generate()
        server_pub_bytes = server_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        # sign the ECDH public key with the server certificate key so the
        # client can verify it came from the real server
        signature = SERVER_PRIVATE_KEY.sign(server_pub_bytes, apad.PKCS1v15(), hsh.SHA256())

        send_raw(conn, json.dumps({
            "type": "SERVER_PUB",
            "pub": base64.b64encode(server_pub_bytes).decode("utf-8"),
            "sig": base64.b64encode(signature).decode("utf-8"),
        }))

        # derive the shared session key from the ECDH exchange
        shared_secret = server_priv.exchange(client_pub)
        session_key = derive_session_key(shared_secret)
        log.info("[SERVER] handshake complete, encrypted session established")
        return session_key

    except Exception:
        log.exception("[SERVER] handshake error")
        return None


def check_replay(req: dict) -> bool:
    """
    Check that a request is not a replay. Verifies the nonce has not been
    seen before and the timestamp is within the acceptable window.

    :param req: the received request dictionary
    :returns: True if request is fresh, False if it should be rejected
    """
    req_id = req.get("req_id", "")
    nonce = req.get("nonce", "")

    if not isinstance(req_id, str) or not req_id or len(req_id) > 128:
        log.warning("[SERVER] request missing valid req_id, rejected")
        return False

    if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
        log.warning("[SERVER] request missing nonce, rejected")
        return False

    try:
        ts = float(req.get("ts", 0))
    except (TypeError, ValueError):
        log.warning("[SERVER] request missing valid timestamp, rejected")
        return False

    now = time.time()
    if abs(now - ts) > NONCE_WINDOW:
        log.warning(f"[SERVER] request timestamp outside window: {ts}")
        return False

    with SEEN_NONCES_LOCK:
        # clean up expired nonces to keep memory usage down
        expired = [n for n, t in SEEN_NONCES.items() if now - t > NONCE_WINDOW]
        for n in expired:
            del SEEN_NONCES[n]

        if nonce in SEEN_NONCES:
            log.warning(f"[SERVER] replay detected, nonce already seen: {nonce}")
            return False

        SEEN_NONCES[nonce] = now
    return True


def check_rate_limit(ip: str) -> bool:
    """
    Check whether a given IP address has exceeded the request rate limit.

    :param ip: client IP address string
    :returns: True if allowed, False if rate limit exceeded
    """
    now = time.time()
    with RATE_TRACKER_LOCK:
        if ip not in RATE_TRACKER:
            RATE_TRACKER[ip] = []
        RATE_TRACKER[ip] = [t for t in RATE_TRACKER[ip] if now - t < RATE_WINDOW]
        if len(RATE_TRACKER[ip]) >= RATE_MAX:
            log.warning(f"[SERVER] rate limit exceeded for {ip}")
            return False
        RATE_TRACKER[ip].append(now)
    return True


def validate_username(username: str) -> bool:
    """
    Reject usernames that contain characters which could be used for
    path manipulation or cause filesystem issues.

    :param username: the username string to validate
    :returns: True if valid, False otherwise
    """
    if not isinstance(username, str) or not username or len(username) > 64:
        return False
    if username in (".", "..") or ".." in username:
        return False

    allowed = set(string.ascii_letters + string.digits + "._-")
    return all(ch in allowed for ch in username)


def safe_path(username: str, filename: str):
    """
    Build a safe file path by resolving the real path and verifying it
    stays inside the user's storage directory.

    :param username: the authenticated username
    :param filename: the requested filename
    :returns: resolved safe path string, or None if path traversal detected
    """
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        log.warning(f"[SERVER] invalid filename by {username}: {filename}")
        return None
    if filename in (".", "..") or "\x00" in filename or "/" in filename or "\\" in filename:
        log.warning(f"[SERVER] invalid filename by {username}: {filename}")
        return None

    user_dir = os.path.realpath(os.path.join(STORAGE_DIR, username))
    full_path = os.path.realpath(os.path.join(user_dir, filename))
    if not full_path.startswith(user_dir + os.sep) and full_path != user_dir:
        log.warning(f"[SERVER] path traversal attempt by {username}: {filename}")
        return None
    if os.path.isdir(full_path):
        log.warning(f"[SERVER] directory path rejected for {username}: {filename}")
        return None
    return full_path


def require_auth(req):
    """
    Retrieve username associated with a token from SESSIONS global.

    :param req: a received request
    :returns: username corresponding to token in request, or None
    """
    token = req.get("token", "")
    if not isinstance(token, str):
        return None
    with SESSIONS_LOCK:
        return SESSIONS.get(token)


def add_to_sessions(token, username):
    """
    Add a token and username to SESSIONS global.

    :param token: a token
    :param username: a username
    :returns: True on success, else False
    """
    with SESSIONS_LOCK:
        if len(SESSIONS) < CLIENT_LIMIT:
            SESSIONS[token] = username
            return True
        return False


def handle_create(conn, key, req, client_ip):
    """
    Handle the CREATE command.
    """
    if not check_rate_limit(client_ip):
        send_json(conn, key, make_response(req, "error", message="too many requests, try again later"))
        return

    raw_username = req.get("username", "")
    raw_password = req.get("password", "")
    if not isinstance(raw_username, str) or not isinstance(raw_password, str):
        send_json(conn, key, make_response(req, "error", message="missing username or password"))
        return

    username = raw_username.strip()
    password = raw_password.strip()

    if not username or not password:
        send_json(conn, key, make_response(req, "error", message="missing username or password"))
        return

    if not validate_username(username):
        log.warning(f"[SERVER] invalid username attempt from {client_ip}: {username}")
        send_json(conn, key, make_response(req, "error", message="invalid username"))
        return

    with USERS_LOCK:
        if username in USERS:
            send_json(conn, key, make_response(req, "error", message="user already exists"))
            return

        try:
            # hash the password before storing it
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            user_dir = os.path.join(STORAGE_DIR, username)
            os.makedirs(user_dir, exist_ok=True)
            USERS[username] = hashed

            with open("users.json", "w", encoding="utf-8") as f:
                json.dump(USERS, f, indent=4)
        except Exception:
            log.exception(f"[SERVER] account creation failed for {username}")
            send_json(conn, key, make_response(req, "error", message="account creation failed"))
            return

    log.info(f"[SERVER] account created: {username} from {client_ip}")
    send_json(conn, key, make_response(req, "ok", message="account created"))


def handle_auth(conn, key, req, client_ip):
    """
    Handle the AUTH command.
    """
    if not check_rate_limit(client_ip):
        send_json(conn, key, make_response(req, "error", message="too many requests, try again later"))
        return

    username = req.get("username", "")
    password = req.get("password", "")
    stored = None

    if isinstance(username, str) and isinstance(password, str):
        with USERS_LOCK:
            stored_hash = USERS.get(username)
        if stored_hash:
            stored = stored_hash.encode("utf-8")
        else:
            stored = None

    if isinstance(username, str) and isinstance(password, str) and stored:
        try:
            if bcrypt.checkpw(password.encode("utf-8"), stored):
                token = str(uuid.uuid4())
                if add_to_sessions(token, username):
                    log.info(f"[SERVER] auth success: {username} from {client_ip}")
                    send_json(conn, key, make_response(req, "ok", token=token))
                else:
                    send_json(conn, key, make_response(req, "error", message="server overload"))
                return
        except Exception:
            pass

    log.warning(f"[SERVER] auth failure: {username} from {client_ip}")
    send_json(conn, key, make_response(req, "error", message="invalid credentials"))


def handle_list(conn, key, req):
    """
    Handle the LIST command.
    """
    username = require_auth(req)
    if not username:
        send_json(conn, key, make_response(req, "error", message="unauthorized"))
        return

    user_dir = os.path.join(STORAGE_DIR, username)

    try:
        files = []
        for filename in os.listdir(user_dir):
            path = os.path.join(user_dir, filename)
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            modified_ts = os.path.getmtime(path)
            files.append({
                "name": filename,
                "modified_ts": modified_ts,
                "digest": digest,
            })
        log.info(f"[SERVER] list by {username}")
        send_json(conn, key, make_response(req, "ok", files=files))
    except Exception:
        log.exception(f"[SERVER] list failed for {username}")
        send_json(conn, key, make_response(req, "error", message="list failed"))


def handle_upload(conn, key, req):
    """
    Handle the UPLOAD command.
    """
    username = require_auth(req)
    if not username:
        send_json(conn, key, make_response(req, "error", message="unauthorized"))
        return

    filename = req.get("filename", "")
    content = req.get("content", "")

    if not isinstance(content, str):
        send_json(conn, key, make_response(req, "error", message="invalid file content"))
        return

    path = safe_path(username, filename)
    if not path:
        send_json(conn, key, make_response(req, "error", message="invalid filename"))
        return

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        ts = os.path.getmtime(path)
        sha256_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        log.info(f"[SERVER] upload: {filename} by {username}")
        send_json(conn, key, make_response(req, "ok",
                                           message=f"upload complete for {username}",
                                           ts=ts,
                                           sha256=sha256_digest))
    except Exception:
        log.exception(f"[SERVER] upload failed for {username}")
        send_json(conn, key, make_response(req, "error", message="upload failed"))


def handle_download(conn, key, req):
    """
    Handle the DOWNLOAD command.
    """
    username = require_auth(req)
    if not username:
        send_json(conn, key, make_response(req, "error", message="unauthorized"))
        return

    filename = req.get("filename", "")
    path = safe_path(username, filename)
    if not path:
        send_json(conn, key, make_response(req, "error", message="invalid filename"))
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        modified_ts = os.path.getmtime(path)
        sha256_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        log.info(f"[SERVER] download: {filename} by {username}")
        send_json(conn, key, make_response(req, "ok",
                                           filename=filename,
                                           content=content,
                                           modified_ts=modified_ts,
                                           sha256=sha256_digest))
    except Exception:
        log.exception(f"[SERVER] download failed for {username}")
        send_json(conn, key, make_response(req, "error", message="download failed"))


def handle_logout(conn, key, req):
    """
    Handle the LOGOUT command.
    """
    token = req.get("token", "")
    if not isinstance(token, str):
        username = None
    else:
        with SESSIONS_LOCK:
            username = SESSIONS.get(token)
    if not username:
        send_json(conn, key, make_response(req, "error", message="unauthorized"))
        return

    # remove the token so it cannot be reused after logout
    with SESSIONS_LOCK:
        SESSIONS.pop(token, None)
    log.info(f"[SERVER] logout: {username}")
    send_json(conn, key, make_response(req, "ok", message=f"{username} logged out"))


def dispatch(conn, key, req, client_ip):
    """
    Retrieve command from request and run handler.

    :param conn: a network connection object
    :param key: the session encryption key
    :param req: a received request
    :param client_ip: the client IP address
    """
    action = req.get("action", "")
    req_id = req.get("req_id", "")

    # reject replayed or stale requests before doing anything else
    if not check_replay(req):
        send_json(conn, key, make_response(req, "error", message="request rejected"))
        return

    # pass req_id into req so handlers can include it in responses
    req["req_id"] = req_id

    if action == "CREATE":
        handle_create(conn, key, req, client_ip)
    elif action == "AUTH":
        handle_auth(conn, key, req, client_ip)
    elif action == "LIST":
        handle_list(conn, key, req)
    elif action == "UPLOAD":
        handle_upload(conn, key, req)
    elif action == "DOWNLOAD":
        handle_download(conn, key, req)
    elif action == "LOGOUT":
        handle_logout(conn, key, req)
    else:
        send_json(conn, key, make_response(req, "error", message="unknown action"))


def handle_client(conn, addr):
    """
    The command processing loop for a client -- perform handshake, then
    read and dispatch requests.

    :param conn: a network connection object
    :param addr: the (IP, PORT) tuple of client
    """
    client_ip = addr[0]
    log.info(f"[SERVER] connection from {addr}")
    try:
        conn.settimeout(15.0)

        # establish encrypted session before processing any commands
        session_key = perform_handshake(conn)
        if not session_key:
            log.warning(f"[SERVER] handshake failed with {addr}")
            conn.close()
            return

        conn.settimeout(300.0)

        while True:
            req = recv_json(conn, session_key)
            if req is None:
                break
            log.info(f"[SERVER] recv from {addr}: action={req.get('action', '?')}")
            dispatch(conn, session_key, req, client_ip)

    except socket.timeout:
        log.warning(f"[SERVER] timed out connection from {addr}")
    except Exception:
        log.exception(f"[SERVER] error with {addr}")
    finally:
        conn.close()
        log.info(f"[SERVER] disconnected {addr}")
        connection_semaphore.release()


def signal_handler(sig, frame):
    print("\n[SERVER] Shutting down")
    sys.exit(0)


def main():
    """
    Create server to listen for connections. A maximum of CLIENT_LIMIT connections
    are allowed. DO NOT MODIFY the value of CLIENT_LIMIT.
    """
    signal.signal(signal.SIGINT, signal_handler)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1.0)
        s.bind((HOST, PORT))
        s.listen(128)

        print(f"[SERVER] listening on {HOST}:{PORT}")

        while True:
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[SERVER] shutting down: {e}")
                break

            if connection_semaphore.acquire(blocking=False):
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            else:
                print(f"[SERVER] rejected connection from {addr}")
                conn.sendall(b'{"status":"error","message":"server busy, try again later"}\n')
                conn.close()


if __name__ == "__main__":
    main()
