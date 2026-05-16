#!/usr/bin/env python3
"""
Validate that post-handshake application messages are opaque ciphertext.

This simulates a MITM capture by recording the raw lines sent over the socket
after the authenticated ECDH handshake has completed.
"""

import base64
import json
import time
import uuid

from fss_test_helpers import SERVER_DIR, assert_condition, connect_secure


def send_recv_with_capture(client, sock, key, obj):
    req = dict(obj)
    req["nonce"] = str(uuid.uuid4())
    req["ts"] = time.time()
    req["req_id"] = str(uuid.uuid4())

    raw_out = client.encrypt_message(key, json.dumps(req)) + b"\n"
    sock.sendall(raw_out)

    raw_in_text = client.recv_line(sock)
    raw_in = raw_in_text.encode("utf-8")
    resp = json.loads(client.decrypt_message(key, raw_in_text))

    assert_condition(resp.get("req_id") == req["req_id"], "response req_id did not match request")
    return raw_out, raw_in, resp


def assert_post_handshake_messages_are_ciphertext(client, sock, key):
    test_file = SERVER_DIR / "server_storage" / "alice" / "test.txt"
    known_content = test_file.read_text(encoding="utf-8", errors="ignore").strip()

    captures = []
    raw_out, raw_in, auth = send_recv_with_capture(client, sock, key, {
        "action": "AUTH",
        "username": "alice",
        "password": "password123",
    })
    captures.extend([raw_out, raw_in])
    assert_condition(auth.get("status") == "ok", f"AUTH failed: {auth}")
    token = auth["token"]

    for request in [
        {"action": "LIST", "token": token},
        {"action": "DOWNLOAD", "token": token, "filename": "test.txt"},
        {"action": "LOGOUT", "token": token},
    ]:
        raw_out, raw_in, resp = send_recv_with_capture(client, sock, key, request)
        captures.extend([raw_out, raw_in])
        assert_condition(resp.get("status") == "ok", f"{request['action']} failed: {resp}")

    decoded_captures = []
    for line in captures:
        decoded = base64.b64decode(line.strip(), validate=True)
        decoded_captures.append(decoded)
        assert_condition(len(decoded) > 28, "encrypted message too short to contain nonce, tag, and ciphertext")

    sensitive_strings = [
        "alice",
        "password123",
        "alice123",
        "bob",
        "AUTH",
        "UPLOAD",
        "DOWNLOAD",
        "LIST",
        "LOGOUT",
        "secret",
        "../bob/letter.txt",
        "test.txt",
    ]
    if known_content:
        sensitive_strings.append(known_content)

    combined = b"".join(decoded_captures)
    exposed = [s for s in sensitive_strings if s.encode("utf-8") in combined]
    assert_condition(not exposed, f"plaintext appeared in post-handshake capture: {exposed}")


def test_mitm_sees_only_ciphertext_after_handshake(secure_connection):
    client, sock, key = secure_connection
    assert_post_handshake_messages_are_ciphertext(client, sock, key)


def main():
    client, sock, key = connect_secure()
    try:
        assert_post_handshake_messages_are_ciphertext(client, sock, key)
    finally:
        sock.close()

    print("PASS T-01 MITM ciphertext: post-handshake capture contains no sensitive plaintext")


if __name__ == "__main__":
    main()
