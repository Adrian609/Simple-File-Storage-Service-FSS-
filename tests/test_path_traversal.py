#!/usr/bin/env python3
"""Validate that ../ path traversal cannot access or overwrite Bob's files."""

from fss_test_helpers import SERVER_DIR, assert_condition, connect_secure, sha256_file


TRAVERSAL_NAME = "../bob/letter.txt"


def main():
    bob_file = SERVER_DIR / "server_storage" / "bob" / "letter.txt"
    assert_condition(bob_file.exists(), f"expected fixture file missing: {bob_file}")
    before_bytes = bob_file.read_bytes()
    before_digest = sha256_file(bob_file)

    client, sock, key = connect_secure()
    try:
        auth = client.send_recv(sock, key, {
            "action": "AUTH",
            "username": "alice",
            "password": "password123",
        })
        assert_condition(auth.get("status") == "ok", f"AUTH failed: {auth}")
        token = auth["token"]

        download = client.send_recv(sock, key, {
            "action": "DOWNLOAD",
            "token": token,
            "filename": TRAVERSAL_NAME,
        })
        assert_condition(download.get("status") == "error", f"traversal download succeeded: {download}")
        assert_condition("content" not in download, f"traversal response exposed content: {download}")

        upload = client.send_recv(sock, key, {
            "action": "UPLOAD",
            "token": token,
            "filename": TRAVERSAL_NAME,
            "content": "secret overwrite attempt",
        })
        assert_condition(upload.get("status") == "error", f"traversal upload succeeded: {upload}")

        logout = client.send_recv(sock, key, {"action": "LOGOUT", "token": token})
        assert_condition(logout.get("status") == "ok", f"LOGOUT failed: {logout}")
    finally:
        sock.close()

    after_bytes = bob_file.read_bytes()
    after_digest = sha256_file(bob_file)
    assert_condition(after_bytes == before_bytes, "Bob's file contents changed")
    assert_condition(after_digest == before_digest, "Bob's file digest changed")

    print("PASS T-02 path traversal: ../bob/letter.txt rejected and Bob's file unchanged")


if __name__ == "__main__":
    main()
