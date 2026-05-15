#!/usr/bin/env python3
"""Validate that a session token cannot be reused after logout."""

from fss_test_helpers import assert_condition, connect_secure


def main():
    client, sock, key = connect_secure()
    try:
        auth = client.send_recv(sock, key, {
            "action": "AUTH",
            "username": "alice",
            "password": "password123",
        })
        assert_condition(auth.get("status") == "ok", f"AUTH failed: {auth}")
        token = auth["token"]

        logout = client.send_recv(sock, key, {"action": "LOGOUT", "token": token})
        assert_condition(logout.get("status") == "ok", f"LOGOUT failed: {logout}")

        reuse = client.send_recv(sock, key, {"action": "LIST", "token": token})
        assert_condition(reuse.get("status") == "error", f"old token was accepted: {reuse}")
        assert_condition(reuse.get("message") == "unauthorized", f"unexpected reuse failure: {reuse}")
    finally:
        sock.close()

    print("PASS T-03 logout token reuse: old token rejected after logout")


if __name__ == "__main__":
    main()
