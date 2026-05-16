#!/usr/bin/env python3
"""
Network Security - University of Denver

client.py

This file holds the client code for a simple file storage service. The original
code was not secure for use in an adversarial network setting. This version has
been rewritten to address the security requirements of the project.

"""

import json
import socket
import getpass
import os
import base64
import uuid
import time
import ipaddress
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives import hashes as hsh
from cryptography.exceptions import InvalidSignature

# Class namespace server IP from setup_net; not a secret and must match cert SAN.
SERVER_HOST = "10.0.8.2"
SERVER_PORT = 9001

MAX_MESSAGE_BYTES = 10 * 1024 * 1024

# path to our CA certificate used to verify the server
CA_CERT_PATH = "ca_cert.pem"


def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derive an AES session key from the ECDH shared secret using HKDF.
    """
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"fss-session-key")
    return hkdf.derive(shared_secret)


def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a string using AES-GCM. Returns base64-encoded ciphertext
    with the nonce prepended.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct)


def decrypt_message(key: bytes, data: str) -> str:
    """
    Decrypt a base64-encoded AES-GCM message.
    """
    raw = base64.b64decode(data, validate=True)
    if len(raw) < 12 + 16:
        raise ValueError("encrypted message too short")
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def recv_line(sock):
    """
    Receive data until newline. Enforces a size limit to prevent
    memory exhaustion from oversized responses.
    """
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("server disconnected")
        data += chunk
        if len(data) > MAX_MESSAGE_BYTES:
            raise ValueError("response exceeded size limit")
    return data.decode("utf-8").strip()


def send_recv(sock, key: bytes, obj: dict) -> dict:
    """
    Add nonce, timestamp, and request ID to the request, encrypt and
    send it, then receive and decrypt the response.

    :param sock: a network connection object
    :param key: the session encryption key
    :param obj: request as a dictionary object
    :returns: response from server as dictionary object
    """
    # add fields needed for replay protection and response verification
    req = dict(obj)
    req["nonce"] = str(uuid.uuid4())
    req["ts"] = time.time()
    req["req_id"] = str(uuid.uuid4())

    sock.sendall(encrypt_message(key, json.dumps(req)) + b"\n")

    line = recv_line(sock)
    resp = json.loads(decrypt_message(key, line))
    if not isinstance(resp, dict):
        raise ValueError("server response was not a JSON object")
    if resp.get("req_id") != req["req_id"]:
        raise ValueError("response request ID mismatch -- possible replay or injection")
    return resp


def certificate_matches_host(server_cert, expected_host: str) -> bool:
    """
    Confirm the certificate identity matches the server we intended to reach.
    Requires exact match: IP address in SERVER_HOST must be present in certificate SAN.
    """
    try:
        expected_ip = ipaddress.ip_address(expected_host)
    except ValueError:
        expected_ip = None

    try:
        san = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if expected_ip is not None:
            # Require exact IP SAN match; no loopback bypass
            if expected_ip in san.get_values_for_type(x509.IPAddress):
                return True
            print(f"[CLIENT] certificate SAN IP mismatch: expected {expected_ip}, got {san.get_values_for_type(x509.IPAddress)}")
            return False
        return expected_host.lower() in [name.lower() for name in san.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        print("[CLIENT] certificate SAN extension not found")
        return False


def verify_server_certificate(cert_pem: bytes, expected_host: str):
    """
    Verify the server certificate against our trusted CA certificate.
    Returns the server certificate public key if valid.
    Raises an exception if verification fails.

    :param cert_pem: the server certificate in PEM format as bytes
    :returns: the server certificate public key
    """
    server_cert = load_pem_x509_certificate(cert_pem)

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = load_pem_x509_certificate(f.read())

    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        apad.PKCS1v15(),
        hsh.SHA256()
    )

    now = datetime.now(timezone.utc)
    if hasattr(server_cert, "not_valid_before_utc"):
        not_before = server_cert.not_valid_before_utc
        not_after = server_cert.not_valid_after_utc
    else:
        not_before = server_cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = server_cert.not_valid_after.replace(tzinfo=timezone.utc)

    if now < not_before or now > not_after:
        raise ValueError("server certificate is expired or not yet valid")

    if not certificate_matches_host(server_cert, expected_host):
        raise ValueError("server certificate identity does not match expected host")

    print("[CLIENT] server certificate verified")
    return server_cert.public_key()


def perform_handshake(sock):
    """
    Perform ECDH key exchange with the server. Verifies the server
    certificate before accepting any key material, then derives the
    shared session key.

    :param sock: a network connection object
    :returns: session key bytes
    """
    # receive and verify server certificate
    line = recv_line(sock)
    msg = json.loads(line)
    if msg.get("type") != "CERT":
        raise ValueError("unexpected message during handshake")

    cert_pem = base64.b64decode(msg.get("cert", ""))
    if not cert_pem:
        raise ValueError("server did not provide a certificate")

    server_cert_pub = verify_server_certificate(cert_pem, SERVER_HOST)

    # generate client ECDH keypair and send the public key to server
    client_priv = X25519PrivateKey.generate()
    client_pub_bytes = client_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    sock.sendall((json.dumps({
        "type": "CLIENT_PUB",
        "pub": base64.b64encode(client_pub_bytes).decode("utf-8")
    }) + "\n").encode("utf-8"))

    # receive server ECDH public key and verify its signature
    line = recv_line(sock)
    msg = json.loads(line)
    if msg.get("type") != "SERVER_PUB":
        raise ValueError("unexpected message during handshake")

    server_ecdh_pub_bytes = base64.b64decode(msg["pub"])
    signature = base64.b64decode(msg["sig"])

    try:
        server_cert_pub.verify(signature, server_ecdh_pub_bytes, apad.PKCS1v15(), hsh.SHA256())
        print("[CLIENT] server key verified")
    except InvalidSignature:
        raise ValueError("server key signature invalid -- possible MITM")

    # derive shared session key
    server_pub = X25519PublicKey.from_public_bytes(server_ecdh_pub_bytes)
    shared_secret = client_priv.exchange(server_pub)
    session_key = derive_session_key(shared_secret)

    print("[CLIENT] encrypted session established")
    return session_key


def main():
    """
    Obtains user command choice from a menu and processes it.
    """
    token = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(15.0)

        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[CLIENT] connected to server at {SERVER_HOST}:{SERVER_PORT}")

        # establish encrypted channel before doing anything else
        try:
            session_key = perform_handshake(sock)
        except Exception as e:
            print(f"[CLIENT] could not establish secure connection: {e}")
            return

        sock.settimeout(300.0)

        while True:
            print("\nChoose:")
            print("1) Login")
            print("2) Create account")
            print("3) List files")
            print("4) Upload file")
            print("5) Download file")
            print("6) Logout")
            print("7) Quit")
            choice = input("> ").strip()

            if choice == "1":
                username = input("Username: ").strip()
                password = getpass.getpass(prompt="Password: ").strip()
                resp = send_recv(sock, session_key, {
                    "action": "AUTH",
                    "username": username,
                    "password": password,
                })
                print(resp)
                if resp.get("status") == "ok":
                    token = resp.get("token")

            elif choice == "2":
                username = input("New username: ").strip()
                password = getpass.getpass(prompt="New password: ").strip()
                confirm = getpass.getpass(prompt="Confirm password: ").strip()

                if password != confirm:
                    print("Error: Passwords do not match")
                    continue

                resp = send_recv(sock, session_key, {
                    "action": "CREATE",
                    "username": username,
                    "password": password,
                })
                print(resp)

            elif choice == "3":
                resp = send_recv(sock, session_key, {
                    "action": "LIST",
                    "token": token,
                })
                print(resp)

            elif choice == "4":
                filename = input("Filename: ").strip()
                print("Enter file content. End with a single line containing EOF")
                lines = []
                while True:
                    line = input()
                    if line == "EOF":
                        break
                    lines.append(line)
                content = "\n".join(lines)

                resp = send_recv(sock, session_key, {
                    "action": "UPLOAD",
                    "token": token,
                    "filename": filename,
                    "content": content,
                })
                print(resp)

            elif choice == "5":
                filename = input("Filename: ").strip()
                resp = send_recv(sock, session_key, {
                    "action": "DOWNLOAD",
                    "token": token,
                    "filename": filename,
                })
                print(resp)

            elif choice == "6":
                resp = send_recv(sock, session_key, {
                    "action": "LOGOUT",
                    "token": token,
                })
                print(resp)
                token = None

            elif choice == "7":
                print("[CLIENT] goodbye")
                break

            else:
                print("Invalid choice")


if __name__ == "__main__":
    main()
