#!/usr/bin/env python3
"""Shared helpers for FSS standalone security validation tests."""

import hashlib
import importlib.util
import socket
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CLIENT_DIR = REPO_ROOT / "client_root" / "home" / "client"
SERVER_DIR = REPO_ROOT / "server_root" / "home" / "server"


def load_client_module():
    client_path = CLIENT_DIR / "client.py"
    spec = importlib.util.spec_from_file_location("fss_client", client_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load client module from {client_path}")

    client = importlib.util.module_from_spec(spec)
    sys.modules["fss_client"] = client
    spec.loader.exec_module(client)
    client.CA_CERT_PATH = str(CLIENT_DIR / "ca_cert.pem")
    return client


def connect_secure():
    client = load_client_module()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15.0)
    sock.connect((client.SERVER_HOST, client.SERVER_PORT))
    key = client.perform_handshake(sock)
    sock.settimeout(30.0)
    return client, sock, key


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_condition(condition, message):
    if not condition:
        raise AssertionError(message)
