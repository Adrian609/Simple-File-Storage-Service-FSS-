#!/usr/bin/env python3
"""Pytest fixtures for FSS security validation tests."""

import pytest

from fss_test_helpers import connect_secure


@pytest.fixture
def secure_connection():
    client, sock, key = connect_secure()
    try:
        yield client, sock, key
    finally:
        sock.close()
