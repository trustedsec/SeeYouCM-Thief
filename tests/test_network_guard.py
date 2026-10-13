"""Keep test fixtures from resolving names through the host's DNS setup."""

import socket

import pytest


def test_network_guard_rejects_hostname_lookups():
    with pytest.raises(socket.gaierror):
        socket.gethostbyname('localhost')
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo('localhost', 80)


def test_network_guard_preserves_ip_literal_lookups():
    assert socket.gethostbyname('127.0.0.1') == '127.0.0.1'
    addresses = socket.getaddrinfo('127.0.0.1', 80)
    assert addresses
    assert all(address[4][0] == '127.0.0.1' for address in addresses)
