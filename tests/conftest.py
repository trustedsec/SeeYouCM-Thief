#!/usr/bin/env python3
"""Shared pytest configuration and fixtures for the SeeYouCM-thief test suite."""
import os
import socket
import sys
from pathlib import Path

import pytest
import requests

# Add the parent directory to sys.path so we can import thief
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from seeyoucm_thief import thief  # noqa: E402


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

@pytest.fixture
def fixtures_dir():
    """Absolute path to tests/fixtures, independent of the invocation cwd."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def thief_script():
    """Absolute path to the repo-root thief.py shim, for subprocess CLI tests."""
    return str(parent_dir / "thief.py")


# ---------------------------------------------------------------------------
# Test-mode / DB fixtures (promoted from duplicated per-file copies)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _disable_test_mode(request, monkeypatch):
    """Ensure _TEST_MODE is False so the real code paths execute for in-process
    tests. Tests that want the fake _TEST_MODE data path (subprocess CLI tests
    that set PYTEST_CURRENT_TEST in a child env, or tests explicitly marked)
    should opt out with @pytest.mark.keep_test_mode."""
    if 'keep_test_mode' in request.keywords:
        return
    monkeypatch.setattr(thief, '_TEST_MODE', False)


@pytest.fixture
def db_path(tmp_path):
    """Return a path to a freshly-initialized thief.db in tmp_path."""
    p = tmp_path / "thief.db"
    thief.init_database(str(p))
    return str(p)


# ---------------------------------------------------------------------------
# Network guard: prevent accidental real network calls from in-process tests
# ---------------------------------------------------------------------------

class _RealNetworkCallError(RuntimeError):
    pass


def _blocked(*a, **kw):
    raise _RealNetworkCallError(
        "real network call attempted in a test (requests/socket not mocked). "
        "Mock the relevant thief.requests / thief.tftpy call, or mark the test "
        "@pytest.mark.allow_network if it's an intentionally-gated integration test."
    )


@pytest.fixture(autouse=True)
def _no_real_network(request, monkeypatch):
    """Autouse guard: any unmocked call into requests' session machinery or a
    raw socket connect() raises immediately instead of hanging for the
    library's default timeout. Tests that mock at a lower level (thief.requests.get,
    thief.tftpy.TftpClient, a _probe_fn/_login_fn injection seam, or a fake
    Session object) never reach these patched targets, so this is safe to
    apply globally. Integration tests are exempt since they gate on env vars
    and pytest.skip() before touching the network."""
    if 'integration' in request.keywords or 'allow_network' in request.keywords:
        return
    monkeypatch.setattr(requests.sessions.Session, 'request', _blocked)
    monkeypatch.setattr(socket.socket, 'connect', _blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', _blocked)


# ---------------------------------------------------------------------------
# Marker registration / auto-tagging
# ---------------------------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line("markers", "allow_network: opt out of the _no_real_network guard")


def pytest_collection_modifyitems(config, items):
    """Auto-apply the 'unit' marker to any test not already carrying one of
    the taxonomy markers, so existing files don't need a mass edit."""
    taxonomy = {"unit", "smoke", "e2e", "integration"}
    for item in items:
        if not (taxonomy & {m.name for m in item.iter_markers()}):
            item.add_marker(pytest.mark.unit)
