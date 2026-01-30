import os
import pytest

import thief


def _get_env(name):
    value = os.getenv(name)
    return value.strip() if value else None


@pytest.mark.integration
def test_real_phone_cucm_mapping():
    phone_ip = _get_env("REAL_PHONE_IP")
    if not phone_ip:
        pytest.skip("REAL_PHONE_IP not set")

    cucm = thief.get_cucm_name_from_phone(phone_ip)
    assert cucm is not None

    expected = _get_env("REAL_CUCM_HOST")
    if expected:
        expected_norm = expected.lower().strip()
        cucm_norm = cucm.lower().strip()
        if "." in expected_norm:
            assert cucm_norm == expected_norm or cucm_norm.endswith(f".{expected_norm}")
        else:
            assert cucm_norm == expected_norm or cucm_norm.split(".")[0] == expected_norm


@pytest.mark.integration
def test_real_phone_hostname():
    phone_ip = _get_env("REAL_PHONE_IP")
    if not phone_ip:
        pytest.skip("REAL_PHONE_IP not set")

    hostname = thief.get_hostname_from_phone(phone_ip)
    assert hostname is not None
