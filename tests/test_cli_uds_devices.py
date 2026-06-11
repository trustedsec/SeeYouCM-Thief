import os
import subprocess


def test_uds_devices_requires_host():
    env = os.environ.copy()
    env["PYTEST_CURRENT_TEST"] = "1"
    result = subprocess.run(
        ["python3", "thief.py", "--uds-devices"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 1
    assert "--uds-devices requires -H/--host" in result.stdout


def test_uds_devices_requires_credentials():
    env = os.environ.copy()
    env["PYTEST_CURRENT_TEST"] = "1"
    result = subprocess.run(
        ["python3", "thief.py", "--uds-devices", "-H", "1.2.3.4"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 1
    assert "--uds-devices requires both --uds-user and --uds-password" in result.stdout
