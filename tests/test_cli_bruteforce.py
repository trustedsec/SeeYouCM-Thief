import os
import subprocess

import pytest

pytestmark = pytest.mark.e2e


def test_bruteforce_requires_phone(thief_script):
    env = os.environ.copy()
    env["PYTEST_CURRENT_TEST"] = "1"
    result = subprocess.run(
        ["python3", thief_script, "--brute-mac"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 1
    assert "You must specify at least one phone" in result.stdout
