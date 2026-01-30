import os
import subprocess


def test_bruteforce_requires_phone():
    env = os.environ.copy()
    env["PYTEST_CURRENT_TEST"] = "1"
    result = subprocess.run(
        ["python3", "thief.py", "--brute-mac"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 1
    assert "You must specify at least one phone" in result.stdout
