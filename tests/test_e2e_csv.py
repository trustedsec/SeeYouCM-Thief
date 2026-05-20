import csv
import os
import subprocess


def test_end_to_end_csv_export(tmp_path):
    db_path = tmp_path / "e2e.db"
    csv_path = tmp_path / "e2e.csv"
    expected_path = tmp_path / "expected.csv"

    test_config = (
        "<device>\n"
        "<sshUserId>admin</sshUserId>\n"
        "<sshPassword>pass123</sshPassword>\n"
        "<userId>user</userId>\n"
        "<adminPassword>secret</adminPassword>\n"
        "</device>"
    )

    env = os.environ.copy()
    env["PYTEST_CURRENT_TEST"] = "1"
    env["THIEF_TEST_CONFIG"] = test_config
    env["THIEF_TEST_PHONE_HOSTNAME"] = "SEP001122334455"

    result = subprocess.run(
        [
            "python3",
            "thief.py",
            "-H",
            "mock-cucm",
            "-p",
            "1.2.3.4",
            "-b",
            "1",
            "--threads",
            "1",
            "--db",
            str(db_path),
            "--csv",
            str(csv_path),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0
    assert csv_path.exists()

    with csv_path.open(newline="") as handle:
        reader = csv.reader(handle)
        rows = list(reader)

    assert rows[0] == ["Timestamp", "Type", "Device", "Username", "Password"]

    # 16 MAC brute-force tasks × 3 rows each, plus 9 DEFAULT TFTP files each
    # downloading the test config (2 Credential rows + 1 Username row = 3 rows each).
    num_default_files = 9  # len(thief.DEFAULT_TFTP_FILES)
    assert len(rows) == 1 + (16 * 3) + (num_default_files * 3)

    timestamp = rows[1][0]
    assert timestamp

    partial_mac = "00112233445"
    expected_data = []
    for i in range(16):
        suffix = f"{i:X}"
        device = f"SEP{partial_mac}{suffix}"
        expected_data.extend(
            [
                [timestamp, "Credential", device, "admin", "pass123"],
                [timestamp, "Credential", device, "admin", "secret"],
                [timestamp, "Username", device, "user", "N/A"],
            ]
        )

    # DEFAULT sentinel tasks all report under device "SEPDEFAULT"; one entry per
    # default file since each fetches an independent copy of the test config.
    for _ in range(num_default_files):
        expected_data.extend(
            [
                [timestamp, "Credential", "SEPDEFAULT", "admin", "pass123"],
                [timestamp, "Credential", "SEPDEFAULT", "admin", "secret"],
                [timestamp, "Username", "SEPDEFAULT", "user", "N/A"],
            ]
        )

    expected_rows = [
        ["Timestamp", "Type", "Device", "Username", "Password"],
        *sorted(expected_data),
    ]

    with expected_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerows(expected_rows)

    actual_rows = [rows[0], *sorted(rows[1:])]
    assert actual_rows == expected_rows
