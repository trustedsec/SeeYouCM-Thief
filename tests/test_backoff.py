"""Unit tests for TFTPBackoffManager's delay curve.

The class is instantiated as a fixture across test_network_mocked.py and
test_bruteforce.py to feed download_worker, but none of those tests assert
the actual escalation/decay behavior documented in its docstring:
  - <=5 consecutive errors: no delay increase
  - 6-10 consecutive errors: +0.1 per error, capped at 2.0
  - >10 consecutive errors: +0.5 per error, capped at 5.0
  - record_success(): resets consecutive_errors to 0, decays delay by 0.01
"""
from seeyoucm_thief import thief


def test_initial_state_has_no_delay():
    mgr = thief.TFTPBackoffManager()
    assert mgr.get_delay() == 0.0
    assert mgr.consecutive_errors == 0
    assert mgr.error_count == 0


def test_no_delay_below_six_consecutive_errors():
    mgr = thief.TFTPBackoffManager()
    for _ in range(5):
        mgr.record_error()
    assert mgr.consecutive_errors == 5
    assert mgr.error_count == 5
    assert mgr.get_delay() == 0.0


def test_delay_grows_by_tenth_between_six_and_ten_errors():
    mgr = thief.TFTPBackoffManager()
    for _ in range(6):
        mgr.record_error()
    assert mgr.consecutive_errors == 6
    assert abs(mgr.get_delay() - 0.1) < 1e-9

    for _ in range(4):  # up to 10 total
        mgr.record_error()
    assert mgr.consecutive_errors == 10
    assert abs(mgr.get_delay() - 0.5) < 1e-9


def test_delay_growth_caps_at_two_before_eleventh_error():
    mgr = thief.TFTPBackoffManager()
    for _ in range(10):
        mgr.record_error()
    assert abs(mgr.get_delay() - 0.5) < 1e-9  # 5 * 0.1, well under the 2.0 cap for this tier


def test_delay_grows_by_half_after_ten_consecutive_errors():
    mgr = thief.TFTPBackoffManager()
    for _ in range(11):
        mgr.record_error()
    assert mgr.consecutive_errors == 11
    # 5 * 0.1 (errors 6-10) + 1 * 0.5 (error 11) = 1.0
    assert abs(mgr.get_delay() - 1.0) < 1e-9


def test_delay_caps_at_five_with_many_consecutive_errors():
    mgr = thief.TFTPBackoffManager()
    for _ in range(200):
        mgr.record_error()
    assert mgr.get_delay() == 5.0


def test_delay_caps_at_two_with_errors_stuck_in_six_to_ten_tier():
    # Regression: if consecutive_errors is reset back into the 6-10 band
    # repeatedly (record_success doesn't reset delay, only consecutive_errors),
    # the +0.1-per-error tier must still respect its own 2.0 cap.
    mgr = thief.TFTPBackoffManager()
    for _ in range(1000):
        mgr.consecutive_errors = 6
        mgr.record_error()  # each call increments consecutive_errors to 7, then checks tier
    assert mgr.get_delay() <= 2.0


def test_record_success_resets_consecutive_errors():
    mgr = thief.TFTPBackoffManager()
    for _ in range(8):
        mgr.record_error()
    assert mgr.consecutive_errors == 8
    mgr.record_success()
    assert mgr.consecutive_errors == 0
    # error_count (lifetime) is untouched by success
    assert mgr.error_count == 8


def test_record_success_decays_delay_by_one_hundredth():
    mgr = thief.TFTPBackoffManager()
    for _ in range(6):
        mgr.record_error()
    delay_before = mgr.get_delay()
    mgr.record_success()
    assert abs(mgr.get_delay() - max(0, delay_before - 0.01)) < 1e-9


def test_record_success_does_not_go_negative():
    mgr = thief.TFTPBackoffManager()
    mgr.record_success()
    assert mgr.get_delay() == 0.0
    mgr.record_success()
    assert mgr.get_delay() == 0.0


def test_error_count_is_lifetime_not_consecutive():
    mgr = thief.TFTPBackoffManager()
    for _ in range(3):
        mgr.record_error()
    mgr.record_success()
    for _ in range(4):
        mgr.record_error()
    assert mgr.error_count == 7
    assert mgr.consecutive_errors == 4
