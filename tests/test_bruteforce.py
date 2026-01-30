import logging
import threading
import queue

import thief


def test_configure_tftpy_logging_levels():
    thief.configure_tftpy_logging(False)
    assert logging.getLogger('tftpy.TftpClient').level == logging.CRITICAL
    assert logging.getLogger('tftpy.TftpContexts').level == logging.CRITICAL
    assert logging.getLogger('tftpy.TftpPacketTypes').level == logging.CRITICAL
    assert logging.getLogger('tftpy').level == logging.CRITICAL

    thief.configure_tftpy_logging(True)
    assert logging.getLogger('tftpy.TftpClient').level == logging.DEBUG
    assert logging.getLogger('tftpy.TftpContexts').level == logging.DEBUG
    assert logging.getLogger('tftpy.TftpPacketTypes').level == logging.DEBUG
    assert logging.getLogger('tftpy').level == logging.DEBUG


def test_backoff_manager_delay_increases():
    manager = thief.TFTPBackoffManager()
    for _ in range(6):
        manager.record_error()
    assert manager.get_delay() > 0


def test_download_worker_uses_task_cucm(monkeypatch):
    work_queue = queue.Queue()
    results_queue = queue.Queue()
    manager = thief.TFTPBackoffManager()

    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: "content")
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)

    t = threading.Thread(
        target=thief.download_worker,
        args=(work_queue, results_queue, None, True, manager, True, 'ignored.db', True, set(), threading.Lock()),
        daemon=True,
    )
    t.start()

    work_queue.put((0, "ABCDEF123456", "SEPABCDEF123456.cnf.xml", "mock-cucm"))
    work_queue.put(None)
    work_queue.join()

    index, full_mac, content, method, was_cached = results_queue.get(timeout=2)
    assert index == 0
    assert full_mac == "ABCDEF123456"
    assert content == "content"


def test_download_worker_tftp_timeouts_and_errors(monkeypatch):
    work_queue = queue.Queue()
    results_queue = queue.Queue()
    manager = thief.TFTPBackoffManager()

    errors = [TimeoutError("tftp timeout"), Exception("tftp random error")]

    def flaky_tftp(*_a, **_kw):
        raise errors.pop(0)

    monkeypatch.setattr(thief, 'download_config_tftp', flaky_tftp)
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)

    t = threading.Thread(
        target=thief.download_worker,
        args=(work_queue, results_queue, "mock-cucm", True, manager, True, 'ignored.db', True, set(), threading.Lock()),
        daemon=True,
    )
    t.start()

    work_queue.put((0, "ABCDEF123456", "SEPABCDEF123456.cnf.xml"))
    work_queue.put((1, "ABCDEF654321", "SEPABCDEF654321.cnf.xml"))
    work_queue.put(None)
    work_queue.join()

    # Both results should be failures and backoff should increase.
    res1 = results_queue.get(timeout=2)
    res2 = results_queue.get(timeout=2)
    assert res1[2] is None
    assert res2[2] is None
    assert manager.get_delay() >= 0
