"""--phone-models: collect one network-config page per Cisco phone model so
support can be added for unverified layouts (replaces cisco-phone-query.sh)."""
import sqlite3
import tarfile

import pytest

import thief


class _Resp:
    def __init__(self, text):
        self.text = text


def _fake_get(pages):
    """requests.get stand-in serving pages[url]; unknown URLs raise like an
    unreachable phone."""
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        if url not in pages:
            raise thief.requests.exceptions.ConnectionError(url)
        return _Resp(pages[url])
    get.calls = calls
    return get


SERVICEABILITY = '/CGI/Java/Serviceability?adapter=device.statistics.device'


# ---------------------------------------------------------------------------
# get_phones_from_db
# ---------------------------------------------------------------------------

def test_get_phones_from_db_unions_tables(tmp_path):
    db = thief.init_database(str(tmp_path / 'thief.db'))
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO phone_cucm (cucm_host, phone_ip, discovery_time) "
                 "VALUES ('cucm', '10.0.0.5', 't')")
    conn.executemany(
        "INSERT INTO mac_prefixes (cucm_host, phone_ip, full_mac, partial_mac, discovery_time) "
        "VALUES ('cucm', ?, ?, 'x', 't')",
        [('10.0.0.5', 'AAA'), ('10.0.0.6', 'BBB')])
    conn.commit()
    conn.close()

    assert thief.get_phones_from_db(db) == ['10.0.0.5', '10.0.0.6']


def test_get_phones_from_db_empty(tmp_path):
    db = thief.init_database(str(tmp_path / 'thief.db'))
    assert thief.get_phones_from_db(db) == []


def test_get_phones_from_db_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        thief.get_phones_from_db(str(tmp_path / 'nope.db'))


# ---------------------------------------------------------------------------
# query_phone_models
# ---------------------------------------------------------------------------

def test_one_page_per_model_and_tarball(tmp_path, monkeypatch):
    get = _fake_get({
        'http://10.0.0.1': '<html>Cisco CP-8865</html>',
        'http://10.0.0.2': '<html>Cisco CP-8865</html>',
        'http://10.0.0.3': '<html>Cisco cp-7811</html>',
        'http://10.0.0.4': '<html>Cisco IP Communicator</html>',  # soft phone: no model
        f'http://10.0.0.1{SERVICEABILITY}': '<html>CUCM Server 1 cucm-a</html>',
        f'http://10.0.0.2{SERVICEABILITY}': '<html>CUCM Server 1 cucm-a</html>',
        f'http://10.0.0.3{SERVICEABILITY}': '<html>Unified CM 1 cucm-a</html>',
    })
    monkeypatch.setattr(thief.requests, 'get', get)

    result = thief.query_phone_models(
        ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.9'],
        output_dir=str(tmp_path), threads=4)

    assert result['models'] == {'CP-8865': '10.0.0.1', 'CP-7811': '10.0.0.3'}
    assert sorted(result['saved']) == ['cisco-CP-7811.html', 'cisco-CP-8865.html']
    assert result['unknown'] == []
    assert (tmp_path / 'cisco-CP-8865.html').read_text() == '<html>CUCM Server 1 cucm-a</html>'
    # only one config-page fetch per model, from the first phone listed
    assert f'http://10.0.0.2{SERVICEABILITY}' not in get.calls
    with tarfile.open(result['tarball']) as tar:
        assert sorted(tar.getnames()) == ['cisco-CP-7811.html', 'cisco-CP-8865.html']


def test_falls_back_to_network_configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(thief.requests, 'get', _fake_get({
        'http://10.0.0.1': 'CP-7945G',
        f'http://10.0.0.1{SERVICEABILITY}': '<html>nothing useful</html>',
        'http://10.0.0.1/NetworkConfiguration': '<html>Unified CM 1 cucm-b</html>',
    }))

    result = thief.query_phone_models(['10.0.0.1'], output_dir=str(tmp_path))

    assert result['saved'] == ['cisco-CP-7945G.html']
    assert (tmp_path / 'cisco-CP-7945G.html').read_text() == '<html>Unified CM 1 cucm-b</html>'


def test_unrecognized_page_is_reported_not_saved(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(thief.requests, 'get', _fake_get({
        'http://10.0.0.1': 'CP-9999',
        f'http://10.0.0.1{SERVICEABILITY}': 'nope',
        'http://10.0.0.1/NetworkConfiguration': 'still nope',
    }))

    result = thief.query_phone_models(['10.0.0.1'], output_dir=str(tmp_path))

    assert result['saved'] == []
    assert result['unknown'] == [('10.0.0.1', 'CP-9999')]
    assert result['tarball'] is None
    assert not (tmp_path / 'cisco-CP-9999.html').exists()
    assert not (tmp_path / 'ciscophones.tgz').exists()
    assert 'http://10.0.0.1' in capsys.readouterr().out


def test_no_models_found(tmp_path, monkeypatch):
    monkeypatch.setattr(thief.requests, 'get', _fake_get({}))
    result = thief.query_phone_models(['10.0.0.1'], output_dir=str(tmp_path))
    assert result == {'models': {}, 'saved': [], 'unknown': [], 'tarball': None}
