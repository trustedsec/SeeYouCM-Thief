import sqlite3

import pytest

from seeyoucm_thief import thief

pytestmark = pytest.mark.smoke

CRED = ('admin', 'pw', 'SEP001122334455.cnf.xml')
USER = ('bob', 'SEP001122334455.cnf.xml')


def _argv(monkeypatch, *args):
    monkeypatch.setattr('sys.argv', ['thief', *args])


@pytest.fixture
def leaves(monkeypatch):
    calls = {'config_names': []}
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda ip: 'cucm.test')
    monkeypatch.setattr(thief, 'get_hostname_from_phone', lambda ip: 'SEP001122334455')
    monkeypatch.setattr(thief, 'get_phones_hostnames_from_reverse', lambda ip: [])

    def fake_names(cucm_host, hostnames=None, use_tftp=True):
        calls['config_names'].append((cucm_host, hostnames))
        return ['SEP001122334455.cnf.xml']

    monkeypatch.setattr(thief, 'get_config_names', fake_names)
    monkeypatch.setattr(thief, 'search_for_secrets', lambda h, f, use_tftp=True: ([CRED], [USER]))
    return calls


def _count(db, table):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
    finally:
        conn.close()


def test_host_only_prints_and_logs(leaves, monkeypatch, tmp_path, capsys):
    db = str(tmp_path / 'thief.db')
    _argv(monkeypatch, '-H', 'cucm.test', '--db', db)
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert 'Discovered 1 config file name(s)' in out
    assert 'admin\tpw\tSEP001122334455.cnf.xml' in out
    assert _count(db, 'credentials') == 1


def test_host_only_no_db_writes_nothing(leaves, monkeypatch, tmp_path):
    db = tmp_path / 'thief.db'
    _argv(monkeypatch, '-H', 'cucm.test', '--db', str(db), '--no-db')
    with pytest.raises(SystemExit):
        thief.main()
    assert not db.exists() or _count(str(db), 'credentials') == 0


def test_single_phone_sequential(leaves, monkeypatch, tmp_path, capsys):
    db = str(tmp_path / 'thief.db')
    _argv(monkeypatch, '-p', '10.0.0.5', '-T', '1', '--db', db)
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert 'detected IP address/hostname for the CUCM server is cucm.test' in out
    assert 'Credentials Found in Configurations!' in out
    assert _count(db, 'phone_cucm') == 1
    assert _count(db, 'credentials') == 1


def test_multiple_phones_threaded(leaves, monkeypatch, tmp_path, capsys):
    db = str(tmp_path / 'thief.db')
    _argv(monkeypatch, '-p', '10.0.0.5', '-p', '10.0.0.6', '--db', db)
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.count('Processing phone:') == 2
    assert len(leaves['config_names']) == 2


def test_phone_without_detectable_cucm_is_skipped(leaves, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda ip: None)
    _argv(monkeypatch, '-p', '10.0.0.5', '-T', '1', '--db', str(tmp_path / 'thief.db'))
    with pytest.raises(SystemExit):
        thief.main()
    assert 'Unable to automatically detect the CUCM Server' in capsys.readouterr().out
    assert leaves['config_names'] == []


def test_phone_with_no_config_names(leaves, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(thief, 'get_config_names', lambda *a, **kw: None)
    _argv(monkeypatch, '-p', '10.0.0.5', '-T', '1', '--db', str(tmp_path / 'thief.db'))
    with pytest.raises(SystemExit):
        thief.main()
    assert 'Unable to detect file names from CUCM' in capsys.readouterr().out


def test_no_phone_no_host_exits_1(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, '--db', str(tmp_path / 'thief.db'))
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 1


def test_enumsubnet_prints_and_logs_found_credentials(leaves, monkeypatch, tmp_path, capsys):
    db = str(tmp_path / 'thief.db')
    monkeypatch.setattr(
        thief, 'enumerate_phones_subnet',
        lambda cidr: [{'ip': '10.0.0.5', 'hostname': 'SEP001122334455',
                       'url': 'http://cucm.test:6970/SEP001122334455.cnf.xml'}],
    )
    monkeypatch.setattr(thief.socket, 'gethostbyname', lambda h: '10.0.0.1')
    _argv(monkeypatch, '-e', '10.0.0.0/30', '--db', db)
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert 'Credentials Found in Configurations!' in out
    assert 'admin\tpw\tSEP001122334455.cnf.xml' in out
    assert 'Usernames Found in Configurations!' in out
    assert _count(db, 'credentials') == 1


def test_enumsubnet_detects_cucm_for_each_phone(leaves, monkeypatch, tmp_path):
    hosts = [
        {'ip': '10.0.0.5', 'hostname': 'SEP000000000005'},
        {'ip': '10.0.0.6', 'hostname': 'SEP000000000006'},
    ]
    detected = []

    def detect(ip):
        detected.append(ip)
        return {'10.0.0.5': 'cucm-a.test', '10.0.0.6': 'cucm-b.test'}[ip]

    monkeypatch.setattr(thief, 'enumerate_phones_subnet', lambda cidr: hosts)
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', detect)
    monkeypatch.setattr(thief.socket, 'gethostbyname', lambda host: '10.0.0.1')

    def config_names(cucm_host, hostnames=None, use_tftp=True):
        leaves['config_names'].append((cucm_host, hostnames))
        return [f'{hostnames[0]}.cnf.xml'] if hostnames else []

    monkeypatch.setattr(thief, 'get_config_names', config_names)
    monkeypatch.setattr(
        thief, 'search_for_secrets',
        lambda cucm, file, use_tftp=True: ([(cucm, 'pw', file)], []),
    )
    db = str(tmp_path / 'thief.db')
    _argv(monkeypatch, '-e', '10.0.0.0/30', '--db', db)

    with pytest.raises(SystemExit) as exc:
        thief.main()

    assert exc.value.code == 0
    assert detected == ['10.0.0.5', '10.0.0.6']
    assert leaves['config_names'] == [
        ('cucm-a.test', ['SEP000000000005']),
        ('cucm-b.test', ['SEP000000000006']),
    ]
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute('SELECT cucm_host, username FROM credentials ORDER BY cucm_host').fetchall()
    finally:
        conn.close()
    assert rows == [('cucm-a.test', 'cucm-a.test'), ('cucm-b.test', 'cucm-b.test')]


def test_enumsubnet_explicit_host_is_used_for_each_phone(leaves, monkeypatch, tmp_path):
    hosts = [
        {'ip': '10.0.0.5', 'hostname': 'SEP000000000005'},
        {'ip': '10.0.0.6', 'hostname': 'SEP000000000006'},
    ]
    monkeypatch.setattr(thief, 'enumerate_phones_subnet', lambda cidr: hosts)
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone',
                        lambda ip: pytest.fail('explicit -H must bypass detection'))
    monkeypatch.setattr(thief.socket, 'gethostbyname', lambda host: '10.0.0.1')
    _argv(monkeypatch, '-e', '10.0.0.0/30', '-H', 'operator.test',
          '--db', str(tmp_path / 'thief.db'))

    with pytest.raises(SystemExit) as exc:
        thief.main()

    assert exc.value.code == 0
    assert leaves['config_names'] == [
        ('operator.test', ['SEP000000000005']),
        ('operator.test', ['SEP000000000006']),
    ]


@pytest.fixture
def subnet_two_cucms(monkeypatch):
    """Two phones on one subnet, each registered to a different CUCM (#50)."""
    calls = {'detect': [], 'config_names': []}
    phone_cucm = {'10.0.0.5': 'cucm-a.test', '10.0.0.6': 'cucm-b.test'}
    monkeypatch.setattr(thief, 'enumerate_phones_subnet', lambda cidr: [
        {'ip': '10.0.0.5', 'hostname': 'SEP0000000000AA',
         'url': 'http://cucm-a.test:6970/SEP0000000000AA.cnf.xml'},
        {'ip': '10.0.0.6', 'hostname': 'SEP0000000000BB',
         'url': 'http://cucm-b.test:6970/SEP0000000000BB.cnf.xml'},
    ])

    def detect(ip):
        calls['detect'].append(ip)
        return phone_cucm.get(ip)

    def names(cucm_host, hostnames=None, use_tftp=True):
        calls['config_names'].append((cucm_host, hostnames))
        return [f'{hostnames[0]}.cnf.xml']

    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', detect)
    monkeypatch.setattr(thief, 'get_config_names', names)
    monkeypatch.setattr(thief, 'search_for_secrets',
                        lambda h, f, use_tftp=True: ([('admin', f'pw-{h}', f)], []))
    monkeypatch.setattr(thief.socket, 'gethostbyname', lambda h: '10.0.0.1')
    return calls, phone_cucm


def _cred_rows(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            'SELECT cucm_host, device, password FROM credentials ORDER BY device'
        ).fetchall()
    finally:
        conn.close()


def test_enumsubnet_skips_phone_with_undetectable_cucm(subnet_two_cucms, monkeypatch, tmp_path, capsys):
    calls, phone_cucm = subnet_two_cucms
    del phone_cucm['10.0.0.5']  # first phone: CUCM detection fails
    db = str(tmp_path / 'thief.db')
    _argv(monkeypatch, '-e', '10.0.0.0/29', '--db', db)
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert 'Unable to automatically detect the CUCM Server for 10.0.0.5. Skipping...' in out
    assert calls['detect'] == ['10.0.0.5', '10.0.0.6']
    assert [cucm for cucm, _ in calls['config_names']] == ['cucm-b.test']
    assert _cred_rows(db) == [('cucm-b.test', 'SEP0000000000BB', 'pw-cucm-b.test')]


def _capture_config_names(monkeypatch):
    """Patch get_config_names to record the use_tftp each call receives (#59)."""
    seen = []

    def fake(cucm_host, hostnames=None, use_tftp=True):
        seen.append(use_tftp)
        return ['SEP001122334455.cnf.xml']

    monkeypatch.setattr(thief, 'get_config_names', fake)
    return seen


def test_phone_path_passes_http_to_config_names(leaves, monkeypatch, tmp_path):
    seen = _capture_config_names(monkeypatch)
    _argv(monkeypatch, '-p', '10.0.0.5', '-T', '1', '--http', '--db', str(tmp_path / 'thief.db'))
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    assert seen == [False]


def test_phone_path_defaults_to_tftp_for_config_names(leaves, monkeypatch, tmp_path):
    """Regression guard (passes before and after the fix)."""
    seen = _capture_config_names(monkeypatch)
    _argv(monkeypatch, '-p', '10.0.0.5', '-T', '1', '--db', str(tmp_path / 'thief.db'))
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    assert seen == [True]


def test_enumsubnet_passes_http_to_config_names(leaves, monkeypatch, tmp_path):
    seen = _capture_config_names(monkeypatch)
    monkeypatch.setattr(thief, 'enumerate_phones_subnet', lambda cidr: [
        {'ip': '10.0.0.5', 'hostname': 'SEP001122334455',
         'url': 'http://cucm.test:6970/SEP001122334455.cnf.xml'},
    ])
    monkeypatch.setattr(thief.socket, 'gethostbyname', lambda h: '10.0.0.1')
    _argv(monkeypatch, '-e', '10.0.0.0/30', '--http', '--db', str(tmp_path / 'thief.db'))
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    assert seen == [False]
