#!/usr/env python3
from thief import parse_cucm, parse_subnet, parse_filename


def _read(fixtures_dir, name):
    return (fixtures_dir / name).read_text()


def test_6921_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-6921.html')) == 'cucm1.example.com'

def test_8945_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-8945.html')) == 'cucm-sub1.example.com'

def test_7945G_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-7945G.html')) == 'cucm1.example.com'

def test_8851_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-8851.html')) == 'cucm1.example.com'

def test_DX80_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-DX80.html')) == 'cucm3.example.com'

def test_7841_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-7841.html')) == 'cucm2.example.com'

def test_7832_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-7832.html')) == 'cucm02.example.com'

def test_8811_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-8811.html')) == 'cucm02.example.com'

def test_6921_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-6921.html')) == '255.255.255.0'

def test_8945_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-8945.html')) == '255.255.255.0'

def test_7945G_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-7945G.html')) == '255.255.255.0'

def test_7841_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-7841.html')) == '255.255.255.0'

def test_8851_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-8851.html')) == '255.255.255.0'

def test_DX80_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-DX80.html')) == '255.255.255.0'

def test_7832_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-7832.html')) == '255.255.254.0'

def test_8811_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-8811.html')) == '255.255.254.0'

def test_ipcommunicator_filename(fixtures_dir):
    assert parse_filename(_read(fixtures_dir, 'cisco-IPC.html')) == 'CIPCTJARKEWICZ.cnf.xml'

def test_8841_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-8841.html')) == 'cucm02.example.com'

def test_8841_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-8841.html')) == '255.255.254.0'

def test_8845_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-8845.html')) == 'cucm02.example.com'

def test_8845_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-8845.html')) == '255.255.254.0'

def test_8865_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-8865.html')) == 'cucm02.example.com'

def test_8865_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-8865.html')) == '255.255.254.0'

def test_7811_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-7811.html')) == 'cucm02.example.com'

def test_7811_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-7811.html')) == '255.255.255.0'

def test_7940G_cucm(fixtures_dir):
    assert parse_cucm(_read(fixtures_dir, 'cisco-CP-7940G.html')) == 'CUCM01.example.com'

def test_7940G_subnet(fixtures_dir):
    assert parse_subnet(_read(fixtures_dir, 'cisco-CP-7940G.html')) == '255.255.255.0'
