#!/usr/env python3
from thief import parse_cucm, parse_subnet, parse_filename

def test_8861_cucm():
    with open('tests/cisco-CP-8861.html') as html_file:
        assert parse_cucm(html_file.read()) == 'test-cucm-pub.example.com'

def test_6921_cucm():
    with open('tests/cisco_CP-6921.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm1.example.com'

def test_8945_cucm():
    with open('tests/cisco-CP-8945.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm-sub1.example.com'

def test_7945G_cucm():
    with open('tests/cisco_CP-7945G.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm1.example.com'

def test_8851_cucm():
    with open('tests/cisco_CP-8851.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm1.example.com'

def test_DX80_cucm():
    with open('tests/cisco_CP-DX80.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm3.example.com'

def test_7841_cucm():
    with open('tests/cisco-CP-7841.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm2.example.com'
def test_7832_cucm():
    with open('tests/cisco-CP-7832.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm02.example.com'
def test_8811_cucm():
    with open('tests/cisco-CP-8811.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm02.example.com'

def test_6921_subnet():
    with open('tests/cisco_CP-6921.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'

def test_8945_subnet():
    with open('tests/cisco-CP-8945.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'

def test_7945G_subnet():
    with open('tests/cisco_CP-7945G.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'

def test_7841_subnet():
    with open('tests/cisco-CP-7841.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'

def test_8851_subnet():
    with open('tests/cisco_CP-8851.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'

def test_DX80_subnet():
    with open('tests/cisco_CP-DX80.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'

def test_7832_subnet():
    with open('tests/cisco-CP-7832.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.254.0'
def test_8811_subnet():
    with open('tests/cisco-CP-8811.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.254.0'

def test_ipcommunicator_filename():
    with open('tests/cisco-IPC.html') as html_file:
        assert parse_filename(html_file.read()) == 'CIPCTJARKEWICZ.cnf.xml'

def test_8841_cucm():
    with open('tests/cisco-CP-8841.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm02.example.com'

def test_8841_subnet():
    with open('tests/cisco-CP-8841.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.254.0'

def test_8845_cucm():
    with open('tests/cisco-CP-8845.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm02.example.com'

def test_8845_subnet():
    with open('tests/cisco-CP-8845.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.254.0'

def test_8865_cucm():
    with open('tests/cisco-CP-8865.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm02.example.com'

def test_8865_subnet():
    with open('tests/cisco-CP-8865.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.254.0'

def test_8861_subnet():
    with open('tests/cisco-CP-8861.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.0.0'

