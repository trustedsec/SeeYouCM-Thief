#!/usr/env python3
from thief import parse_cucm, parse_subnet, parse_filename, detect_phone_model, warn_if_unknown_phone_model, KNOWN_PHONE_MODELS, parse_status_table

def test_status_table_basic_row():
    page = '<table><tr><td><b>Host Name</b></td><td width=20></td><td><b>SEP001122334455</b></td></tr></table>'
    assert parse_status_table(page) == [('Host Name', 'SEP001122334455')]

def test_status_table_skips_single_cell_rows():
    # Nav-menu rows (e.g. "Device Information" links) have only one cell
    # and must not be returned as label/value pairs.
    page = '<table><tr><td><b><a href="/DeviceInformation">Device Information</a></b></td></tr></table>'
    assert parse_status_table(page) == []

def test_status_table_decodes_html_entities():
    page = ('<tr><TD><B> Unified CM1</B></TD><td width=20></TD>'
            '<TD><B>cucm&#x2D;sub1&#x2D;ucce.example.com   </B></TD></tr>')
    assert parse_status_table(page) == [('Unified CM1', 'cucm-sub1-ucce.example.com')]

def test_status_table_tolerates_uppercase_tags_and_multiline():
    page = '''<TR><TD><B>CallManager 1</B></TD>
<td width=20></TD>
<TD><B>CUCM01.example.com  Active</B></TD>
</TR>'''
    assert parse_status_table(page) == [('CallManager 1', 'CUCM01.example.com  Active')]

def test_status_table_handles_nested_layout_tables():
    # Real phone pages nest a full navigation-menu <table> inside the
    # first <td> of the outer layout row; the label/value table lives in
    # a second nested table inside the outer row's second <td>. The
    # single-cell nav rows must not corrupt extraction of the real rows.
    page = '''
    <TABLE><TR>
      <TD>
        <TABLE><TR><TD><B><a href="/DeviceInformation">Device Information</a></B></TD></TR></TABLE>
      </TD>
      <TD>
        <TABLE><TR><TD><B>Host Name</B></TD><td width=20></TD><TD><B>SEP001122334455</B></TD></TR></TABLE>
      </TD>
    </TR></TABLE>
    '''
    assert parse_status_table(page) == [('Host Name', 'SEP001122334455')]

def test_status_table_empty_input():
    assert parse_status_table(None) == []
    assert parse_status_table('') == []

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


def test_7811_cucm():
    with open('tests/cisco-CP-7811.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm02.example.com'

def test_7811_subnet():
    with open('tests/cisco-CP-7811.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'
def test_7940G_cucm():
    with open('tests/cisco-CP-7940G.html') as html_file:
        assert parse_cucm(html_file.read()) == 'CUCM01.example.com'

def test_7940G_subnet():
    with open('tests/cisco-CP-7940G.html') as html_file:
        assert parse_subnet(html_file.read()) == '255.255.255.0'

def test_7811_html_entities_cucm():
    # Some firmwares HTML-entity-encode punctuation (e.g. '-' as '&#x2D;')
    # in the status page; the CUCM hostname must not be truncated at the
    # entity boundary.
    with open('tests/cisco-CP-7811-html-entities.html') as html_file:
        assert parse_cucm(html_file.read()) == 'cucm-sub1-ucce.example.com'

def test_8851_html_entities_cucm():
    with open('tests/cisco-CP-8851-html-entities.html') as html_file:
        assert parse_cucm(html_file.read()) == 'hf-ucm-sub1.example.com'

def test_detect_phone_model_known():
    with open('tests/cisco-CP-7811-html-entities.html') as html_file:
        assert detect_phone_model(html_file.read()) == 'CP-7811'

def test_detect_phone_model_none():
    assert detect_phone_model('<html>no model here</html>') is None

def test_warn_if_unknown_phone_model_known_is_silent(capsys):
    with open('tests/cisco-CP-7811-html-entities.html') as html_file:
        model = warn_if_unknown_phone_model(html_file.read())
    assert model == 'CP-7811'
    assert capsys.readouterr().out == ''

def test_warn_if_unknown_phone_model_unverified_model_flags(capsys):
    # CP-8831 is a real model seen in the field with no test fixture /
    # verified page layout backing parse_cucm yet.
    page = '<html>Cisco IP Phone CP-8831 ( SEP001122334455 )</html>'
    model = warn_if_unknown_phone_model(page)
    assert model == 'CP-8831'
    out = capsys.readouterr().out
    assert 'Unknown phone model CP-8831' in out
    assert 'cisco-phone-query.sh' in out

def test_known_phone_models_matches_fixtures():
    assert 'CP-8831' not in KNOWN_PHONE_MODELS
    assert 'CP-7811' in KNOWN_PHONE_MODELS

