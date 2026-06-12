from seeyoucm_thief import thief


def test_print_directory_table_renders_rows(capsys):
    records = [
        {'username': 'jdoe', 'phone_number': '1001', 'display_name': 'John Doe'},
        {'username': 'asmith', 'phone_number': '1002', 'first_name': 'Ann',
         'last_name': 'Smith', 'display_name': ''},
    ]
    thief.print_directory_table(records)
    out = capsys.readouterr().out
    # header columns present
    assert 'Username' in out
    assert 'Extension' in out
    # row data present
    assert 'jdoe' in out and '1001' in out and 'John Doe' in out
    # falls back to first+last when display_name is empty
    assert 'asmith' in out and '1002' in out and 'Ann Smith' in out


def test_print_directory_table_empty_is_safe(capsys):
    thief.print_directory_table([])
    out = capsys.readouterr().out
    # header still prints; no crash
    assert 'Username' in out
