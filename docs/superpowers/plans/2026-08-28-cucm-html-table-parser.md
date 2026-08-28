# CUCM Status-Page HTML Table Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `parse_cucm`'s whole-document regex matching with a real HTML table parser (a Python port of the technique used by [bc0la/cucmber](https://github.com/bc0la/cucmber)), so CUCM hostname extraction generalizes across phone firmware layout variance (tag case, whitespace, HTML-entity encoding) instead of growing an ever-larger regex alternation.

**Architecture:** Add a small `HTMLParser` subclass (`_StatusTableParser`) that walks a Cisco phone status page's `<tr>`/`<td>` markup and emits ordered `(label, value)` pairs — this is the structural equivalent of cucmber's Go DOM walk. `parse_cucm` is rewritten to consume those pairs: it categorizes rows by label (CallManager/Unified-CM/CUCM-server family, then TFTP-server fallback) and extracts the leading hostname/IP token from the value, preferring rows whose value is marked `Active`. Because `HTMLParser` decodes HTML entities and normalizes tag case as part of parsing, the `html.unescape()` special-case added for CP-7811/CP-8851 becomes unnecessary and is removed. No new dependencies — `html.parser.HTMLParser` is Python stdlib. `parse_subnet`, `parse_filename`, and `detect_phone_model` are unaffected and stay regex-based (they aren't hitting the layout-variance bug class this plan addresses).

**Tech Stack:** Python 3.13, stdlib `html.parser.HTMLParser`, pytest, `uv run pytest`.

## Global Constraints

- Single-module layout: all runtime logic stays in `src/seeyoucm_thief/thief.py` (per project CLAUDE.md) — do not split into new files.
- Every existing `tests/test_parser.py` assertion must keep passing unchanged (same fixture files, same expected output strings) — this is a technique swap, not a behavior change for any currently-covered model.
- No new third-party dependencies. `html.parser` is stdlib.
- Work happens in a dedicated git worktree per user's global git-worktree policy; branch from `dev` (this repo's integration branch, confirmed via `git branch -r`); do not touch `main` directly.
- Follow this repo's existing warning convention: user-facing warnings are `print(f'[!] ...')` (see `warn_if_unknown_phone_model`).

---

## File Structure

Only one file changes:

- **Modify `src/seeyoucm_thief/thief.py`**:
  - Remove `import html` (line 5) — no longer used once `parse_cucm` stops calling `html.unescape()`.
  - Add `from html.parser import HTMLParser` near the top import block.
  - Add `_StatusTableParser` (new `HTMLParser` subclass) and `parse_status_table(page)` (thin wrapper function) directly above `parse_cucm` (currently starts at line 155).
  - Replace the body of `parse_cucm` (lines 155–178) to consume `parse_status_table()` output instead of regexing the raw page.
  - `detect_phone_model`, `warn_if_unknown_phone_model`, `parse_subnet`, `parse_filename` are untouched.
- **Modify `tests/test_parser.py`**: add unit tests for `parse_status_table` (Task 1) and a regression test proving the new implementation is *more* correct than the old one on a case the raw-regex approach could get wrong (Task 2, Step 3).

## Task 1: `parse_status_table` — generic HTML table-row extractor

**Files:**
- Modify: `src/seeyoucm_thief/thief.py:3-5` (imports), and insert new code above `src/seeyoucm_thief/thief.py:155` (current `def parse_cucm`)
- Test: `tests/test_parser.py`

**Interfaces:**
- Produces: `parse_status_table(page: str | None) -> list[tuple[str, str]]` — returns ordered `(label, value)` pairs for every `<tr>` that contains at least two non-empty `<td>`/`<th>` cells (extra cells beyond the first two, e.g. spacer `<td width=20></td>` cells that are empty, or a third cell, are ignored — only `cells[0]` and `cells[1]` are kept). Returns `[]` for falsy/empty input. Entity references in cell text (e.g. `&#x2D;`, `&amp;`) are already decoded in the returned strings.
- Task 2 consumes this function's return value directly.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_parser.py` (after the existing imports, before the first test function):

```python
from thief import parse_status_table

def test_status_table_basic_row():
    page = '<table><tr><td><b>Host Name</b></td><td width=20></td><td><b>SEP001122334455</b></td></tr></table>'
    assert parse_status_table(page) == [('Host Name', 'SEP001122334455')]

def test_status_table_skips_single_cell_rows():
    # Nav-menu rows (e.g. "Device Information" links) have only one cell
    # and must not be returned as label/value pairs.
    page = '<table><tr><td><b><a href="/DeviceInformation">Device Information</a></b></td></tr></table>'
    assert parse_status_table(page) == []

def test_status_table_decodes_html_entities():
    page = ('<TD><B> Unified CM1</B></TD><td width=20></TD>'
            '<TD><B>cucm&#x2D;sub1&#x2D;ucce.example.com   </B></TD>')
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /path/to/worktree && uv run pytest tests/test_parser.py -k status_table -v`
Expected: FAIL with `ImportError: cannot import name 'parse_status_table' from 'thief'` (or `ModuleNotFoundError`) — the function doesn't exist yet.

- [ ] **Step 3: Implement `_StatusTableParser` and `parse_status_table`**

In `src/seeyoucm_thief/thief.py`, change the import block (lines 3-5):

```python
import argparse
import requests
import re
from html.parser import HTMLParser
import ipaddress
```

(This replaces `import re` / `import html` / `import ipaddress` — i.e. delete the `import html` line and add the `from html.parser import HTMLParser` line in its place, keeping `import re` and `import ipaddress` as they are.)

Then, directly above `def parse_cucm(page):` (currently line 155), insert:

```python
class _StatusTableParser(HTMLParser):
    """Walks a Cisco phone status page's <tr>/<td> markup into ordered
    (label, value) pairs. Using a real parser instead of regex-on-raw-markup
    means tag case, extra whitespace, and HTML-entity-encoded punctuation
    (e.g. '-' as '&#x2D;') are handled for free instead of needing bespoke
    regex fixes per firmware quirk."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self._row_stack = []
        self._cell_stack = []

    def handle_starttag(self, tag, attrs):
        if tag == 'tr':
            self._row_stack.append([])
        elif tag in ('td', 'th'):
            self._cell_stack.append([])

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self._cell_stack:
            text = ''.join(self._cell_stack.pop()).strip()
            if text and self._row_stack:
                self._row_stack[-1].append(text)
        elif tag == 'tr' and self._row_stack:
            cells = self._row_stack.pop()
            if len(cells) >= 2:
                self.rows.append((cells[0], cells[1]))

    def handle_data(self, data):
        if self._cell_stack:
            self._cell_stack[-1].append(data)


def parse_status_table(page):
    """Parse a Cisco phone status page into ordered (label, value) pairs
    from its <tr>/<td> rows. Rows with fewer than two non-empty cells
    (e.g. single-cell nav-menu links) are dropped."""
    if not page:
        return []
    parser = _StatusTableParser()
    parser.feed(page)
    return parser.rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_parser.py -k status_table -v`
Expected: all 6 new tests PASS.

- [ ] **Step 5: Run the full suite to confirm no regressions**

Run: `uv run pytest -q`
Expected: same pass count as before this task (this task is additive — `parse_cucm` hasn't been touched yet) — all prior tests still pass.

- [ ] **Step 6: Commit**

```bash
git add src/seeyoucm_thief/thief.py tests/test_parser.py
git commit -m "feat: add HTML table-row parser for phone status pages"
```

---

## Task 2: Port `parse_cucm` to consume `parse_status_table`

**Files:**
- Modify: `src/seeyoucm_thief/thief.py:155-178` (current `def parse_cucm` body, per Task 1's line numbers before edits — re-locate by function name, not line number, since Task 1 shifted lines)
- Test: `tests/test_parser.py`

**Interfaces:**
- Consumes: `parse_status_table(page) -> list[tuple[str, str]]` from Task 1.
- Produces: `parse_cucm(page: str | None) -> str | None` — same public signature and contract as before. No caller changes needed (`get_cucm_name_from_phone`, `enumerate_phones_subnet` already call `parse_cucm(...)` and don't need modification).

- [ ] **Step 1: Write the new regression test first (this is the case old regex-on-raw-markup could get wrong)**

Add to `tests/test_parser.py`:

```python
def test_cucm_ignores_unrelated_active_marker_before_cm_row():
    # A field unrelated to CUCM that also happens to end in "... Active"
    # earlier in the document must not be picked over the real CM row.
    # The old whole-document regex `([A-Za-z0-9._-]+)\s+Active` had no
    # label awareness and would have matched whichever "Active" came
    # first in the raw markup, regardless of which field it belonged to.
    page = (
        '<table>'
        '<tr><td><b>Some Other Field</b></td><td width=20></td>'
        '<td><b>unrelated-value Active</b></td></tr>'
        '<tr><td><b>Unified CM1</b></td><td width=20></td>'
        '<td><b>cucm02.example.com  Active</b></td></tr>'
        '</table>'
    )
    assert parse_cucm(page) == 'cucm02.example.com'
```

- [ ] **Step 2: Run it to verify it fails against the current (pre-port) implementation**

Run: `uv run pytest tests/test_parser.py::test_cucm_ignores_unrelated_active_marker_before_cm_row -v`
Expected: FAIL — `assert 'unrelated-value' == 'cucm02.example.com'` (the old global regex matches the first "word Active" in the document, which is the unrelated field).

- [ ] **Step 3: Replace `parse_cucm`'s implementation**

Find `def parse_cucm(page):` in `src/seeyoucm_thief/thief.py` and replace its entire body with:

```python
_CM_LABEL_RE = re.compile(r'unified\s*cm|cucm|call\s*manager', re.IGNORECASE)
_TFTP_LABEL_RE = re.compile(r'tftp\s*server', re.IGNORECASE)
_LEADING_HOST_RE = re.compile(r'^([A-Za-z0-9._-]+)')
_ACTIVE_VALUE_RE = re.compile(r'^([A-Za-z0-9._-]+)\s+Active\b', re.IGNORECASE)


def parse_cucm(page):
    rows = parse_status_table(page)
    if not rows:
        return None

    cm_rows = [(label, value) for label, value in rows
               if value and _CM_LABEL_RE.search(label)]

    # Prefer whichever CM row is explicitly marked as the active node.
    for _, value in cm_rows:
        match = _ACTIVE_VALUE_RE.match(value)
        if match:
            return match.group(1)

    # No "Active" marker present (older/alternate layouts) — take the
    # first CM row in document order, matching the field ordering phones
    # use to list their primary CallManager first.
    for _, value in cm_rows:
        match = _LEADING_HOST_RE.match(value)
        if match:
            return match.group(1)

    # Fall back to the TFTP server field, which is usually the same host.
    tftp_rows = [(label, value) for label, value in rows
                 if value and _TFTP_LABEL_RE.search(label)]
    for _, value in tftp_rows:
        match = _LEADING_HOST_RE.match(value)
        if match:
            return match.group(1)

    return None
```

Place the four `_CM_LABEL_RE` / `_TFTP_LABEL_RE` / `_LEADING_HOST_RE` / `_ACTIVE_VALUE_RE` module-level regex constants directly above the new `parse_cucm` definition (compiled once at import time, not per call).

- [ ] **Step 4: Run the new regression test to verify it now passes**

Run: `uv run pytest tests/test_parser.py::test_cucm_ignores_unrelated_active_marker_before_cm_row -v`
Expected: PASS.

- [ ] **Step 5: Run every existing `parse_cucm`-related test to confirm zero behavior change**

Run: `uv run pytest tests/test_parser.py -k cucm -v`
Expected: all of the following PASS with unchanged expected values (this is the full list of pre-existing `parse_cucm` assertions — verify every one individually in the output, don't just check the summary count):
- `test_6921_cucm` → `'cucm1.example.com'`
- `test_8945_cucm` → `'cucm-sub1.example.com'`
- `test_7945G_cucm` → `'cucm1.example.com'`
- `test_8851_cucm` → `'cucm1.example.com'`
- `test_DX80_cucm` → `'cucm3.example.com'`
- `test_7841_cucm` → `'cucm2.example.com'`
- `test_7832_cucm` → `'cucm02.example.com'`
- `test_8811_cucm` → `'cucm02.example.com'`
- `test_8841_cucm` → `'cucm02.example.com'`
- `test_8845_cucm` → `'cucm02.example.com'`
- `test_8865_cucm` → `'cucm02.example.com'`
- `test_7811_cucm` → `'cucm02.example.com'`
- `test_7940G_cucm` → `'CUCM01.example.com'`
- `test_7811_html_entities_cucm` → `'cucm-sub1-ucce.example.com'`
- `test_8851_html_entities_cucm` → `'hf-ucm-sub1.example.com'`
- `test_cucm_ignores_unrelated_active_marker_before_cm_row` → `'cucm02.example.com'`

If any of these fail, do not adjust the expected value in the test — the fixture files encode real observed phone output. Instead, re-examine the failing fixture's actual HTML (`tests/cisco-CP-<model>*.html`) and adjust the `parse_cucm` label/value selection logic (Step 3) until it matches. This is the acceptance bar for the whole task.

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -q`
Expected: same total pass count as Task 1's Step 5, plus the one new regression test (net +1 passed), 0 failed.

- [ ] **Step 7: Commit**

```bash
git add src/seeyoucm_thief/thief.py tests/test_parser.py
git commit -m "refactor: port parse_cucm to the HTML table parser, drop html.unescape special-case"
```

---

## Task 3: Verify no dead imports/usages remain, update CLAUDE.md

**Files:**
- Modify: `src/seeyoucm_thief/thief.py` (verification only, no further code changes expected)
- Modify: `CLAUDE.md`

**Interfaces:** None — this task is verification and documentation only.

- [ ] **Step 1: Confirm `html` (the stdlib `html` module, as opposed to `html.parser.HTMLParser`) is no longer imported or referenced anywhere**

Run: `grep -n '\bhtml\.unescape\|^import html$' src/seeyoucm_thief/thief.py`
Expected: no output. (Local parameter names literally called `html`, e.g. `def parse_subnet(html):`, are fine and expected — they're unrelated local shadowing, not the removed import.)

- [ ] **Step 2: Confirm no other code path still expects `parse_cucm` to accept already-unescaped input or otherwise depends on the old regex internals**

Run: `grep -n 'parse_cucm(' src/seeyoucm_thief/thief.py`
Expected: exactly two call sites — inside `enumerate_phones_subnet` and `get_cucm_name_from_phone` — both simply passing `http_response.text` / `resp.text` straight through, unchanged from before this plan.

- [ ] **Step 3: Add a short architecture note to CLAUDE.md**

In `CLAUDE.md`, under the `### Credential parsing` section (or add a new `### Phone status-page parsing` section directly above it), add:

```markdown
### Phone status-page parsing
`parse_cucm` (in `thief.py`) extracts the CUCM/CallManager hostname from a phone's status page by parsing its `<tr>/<td>` markup with a stdlib `HTMLParser` subclass (`_StatusTableParser`) into ordered `(label, value)` pairs, then matching on the label (`Unified CM`, `CUCM Server`, `CallManager`, falling back to `TFTP Server`). This replaced a whole-document regex approach that broke on HTML-entity-encoded punctuation (e.g. `-` as `&#x2D;`) and was sensitive to tag case; a real parser handles both for free. When a genuinely new label wording shows up (via `cisco-phone-query.sh` captures — see `KNOWN_PHONE_MODELS`), extend the `_CM_LABEL_RE` / `_TFTP_LABEL_RE` patterns rather than adding new raw-markup regexes.
```

- [ ] **Step 4: Run the full suite one final time**

Run: `uv run pytest -q`
Expected: all tests pass, 0 failed.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document the HTML table-parser approach for phone status pages"
```

---

## Self-Review Notes

- **Spec coverage**: Task 1 builds the generic extractor (with unit tests independent of real fixtures, including the nested-table edge case actually present in `tests/cisco-CP-7940G.html`'s nav-menu layout). Task 2 ports `parse_cucm` and proves parity against all 15 existing fixture-backed assertions plus a new test showing the port is strictly more correct (label-scoped "Active" matching vs. the old label-blind global match). Task 3 cleans up the now-dead `html` import and documents the change. `detect_phone_model`/`parse_subnet`/`parse_filename` are explicitly out of scope (documented in Architecture) since they aren't affected by the bug class this plan fixes.
- **No placeholders**: every step has literal code/commands; the "if any of these fail" guidance in Task 2 Step 5 tells the implementer exactly what NOT to do (don't change expected test values) rather than vaguely saying "fix it."
- **Type/name consistency**: `parse_status_table` name and signature are identical between Task 1 (produces) and Task 2 (consumes). `parse_cucm`'s signature (`str | None -> str | None`) is unchanged from the pre-plan version, so no caller elsewhere in `thief.py` needs updating.
