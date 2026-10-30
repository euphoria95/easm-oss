#!/usr/bin/env python3
"""
Tests for the declarative XLSX writer (xlsx_workbook.py).

Workbooks are inspected as the zip of XML parts they are, so no reader
library (openpyxl) is needed.

Run: python3 scripts/test_xlsx_workbook.py
Exit 0 = all tests passed.
"""

import html
import io
import re
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    import xlsxwriter  # noqa: F401
except ImportError:
    xlsxwriter = None

if xlsxwriter:
    from xlsx_workbook import Column, Sheet, sheet_name, write_workbook  # noqa: E402


def _parts(buf: io.BytesIO) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as z:
        return {n: z.read(n).decode() for n in z.namelist() if n.endswith(".xml")}


def _sheet_names(parts) -> list[str]:
    return re.findall(r'<sheet name="([^"]+)"', parts["xl/workbook.xml"])


def _shared(parts) -> list[str]:
    return [html.unescape(re.sub(r"<[^>]+>", "", si)) for si in
            re.findall(r"<si>(.*?)</si>", parts.get("xl/sharedStrings.xml", ""), re.S)]


@unittest.skipUnless(xlsxwriter, "XlsxWriter not installed")
class WorkbookLayout(unittest.TestCase):
    COLS = [
        Column("Host", "host", note="hostname"),
        Column("Ports", "ports", "list"),
        Column("Owned", "owned", "bool"),
        Column("Count", "n", "int"),
        Column("Expiry", "exp", "date"),
        Column("URL", "url", "url"),
        Column("Decision", "d", colors={"include": "#C9F2E6"}),
        Column("Upper", lambda r: r["host"].upper()),
    ]
    ROWS = [
        {"host": "a.example.com", "ports": [443, 8443], "owned": True, "n": 3,
         "exp": "2027-01-02T00:00:00Z", "url": "https://a.example.com", "d": "include"},
        {"host": "b.example.com", "ports": [], "owned": False, "n": None,
         "exp": "not a date", "url": "javascript:alert(1)", "d": "exclude"},
    ]

    def _write(self, sheets, **kw):
        buf = io.BytesIO()
        counts = write_workbook(buf, sheets, title="T", **kw)
        return counts, _parts(buf)

    def test_sheet_order_and_counts(self):
        counts, parts = self._write([Sheet("Data", self.COLS, self.ROWS, "rows"),
                                     Sheet("Empty", self.COLS[:2], [])],
                                    metadata=[("Scan ID", "s1"), ("Total", 2)])
        self.assertEqual(_sheet_names(parts), ["Summary", "Data", "Empty", "Columns"])
        self.assertEqual(counts, {"Data": 2, "Empty": 0, "Columns": len(self.COLS) + 2})
        strings = _shared(parts)
        for s in ("Scan ID", "s1", "Data", "rows", "No rows", "hostname"):
            self.assertIn(s, strings)

    def test_value_rendering(self):
        _, parts = self._write([Sheet("Data", self.COLS, self.ROWS)])
        strings = _shared(parts)
        self.assertIn("443, 8443", strings)                 # list joined
        self.assertIn("Yes", strings)                       # bool
        self.assertIn("No", strings)
        self.assertIn("A.EXAMPLE.COM", strings)             # callable extractor
        self.assertIn("not a date", strings)                # unparseable date kept as text
        self.assertIn("javascript:alert(1)", strings)       # non-http URL stays text
        rels = "".join(v for k, v in parts.items() if "worksheets/_rels" in k)
        self.assertNotIn("javascript:", rels)
        sheet = parts["xl/worksheets/sheet2.xml"]
        self.assertIn("<v>3</v>", sheet)                    # int written as number
        self.assertIn("<v>46389</v>", sheet)                # 2027-01-02 as an Excel serial date
        self.assertIn("<tableParts", sheet)                 # Excel table → filters

    def test_untrusted_strings_never_become_formulas(self):
        evil = "=cmd|' /C calc'!A0"
        cols = [Column("Title", "t"), Column("Host", "h")]
        _, parts = self._write([Sheet("Data", cols, [{"t": evil, "h": "+1+1"}, {"t": "@SUM(1)", "h": "-2"}])],
                               metadata=[("Note", "=HYPERLINK(\"http://x\")")])
        for name, xml in parts.items():
            self.assertNotIn("<f>", xml, name)
        strings = _shared(parts)
        for s in (evil, "+1+1", "@SUM(1)", "-2"):
            self.assertIn(s, strings)

    def test_sheet_name_sanitizing(self):
        taken = set()
        self.assertEqual(sheet_name("A/B:C*?[x]", taken), "A-B-C---x-")
        long = sheet_name("Tenable WAS Candidates — extended list", taken)
        self.assertEqual(len(long), 31)
        self.assertEqual(sheet_name("summary", {"summary"}), "summary (2)")
        _, parts = self._write([Sheet("Columns", self.COLS[:1], []), Sheet("x" * 40, self.COLS[:1], [])])
        names = _sheet_names(parts)
        self.assertEqual(len(names), len({n.lower() for n in names}))
        self.assertTrue(all(len(n) <= 31 for n in names))

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            write_workbook(io.BytesIO(), [Sheet("S", [Column("A", "a", "money")], [])], title="T")

    def test_path_target(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "w.xlsx"
            write_workbook(str(path), [Sheet("S", self.COLS, self.ROWS)], title="T")
            self.assertTrue(zipfile.is_zipfile(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
