#!/usr/bin/env python3
"""
EASM Pipeline — declarative XLSX workbook writer.

A workbook is declared as a list of Sheet specs, each a list of typed Column
specs over plain row dicts. write_workbook() renders them with a consistent
layout, so every export reads the same way:

  Summary   title, metadata block, optional small tables, index of sheets
  <sheets>  one Excel Table per sheet (banded, filterable, frozen header,
            header comments carrying each column's description)
  Columns   data dictionary generated from the Column specs

Scanned data is untrusted: strings are always written as text (never parsed
as formulas or numbers), and only http(s) values in "url" columns become links.

No DuckDB or Tenable knowledge here — see tenable_xlsx.py for an instance.
"""

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Callable, Iterable

import xlsxwriter

KINDS = ("text", "int", "float", "bool", "list", "date", "url")

MAX_CELL_CHARS = 32767          # Excel cell text limit
MAX_URL_CHARS = 2079            # Excel hyperlink limit
MAX_SHEET_NAME = 31
_SHEET_NAME_BAD = re.compile(r"[\[\]:*?/\\]")

HEADER_FILL = "#1F2A26"
HEADER_FONT = "#E6F2EE"
TABLE_STYLE = "Table Style Light 9"


@dataclass(frozen=True)
class Column:
    header: str
    value: str | Callable[[dict], Any]   # row key or extractor
    kind: str = "text"
    width: int = 16
    note: str = ""                        # header comment + data dictionary
    colors: dict[str, str] | None = None  # cell value → fill colour

    def get(self, row: dict) -> Any:
        return self.value(row) if callable(self.value) else row.get(self.value)


@dataclass(frozen=True)
class Sheet:
    name: str
    columns: list[Column]
    rows: Iterable[dict]
    description: str = ""


def sheet_name(name: str, taken: set[str] | None = None) -> str:
    """Excel-safe, unique (case-insensitive) worksheet name."""
    base = _SHEET_NAME_BAD.sub("-", name).strip("'").strip() or "Sheet"
    base = base[:MAX_SHEET_NAME]
    taken = taken if taken is not None else set()
    out, n = base, 2
    while out.lower() in taken:
        suffix = f" ({n})"
        out = base[:MAX_SHEET_NAME - len(suffix)] + suffix
        n += 1
    taken.add(out.lower())
    return out


def _parse_date(v) -> datetime | None:
    if isinstance(v, datetime):
        return v.replace(tzinfo=None)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day)
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v).strip().replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, (list, tuple, set)):
        return ", ".join(_text(x) for x in v if x not in (None, ""))
    return str(v)[:MAX_CELL_CHARS]


class _Writer:
    def __init__(self, target):
        self.wb = xlsxwriter.Workbook(target, {
            "strings_to_formulas": False,
            "strings_to_numbers": False,
            "strings_to_urls": False,
            "remove_timezone": True,
            "in_memory": True,
        })
        self.taken: set[str] = set()
        self._formats: dict[tuple, Any] = {}

    def fmt(self, **props):
        key = tuple(sorted(props.items()))
        if key not in self._formats:
            self._formats[key] = self.wb.add_format({"valign": "top", **props})
        return self._formats[key]

    def cell(self, ws, r: int, c: int, col: Column, value):
        fill = (col.colors or {}).get(_text(value)) if col.colors else None
        base = {"bg_color": fill} if fill else {}

        if value is None or value == "" or value == []:
            ws.write_blank(r, c, None, self.fmt(**base))
        elif col.kind in ("int", "float") and isinstance(value, (int, float)) and not isinstance(value, bool):
            ws.write_number(r, c, value, self.fmt(num_format="0" if col.kind == "int" else "0.00", **base))
        elif col.kind == "date" and (d := _parse_date(value)):
            ws.write_datetime(r, c, d, self.fmt(num_format="yyyy-mm-dd", **base))
        elif col.kind == "url" and isinstance(value, str) and value.startswith(("http://", "https://")) \
                and len(value) <= MAX_URL_CHARS:
            ws.write_url(r, c, value, self.fmt(font_color="#1F6FB2", underline=1, **base), string=value)
        else:
            ws.write_string(r, c, _text(value), self.fmt(**base))

    def data_sheet(self, sheet: Sheet, name: str, rows: list[dict]):
        ws = self.wb.add_worksheet(name)
        cols = sheet.columns
        header = self.fmt(bold=True, font_color=HEADER_FONT, bg_color=HEADER_FILL, text_wrap=True)

        for c, col in enumerate(cols):
            ws.set_column(c, c, col.width)
        if rows:
            ws.add_table(0, 0, len(rows), len(cols) - 1, {
                "name": "T_" + re.sub(r"\W", "_", name),
                "style": TABLE_STYLE,
                "columns": [{"header": col.header, "header_format": header} for col in cols],
            })
            for r, row in enumerate(rows, start=1):
                for c, col in enumerate(cols):
                    self.cell(ws, r, c, col, col.get(row))
        else:
            for c, col in enumerate(cols):
                ws.write_string(0, c, col.header, header)
            ws.write_string(1, 0, "No rows", self.fmt(italic=True, font_color="#888888"))

        for c, col in enumerate(cols):
            if col.note:
                ws.write_comment(0, c, col.note, {"x_scale": 2, "y_scale": 1.2})
        ws.set_row(0, 30)
        ws.freeze_panes(1, 1)

    def summary(self, ws, title: str, metadata, sections, index):
        bold = self.fmt(bold=True)
        key_fmt = self.fmt(bold=True, font_color="#47564F")
        head = self.fmt(bold=True, font_color=HEADER_FONT, bg_color=HEADER_FILL)
        link = self.fmt(font_color="#1F6FB2", underline=1)
        ws.set_column(0, 0, 30)
        ws.set_column(1, 1, 60)
        ws.set_column(2, 12, 14)

        ws.write_string(0, 0, title, self.fmt(bold=True, font_size=16))
        r = 2
        for key, value in metadata:
            ws.write_string(r, 0, key, key_fmt)
            if isinstance(value, datetime):
                ws.write_datetime(r, 1, value, self.fmt(num_format="yyyy-mm-dd hh:mm", align="left"))
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                ws.write_number(r, 1, value, self.fmt(align="left"))
            else:
                ws.write_string(r, 1, _text(value), self.fmt(text_wrap=True))
            r += 1

        for heading, table in sections:
            r += 1
            ws.write_string(r, 0, heading, self.fmt(bold=True, font_size=12))
            r += 1
            for i, cells in enumerate(table):
                for c, v in enumerate(cells):
                    if i == 0:
                        ws.write_string(r, c, _text(v), head)
                    elif isinstance(v, (int, float)) and not isinstance(v, bool):
                        ws.write_number(r, c, v)
                    else:
                        ws.write_string(r, c, _text(v), self.fmt(text_wrap=True))
                r += 1

        r += 1
        ws.write_string(r, 0, "Sheets", self.fmt(bold=True, font_size=12))
        r += 1
        for c, h in enumerate(("Sheet", "Description", "Rows")):
            ws.write_string(r, c, h, head)
        r += 1
        for name, description, count in index:
            ws.write_url(r, 0, f"internal:'{name}'!A1", link, string=name)
            ws.write_string(r, 1, description, self.fmt(text_wrap=True))
            ws.write_number(r, 2, count, bold)
            r += 1


def _dictionary(sheets: list[tuple[str, Sheet]]) -> Sheet:
    rows = [{"sheet": name, "column": col.header, "kind": col.kind, "note": col.note}
            for name, s in sheets for col in s.columns]
    return Sheet("Columns", [
        Column("Sheet", "sheet", width=26),
        Column("Column", "column", width=26),
        Column("Type", "kind", width=8),
        Column("Description", "note", width=90),
    ], rows, "Data dictionary: what each column means")


def write_workbook(target, sheets: list[Sheet], *, title: str,
                   metadata: list[tuple[str, Any]] = (),
                   sections: list[tuple[str, list[list]]] = ()) -> dict[str, int]:
    """Render sheets to target (path or binary file object such as BytesIO).
    sections: (heading, rows) small tables on Summary — rows[0] is the header.
    Returns {sheet name: row count}."""
    for s in sheets:
        bad = [c.kind for c in s.columns if c.kind not in KINDS]
        if bad:
            raise ValueError(f"{s.name}: unknown column kind {bad[0]!r}")

    w = _Writer(target)
    summary_ws = w.wb.add_worksheet(sheet_name("Summary", w.taken))

    named = [(sheet_name(s.name, w.taken), s) for s in sheets]
    named.append((sheet_name("Columns", w.taken), _dictionary(named)))

    counts = {}
    index = []
    for name, s in named:
        rows = list(s.rows)
        w.data_sheet(s, name, rows)
        counts[name] = len(rows)
        index.append((name, s.description, len(rows)))

    w.summary(summary_ws, title, list(metadata), list(sections), index)
    summary_ws.activate()
    w.wb.close()
    return counts
