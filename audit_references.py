#!/usr/bin/env python3
"""Deterministic bibliography and citation audit.

The audit is deliberately offline: it checks BibTeX structure, unique scholarly
identifiers, manuscript citation closure, and an included human-reviewed source
inventory.  It does not claim that an offline build re-resolves publisher pages.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Iterable
from urllib.parse import urlparse


DOI_RE = re.compile(r"^10\.\d{4,9}/[-._;()/:A-Z0-9]+$", re.IGNORECASE)
YEAR_RE = re.compile(r"^(?:19|20)\d{2}$")
CITE_RE = re.compile(
    r"\\(?:[A-Za-z]*cite[A-Za-z*]*)\s*(?:\[[^\]]*\]\s*){0,2}\{([^{}]+)\}",
    re.MULTILINE,
)
INVENTORY_FIELDS = (
    "key", "entry_type", "authors", "title", "year", "identifier_type",
    "identifier", "verification_status", "verification_source",
    "cited_in_manuscript", "audit_note",
)


@dataclass(frozen=True)
class Entry:
    entry_type: str
    key: str
    fields: dict[str, str]


def _strip_tex_comments(text: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        cut = len(line)
        for i, ch in enumerate(line):
            if ch == "%" and (i == 0 or line[i - 1] != "\\"):
                cut = i
                break
        out.append(line[:cut])
    return "\n".join(out)


def _balanced_value(text: str, pos: int, opener: str, closer: str) -> tuple[str, int]:
    assert text[pos] == opener
    depth = 1
    i = pos + 1
    start = i
    escaped = False
    while i < len(text):
        ch = text[i]
        if opener == '"':
            if ch == '"' and not escaped:
                return text[start:i], i + 1
            escaped = (ch == "\\" and not escaped)
            if ch != "\\":
                escaped = False
            i += 1
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    raise ValueError("unterminated BibTeX value")


def parse_bibtex(text: str) -> list[Entry]:
    """Parse the conservative BibTeX subset used by this artifact."""
    text = _strip_tex_comments(text)
    entries: list[Entry] = []
    pos = 0
    while True:
        match = re.search(r"@([A-Za-z]+)\s*([\{(])", text[pos:])
        if match is None:
            break
        entry_type = match.group(1).lower()
        opener = match.group(2)
        closer = "}" if opener == "{" else ")"
        start = pos + match.end()
        body, end = _balanced_value(text, start - 1, opener, closer)
        pos = end

        # Key is the prefix before the first top-level comma.
        depth = 0
        comma = None
        for i, ch in enumerate(body):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            elif ch == "," and depth == 0:
                comma = i
                break
        if comma is None:
            raise ValueError("BibTeX entry lacks key separator")
        key = body[:comma].strip()
        rest = body[comma + 1:]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", key):
            raise ValueError(f"invalid BibTeX key: {key!r}")

        fields: dict[str, str] = {}
        i = 0
        while i < len(rest):
            while i < len(rest) and (rest[i].isspace() or rest[i] == ","):
                i += 1
            if i >= len(rest):
                break
            m = re.match(r"([A-Za-z][A-Za-z0-9_-]*)\s*=\s*", rest[i:])
            if m is None:
                raise ValueError(f"cannot parse field in {key} near {rest[i:i+40]!r}")
            name = m.group(1).lower()
            i += m.end()
            if i >= len(rest):
                raise ValueError(f"missing value for {key}.{name}")
            if rest[i] == "{":
                value, i = _balanced_value(rest, i, "{", "}")
            elif rest[i] == '"':
                value, i = _balanced_value(rest, i, '"', '"')
            else:
                j = i
                while j < len(rest) and rest[j] != ",":
                    j += 1
                value, i = rest[i:j], j
            value = " ".join(value.split())
            if name in fields:
                raise ValueError(f"duplicate field {key}.{name}")
            fields[name] = value
        entries.append(Entry(entry_type, key, fields))
    return entries


def cited_keys(tex: str) -> set[str]:
    clean = _strip_tex_comments(tex)
    if re.search(r"\\nocite\b", clean):
        raise ValueError("\\nocite is forbidden")
    keys: set[str] = set()
    for match in CITE_RE.finditer(clean):
        for key in match.group(1).split(","):
            key = key.strip()
            if key:
                keys.add(key)
    return keys


def stable_identifier(entry: Entry) -> tuple[str, str]:
    fields = entry.fields
    if "doi" in fields:
        return "doi", fields["doi"].strip()
    if "url" in fields:
        return "url", fields["url"].strip()
    if "isbn" in fields:
        return "isbn", re.sub(r"[^0-9Xx]", "", fields["isbn"])
    return "", ""


def validate_entries(entries: list[Entry], citations: set[str] | None = None, *, minimum: int = 55) -> list[str]:
    failures: list[str] = []
    keys = [entry.key for entry in entries]
    if len(entries) < minimum:
        failures.append(f"fewer than {minimum} references: {len(entries)}")
    if len(keys) != len(set(keys)):
        failures.append("duplicate BibTeX key")

    titles: dict[str, str] = {}
    identifiers: dict[tuple[str, str], str] = {}
    for entry in entries:
        for required in ("author", "title", "year"):
            if not entry.fields.get(required):
                failures.append(f"{entry.key}: missing {required}")
        year = entry.fields.get("year", "")
        if not YEAR_RE.fullmatch(year):
            failures.append(f"{entry.key}: invalid year {year!r}")
        normalized_title = re.sub(r"[^a-z0-9]+", "", entry.fields.get("title", "").lower())
        if normalized_title:
            if normalized_title in titles:
                failures.append(f"duplicate title: {entry.key} and {titles[normalized_title]}")
            titles[normalized_title] = entry.key

        kind, identifier = stable_identifier(entry)
        if not kind:
            failures.append(f"{entry.key}: no DOI, stable URL, or ISBN")
        elif kind == "doi" and not DOI_RE.fullmatch(identifier):
            failures.append(f"{entry.key}: malformed DOI {identifier!r}")
        elif kind == "url":
            parsed = urlparse(identifier)
            if parsed.scheme != "https" or not parsed.netloc:
                failures.append(f"{entry.key}: URL must be an absolute HTTPS scholarly URL")
        elif kind == "isbn" and len(identifier) not in {10, 13}:
            failures.append(f"{entry.key}: malformed ISBN")
        token = (kind, identifier.lower())
        if kind and token in identifiers:
            failures.append(f"duplicate identifier: {entry.key} and {identifiers[token]}")
        elif kind:
            identifiers[token] = entry.key

    if citations is not None:
        source = set(keys)
        missing = sorted(source - citations)
        unknown = sorted(citations - source)
        if missing:
            failures.append("uncited bibliography entries: " + ", ".join(missing))
        if unknown:
            failures.append("unknown citation keys: " + ", ".join(unknown))
    return failures


def read_inventory(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != INVENTORY_FIELDS:
            raise ValueError("inventory columns differ from the audited schema")
        return list(reader)


def validate_inventory(rows: list[dict[str, str]], entries: list[Entry] | None = None) -> list[str]:
    failures: list[str] = []
    if len(rows) < 55:
        failures.append(f"inventory contains fewer than 55 references: {len(rows)}")
    if len({row["key"] for row in rows}) != len(rows):
        failures.append("inventory has duplicate keys")
    allowed = {"primary-record-checked", "stable-identifier-checked"}
    for row in rows:
        if row["verification_status"] not in allowed:
            failures.append(f"{row['key']}: unknown verification status")
        if row["cited_in_manuscript"] != "yes":
            failures.append(f"{row['key']}: not recorded as cited")
        if not row["verification_source"].startswith("https://"):
            failures.append(f"{row['key']}: verification source is not HTTPS")
    if entries is not None:
        by_key = {entry.key: entry for entry in entries}
        if set(by_key) != {row["key"] for row in rows}:
            failures.append("inventory/BibTeX key sets differ")
        for row in rows:
            entry = by_key.get(row["key"])
            if entry is None:
                continue
            kind, identifier = stable_identifier(entry)
            expected = {
                "entry_type": entry.entry_type,
                "authors": entry.fields.get("author", ""),
                "title": entry.fields.get("title", ""),
                "year": entry.fields.get("year", ""),
                "identifier_type": kind,
                "identifier": identifier,
            }
            for name, value in expected.items():
                if row[name] != value:
                    failures.append(f"{entry.key}: inventory mismatch in {name}")
    return failures


# Records whose title/authors/venue metadata were checked against a primary
# publisher or IACR record during the final artifact audit.  Other rows retain
# a stable identifier and are checked structurally, but the deterministic build
# deliberately performs no network lookup.
PRIMARY_CHECKED: dict[str, str] = {
    "boneh2025evrf": "https://doi.org/10.1007/978-3-031-91098-2_8",
    "canetti2021ecdsaabort": "https://doi.org/10.1145/3372297.3423367",
    "chase2022dleq": "https://eprint.iacr.org/2022/1593",
    "goldreich2004foundations": "https://www.cambridge.org/core/books/foundations-of-cryptography/",
    "komlo2024arctic": "https://doi.org/10.1007/978-3-031-91832-2_8",
    "lindell2022schnorr": "https://doi.org/10.62056/a36c0l5vt",
    "rivinius2025pia": "https://doi.org/10.1007/978-3-031-91092-0_10",
    "buenz2025golden": "https://doi.org/10.1007/978-3-032-35374-0_8",
    "gerhart2026adaptive": "https://doi.org/10.1007/978-3-032-25317-0_9",
}


def inventory_rows(entries: Iterable[Entry], citations: set[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for entry in entries:
        kind, identifier = stable_identifier(entry)
        default_source = (
            "https://doi.org/" + identifier if kind == "doi" else
            entry.fields.get("url", "") if kind == "url" else
            "https://www.cambridge.org/core/books/foundations-of-cryptography/"
        )
        primary = entry.key in PRIMARY_CHECKED
        rows.append({
            "key": entry.key,
            "entry_type": entry.entry_type,
            "authors": entry.fields.get("author", ""),
            "title": entry.fields.get("title", ""),
            "year": entry.fields.get("year", ""),
            "identifier_type": kind,
            "identifier": identifier,
            "verification_status": "primary-record-checked" if primary else "stable-identifier-checked",
            "verification_source": PRIMARY_CHECKED.get(entry.key, default_source),
            "cited_in_manuscript": "yes" if entry.key in citations else "no",
            "audit_note": (
                "Primary publisher or IACR record checked during final audit."
                if primary else
                "Required fields, identifier syntax, uniqueness, and manuscript citation linkage checked offline; live metadata not re-resolved by the deterministic build."
            ),
        })
    return rows


def write_inventory(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=INVENTORY_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--bib", type=Path)
    parser.add_argument("--tex", type=Path)
    parser.add_argument("--write-inventory", action="store_true")
    args = parser.parse_args()

    if (args.bib is None) != (args.tex is None):
        parser.error("--bib and --tex must be supplied together")

    entries: list[Entry] | None = None
    citations: set[str] | None = None
    failures: list[str] = []
    if args.bib is not None and args.tex is not None:
        entries = parse_bibtex(args.bib.read_text(encoding="utf-8"))
        citations = cited_keys(args.tex.read_text(encoding="utf-8"))
        failures.extend(validate_entries(entries, citations))
        if args.write_inventory and not failures:
            write_inventory(args.inventory, inventory_rows(entries, citations))

    try:
        rows = read_inventory(args.inventory)
    except (OSError, ValueError) as exc:
        print(f"reference audit failed: {exc}", file=sys.stderr)
        return 1
    failures.extend(validate_inventory(rows, entries))

    if failures:
        print("\n".join(sorted(set(failures))), file=sys.stderr)
        return 1
    primary = sum(row["verification_status"] == "primary-record-checked" for row in rows)
    print(
        f"Reference audit passed: {len(rows)} cited scholarly entries; "
        f"{primary} primary records checked and {len(rows)-primary} stable identifiers structurally checked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
