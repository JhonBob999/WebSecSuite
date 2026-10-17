"""Strict, offline hostname normalization and local target imports."""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import idna


@dataclass
class TargetRecord:
    hostname: str
    source: str
    selected: bool = False
    validation_state: str = "Valid"
    scope_status: str = "Unreviewed"


@dataclass(frozen=True)
class ImportIssue:
    row: int
    value: str
    reason: str


@dataclass
class ImportReport:
    targets: list[TargetRecord] = field(default_factory=list)
    issues: list[ImportIssue] = field(default_factory=list)
    duplicates: int = 0


def _one_line(value: str) -> str:
    return " ".join(value.split())


def normalize_hostname(value: str) -> str:
    """Return a canonical ASCII hostname, without resolving or fetching it."""
    if not isinstance(value, str):
        raise ValueError("Hostname must be text.")
    hostname = value.strip()
    if not hostname:
        raise ValueError("Hostname is empty.")
    if re.search(r"[/\\:@?#*]", hostname):
        raise ValueError("Enter a hostname without a URL, port, credentials, path, or wildcard.")

    try:
        for character in hostname:
            # IDNA validates contextual joiners against their surrounding script.
            if character not in ("\u200c", "\u200d") and (
                unicodedata.category(character)[0] in "CZ" or character.isspace()
            ):
                raise ValueError("Hostname contains a control, invisible, or whitespace character.")
            mapped = idna.uts46_remap(character, std3_rules=True, transitional=False)
            if not mapped or (character != "." and "." in mapped):
                raise ValueError("Hostname contains an invisible character or non-ASCII dot separator.")

        if hostname.endswith("."):
            hostname = hostname[:-1]
        if len(hostname.split(".")) < 2:
            raise ValueError("Hostname must contain at least two labels.")

        canonical = idna.encode(
            hostname, uts46=True, std3_rules=True, transitional=False
        ).decode("ascii").lower()
        if len(canonical) > 253:
            raise ValueError("Hostname exceeds 253 characters.")
        labels = canonical.split(".")
        if any(not label or len(label) > 63 for label in labels):
            raise ValueError("Hostname labels must contain between 1 and 63 characters.")
        if idna.decode(labels[-1]).isnumeric():
            raise ValueError("Hostname must not have a numeric-only top-level label.")
    except idna.IDNAError as error:
        raise ValueError("Invalid hostname: " + _one_line(str(error))) from None

    try:
        ipaddress.ip_address(canonical)
    except ValueError:
        return canonical
    raise ValueError("IP addresses are not accepted; enter a hostname.")


def _add_target(
    report: ImportReport, seen: set[str], value: str, row: int, source: str
) -> None:
    try:
        hostname = normalize_hostname(value)
    except ValueError as error:
        report.issues.append(ImportIssue(row, value, _one_line(str(error))))
        return
    if hostname in seen:
        report.duplicates += 1
        return
    seen.add(hostname)
    report.targets.append(TargetRecord(hostname=hostname, source=source))


def _physical_lines(text: str) -> list[str]:
    """Split CR/LF rows without treating Unicode separators as valid newlines."""
    lines = re.split(r"\r\n|\r|\n", text)
    if lines and lines[-1] == "" and text.endswith(("\r", "\n")):
        lines.pop()
    return lines


def parse_text(text: str, source: str = "paste") -> ImportReport:
    report = ImportReport()
    if not text.strip():
        return report
    seen: set[str] = set()
    for row, value in enumerate(_physical_lines(text), 1):
        _add_target(report, seen, value, row, source)
    return report


def _csv_reader(text: str):
    return csv.reader(io.StringIO(text.removeprefix("\ufeff"), newline=""), strict=True)


def _csv_headers(reader) -> list[str]:
    try:
        raw_headers = next(reader)
    except StopIteration:
        return []
    except csv.Error as error:
        raise ValueError("Malformed CSV header: " + _one_line(str(error))) from None
    headers = [header.strip().strip("\ufeff").strip() for header in raw_headers]
    if not headers or any(not header for header in headers):
        raise ValueError("CSV headers must be nonempty.")
    if len(set(headers)) != len(headers):
        raise ValueError("CSV headers must be unique; duplicate column names were found.")
    return headers


def csv_columns(text: str) -> list[str]:
    """Read normalized header names for an explicit CSV column selection."""
    if not text.removeprefix("\ufeff").strip():
        return []
    return _csv_headers(_csv_reader(text))


def parse_csv(text: str, domain_column: str) -> ImportReport:
    report = ImportReport()
    if not text.removeprefix("\ufeff").strip():
        return report
    reader = _csv_reader(text)
    lines = _physical_lines(text.removeprefix("\ufeff"))
    try:
        headers = _csv_headers(reader)
    except ValueError as error:
        report.issues.append(ImportIssue(1, lines[0] if lines else "", str(error)))
        return report
    if domain_column not in headers:
        report.issues.append(ImportIssue(1, str(domain_column or ""), "Choose an exact CSV domain column from the header."))
        return report
    column_index = headers.index(domain_column)
    seen: set[str] = set()
    while True:
        row = reader.line_num + 1
        try:
            values = next(reader)
        except StopIteration:
            break
        except csv.Error as error:
            raw_value = "\n".join(lines[row - 1:reader.line_num])
            reason = "Malformed CSV row: " + _one_line(str(error))
            advanced = reader.line_num >= row
            if not advanced:
                reason += " Import stopped because the CSV parser did not advance."
            report.issues.append(ImportIssue(row, raw_value, reason))
            if not advanced:
                break
            continue
        if len(values) != len(headers):
            raw_value = "\n".join(lines[row - 1:reader.line_num])
            report.issues.append(ImportIssue(row, raw_value, f"CSV row has {len(values)} columns; expected {len(headers)}."))
            continue
        _add_target(report, seen, values[column_index], row, "csv")
    return report


def read_target_text(path: str | Path) -> str:
    """Read local TXT/CSV content with the same guards for imports and previews."""
    path_text = str(path)
    if path_text.replace("\\", "/").startswith("//") or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", path_text):
        raise ValueError("Choose a local TXT or CSV file.")
    file_path = Path(path)
    if file_path.suffix.lower() not in {".txt", ".csv"}:
        raise ValueError("Unsupported file type; choose a TXT or CSV file.")
    return file_path.read_text(encoding="utf-8-sig")


def read_target_file(
    path: str | Path, source: str, domain_column: str | None = None
) -> ImportReport:
    """Read a local UTF-8 TXT or CSV file; file errors become import issues."""
    try:
        text = read_target_text(path)
    except (OSError, UnicodeError, ValueError) as error:
        reason = _one_line(str(error))
        if isinstance(error, (OSError, UnicodeError)):
            reason = "Could not read target file: " + reason
        return ImportReport(issues=[ImportIssue(0, str(path), reason)])
    if Path(path).suffix.lower() == ".txt":
        return parse_text(text, source=source)
    report = parse_csv(text, domain_column if domain_column is not None else "")
    for target in report.targets:
        target.source = source
    return report
