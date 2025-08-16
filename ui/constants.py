# ui/constants.py
from __future__ import annotations
from enum import IntEnum
from typing import Optional
from PySide6.QtGui import QColor, QBrush

# --- Колонки таблицы задач ---
class Col(IntEnum):
    URL     = 0
    Status  = 1
    Code    = 2
    Time    = 3
    Results = 4
    Params  = 5
    Cookies = 6

# Если где-то меняются заголовки/порядок – используем это для авто-карты.
HEADER_TO_COLNAME = {
    "URL": "URL",
    "Status": "Status",
    "Code": "Code",
    "Time": "Time",
    "Results": "Results",
    "Params": "Params",
    "Cookies": "Cookies",
}

def build_col_index_from_headers(headers: list[str]) -> dict[str, int]:
    """
    Строит карту 'URL' -> индекс по реальным заголовкам QTableWidget.
    Используй один раз в __init__ после setHorizontalHeaderLabels(...).
    """
    mapping: dict[str, int] = {}
    for idx, h in enumerate(headers):
        key = HEADER_TO_COLNAME.get(h.strip(), None)
        if key:
            mapping[key] = idx
    return mapping

# --- Тексты статусов задач ---
class TaskStatus:
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE    = "DONE"
    FAILED  = "FAILED"
    STOPPED = "STOPPED"

STATUS_TITLES = {
    TaskStatus.PENDING: "Pending",
    TaskStatus.RUNNING: "Running",
    TaskStatus.DONE:    "Done",
    TaskStatus.FAILED:  "Failed",
    TaskStatus.STOPPED: "Stopped",
}

# --- Палитра для статусов (фон/текст) ---
CLR_BG_PENDING = QColor("#f4f4f4")
CLR_BG_RUNNING = QColor("#e8f4ff")
CLR_BG_DONE    = QColor("#eafbea")
CLR_BG_FAILED  = QColor("#ffebea")
CLR_BG_STOPPED = QColor("#f7f7f7")

CLR_TXT_DEFAULT = QColor("#202020")
CLR_TXT_MUTED   = QColor("#666666")

STATUS_BG = {
    TaskStatus.PENDING: CLR_BG_PENDING,
    TaskStatus.RUNNING: CLR_BG_RUNNING,
    TaskStatus.DONE:    CLR_BG_DONE,
    TaskStatus.FAILED:  CLR_BG_FAILED,
    TaskStatus.STOPPED: CLR_BG_STOPPED,
}

def status_text(status: str) -> str:
    return STATUS_TITLES.get(status, status or "")

def status_brush(status: str) -> Optional[QBrush]:
    c = STATUS_BG.get(status)
    return QBrush(c) if c else None

# --- Цвета по HTTP-коду ---
# 2xx – зелёный, 3xx – синий, 4xx – оранжевый, 5xx – красный, прочее – серый
CLR_CODE_2XX = QColor("#1f7a1f")
CLR_CODE_3XX = QColor("#1f5f9f")
CLR_CODE_4XX = QColor("#b36b00")
CLR_CODE_5XX = QColor("#b31f1f")
CLR_CODE_XXX = QColor("#555555")

def code_color(code: Optional[int]) -> QColor:
    if code is None:
        return CLR_CODE_XXX
    try:
        c = int(code)
    except (TypeError, ValueError):
        return CLR_CODE_XXX
    if 200 <= c <= 299:
        return CLR_CODE_2XX
    if 300 <= c <= 399:
        return CLR_CODE_3XX
    if 400 <= c <= 499:
        return CLR_CODE_4XX
    if 500 <= c <= 599:
        return CLR_CODE_5XX
    return CLR_CODE_XXX

def code_text(code: Optional[int]) -> str:
    return "" if code is None else str(code)
