# core/scraper/exporter.py
from __future__ import annotations
import csv, json, os
from typing import Iterable
from pathlib import Path
from datetime import datetime

def _task_to_row(task) -> dict:
    base = {
        "id": getattr(task, "id", ""),
        "url": getattr(task, "url", ""),
        "method": getattr(task, "method", "GET"),
        "status": getattr(getattr(task, "status", ""), "value", str(getattr(task, "status", ""))),
        "progress": getattr(task, "progress", 0),
        "retries": getattr(task, "retries", 0),
        "timeout": getattr(task, "timeout", ""),
        "user_agent": getattr(task, "user_agent", ""),
        "proxy": getattr(task, "proxy", ""),
    }

    # Если есть результат — развернём
    result = getattr(task, "result", None)
    if isinstance(result, dict):
        base["result_status_code"] = result.get("status_code", "")
        base["result_final_url"] = result.get("final_url", "")
        base["result_title"] = result.get("title", "")
        base["result_content_len"] = result.get("content_len", "")
        timings = result.get("timings", {}) or {}
        base["result_request_ms"] = timings.get("request_ms", "")
        base["result_total_ms"] = timings.get("total_ms", "")
        # Можно добавить важные заголовки:
        headers = result.get("headers", {}) or {}
        for hk in ("server", "content-type", "content-length", "date", "via", "x-powered-by"):
            base[f"header_{hk}"] = headers.get(hk, "")
    else:
        base["result_status_code"] = ""
        base["result_final_url"] = ""
        base["result_title"] = ""
        base["result_content_len"] = ""
        base["result_request_ms"] = ""
        base["result_total_ms"] = ""
    return base

def _ensure_dir(path: str):
    folder = os.path.dirname(path)
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

def _export_csv(tasks: Iterable, path: str):
    rows = [_task_to_row(t) for t in tasks]
    if not rows:
        raise ValueError("No data to export.")
    _ensure_dir(path)
    # поля фиксируем по первому ряду
    fieldnames = list(rows[0].keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

def _export_json(tasks: Iterable, path: str):
    rows = [_task_to_row(t) for t in tasks]
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)

def _export_xlsx(tasks: Iterable, path: str):
    try:
        from openpyxl import Workbook
    except Exception as e:
        raise RuntimeError("openpyxl is not installed. Run: pip install openpyxl") from e

    rows = [_task_to_row(t) for t in tasks]
    if not rows:
        raise ValueError("No data to export.")
    _ensure_dir(path)

    wb = Workbook()
    ws = wb.active
    ws.title = "Scraper"

    headers = list(rows[0].keys())
    ws.append(headers)
    for r in rows:
        ws.append([r.get(h, "") for h in headers])

    # Авто-ширина по содержимому (простая эвристика)
    for col_idx, h in enumerate(headers, start=1):
        max_len = max((len(str(row.get(h, ""))) for row in rows), default=len(h))
        max_len = max(max_len, len(h))
        ws.column_dimensions[ws.cell(row=1, column=col_idx).column_letter].width = min(max_len + 2, 80)

    wb.save(path)

def export_tasks(tasks: Iterable, fmt: str, path: str) -> str:
    fmt = (fmt or "").lower()
    if fmt not in {"csv", "json", "xlsx"}:
        raise ValueError(f"Unsupported format: {fmt}")
    if fmt == "csv":
        _export_csv(tasks, path)
    elif fmt == "json":
        _export_json(tasks, path)
    elif fmt == "xlsx":
        _export_xlsx(tasks, path)
    return path

def default_exports_dir() -> str:
    """Папка для отчётов внутри проекта: <root>/data/exports"""
    # __file__ → core/scraper/exporter.py → поднимаемся к корню проекта
    root = Path(__file__).resolve().parents[2]
    out = root / "data" / "exports"
    out.mkdir(parents=True, exist_ok=True)
    return str(out)

def suggest_filename(fmt: str, scope: str = "All") -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"scraper_{scope.lower()}_{ts}.{fmt.lower()}"
    return base
