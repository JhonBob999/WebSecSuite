from __future__ import annotations

import csv
import json
import os
import tempfile
from dataclasses import is_dataclass, asdict
from typing import Any, Iterable, Mapping

# ---- Публичное API --------------------------------------------------------


def task_to_record(task_or_payload: Any) -> dict[str, Any]:
    """
    Приводит объект задачи (Task) ИЛИ "сырой" payload/dict к единому плоскому словарю (record).
    В record включаем самые полезные поля для анализа/экспорта.

    Поддерживаемые источники:
      - task объект: ожидаются атрибуты .id, .url, .method, .params, .result
      - dict payload: берём как есть (как будто это .result)
    """
    # 1) Вытащим task/result максимально безопасно
    if isinstance(task_or_payload, Mapping):
        task_id = task_or_payload.get("task_id") or task_or_payload.get("id") or ""
        url = task_or_payload.get("url") or ""
        method = _str_or(task_or_payload.get("method"), "")
        params = task_or_payload.get("params") or {}
        result = task_or_payload
    else:
        # объект задачи
        task = task_or_payload
        task_id = getattr(task, "id", "") or ""
        url = getattr(task, "url", "") or ""
        method = _str_or(getattr(task, "method", None), "")
        params = getattr(task, "params", {}) or {}
        result = getattr(task, "result", {}) or {}

        # dataclass params → dict
        if is_dataclass(params):
            params = asdict(params)

    # 2) Достаём поля из params/result
    user_agent = ""
    proxy = ""
    timeout = None
    retries = None
    headers_req = None

    if isinstance(params, Mapping):
        user_agent = _str_or(params.get("user_agent"), "")
        proxy = _str_or(params.get("proxy"), "")
        timeout = params.get("timeout")
        retries = params.get("retries")
        headers_req = params.get("headers")

    final_url = _str_or(_deep_get(result, "final_url"), "") or _str_or(result.get("url"), url)
    status_code = _deep_get(result, "status_code")
    content_len = _deep_get(result, "content_len")
    request_ms = _deep_get(result, "timings", "request_ms")
    title = _str_or(_deep_get(result, "title"), "")

    redirect_chain = _deep_get(result, "redirect_chain") or []
    redirects = None
    if isinstance(redirect_chain, (list, tuple)):
        redirects = len(redirect_chain)

    headers_resp = _deep_get(result, "headers")

    # 3) Сформируем плоский record (без вложенности)
    record: dict[str, Any] = {
        "task_id": task_id,
        "url": url,
        "final_url": final_url,
        "method": method,
        "status_code": status_code,
        "content_len": content_len,
        "request_ms": request_ms,
        "redirects": redirects,
        "title": title,
        # Параметры запроса
        "user_agent": user_agent,
        "proxy": proxy,
        "timeout": timeout,
        "retries": retries,
        # Заголовки (req/resp) — как JSON-строки для CSV/XLSX
        "headers_request": _maybe_json_string(headers_req),
        "headers_response": _maybe_json_string(headers_resp),
        # Полный сырый result — удобно для JSON-экспорта без потерь:
        "_raw_result": result,
    }

    return record


def export(records: Iterable[Mapping[str, Any]], path: str, fmt: str = "csv") -> str:
    """
    Единая точка экспорта. Поддержка форматов: csv/json/xlsx
    - records: итератор словарей (результат task_to_record или аналогичный)
    - path: конечный путь (расширение можно не учитывать — приоритет у fmt)
    - fmt: 'csv' | 'json' | 'xlsx'

    Возвращает финальный путь к записанному файлу.
    """
    fmt = (fmt or "").lower().strip()
    if fmt not in {"csv", "json", "xlsx"}:
        raise ValueError(f"Unsupported export format: {fmt}")

    # Нормализуем список (нужен второй проход для объединения полей в CSV/XLSX)
    items = [dict(r) for r in records]

    # Гарантируем существование директории
    _ensure_parent_dir(path)

    if fmt == "json":
        _to_json(items, path)
    elif fmt == "csv":
        _to_csv(items, path)
    else:
        _to_xlsx(items, path)

    return path


# ---- Внутренние реализации -------------------------------------------------


def _to_json(items: list[dict[str, Any]], path: str) -> None:
    """
    JSON экспорт: сохраняем массив records, но поле '_raw_result' оставляем как есть (dict),
    чтобы не терять данные. Остальные поля уже плоские.
    """
    # Безопасная атомарная запись
    data = items
    _atomic_write_json(path, data, ensure_ascii=False, indent=2)


def _to_csv(items: list[dict[str, Any]], path: str) -> None:
    """
    CSV экспорт: объединяем все ключи как заголовки,
    dict/list значения сериализуем в JSON-строку,
    кодировка utf-8-sig (Excel-friendly).
    """
    if not items:
        # создадим пустой CSV с нулевой строкой заголовков
        _atomic_write_text(path, "", encoding="utf-8-sig")
        return

    # Объединение ключей всех строк
    fieldnames = _union_keys(items)

    def row_gen():
        for it in items:
            yield {k: _scalarize(it.get(k)) for k in fieldnames}

    with _atomic_writer(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, dialect="excel", quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in row_gen():
            writer.writerow(row)


def _to_xlsx(items: list[dict[str, Any]], path: str) -> None:
    """
    XLSX экспорт через openpyxl.
    dict/list → JSON-строки (как в CSV).
    """
    try:
        import openpyxl  # type: ignore
        from openpyxl.utils import get_column_letter  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "Для экспорта в .xlsx требуется пакет 'openpyxl'. Установите: pip install openpyxl"
        ) from e

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "export"

    fieldnames = _union_keys(items)

    # Заголовки
    ws.append(list(fieldnames))

    # Строки
    for it in items:
        ws.append([_scalarize(it.get(k)) for k in fieldnames])

    # Простая авто-ширина по максимуму длины значения (ограничим до разумных пределов)
    MAX = 60
    for idx, key in enumerate(fieldnames, start=1):
        col = get_column_letter(idx)
        max_len = len(str(key))
        for row in ws.iter_rows(min_row=2, min_col=idx, max_col=idx):
            val = row[0].value
            if val is None:
                continue
            max_len = max(max_len, len(str(val)))
        ws.column_dimensions[col].width = min(MAX, max_len + 2)

    # Атомарная запись файла
    _atomic_write_xlsx(wb, path)


# ---- Утилиты ---------------------------------------------------------------


def _str_or(value: Any, default: str) -> str:
    return value if isinstance(value, str) else default


def _deep_get(obj: Any, *keys: str) -> Any:
    cur = obj
    for k in keys:
        if isinstance(cur, Mapping) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur


def _maybe_json_string(val: Any) -> Any:
    """Возвращает JSON-строку для dict/list, иначе оригинальное значение."""
    if isinstance(val, (dict, list, tuple)):
        try:
            return json.dumps(val, ensure_ascii=False)
        except Exception:
            return str(val)
    return val


def _scalarize(val: Any) -> Any:
    """
    Приводит значение к безопасному для CSV/XLSX виду:
    - dict/list → JSON-строка
    - None → ""
    - остальное → как есть
    """
    if val is None:
        return ""
    if isinstance(val, (dict, list, tuple)):
        try:
            return json.dumps(val, ensure_ascii=False)
        except Exception:
            return str(val)
    return val


def _union_keys(items: list[dict[str, Any]]) -> list[str]:
    keys: dict[str, None] = {}
    for it in items:
        for k in it.keys():
            keys.setdefault(k, None)
    return list(keys.keys())


def _ensure_parent_dir(path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)


# ---- Атомарные записи ------------------------------------------------------


def _atomic_writer(path: str, mode: str, **kwargs):
    """
    Контекстный менеджер для атомарной записи текстовых файлов.
    Записываем во временный файл и затем os.replace → path.
    """
    tmp_dir = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", dir=tmp_dir)
    os.close(fd)

    class _CM:
        def __enter__(self_inner):
            self_inner._f = open(tmp_path, mode, **kwargs)
            return self_inner._f

        def __exit__(self_inner, exc_type, exc, tb):
            self_inner._f.close()
            if exc_type is None:
                os.replace(tmp_path, path)
            else:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    return _CM()


def _atomic_write_text(path: str, text: str, encoding: str = "utf-8") -> None:
    with _atomic_writer(path, "w", encoding=encoding, newline="") as f:
        f.write(text)


def _atomic_write_json(path: str, data: Any, ensure_ascii: bool = False, indent: int | None = 2) -> None:
    with _atomic_writer(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=ensure_ascii, indent=indent)


def _atomic_write_xlsx(workbook: Any, path: str) -> None:
    # openpyxl сам пишет атомарно плохо, поэтому вручную во временный и replace
    tmp_dir = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".xlsx", dir=tmp_dir)
    os.close(fd)
    try:
        workbook.save(tmp_path)
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass