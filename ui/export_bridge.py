from __future__ import annotations

import csv
import json
import os
import tempfile
from dataclasses import is_dataclass, asdict
from typing import Any, Iterable, Mapping
from core.scraper.request_params import normalize_params

PREVIEW_PREFERRED_COLUMNS: list[str] = [
    "final_url",
    "status_code",
    "title",
    "content_len",
    "request_ms",
    "redirects",
    "candidates_total",
    "candidates_xss",
    "candidates_sqli",
    "candidates_lfi",
    "candidates_ssrf",
    "candidates_types_present",
    "candidates_max_confidence",
]

PREVIEW_HIDDEN_RAW_FIELDS: set[str] = {
    "candidates",
    "candidates_summary",
    "discovery",
    "fingerprint",
    "forms",
    "headers",
    "timings",
    "parameter_intelligence",
}


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
    normalized_params = normalize_params(params if isinstance(params, Mapping) else {})

    user_agent = _str_or(normalized_params.get("user_agent"), "")
    proxy = _str_or(normalized_params.get("proxy"), "")
    timeout = normalized_params.get("timeout")
    retries = normalized_params.get("retries")
    headers_req = normalized_params.get("headers", {})


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

    # 3) Сформируем export-friendly record без потери полезных derived полей из payload.
    #    Важно: начинаем с payload, чтобы preview/export использовали общий нормализованный источник.
    record: dict[str, Any] = dict(result) if isinstance(result, Mapping) else {}

    record.setdefault("task_id", task_id)
    record.setdefault("url", url)
    record["final_url"] = final_url
    record["method"] = method or _str_or(record.get("method"), "")
    record["status_code"] = status_code
    record["content_len"] = content_len
    record["request_ms"] = request_ms
    record["redirects"] = redirects
    record["title"] = title

    # Параметры запроса
    record["user_agent"] = user_agent
    record["proxy"] = proxy
    record["timeout"] = timeout
    record["retries"] = retries

    # Заголовки (req/resp) — как JSON-строки для CSV/XLSX
    record["headers_request"] = _maybe_json_string(headers_req)
    record["headers_response"] = _maybe_json_string(headers_resp)

    # Полный сырый result — удобно для JSON-экспорта без потерь:
    record["_raw_result"] = result

    record.update(derive_candidate_summary_fields(result))

    return record


def derive_candidate_summary_fields(result: Any) -> dict[str, Any]:
    """
    Возвращает export-friendly candidate-derived summary fields
    из raw result без модификации исходного payload.
    """
    summary_defaults: dict[str, Any] = {
        "candidates_total": 0,
        "candidates_xss": 0,
        "candidates_sqli": 0,
        "candidates_lfi": 0,
        "candidates_ssrf": 0,
        "candidates_types_present": "",
        "candidates_max_confidence": "",
    }
    if not isinstance(result, Mapping):
        return summary_defaults

    out = dict(summary_defaults)
    out.update(_extract_candidate_counts(result))
    out.update(_extract_candidate_debug_fields(result))
    return out


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

    source_records = [dict(r) for r in records]
    # Нормализуем список к export-friendly плоскому виду (включая candidate summary поля).
    items = [task_to_record(r) for r in source_records]

    # Гарантируем существование директории
    _ensure_parent_dir(path)

    if fmt == "json":
        _to_json(items, path)
    else:
        tabular_items = normalize_preview_rows(source_records)
        columns = preview_column_order(tabular_items)
        if fmt == "csv":
            _to_csv(tabular_items, path, fieldnames=columns)
        else:
            _to_xlsx(tabular_items, path, fieldnames=columns)

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


def _to_csv(items: list[dict[str, Any]], path: str, fieldnames: list[str] | None = None) -> None:
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
    fieldnames = fieldnames or _union_keys(items)

    def row_gen():
        for it in items:
            yield {k: _scalarize(it.get(k)) for k in fieldnames}

    with _atomic_writer(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, dialect="excel", quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in row_gen():
            writer.writerow(row)


def _to_xlsx(items: list[dict[str, Any]], path: str, fieldnames: list[str] | None = None) -> None:
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

    fieldnames = fieldnames or _union_keys(items)

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


def _to_int_count(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            return int(value.strip())
    except Exception:
        pass
    return default


def _extract_candidate_counts(rec: Mapping[str, Any]) -> dict[str, int]:
    summary = rec.get("candidates_summary")
    if not isinstance(summary, Mapping):
        candidates = rec.get("candidates")
        if isinstance(candidates, Mapping):
            summary = candidates.get("summary")
        else:
            summary = None

    if not isinstance(summary, Mapping):
        return {}

    by_type = summary.get("by_type") if isinstance(summary.get("by_type"), Mapping) else {}
    return {
        "candidates_total": _to_int_count(summary.get("total"), 0),
        "candidates_xss": _to_int_count(by_type.get("xss_candidate"), 0),
        "candidates_sqli": _to_int_count(by_type.get("sqli_candidate"), 0),
        "candidates_lfi": _to_int_count(by_type.get("lfi_candidate"), 0),
        "candidates_ssrf": _to_int_count(by_type.get("ssrf_candidate"), 0),
    }


def _extract_candidate_debug_fields(rec: Mapping[str, Any]) -> dict[str, str]:
    candidates = rec.get("candidates")
    candidates_all = candidates.get("all") if isinstance(candidates, Mapping) else None
    if not isinstance(candidates_all, list):
        return {
            "candidates_types_present": "",
            "candidates_max_confidence": "",
        }

    type_map = {
        "xss_candidate": "xss",
        "sqli_candidate": "sqli",
        "lfi_candidate": "lfi",
        "ssrf_candidate": "ssrf",
    }
    type_order = ("xss_candidate", "sqli_candidate", "lfi_candidate", "ssrf_candidate")
    confidence_rank = {
        "low": 1,
        "medium": 2,
        "high": 3,
    }

    found_types = set()
    max_confidence_value = ""
    max_confidence_rank = 0

    for item in candidates_all:
        if not isinstance(item, Mapping):
            continue

        raw_type = item.get("type")
        if isinstance(raw_type, str) and raw_type in type_map:
            found_types.add(raw_type)

        raw_confidence = item.get("confidence")
        if isinstance(raw_confidence, str):
            conf = raw_confidence.strip().lower()
            rank = confidence_rank.get(conf, 0)
            if rank > max_confidence_rank:
                max_confidence_rank = rank
                max_confidence_value = conf

    return {
        "candidates_types_present": ",".join(type_map[t] for t in type_order if t in found_types),
        "candidates_max_confidence": max_confidence_value,
    }


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


def preview_column_order(items: list[Mapping[str, Any]]) -> list[str]:
    """
    Общий порядок колонок для Data Preview и CSV/XLSX export:
    preferred -> остальные (sorted).
    """
    keys = set()
    for it in items:
        keys.update(it.keys())
    rest = sorted(k for k in keys if k not in PREVIEW_PREFERRED_COLUMNS)
    return [k for k in PREVIEW_PREFERRED_COLUMNS if k in keys] + rest


def _tabular_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Фильтрует внутренние/сырые поля для CSV/XLSX экспорта.
    """
    hidden = {"_raw_result", "candidates", "candidates_summary"}
    out: list[dict[str, Any]] = []
    for it in items:
        out.append({k: v for k, v in it.items() if k not in hidden})
    return out


def normalize_preview_rows(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """
    Приводит записи к той же normalized schema, что используется в Data Preview table:
    - нормализует ключи;
    - добавляет derived candidate summary;
    - скрывает bulky/raw поля, которых нет в превью-таблице;
    - применяет compact-значения для колонок превью.
    """
    out: list[dict[str, Any]] = []
    for rec in records:
        if not isinstance(rec, Mapping):
            rec = {"value": rec}

        row: dict[str, Any] = {}
        for key, value in rec.items():
            nk = _normalize_preview_key(key)
            if nk in row:
                i = 2
                while f"{nk}#{i}" in row:
                    i += 1
                nk = f"{nk}#{i}"
            row[nk] = value

        row.update(derive_candidate_summary_fields(rec))

        for hidden_key in PREVIEW_HIDDEN_RAW_FIELDS:
            row.pop(hidden_key, None)

        compacted: dict[str, Any] = {}
        for key, value in row.items():
            compacted[key] = _compact_preview_value(key, value)

        out.append(compacted)
    return out


def _normalize_preview_key(key: Any) -> str:
    if key is None:
        return "__none__"
    norm = str(key).replace("\ufeff", "").strip()
    return norm if norm else "__empty__"


def _compact_preview_value(key: str, val: Any) -> Any:
    if key == "forms_summary" and isinstance(val, Mapping):
        fs = val
        return (
            f"total={fs.get('forms_total', 0)}, "
            f"unique={fs.get('forms_unique', fs.get('forms_total', 0))}, "
            f"inputs={fs.get('inputs_total', 0)}, "
            f"unique_inputs={fs.get('inputs_unique_total', fs.get('inputs_total', 0))}, "
            f"names={fs.get('unique_input_names', 0)}"
        )
    if key == "forms" and isinstance(val, list):
        return _compact_forms(val)
    return val


def _compact_forms(forms: list[Any]) -> str:
    if not forms:
        return "[]"
    parts: list[str] = []
    max_forms = 2
    for idx, form in enumerate(forms[:max_forms], 1):
        if not isinstance(form, Mapping):
            continue
        method = str(form.get("method") or "").upper()
        action = str(form.get("action") or "")
        action_short = action if len(action) <= 120 else action[:119] + "…"
        enctype = form.get("enctype") or ""
        inputs_count = form.get("inputs_count") or len(form.get("inputs", []) or [])
        has_file = 1 if form.get("has_file") else 0
        names = form.get("input_names") or []
        names_short = ", ".join((str(n) if n is not None else "") for n in names[:10])
        if len(names) > 10:
            names_short += ", …"
        parts.append(
            f"[{idx}] {method} {action_short} enctype={enctype} inputs={inputs_count} file={has_file} names={names_short}"
        )
    if len(forms) > max_forms:
        parts.append(f"... +{len(forms) - max_forms} more")
    out = " | ".join(parts)
    return out if len(out) <= 2000 else out[:1999] + "…"


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
