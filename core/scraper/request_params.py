# core/scraper/request_params.py
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_PARAMS: Dict[str, Any] = {
    "method": "GET",
    "headers": {},
    "proxy": "",
    "timeout": 15,
    "retries": 2,
    "user_agent": DEFAULT_USER_AGENT,
}


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    if isinstance(value, tuple):
        return [_sanitize_value(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def normalize_params(user_params: dict | None) -> dict:
    raw = deepcopy(user_params or {})
    raw = _sanitize_value(raw)

    params: Dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}

    timeout = _coerce_int(params.get("timeout"))
    if timeout is None or timeout <= 0:
        timeout = int(DEFAULT_PARAMS["timeout"])

    retries = _coerce_int(params.get("retries"))
    if retries is None or retries < 0:
        retries = int(DEFAULT_PARAMS["retries"])

    user_agent = params.get("user_agent")
    if not isinstance(user_agent, str) or not user_agent.strip():
        user_agent = str(DEFAULT_PARAMS["user_agent"])

    params["timeout"] = timeout
    params["retries"] = retries
    params["user_agent"] = user_agent

    if "headers" not in params or params.get("headers") is None:
        params["headers"] = deepcopy(DEFAULT_PARAMS["headers"])

    if "proxy" not in params or params.get("proxy") is None:
        params["proxy"] = DEFAULT_PARAMS["proxy"]

    if "method" not in params or not params.get("method"):
        params["method"] = DEFAULT_PARAMS["method"]

    return params


if __name__ == "__main__":
    sample = {"user_agent": "", "timeout": None, "retries": None}
    normalized = normalize_params(sample)
    assert normalized["user_agent"], "user_agent default not applied"
    assert normalized["timeout"] is not None, "timeout default not applied"
    assert normalized["retries"] is not None, "retries default not applied"
    print("normalize_params self-check OK:", normalized)
