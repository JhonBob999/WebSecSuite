# core/scraper/runnables.py
from __future__ import annotations

# === SECTION === Imports & Typing
import time
import threading
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from PySide6.QtCore import QObject, Signal, QRunnable

from utils.html_utils import extract_title
from core.cookies.storage import load_cookiejar, save_cookiejar, resolve_cookie_path
from core.discovery.url_discovery import discover, parse_forms_from_html
from core.discovery.endpoint_classifier import classify_endpoint_type
from core.discovery.candidate_generation import generate_candidates
from core.discovery.finding_artifacts import build_finding_artifacts
from core.scraper.fingerprinting import build_passive_fingerprint
from core.discovery.parameter_intelligence import analyze_query_params


# === SECTION === Signals
class WorkerSignals(QObject):
    """Thread-safe события из воркера в UI."""
    task_log = Signal(str, str, str)      # task_id, level, text
    task_status = Signal(str, str)        # task_id, status_str
    task_progress = Signal(str, int)      # task_id, progress 0..100
    task_result = Signal(str, dict)       # task_id, payload
    task_error = Signal(str, str)         # task_id, error_str
    task_finished = Signal(str)           # task_id


# === SECTION === Scraper Runnable
class ScraperRunnable(QRunnable):
    # --- Lifecycle ---
    def __init__(self, task: Any, signals: WorkerSignals):
        super().__init__()
        self.task = task
        self.signals = signals

        # Кооперативные флаги
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # set = разрешено выполнять
        self._is_paused = False  # внутренний флаг для UX-логов/статусов

    # --- Cooperative control API (called by TaskManager) ---
    def request_stop(self) -> None:
        # Останавливаем и обязательно "пробуждаем" из паузы, чтобы поток не завис
        self._stop_event.set()
        self._pause_event.set()
        try:
            self.signals.task_log.emit(getattr(self.task, "id", ""), "INFO", "Stop requested")
        except Exception:
            pass

    def request_pause(self) -> None:
        if not self._is_paused:
            self._is_paused = True
            self._pause_event.clear()
            tid = getattr(self.task, "id", "")
            try:
                self.signals.task_status.emit(tid, "Paused")
                self.signals.task_log.emit(tid, "INFO", "Paused")
            except Exception:
                pass

    def request_resume(self) -> None:
        if self._is_paused:
            self._is_paused = False
            self._pause_event.set()
            tid = getattr(self.task, "id", "")
            try:
                self.signals.task_status.emit(tid, "Running")
                self.signals.task_log.emit(tid, "INFO", "Resumed")
            except Exception:
                pass

    # --- Internal helpers ---
    def _check_stop(self, tid: str) -> bool:
        """Возвращает True, если нужно прекратить выполнение прямо сейчас."""
        if self._stop_event.is_set():
            self.signals.task_status.emit(tid, "Stopped")
            self.signals.task_log.emit(tid, "INFO", "Stopped cooperatively")
            return True
        return False

    def _pause_gate(self, tid: str, ping_sec: float = 5.0) -> bool:
        """
        Кооперативная пауза: блокируемся, пока _pause_event не set().
        Раз в ping_sec пишем в лог "Paused…".
        Возвращаем False, если в ожидании пришёл stop.
        """
        if self._pause_event.is_set():
            return True

        last_ping = 0.0
        # На входе мы уже на паузе
        while not self._pause_event.is_set():
            if self._stop_event.is_set():
                # Прерываем ожидание паузы из-за стопа
                return False
            now = time.perf_counter()
            if now - last_ping >= ping_sec:
                self.signals.task_log.emit(tid, "INFO", "Paused…")
                last_ping = now
            # Короткий сон, чтобы не крутить CPU
            time.sleep(0.05)
        return True

    def _now_iso_utc(self) -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _build_request_recipe(
        self,
        *,
        request_url: str,
        method: str,
        headers: Optional[Dict[str, Any]],
        cookie_path: Optional[str],
        redirects: int,
        timeout: Any,
        payload_source: str,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        safe_headers: Dict[str, str] = {}
        try:
            for k, v in dict(headers or {}).items():
                if k is None:
                    continue
                safe_headers[str(k)] = "" if v is None else str(v)
        except Exception:
            safe_headers = {}

        safe_timeout: Optional[float] = None
        try:
            if timeout is not None:
                safe_timeout = float(timeout)
        except Exception:
            safe_timeout = None

        try:
            safe_redirects = int(redirects)
        except Exception:
            safe_redirects = 0

        return {
            "url": str(request_url or ""),
            "method": str(method or "GET").upper(),
            "headers": safe_headers,
            "cookie_path": str(cookie_path or ""),
            "redirects": max(0, safe_redirects),
            "timeout": safe_timeout,
            "payload_source": str(payload_source or "direct_url"),
            "timestamp": timestamp or self._now_iso_utc(),
        }

    def _compact_headers(self, headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
        compact: Dict[str, str] = {}
        try:
            for k, v in dict(headers or {}).items():
                if k is None:
                    continue
                compact[str(k)] = "" if v is None else str(v)
        except Exception:
            compact = {}
        return compact

    def _safe_body_preview(
        self,
        *,
        body: bytes,
        content_type: str,
        max_bytes: int = 8192,
        max_chars: int = 4096,
    ) -> str:
        if not body:
            return ""

        body_head = body[:max_bytes]
        ct = (content_type or "").lower()
        looks_textual = any(
            token in ct
            for token in ("text/", "json", "xml", "html", "javascript", "x-www-form-urlencoded")
        )
        if not looks_textual and b"\x00" in body_head:
            return f"[binary body {len(body)} bytes]"

        try:
            preview = body_head.decode("utf-8", errors="replace")
        except Exception:
            return f"[binary body {len(body)} bytes]"

        if len(preview) > max_chars:
            preview = preview[:max_chars]
        return preview

    def _build_response_snapshot(self, response: Optional[httpx.Response] = None) -> Dict[str, Any]:
        if response is None:
            return {
                "status_code": None,
                "headers": {},
                "content_type": "",
                "content_length": 0,
                "body_preview": "",
                "body_hash": "",
            }

        headers = self._compact_headers(dict(getattr(response, "headers", {}) or {}))
        body = b""
        try:
            body = bytes(getattr(response, "content", b"") or b"")
        except Exception:
            body = b""

        content_type = headers.get("content-type") or headers.get("Content-Type") or ""
        body_hash = hashlib.sha256(body).hexdigest() if body else ""
        content_length = len(body)

        return {
            "status_code": getattr(response, "status_code", None),
            "headers": headers,
            "content_type": content_type,
            "content_length": content_length,
            "body_preview": self._safe_body_preview(body=body, content_type=content_type),
            "body_hash": body_hash,
        }

    # --- Main entry point ---
    def run(self) -> None:
        tid = getattr(self.task, "id", "")
        url = getattr(self.task, "url", "")
        method = (getattr(self.task, "method", None) or "GET").upper()
        headers = getattr(self.task, "headers", None) or {}
        proxy = getattr(self.task, "proxy", None) or None
        timeout = getattr(self.task, "timeout", None)

        # --- читаем параметры для cookies из task.params (если есть)
        params = getattr(self.task, "params", {}) or {}
        cookie_file = params.get("cookie_file") or getattr(self.task, "cookie_file", None)
        auto_save_cookies = params.get("auto_save_cookies", True)
        payload_source = (
            params.get("payload_source")
            or params.get("source_type")
            or ("discovered_url" if getattr(self.task, "source_url", None) else "direct_url")
        )
        recipe_cookie_path = str(cookie_file or "")

        self.signals.task_status.emit(tid, "Running")
        self.signals.task_progress.emit(tid, 0)
        t0_total = time.perf_counter()

        try:
            # стоп/пауза до старта запроса
            if self._check_stop(tid):
                self.signals.task_finished.emit(tid)
                return
            if not self._pause_gate(tid):
                self.signals.task_finished.emit(tid)
                return

            # --- автозагрузка cookies по cookie_file или домену из URL
            jar, cookie_path, loaded = load_cookiejar(url=url, cookie_file=cookie_file)
            recipe_cookie_path = str(cookie_path or recipe_cookie_path or "")
            self.signals.task_log.emit(tid, "INFO", f"Cookies loaded: {loaded} from {cookie_path}")

            # лог запроса
            self.signals.task_log.emit(tid, "INFO", f"Request {method} {url}")

            # === HTTP request ===
            t0_req = time.perf_counter()
            with httpx.Client(
                timeout=timeout,
                headers=headers,
                proxy=proxy,
                follow_redirects=True,
                cookies=jar
            ) as client:
                resp = client.request(method, url)

                # --- автосохранение cookies (пока клиент ещё открыт)
            if auto_save_cookies:
                # 1) Выбираем целевой путь:
                #    - если пользователь выбрал Custom File -> сохраняем туда
                #    - иначе -> доменный файл по URL
                if cookie_file:
                    target_path = Path(cookie_file).expanduser()
                    if not target_path.is_absolute():
                        # поддержка относительных путей (если вдруг в UI дадим относительный)
                        target_path = (Path.cwd() / target_path).resolve()
                else:
                    target_path = resolve_cookie_path(str(resp.url) if resp else url)

                saved = save_cookiejar(target_path, client.cookies)

                # сколько cookies реально есть
                try:
                    jar_count = len(list(client.cookies.jar))
                except Exception:
                    jar_count = len(list(client.cookies))

                # обновляем metadata в params (ВАЖНО: не затираем cookie_file доменным, если был custom)
                params = getattr(self.task, "params", {}) or {}
                params["cookie_file"] = str(target_path)
                params["cookies_count"] = int(jar_count)

                # источник:
                # - manual оставляем, если пользователь руками выставил custom (не перетираем)
                # - иначе auto
                if jar_count > 0:
                    if not params.get("cookies_source"):
                        params["cookies_source"] = "auto"
                else:
                    params.pop("cookies_source", None)

                setattr(self.task, "params", params)
                if hasattr(self.task, "cookies_path"):
                    setattr(self.task, "cookies_path", str(target_path))
                recipe_cookie_path = str(target_path)

                self.signals.task_log.emit(tid, "INFO", f"Cookies saved: {saved} → {target_path}")

                    
            req_ms = int((time.perf_counter() - t0_req) * 1000)

            # Кооперативные пауза/стоп после запроса
            if self._check_stop(tid):
                self.signals.task_finished.emit(tid)
                return
            if not self._pause_gate(tid):
                self.signals.task_finished.emit(tid)
                return

            # === Redirect chain ===
            redirect_chain: List[Dict[str, Optional[str]]] = [
                {
                    "status_code": r.status_code,
                    "url": str(r.url),
                    "location": r.headers.get("Location"),
                }
                for r in (resp.history or [])
            ]
            used_method = method
            used_request_headers: Dict[str, Any] = headers
            try:
                used_method = str(getattr(resp.request, "method", method) or method).upper()
                used_request_headers = dict(getattr(resp.request, "headers", {}) or headers or {})
            except Exception:
                pass

            self.signals.task_progress.emit(tid, 50)

            # === Response analysis ===
            html_title = ""
            try:
                html_title = extract_title(resp.text)
            except Exception:
                html_title = ""

            total_ms = int((time.perf_counter() - t0_total) * 1000)
            
            # === Forms parsing (HTML only) ===
            forms_pack = {"forms": [], "summary": {"forms_total": 0, "inputs_total": 0, "unique_input_names": 0}}
            try:
                ct = (resp.headers.get("content-type") or resp.headers.get("Content-Type") or "")
                if "html" in ct.lower():
                    forms_pack = parse_forms_from_html(resp.text or "", str(resp.url))
            except Exception:
                pass

            # Cookies seen (safe for malformed cookie jars/headers)
            cookie_names: List[str] = []
            try:
                cookie_names = [c.name for c in resp.cookies.jar if getattr(c, "name", None)]
            except Exception:
                try:
                    cookie_names = [k for k in resp.cookies.keys()]
                except Exception:
                    cookie_names = []

            set_cookie_headers: List[str] = []
            try:
                set_cookie_headers = list(resp.headers.get_list("set-cookie"))
            except Exception:
                raw_set_cookie = resp.headers.get("set-cookie") or ""
                if raw_set_cookie:
                    set_cookie_headers = [raw_set_cookie]

            fingerprint = build_passive_fingerprint(
                headers=dict(resp.headers),
                html=resp.text or "",
                cookie_names=cookie_names,
                set_cookie_headers=set_cookie_headers,
            )
            
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(str(resp.url))
            query_params = parse_qs(parsed.query)
            param_intel_pack = analyze_query_params(query_params)
            param_intel = param_intel_pack.get("params", [])
            param_intel_summary = param_intel_pack.get(
                "summary",
                {"total": 0, "by_category": {}, "high_risk": 0},
            )

            result: Dict[str, Any] = {
                "status_code": resp.status_code,
                "final_url": str(resp.url),
                "endpoint_type": classify_endpoint_type(str(resp.url)),
                "title": html_title,
                "content_len": len(resp.content),
                "headers": dict(resp.headers),
                "redirect_chain": redirect_chain,
                "forms": forms_pack.get("forms", []),
                "forms_summary": forms_pack.get("summary", {"forms_total": 0, "inputs_total": 0, "unique_input_names": 0}),
                "fingerprint": fingerprint,
                "parameter_intelligence": param_intel,
                "parameter_intelligence_summary": param_intel_summary,
                "timings": {
                    "request_ms": req_ms,
                    "total_ms": total_ms,
                },
                "request_recipe": self._build_request_recipe(
                    request_url=url,
                    method=used_method,
                    headers=used_request_headers,
                    cookie_path=recipe_cookie_path,
                    redirects=len(redirect_chain),
                    timeout=timeout,
                    payload_source=str(payload_source or "direct_url"),
                    timestamp=self._now_iso_utc(),
                ),
                "response_snapshot": self._build_response_snapshot(resp),
            }
            result["discovery"] = discover(resp.text or "", str(resp.url))

            pipeline_final_url = (
                result.get("final_url")
                or str(resp.url or "")
                or str(url or "")
                or str(getattr(self.task, "source_url", "") or "")
            )
            pipeline_parameter_intelligence = result.get("parameter_intelligence")
            pipeline_classified_urls_by_scope = None
            if isinstance(result.get("discovery"), dict):
                pipeline_classified_urls_by_scope = result["discovery"].get("classified_urls_by_scope")

            try:
                result["candidates"] = generate_candidates(
                    final_url=pipeline_final_url,
                    classified_urls_by_scope=pipeline_classified_urls_by_scope,
                    parameter_intelligence=pipeline_parameter_intelligence,
                )
                result["candidates_summary"] = result["candidates"].get("summary", {})
            except Exception as e:
                self.signals.task_log.emit(tid, "ERROR", f"Candidate generation failed: {e}")
                result["candidates"] = generate_candidates(
                    final_url=pipeline_final_url,
                    classified_urls_by_scope=None,
                    parameter_intelligence=None,
                )
                result["candidates_summary"] = result["candidates"].get("summary", {})
            result["finding_artifacts"] = build_finding_artifacts(
                candidates=result.get("candidates"),
                request_recipe=result.get("request_recipe"),
                response_snapshot=result.get("response_snapshot"),
                status_code=result.get("status_code"),
                final_url=result.get("final_url"),
            )

            self.task.result = result

            # Последняя проверка остановки перед эмитом
            if self._check_stop(tid):
                self.signals.task_finished.emit(tid)
                return
            if not self._pause_gate(tid):
                self.signals.task_finished.emit(tid)
                return

            # Логируем редиректы (если были)
            if result["redirect_chain"]:
                for step in result["redirect_chain"]:
                    sc = step.get("status_code", "")
                    u = step.get("url", "")
                    self.signals.task_log.emit(tid, "INFO", f"Redirect {sc} → {u}")

            # Финальные сигналы
            self.signals.task_result.emit(tid, result)
            self.signals.task_status.emit(tid, "Done")
            self.signals.task_progress.emit(tid, 100)
            self.signals.task_log.emit(
                tid,
                "INFO",
                f"Done {result['final_url']} ({result['status_code']}) "
                f"[{result['timings']['total_ms']} ms]",
            )

        except httpx.HTTPError as e:
            self.task.result = {
                "error": f"httpx error: {e}",
                "request_recipe": self._build_request_recipe(
                    request_url=url,
                    method=method,
                    headers=headers,
                    cookie_path=recipe_cookie_path,
                    redirects=0,
                    timeout=timeout,
                    payload_source=str(payload_source or "direct_url"),
                    timestamp=self._now_iso_utc(),
                ),
                "response_snapshot": self._build_response_snapshot(),
            }
            self.task.result["finding_artifacts"] = build_finding_artifacts(
                candidates=self.task.result.get("candidates"),
                request_recipe=self.task.result.get("request_recipe"),
                response_snapshot=self.task.result.get("response_snapshot"),
                status_code=self.task.result.get("status_code"),
                final_url=self.task.result.get("final_url"),
            )
            self.signals.task_error.emit(tid, f"httpx error: {e}")
            self.signals.task_status.emit(tid, "Failed")
        except Exception as e:
            self.task.result = {
                "error": f"Unhandled error: {e}",
                "request_recipe": self._build_request_recipe(
                    request_url=url,
                    method=method,
                    headers=headers,
                    cookie_path=recipe_cookie_path,
                    redirects=0,
                    timeout=timeout,
                    payload_source=str(payload_source or "direct_url"),
                    timestamp=self._now_iso_utc(),
                ),
                "response_snapshot": self._build_response_snapshot(),
            }
            self.task.result["finding_artifacts"] = build_finding_artifacts(
                candidates=self.task.result.get("candidates"),
                request_recipe=self.task.result.get("request_recipe"),
                response_snapshot=self.task.result.get("response_snapshot"),
                status_code=self.task.result.get("status_code"),
                final_url=self.task.result.get("final_url"),
            )
            self.signals.task_error.emit(tid, f"Unhandled error: {e}")
            self.signals.task_status.emit(tid, "Failed")
        finally:
            self.signals.task_finished.emit(tid)
