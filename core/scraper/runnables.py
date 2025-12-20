# core/scraper/runnables.py
from __future__ import annotations

# === SECTION === Imports & Typing
import time
import threading
from typing import Any, Dict, List, Optional

import httpx
from PySide6.QtCore import QObject, Signal, QRunnable

from utils.html_utils import extract_title
from core.cookies.storage import load_cookiejar, save_cookiejar


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

    # --- Main entry point ---
    def run(self) -> None:
        tid = getattr(self.task, "id", "")
        url = getattr(self.task, "url", "")
        method = (getattr(self.task, "method", None) or "GET").upper()
        headers = getattr(self.task, "headers", None) or {}
        proxy = getattr(self.task, "proxy", None) or None
        timeout = getattr(self.task, "timeout", None)

        # --- NEW: читаем параметры для cookies из task.params (если есть)
        params = getattr(self.task, "params", {}) or {}
        cookie_file = params.get("cookie_file") or getattr(self.task, "cookie_file", None)
        auto_save_cookies = params.get("auto_save_cookies", True)

        self.signals.task_status.emit(tid, "Running")
        self.signals.task_progress.emit(tid, 0)
        t0_total = time.perf_counter()

        try:
            # стоп/пауза до старта запроса
            if self._check_stop(tid):
                self.signals.task_finished.emit(tid); return
            if not self._pause_gate(tid):
                self.signals.task_finished.emit(tid); return

            # --- NEW: автозагрузка cookies по cookie_file или домену из URL
            jar, cookie_path, loaded = load_cookiejar(url=url, cookie_file=cookie_file)
            self.signals.task_log.emit(tid, "INFO", f"Cookies loaded: {loaded} from {cookie_path}")

            # лог запроса
            self.signals.task_log.emit(tid, "INFO", f"Request {method} {url}")

            # === HTTP request ===
            # httpx >= 0.28: proxy=, follow_redirects=True
            t0_req = time.perf_counter()
            with httpx.Client(timeout=timeout, headers=headers, proxy=proxy,
                          follow_redirects=True, cookies=jar) as client:
                resp = client.request(method, url)
                # --- NEW: автосохранение cookies (пока клиент ещё открыт)
                if auto_save_cookies:
                    saved = save_cookiejar(cookie_path, client.cookies)
                    self.signals.task_log.emit(tid, "INFO", f"Cookies saved: {saved} → {cookie_path}")
                    
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

            self.signals.task_progress.emit(tid, 50)

            # === Response analysis ===
            html_title = ""
            try:
                # Если ответ текстовый — извлекаем title
                html_title = extract_title(resp.text)
            except Exception:
                # В бинарных ответах .text может кинуть ошибки — тихо игнорим
                html_title = ""

            total_ms = int((time.perf_counter() - t0_total) * 1000)

            result: Dict[str, Any] = {
                "status_code": resp.status_code,
                "final_url": str(resp.url),
                "title": html_title,
                "content_len": len(resp.content),
                "headers": dict(resp.headers),
                "redirect_chain": redirect_chain,
                "timings": {
                    "request_ms": req_ms,
                    "total_ms": total_ms,
                },
            }
            
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
            self.signals.task_error.emit(tid, f"httpx error: {e}")
            self.signals.task_status.emit(tid, "Failed")
        except Exception as e:
            self.signals.task_error.emit(tid, f"Unhandled error: {e}")
            self.signals.task_status.emit(tid, "Failed")
        finally:
            self.signals.task_finished.emit(tid)
