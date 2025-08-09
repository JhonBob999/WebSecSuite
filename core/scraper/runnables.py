# core/scraper/runnables.py
from __future__ import annotations

# === SECTION === Imports & Typing
import time
import threading
from typing import Any, Dict, List, Optional

import httpx
from PySide6.QtCore import QObject, Signal, QRunnable

from utils.html_utils import extract_title


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
    """
    Исполняемая задача парсинга/запроса.
    Ожидается, что self.task имеет поля: id, url, method, headers, proxy, timeout, ...
    """

    # --- Lifecycle ---
    def __init__(self, task: Any, signals: WorkerSignals):
        super().__init__()
        self.task = task
        self.signals = signals

        # Кооперативные флаги
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # set = разрешено выполнять

    # --- Cooperative control API (called by TaskManager) ---
    def request_stop(self) -> None:
        self._stop_event.set()

    def request_pause(self) -> None:
        self._pause_event.clear()

    def request_resume(self) -> None:
        self._pause_event.set()

    # --- Internal helpers ---
    def _check_stop(self, tid: str) -> bool:
        """Возвращает True, если нужно прекратить выполнение прямо сейчас."""
        if self._stop_event.is_set():
            self.signals.task_status.emit(tid, "Stopped")
            self.signals.task_log.emit(tid, "INFO", "Stopped cooperatively")
            return True
        return False

    def _wait_pause(self, tid: str, ping_sec: float = 3.0) -> None:
        """
        Ожидаем выхода из паузы. Каждые ping_sec шлём INFO лог.
        Не блокируем UI — это в пуле.
        """
        last_ping = time.perf_counter()
        while not self._pause_event.is_set():
            time.sleep(0.05)
            now = time.perf_counter()
            if now - last_ping >= ping_sec:
                self.signals.task_log.emit(tid, "INFO", "Paused…")
                last_ping = now

    # --- Main entry point ---
    def run(self) -> None:
        tid = getattr(self.task, "id", "")
        url = getattr(self.task, "url", "")
        method = (getattr(self.task, "method", None) or "GET").upper()
        headers = getattr(self.task, "headers", None) or {}
        proxy = getattr(self.task, "proxy", None) or None
        timeout = getattr(self.task, "timeout", None)

        self.signals.task_status.emit(tid, "Running")
        self.signals.task_progress.emit(tid, 0)
        t0_total = time.perf_counter()

        try:
            # Кооперативная остановка / пауза до старта запроса
            if self._check_stop(tid):
                self.signals.task_finished.emit(tid)
                return
            self._wait_pause(tid)

            # Лог запроса
            self.signals.task_log.emit(tid, "INFO", f"Request {method} {url}")

            # === HTTP request ===
            # httpx >= 0.28: используем proxy= и follow_redirects=True
            # Если нужен verify=False/клиентские сертификаты — добавим позже через params.
            t0_req = time.perf_counter()
            with httpx.Client(timeout=timeout, headers=headers, proxy=proxy, follow_redirects=True) as client:
                resp = client.request(method, url)
            req_ms = int((time.perf_counter() - t0_req) * 1000)

            # Кооперативные пауза/стоп после запроса
            if self._check_stop(tid):
                self.signals.task_finished.emit(tid)
                return
            self._wait_pause(tid)

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

            # Последняя проверка остановки перед эмитом
            if self._check_stop(tid):
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
