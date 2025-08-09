# core/scraper/task_worker.py
from __future__ import annotations
import re
import time
import json
from dataclasses import asdict
from typing import Optional, Dict, Any

from PySide6.QtCore import QObject, QThread, Signal
import httpx

from .task_types import ScrapeTask, TaskStatus

TITLE_RE = re.compile(br"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class TaskWorker(QThread):
    # Предполагаю, что сигналы объявлены тут (может быть у тебя иначе — адаптируй)
    task_log = Signal(str, str, str)      # task_id, level, text
    task_status = Signal(str, str)        # task_id, status_str
    task_progress = Signal(str, int)      # task_id, progress 0..100
    task_result = Signal(str, dict)       # task_id, payload
    task_error = Signal(str, str)         # task_id, error_str
    task_finished = Signal(str)           # task_id

    def __init__(self, task: ScrapeTask, cookie_manager=None, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.task = task
        self._should_stop = False
        self._paused = False
        self.cookie_manager = cookie_manager  # если уже есть у тебя менеджер

    # --- контроль выполнения ---
    def request_stop(self):
        self._should_stop = True

    def should_stop(self) -> bool:
        return self._should_stop

    # (пауза добавим позже)
    # def request_pause(self): self._paused = True
    # def resume(self): self._paused = False

    # --- утилиты логов ---
    def log(self, level: str, msg: str):
        self.task_log.emit(self.task.id, level, msg)

    def set_status(self, status: TaskStatus):
        self.task.status = status
        self.task_status.emit(self.task.id, status.value)

    def set_progress(self, value: int):
        self.task.progress = value
        self.task_progress.emit(self.task.id, value)

    # --- HTTP клиент ---
    def _build_client(self) -> httpx.Client:
        headers = dict(self.task.headers or {})
        if self.task.user_agent and "user-agent" not in {k.lower(): v for k, v in headers.items()}:
            headers["User-Agent"] = self.task.user_agent

        proxies = None
        if self.task.proxy:
            # поддержка http/https/socks5://user:pass@host:port
            proxies = {
                "http": self.task.proxy,
                "https": self.task.proxy,
            }

        timeout = httpx.Timeout(self.task.timeout or 15.0)

        # Cookies: если будешь подтягивать доменные cookies через cookie_manager
        jar = None
        if self.cookie_manager is not None:
            try:
                jar = self.cookie_manager.load_for_url(self.task.url)  # ожидаем dict[str, str] или httpx.Cookies
            except Exception:
                jar = None

        client = httpx.Client(
            headers=headers,
            proxy=proxies,
            timeout=timeout,
            follow_redirects=True,
            cookies=jar
        )
        return client

    def _short_headers(self, headers: httpx.Headers) -> Dict[str, str]:
        # Обрезаем/нормализуем для сохранения
        allow = {"server", "content-type", "content-length", "date", "via", "x-powered-by", "cf-ray"}
        out = {}
        for k, v in headers.items():
            if k.lower() in allow:
                out[k] = v
        return out

    def _extract_title(self, content: bytes) -> Optional[str]:
        m = TITLE_RE.search(content)
        if not m:
            return None
        try:
            title_bytes = m.group(1).strip()
            # примитивная попытка декодирования
            for enc in ("utf-8", "windows-1251", "latin-1"):
                try:
                    return title_bytes.decode(enc, errors="ignore").strip()
                except Exception:
                    continue
        except Exception:
            pass
        return None

    # --- основная логика ---
    def run(self):
        t0 = time.perf_counter()
        self.set_status(TaskStatus.RUNNING)
        self.set_progress(0)
        self.log("INFO", f"Started: {self.task.url}")

        try:
            with self._build_client() as client:
                # Прогресс: resolving
                if self.should_stop(): raise RuntimeError("Stopped")
                self.set_progress(5)

                # Ретраи
                attempts = int(self.task.retries or 0) + 1
                backoff = 0.5
                last_exc = None

                for attempt in range(1, attempts + 1):
                    if self.should_stop(): raise RuntimeError("Stopped")

                    try:
                        self.log("INFO", f"Request ({attempt}/{attempts}) {self.task.method} {self.task.url}")
                        t_req = time.perf_counter()
                        resp = client.request(
                            self.task.method or "GET",
                            self.task.url,
                            data=self.task.body if hasattr(self.task, "body") else None
                        )
                        t_resp = time.perf_counter()

                        # Прогресс: response
                        self.set_progress(50)

                        # Разбор результата
                        content = resp.content or b""
                        title = self._extract_title(content)
                        payload = {
                            "status_code": resp.status_code,
                            "final_url": str(resp.url),
                            "headers": self._short_headers(resp.headers),
                            "content_len": len(content),
                            "title": title,
                            "timings": {
                                "request_ms": int((t_resp - t_req) * 1000),
                                "total_ms": int((time.perf_counter() - t0) * 1000),
                            },
                        }

                        # Сохраним cookies, если менеджер есть
                        if self.cookie_manager is not None:
                            try:
                                self.cookie_manager.save_for_url(self.task.url, client.cookies)
                            except Exception:
                                pass

                        # Прогресс: parse→done
                        self.set_progress(90)
                        self.task.result = payload
                        self.set_progress(100)
                        self.set_status(TaskStatus.DONE)
                        self.task_result.emit(self.task.id, payload)
                        self.log("INFO", "Done.")
                        self.task_finished.emit(self.task.id)
                        return

                    except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.ConnectError, httpx.HTTPError) as e:
                        last_exc = e
                        self.log("WARN", f"{type(e).__name__}: {e}")
                        if attempt < attempts:
                            self.log("INFO", f"Retry in {backoff:.1f}s…")
                            self.set_progress(min(80, 10 + attempt * 10))
                            time.sleep(backoff)
                            backoff *= 2
                            continue
                        else:
                            raise

                # Если внезапно вышли из цикла без return/raise
                raise RuntimeError(f"Request failed: {last_exc}")

        except Exception as e:
            if str(e) == "Stopped":
                self.set_status(TaskStatus.STOPPED)
                self.log("INFO", "Stopped by user.")
            else:
                self.set_status(TaskStatus.FAILED)
                self.task_error.emit(self.task.id, f"{type(e).__name__}: {e}")
                self.log("ERROR", f"{type(e).__name__}: {e}")
        finally:
            self.task_finished.emit(self.task.id)
