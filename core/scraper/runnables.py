from PySide6.QtCore import QObject, Signal, QRunnable
from utils.html_utils import extract_title
import time, httpx, threading, requests

class WorkerSignals(QObject):
    task_log = Signal(str, str, str)      # task_id, level, text
    task_status = Signal(str, str)        # task_id, status_str
    task_progress = Signal(str, int)      # task_id, progress 0..100
    task_result = Signal(str, dict)       # task_id, payload
    task_error = Signal(str, str)         # task_id, error_str
    task_finished = Signal(str)           # task_id


class ScraperRunnable(QRunnable):
    def __init__(self, task, signals: WorkerSignals):
        super().__init__()
        self.task = task                 # твой ScrapeTask (id, url, headers, proxy, timeout, retries, cookies_path, ...)
        self.signals = signals
        # Флаги для Stop/Pause (pause будем включать позже)
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()  # по умолчанию не паузим
        self._pause_event.set()                # set = разрешено выполнять
        

    # публичные методы для TaskManager:
    def request_stop(self): self._stop_event.set()

    def request_pause(self): self._pause_event.clear()
        
    def request_resume(self): self._pause_event.set()
        
    # Запуск     
    def run(self):
        tid = self.task.id
        self.signals.task_status.emit(tid, "Running")
        self.signals.task_progress.emit(tid, 0)
        t0 = time.perf_counter()

        try:
            # кооперативная остановка
            if self._stop_event.is_set():
                self.signals.task_status.emit(tid, "Stopped")
                self.signals.task_finished.emit(tid)
                return

            # пауза (если будет включена)
            self._pause_event.wait()

            method  = (getattr(self.task, "method", None) or "GET").upper()
            headers = getattr(self.task, "headers", None) or {}
            proxy   = getattr(self.task, "proxy", None) or None
            timeout = getattr(self.task, "timeout", None)

            self.signals.task_log.emit(tid, "INFO", f"Request {method} {self.task.url}")

            with httpx.Client(timeout=timeout, headers=headers, proxy=proxy, follow_redirects=True) as client:
                resp = client.request(method, self.task.url)

                # цепочка редиректов
                redirect_chain = [
                    {
                        "status_code": r.status_code,
                        "url": str(r.url),
                        "location": r.headers.get("Location")
                    }
                    for r in resp.history
                ]

                self.signals.task_progress.emit(tid, 50)

                # аналитика ответа
                html_title = extract_title(resp.text)
                result = {
                    "url": self.task.url,
                    "status_code": resp.status_code,
                    "title": html_title,
                    "content_length": len(resp.content),
                    "elapsed_request_ms": int((resp.elapsed.total_seconds() if resp.elapsed else 0) * 1000),
                    "headers": dict(resp.headers),
                    "redirect_chain": redirect_chain,
                }

            if self._stop_event.is_set():
                self.signals.task_status.emit(tid, "Stopped")
                self.signals.task_log.emit(tid, "INFO", "Stopped before emitting result")
            else:
                # логируем редиректы (если были)
                if result["redirect_chain"]:
                    for step in result["redirect_chain"]:
                        self.signals.task_log.emit(tid, "INFO", f"Redirect {step['status_code']} → {step['url']}")

                self.signals.task_result.emit(tid, result)
                self.signals.task_status.emit(tid, "Done")
                self.signals.task_progress.emit(tid, 100)
                self.signals.task_log.emit(tid, "INFO", f"Done {self.task.url} ({result['status_code']})")

        except Exception as e:
            self.signals.task_error.emit(tid, str(e))
            self.signals.task_status.emit(tid, "Failed")
        finally:
            self.signals.task_finished.emit(tid)