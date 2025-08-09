# core/scraper/task_worker.py
from __future__ import annotations
from PySide6.QtCore import QObject, Signal, Slot, QThread
from time import sleep
from typing import Dict, Any

from .task_types import ScrapeTask, TaskStatus


class TaskWorker(QObject):
    # Сигналы наружу (обязательно только типы, без сложных объектов Qt)
    sig_log = Signal(str, str, str)        # (task_id, level, text)
    sig_status = Signal(str, str)          # (task_id, status)
    sig_progress = Signal(str, int)        # (task_id, progress 0..100)
    sig_result = Signal(str, dict)         # (task_id, payload/result)
    sig_error = Signal(str, str)           # (task_id, error_str)
    sig_finished = Signal(str)             # (task_id) — закончена работа (успешно/остановка/ошибка)

    def __init__(self, task: ScrapeTask):
        super().__init__()
        self._task = task
        self._should_stop = False

    @Slot()
    def run(self) -> None:
        """Основной цикл работы — тут имитация 'запросов' с прогрессом."""
        print(f"DEBUG: воркер стартовал для {self._task.url}")
        task_id = self._task.id
        try:
            self.sig_status.emit(task_id, TaskStatus.RUNNING.value)
            self.sig_log.emit(task_id, "INFO", f"Started: {self._task.url}")

            total_steps = 20
            for i in range(total_steps + 1):
                if self._should_stop:
                    self.sig_log.emit(task_id, "WARN", "Stop requested. Cleaning up…")
                    self.sig_status.emit(task_id, TaskStatus.STOPPED.value)
                    self.sig_finished.emit(task_id)
                    return

                # имитация “работы”
                sleep(0.4)
                progress = int(i * 100 / total_steps)
                self.sig_progress.emit(task_id, progress)
                if i % 5 == 0:
                    self.sig_log.emit(task_id, "INFO", f"Processing step {i}/{total_steps}…")

            # Результат мок‑обработки
            payload: Dict[str, Any] = {"url": self._task.url, "content_len": 12345}
            self.sig_result.emit(task_id, payload)
            self.sig_status.emit(task_id, TaskStatus.DONE.value)
            self.sig_log.emit(task_id, "INFO", "Done.")
            self.sig_finished.emit(task_id)

        except Exception as e:
            self.sig_error.emit(task_id, str(e))
            self.sig_status.emit(task_id, TaskStatus.ERROR.value)
            self.sig_finished.emit(task_id)

    def request_stop(self) -> None:
        """Гладкая остановка."""
        self._should_stop = True
