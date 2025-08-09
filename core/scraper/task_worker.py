# core/scraper/task_worker.py
from __future__ import annotations

# === SECTION === Imports & Typing
from typing import Optional
from PySide6.QtCore import QObject, Signal, QThreadPool

from .task_types import ScrapeTask, TaskStatus
from .runnables import ScraperRunnable, WorkerSignals


# === SECTION === Adapter: TaskWorker → ScraperRunnable
class TaskWorker(QObject):
    """
    ЛЕГАСИ-адаптер под старое API "TaskWorker (QThread)".
    Теперь это просто оболочка вокруг ScraperRunnable (QRunnable),
    чтобы:
      - не дублировать сетевую логику,
      - сохранить совместимость с местами, где ждут TaskWorker.
    """

    # Сигналы совпадают с WorkerSignals (пробрасываются 1:1)
    task_log = Signal(str, str, str)      # task_id, level, text
    task_status = Signal(str, str)        # task_id, status_str
    task_progress = Signal(str, int)      # task_id, progress 0..100
    task_result = Signal(str, dict)       # task_id, payload
    task_error = Signal(str, str)         # task_id, error_str
    task_finished = Signal(str)           # task_id

    # === SECTION === Init & State
    def __init__(self, task: ScrapeTask, cookie_manager=None, parent: Optional[QObject] = None):
        """
        cookie_manager оставлен для совместимости, но реальная работа происходит
        внутри ScraperRunnable (там можно расширить поддержку куки при необходимости).
        """
        super().__init__(parent)
        self.task = task
        self.cookie_manager = cookie_manager
        self._pool = QThreadPool.globalInstance()
        self._runnable: Optional[ScraperRunnable] = None

    # === SECTION === Lifecycle
    def start(self) -> None:
        """
        Запуск подкапотного ScraperRunnable в QThreadPool.
        """
        if self._runnable is not None:
            # Уже запущен — игнорируем повторный старт
            return

        # Готовим сигналы и раннабл (в точности как в TaskManager)
        signals = WorkerSignals()
        signals.task_log.connect(self.task_log)
        signals.task_status.connect(self.task_status)
        signals.task_progress.connect(self.task_progress)
        signals.task_result.connect(self.task_result)
        signals.task_error.connect(self.task_error)
        signals.task_finished.connect(self._on_finished)

        self._runnable = ScraperRunnable(self.task, signals)
        self._pool.start(self._runnable)

    def _on_finished(self, task_id: str) -> None:
        # Освобождаем ссылку, отдаём наружу сигнал finished
        try:
            self.task_finished.emit(task_id)
        finally:
            self._runnable = None

    # === SECTION === Cooperative control
    def request_stop(self) -> None:
        if self._runnable:
            self._runnable.request_stop()

    def request_pause(self) -> None:
        if self._runnable:
            self._runnable.request_pause()
            # Сразу пробросим статус в совместимом стиле
            self.task_status.emit(self.task.id, TaskStatus.PAUSED.value if hasattr(TaskStatus, "PAUSED") else "Paused")

    def request_resume(self) -> None:
        if self._runnable:
            self._runnable.request_resume()
            self.task_status.emit(self.task.id, TaskStatus.RUNNING.value)

    # === SECTION === Introspection
    def is_running(self) -> bool:
        return self._runnable is not None
