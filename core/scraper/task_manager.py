# core/scraper/task_manager.py
from __future__ import annotations
from PySide6.QtCore import QObject, Signal, QThreadPool
from typing import Dict, Optional

from .task_types import ScrapeTask, TaskStatus
from .runnables import WorkerSignals, ScraperRunnable


class TaskManager(QObject):
    # Пробрасываем события вверх (в контроллер UI)
    task_log = Signal(str, str, str)        # (task_id, level, text)
    task_status = Signal(str, str)          # (task_id, status)
    task_progress = Signal(str, int)        # (task_id, progress)
    task_result = Signal(str, dict)         # (task_id, payload)
    task_error = Signal(str, str)           # (task_id, error_str)
    task_reset = Signal(str)            # task_id , reset
    task_restarted = Signal(str)        # task_id , restart all selected

    def __init__(self):
        super().__init__()
        self._tasks: Dict[str, ScrapeTask] = {}
        self.pool = QThreadPool.globalInstance()
        self.max_concurrent_tasks = 4
        self.pool.setMaxThreadCount(self.max_concurrent_tasks)

        self._runnables: Dict[str, ScraperRunnable] = {}


    # ---------- CRUD задач ----------
    def create_task(self, url: str, params: Optional[dict] = None) -> str:
        task = ScrapeTask.new(url, params)
        self._tasks[task.id] = task
        return task.id

    def get_task(self, task_id: str):
        return self._tasks.get(task_id)

    def get_all_tasks(self):
        return list(self._tasks.values())
    
    def update_task_params(self, task_id: str, params: dict) -> bool:
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.params = dict(params or {})
        return True

    # ---------- Управление исполнением ----------


    # ---------- Управление исполнением ----------
    def start_all(self) -> None:
        for task in self._tasks.values():
            if task.status in (TaskStatus.PENDING, TaskStatus.STOPPED, TaskStatus.FAILED, TaskStatus.DONE):
                self.start_task(task.id)

    def start_task(self, task_id: str) -> bool:
        # уже бежит?
        if task_id in self._runnables:
            return False
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"No such task: {task_id}")
        # если уже RUNNING — не дублируем
        if getattr(task, "status", None) == TaskStatus.RUNNING:
            return False

        # Готовим сигналы и раннабл
        signals = WorkerSignals()
        signals.task_log.connect(self.task_log)
        signals.task_status.connect(self._on_worker_status)
        signals.task_progress.connect(self.task_progress)
        signals.task_result.connect(self.task_result)
        signals.task_error.connect(self.task_error)
        signals.task_finished.connect(self._on_worker_finished)

        runnable = ScraperRunnable(task, signals)
        self._runnables[task_id] = runnable

        self.pool.start(runnable)
        return True


    def stop_task(self, task_id: str) -> None:
        r = self._runnables.get(task_id)
        if r:
            r.request_stop()

    def stop_all(self) -> None:
        for r in list(self._runnables.values()):
            r.request_stop()

            
    def reset_task(self, task_id: str) -> bool:
        """Сбрасывает задачу в состояние PENDING, очищает прогресс/результат.
           Если задача запущена — останавливает перед сбросом.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        # если запущена — корректно останавливаем
        try:
            if getattr(task, "status", None) == TaskStatus.PENDING:
                self.stop_task(task_id)
        except Exception:
            pass

        # Обнуляем поля
        task.status = "Pending"
        task.progress = 0
        task.result = None
        task.error = None
        task.started_at = None
        task.finished_at = None
        
        self._runnables.pop(task_id, None)  # на всякий случай убрать ссылку
        self.task_reset.emit(task_id)
        return True


    def restart_task(self, task_id: str) -> bool:
        """Сбрасывает и сразу запускает задачу."""
        if not self.reset_task(task_id):
            return False
        ok = self.start_task(task_id)
        if ok:
            self.task_restarted.emit(task_id)
        return ok

    def restart_selected_tasks(self, task_ids) -> None:
        """Перезапуск нескольких задач."""
        for tid in task_ids:
            self.restart_task(tid)

    # ---------- Внутренние обработчики ----------
    def _on_worker_status(self, task_id: str, status_str: str) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        task.status = TaskStatus(status_str)
        if task.status == TaskStatus.RUNNING and task.started_at is None:
            from datetime import datetime
            task.started_at = datetime.utcnow()
        if task.status in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.STOPPED):
            from datetime import datetime
            task.finished_at = datetime.utcnow()
        self.task_status.emit(task_id, status_str)

    def _on_worker_finished(self, task_id: str) -> None:
        # раннабл сам завершился — убираем из реестра
        self._runnables.pop(task_id, None)


    def is_running(self, task_id: str) -> bool:
        return task_id in self._runnables


    def remove_task(self, task_id: str) -> bool:
        # если бежит — мягко останавливаем
        if task_id in self._runnables:
            self.stop_task(task_id)
        existed = self._tasks.pop(task_id, None) is not None
        self._runnables.pop(task_id, None)
        try:
            self.task_log.emit(task_id, "INFO", "Task removed")
        except Exception:
            pass
        return existed

    
    # Контроль Тредов и Потоков для безопасного завершения
    
    def active_task_ids(self):
        return list(self._runnables.keys())

    def is_idle(self) -> bool:
        return not self._runnables

    def shutdown(self, timeout_ms: int = 5000) -> dict:
        summary = {"stopped": 0, "joined": 0, "left": []}
        if self._runnables:
            for r in list(self._runnables.values()):
                r.request_stop()
            summary["stopped"] = len(self._runnables)

        self.pool.waitForDone(timeout_ms)  # без if
        summary["left"] = list(self._runnables.keys())
        summary["joined"] = summary["stopped"] - len(summary["left"])
        return summary
