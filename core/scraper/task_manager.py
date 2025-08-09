# core/scraper/task_manager.py
from __future__ import annotations
from PySide6.QtCore import QObject, Signal, QThread
from typing import Dict, Optional, Iterable

from .task_types import ScrapeTask, TaskStatus
from .task_worker import TaskWorker


class TaskManager(QObject):
    # Пробрасываем события вверх (в контроллер UI)
    task_log = Signal(str, str, str)        # (task_id, level, text)
    task_status = Signal(str, str)          # (task_id, status)
    task_progress = Signal(str, int)        # (task_id, progress)
    task_result = Signal(str, dict)         # (task_id, payload)
    task_error = Signal(str, str)           # (task_id, error_str)

    def __init__(self):
        super().__init__()
        self._tasks: Dict[str, ScrapeTask] = {}
        self._threads: Dict[str, QThread] = {}
        self._workers: Dict[str, TaskWorker] = {}

    # ---------- CRUD задач ----------
    def create_task(self, url: str, params: Optional[dict] = None) -> str:
        task = ScrapeTask.new(url, params)
        self._tasks[task.id] = task
        return task.id

    def get_task(self, task_id: str) -> Optional[ScrapeTask]:
        return self._tasks.get(task_id)

    def tasks(self) -> Iterable[ScrapeTask]:
        return list(self._tasks.values())

    # ---------- Управление исполнением ----------
    def start_task(self, task_id: str) -> None:
        if task_id in self._threads:
            # уже запущена
            return
        task = self._tasks.get(task_id)
        if not task:
            return

        # Подготовка воркера и треда
        worker = TaskWorker(task)
        thread = QThread()
        worker.moveToThread(thread)

        # Проброс сигналов воркера -> менеджер
        worker.sig_log.connect(self.task_log)
        worker.sig_status.connect(self._on_worker_status)
        worker.sig_progress.connect(self.task_progress)
        worker.sig_result.connect(self.task_result)
        worker.sig_error.connect(self.task_error)
        worker.sig_finished.connect(self._on_worker_finished)

        # Старт/стоп связка
        thread.started.connect(worker.run)

        # Запоминаем ссылки (чтобы не освободило GC)
        self._workers[task_id] = worker
        self._threads[task_id] = thread

        # Запуск
        thread.start()

    def start_all(self) -> None:
        for task in self._tasks.values():
            if task.status in (TaskStatus.PENDING, TaskStatus.STOPPED, TaskStatus.ERROR, TaskStatus.DONE):
                # Разрешим повторный запуск с любого статуса, кроме RUNNING
                self.start_task(task.id)

    def stop_task(self, task_id: str) -> None:
        worker = self._workers.get(task_id)
        if worker:
            worker.request_stop()

    def stop_all(self) -> None:
        for task_id in list(self._workers.keys()):
            self.stop_task(task_id)

    # ---------- Внутренние обработчики ----------
    def _on_worker_status(self, task_id: str, status_str: str) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        task.status = TaskStatus(status_str)
        if task.status == TaskStatus.RUNNING and task.started_at is None:
            from datetime import datetime
            task.started_at = datetime.utcnow()
        if task.status in (TaskStatus.DONE, TaskStatus.ERROR, TaskStatus.STOPPED):
            from datetime import datetime
            task.finished_at = datetime.utcnow()
        self.task_status.emit(task_id, status_str)

    def _on_worker_finished(self, task_id: str) -> None:
        # Отключаем и очищаем тред/воркер
        thread = self._threads.pop(task_id, None)
        worker = self._workers.pop(task_id, None)
        if thread:
            thread.quit()
            thread.wait()
            thread.deleteLater()
        # worker удалится сборщиком мусора

    # Удобный хелпер (не обязателен, пригодится позже)
    def is_running(self, task_id: str) -> bool:
        return task_id in self._threads
