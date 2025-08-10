# core/scraper/task_manager.py
from __future__ import annotations

# === SECTION === Imports & Typing
from typing import Dict, Optional, Iterable, List
from datetime import datetime
import copy
import uuid

from PySide6.QtCore import QObject, Signal, QThreadPool

from .task_types import ScrapeTask, TaskStatus
from .runnables import WorkerSignals, ScraperRunnable


# === SECTION === TaskManager (proxy signals → UI, state holder)
class TaskManager(QObject):
    # Сигналы наружу (слушает UI-контроллер)
    task_log = Signal(str, str, str)        # (task_id, level, text)
    task_status = Signal(str, str)          # (task_id, status)
    task_progress = Signal(str, int)        # (task_id, progress)
    task_result = Signal(str, dict)         # (task_id, payload)
    task_error = Signal(str, str)           # (task_id, error_str)
    task_reset = Signal(str)                # (task_id)
    task_restarted = Signal(str)            # (task_id)
    task_added = Signal(object)   # Task

    # === SECTION === Init & state
    def __init__(self):
        super().__init__()
        self._tasks: Dict[str, ScrapeTask] = {}
        self._runnables: Dict[str, ScraperRunnable] = {}

        self.pool = QThreadPool.globalInstance()
        self.max_concurrent_tasks = 4
        self.pool.setMaxThreadCount(self.max_concurrent_tasks)

    # === SECTION === Concurrency control
    def set_max_concurrency(self, n: int) -> None:
        """Изменить максимальное число параллельных задач на лету."""
        n = max(1, int(n))
        self.max_concurrent_tasks = n
        self.pool.setMaxThreadCount(n)
        self.task_log.emit("", "INFO", f"Max concurrency set to {n}")

    # === SECTION === CRUD
    def create_task(self, url: str, params: Optional[dict] = None) -> str:
        task = ScrapeTask.new(url, params)
        self._tasks[task.id] = task
        return task.id

    def get_task(self, task_id: str) -> Optional[ScrapeTask]:
        return self._tasks.get(task_id)

    def get_all_tasks(self) -> List[ScrapeTask]:
        return list(self._tasks.values())

    def update_task_params(self, task_id: str, params: dict) -> bool:
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.params = dict(params or {})
        return True

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
    
    def duplicate_tasks(self, task_or_id):
        """
        Клонирует задачу:
        - deep copy
        - новый id и имя "(copy)"
        - сброс статусов/результатов/прогресса
        - добавляет в self._tasks
        - эмитит task_added(new_task)
        """
        # источник
        src = self.get_task(task_or_id) if isinstance(task_or_id, str) else task_or_id
        if src is None:
            raise ValueError("duplicate_task: source task not found")

        new_task = copy.deepcopy(src)

        # новый id/имя
        new_task.id = uuid.uuid4().hex
        if getattr(new_task, "name", None):
            new_task.name = f"{new_task.name} (copy)"

        # сброс состояния
        if hasattr(new_task, "status"):
            new_task.status = TaskStatus.PENDING
        for attr, val in [
            ("result", None),
            ("progress", 0),
            ("error", None),
            ("final_url", None),
            ("status_code", None),
            ("content_len", None),
            ("timings", None),
            ("redirect_chain", None),
            ("headers", None),
            ("started_at", None),
            ("finished_at", None),
        ]:
            if hasattr(new_task, attr):
                setattr(new_task, attr, val)

        # убрать возможные ссылки на раннаблы/потоки
        for attr in ("worker", "runnable", "_future", "_thread"):
            if hasattr(new_task, attr):
                setattr(new_task, attr, None)

        # даты
        if hasattr(new_task, "created_at"):
            new_task.created_at = datetime.utcnow()

        # клон params
        if hasattr(new_task, "params") and new_task.params is not None:
            try:
                new_task.params = copy.deepcopy(new_task.params)
            except Exception:
                pass

        # сохранить
        self._tasks[new_task.id] = new_task

        # уведомить UI
        try:
            self.task_added.emit(new_task)
        except Exception:
            pass

        return new_task

    # === SECTION === Start/Stop (single & bulk)
    def start_task(self, task_id: str) -> bool:
        # Уже бежит?
        if task_id in self._runnables:
            return False
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"No such task: {task_id}")
        # Если уже RUNNING — не дублируем
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

    def start_all(self) -> None:
        for task in self._tasks.values():
            if task.status in (TaskStatus.PENDING, TaskStatus.STOPPED, TaskStatus.FAILED, TaskStatus.DONE):
                self.start_task(task.id)

    def start_selected(self, task_ids: Iterable[str]) -> None:
        for tid in task_ids:
            task = self._tasks.get(tid)
            if not task:
                continue
            if task.status in (TaskStatus.PENDING, TaskStatus.STOPPED, TaskStatus.FAILED, TaskStatus.DONE):
                self.start_task(tid)

    def stop_task(self, task_id: str) -> None:
        """
        Запрашиваем кооперативную остановку.
        ВАЖНО: если задача была на паузе — «будим» её перед стопом, чтобы она вышла из _wait_pause().
        """
        r = self._runnables.get(task_id)
        if r:
            # «Будим» на случай паузы, затем стоп
            try:
                r.request_resume()
            finally:
                r.request_stop()

    def stop_all(self) -> None:
        for tid, r in list(self._runnables.items()):
            try:
                r.request_resume()
            finally:
                r.request_stop()

    # === SECTION === Pause/Resume (single & bulk)
    def pause_task(self, task_id: str) -> None:
        r = self._runnables.get(task_id)
        if r:
            r.request_pause()
            # Синхронизируем локальное состояние задачи (воркер паузу не эмитит)
            task = self._tasks.get(task_id)
            if task:
                task.status = TaskStatus.PAUSED
            self.task_status.emit(task_id, TaskStatus.PAUSED.value)
            self.task_log.emit(task_id, "INFO", "Pause requested")

    def resume_task(self, task_id: str) -> None:
        r = self._runnables.get(task_id)
        if r:
            r.request_resume()
            task = self._tasks.get(task_id)
            if task:
                task.status = TaskStatus.RUNNING
                if task.started_at is None:
                    task.started_at = datetime.utcnow()
            self.task_status.emit(task_id, TaskStatus.RUNNING.value)
            self.task_log.emit(task_id, "INFO", "Resume requested")

    def pause_all(self) -> None:
        for tid, r in list(self._runnables.items()):
            r.request_pause()
            task = self._tasks.get(tid)
            if task:
                task.status = TaskStatus.PAUSED
            self.task_status.emit(tid, TaskStatus.PAUSED.value)
        self.task_log.emit("", "INFO", "Pause requested for all active tasks")

    def resume_all(self) -> None:
        for tid, r in list(self._runnables.items()):
            r.request_resume()
            task = self._tasks.get(tid)
            if task:
                task.status = TaskStatus.RUNNING
                if task.started_at is None:
                    task.started_at = datetime.utcnow()
            self.task_status.emit(tid, TaskStatus.RUNNING.value)
        self.task_log.emit("", "INFO", "Resume requested for all active tasks")

    # === SECTION === Reset/Restart
    def reset_task(self, task_id: str) -> bool:
        """
        Сбрасывает задачу в PENDING и очищает прогресс/результат.
        Если задача запущена — останавливает перед сбросом.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        # если запущена — корректно останавливаем
        try:
            if getattr(task, "status", None) in (TaskStatus.RUNNING, TaskStatus.PAUSED):
                self.stop_task(task_id)
        except Exception:
            pass

        # Обнуляем поля
        task.status = TaskStatus.PENDING
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

    def restart_selected_tasks(self, task_ids: Iterable[str]) -> None:
        """Перезапуск нескольких задач."""
        for tid in task_ids:
            self.restart_task(tid)

    # === SECTION === Worker callbacks
    def _on_worker_status(self, task_id: str, status_str: str) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        # Нормализуем в enum (ожидаем точные строки из воркера)
        try:
            task.status = TaskStatus(status_str)
        except ValueError:
            # Если пришло неожиданное значение — прокинем как есть, но в лог отметим.
            self.task_log.emit(task_id, "WARN", f"Unknown status from worker: {status_str}")
            # Не падаем и просто транслируем
        # Таймстемпы
        if task.status == TaskStatus.RUNNING and task.started_at is None:
            task.started_at = datetime.utcnow()
        if task.status in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.STOPPED):
            task.finished_at = datetime.utcnow()
        # Проксируем наружу (UI)
        self.task_status.emit(task_id, status_str)

    def _on_worker_finished(self, task_id: str) -> None:
        # Воркер завершился — удаляем его из реестра
        self._runnables.pop(task_id, None)

    # === SECTION === Introspection & shutdown
    def is_running(self, task_id: str) -> bool:
        return task_id in self._runnables

    def active_task_ids(self) -> List[str]:
        return list(self._runnables.keys())

    def is_idle(self) -> bool:
        return not self._runnables

    def shutdown(self, timeout_ms: int = 5000) -> dict:
        """
        Мягкая остановка всех раннаблов и ожидание завершения пула.
        Возвращает summary для логов.
        """
        summary = {"stopped": 0, "joined": 0, "left": []}
        if self._runnables:
            for tid, r in list(self._runnables.items()):
                try:
                    r.request_resume()   # на случай паузы
                finally:
                    r.request_stop()
            summary["stopped"] = len(self._runnables)

        self.pool.waitForDone(timeout_ms)
        summary["left"] = list(self._runnables.keys())
        summary["joined"] = summary["stopped"] - len(summary["left"])
        return summary
