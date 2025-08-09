# core/scraper/task_types.py
from __future__ import annotations

# === SECTION === Imports & Typing
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Any, Dict, Optional
import uuid


# === SECTION === Status Enum
class TaskStatus(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    PAUSED  = "Paused"   # добавлено
    DONE    = "Done"
    ERROR   = "Error"    # оставляем для совместимости (если где-то используется)
    FAILED  = "Failed"
    STOPPED = "Stopped"


# === SECTION === Dataclass: ScrapeTask
@dataclass
class ScrapeTask:
    # --- identity & target ---
    id: str
    url: str

    # --- request params (top-level, синхронизируются с .params) ---
    method: str = "GET"
    headers: Dict[str, Any] = field(default_factory=dict)
    user_agent: str = ""
    proxy: str = ""              # "http://user:pass@host:port" или "socks5://host:port"
    timeout: float = 15.0
    retries: int = 2

    # --- runtime state ---
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_error: Optional[str] = None
    progress: int = 0

    # --- results ---
    result: Optional[Dict[str, Any]] = None
    result_path: Optional[str] = None
    cookies_path: Optional[str] = None  # опционально: путь к файлу cookies (если используем)

    # --- raw params (источник правды для UI/пресетов) ---
    params: Dict[str, Any] = field(default_factory=dict)

    # === SECTION === Lifecycle
    def __post_init__(self) -> None:
        """
        Если в конструктор уже подали params, применяем их к верхним полям,
        чтобы раннабл видел актуальные значения.
        """
        if self.params:
            self.apply_params(self.params)

        # авто‑вставка User-Agent в headers, если задан user_agent
        if self.user_agent:
            hk = next((k for k in self.headers.keys() if k.lower() == "user-agent"), None)
            if hk is None:
                # не перетираем, если уже есть в headers
                self.headers["User-Agent"] = self.user_agent

    # === SECTION === Public API
    @staticmethod
    def new(url: str, params: Optional[Dict[str, Any]] = None) -> "ScrapeTask":
        """
        Фабрика новой задачи. params может содержать:
        method, headers, user_agent, proxy, timeout, retries (+ любые будущие поля).
        """
        p = dict(params or {})
        task = ScrapeTask(
            id=str(uuid.uuid4()),
            url=url,
            params=p,  # положим как есть; __post_init__ вызовет apply_params
        )
        return task

    def apply_params(self, params: Optional[Dict[str, Any]] = None) -> None:
        """
        Применяет словарь параметров (и сохраняет его в self.params),
        синхронизируя верхнеуровневые поля (method/headers/user_agent/…).
        """
        if params is not None:
            self.params = dict(params or {})

        self.method    = self.params.get("method", self.method or "GET")
        self.headers   = dict(self.params.get("headers", self.headers or {}))
        self.user_agent = self.params.get("user_agent", self.user_agent or "")
        self.proxy     = self.params.get("proxy", self.proxy or "")
        self.timeout   = self.params.get("timeout", self.timeout if self.timeout is not None else 15.0)
        self.retries   = self.params.get("retries", self.retries if self.retries is not None else 2)

        # user-agent → headers, если явно задан
        if self.user_agent:
            hk = next((k for k in self.headers.keys() if k.lower() == "user-agent"), None)
            if hk is None:
                self.headers["User-Agent"] = self.user_agent

    def to_params(self) -> Dict[str, Any]:
        """
        Возвращает «актуальные» параметры запроса как словарь — удобно для пресетов/экспорта.
        """
        out = dict(self.params)  # базироваться на исходном
        out.update({
            "method": self.method,
            "headers": dict(self.headers),
            "user_agent": self.user_agent,
            "proxy": self.proxy,
            "timeout": self.timeout,
            "retries": self.retries,
        })
        return out

    # === SECTION === Helpers
    def reset_runtime(self) -> None:
        """Сбрасывает прогресс/результат и временные метки без изменения целевых параметров."""
        self.status = TaskStatus.PENDING
        self.progress = 0
        self.result = None
        self.last_error = None
        self.started_at = None
        self.finished_at = None

    def is_terminal(self) -> bool:
        return self.status in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.STOPPED, TaskStatus.ERROR)

    def is_running(self) -> bool:
        return self.status == TaskStatus.RUNNING
