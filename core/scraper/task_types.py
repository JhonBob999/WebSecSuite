# core/scraper/task_types.py
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Any, Dict, Optional
import uuid


class TaskStatus(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    DONE = "Done"
    ERROR = "Error"
    STOPPED = "Stopped"
    FAILED = "Failed"


@dataclass
class ScrapeTask:
    id: str
    url: str
    method: str = "GET"
    headers: Dict[str, Any] = field(default_factory=dict)
    user_agent: str = ""
    proxy: str = ""  # формат: http://user:pass@host:port или socks5://host:port
    timeout: float = 15.0
    retries: int = 2

    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_error: Optional[str] = None
    result_path: Optional[str] = None
    progress: int = 0
    result: Optional[dict] = None

    @staticmethod
    def new(url: str, params: Optional[Dict[str, Any]] = None) -> "ScrapeTask":
        params = params or {}
        return ScrapeTask(
            id=str(uuid.uuid4()),
            url=url,
            method=params.get("method", "GET"),
            headers=params.get("headers", {}),
            user_agent=params.get("user_agent", ""),
            proxy=params.get("proxy", ""),
            timeout=params.get("timeout", 15.0),
            retries=params.get("retries", 2),
        )

