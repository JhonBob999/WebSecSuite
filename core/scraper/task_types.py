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


@dataclass
class ScrapeTask:
    id: str
    url: str
    params: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_error: Optional[str] = None
    result_path: Optional[str] = None
    progress: int = 0

    @staticmethod
    def new(url: str, params: Optional[Dict[str, Any]] = None) -> "ScrapeTask":
        return ScrapeTask(
            id=str(uuid.uuid4()),
            url=url,
            params=params or {},
        )
