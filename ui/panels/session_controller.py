# ui/panels/session_controller.py
from __future__ import annotations

# === SECTION === Imports & Typing
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QDateTime
from PySide6.QtWidgets import QFileDialog, QMessageBox, QTableWidgetSelectionRange

from core.paths import project_root
from core.scraper.task_types import ScrapeTask, TaskStatus
from core.session_persistence import (
    build_scraper_session,
    extract_annotation_store,
    load_session,
    save_session,
    session_contains_sensitive_data,
    validate_session_data,
)
from ui.constants import Col


# === SECTION === SessionController
class SessionController:
    """
    Session save/load for the scraper tab: snapshotting tasks into a
    session dict, writing/reading the session JSON file, and restoring the
    task table + task_manager state from a loaded session.

    Extracted from ScraperTabController (was 18 inline methods there).
    Follows the same constructor shape as ScraperActions (parent/table_ctl/
    task_manager/log_panel) so it plugs into the existing composition
    instead of inventing a new wiring style.
    """

    def __init__(self, parent, table_ctl, task_manager, log_panel):
        self.parent = parent
        self.table_ctl = table_ctl
        self.task_manager = task_manager
        self.log_panel = log_panel

    # === SECTION === Snapshot building (save)
    def collect_snapshot(self) -> dict:
        table = self.table_ctl.table
        current_row = table.currentRow()
        selected_task_id = self.table_ctl.task_id_by_row(current_row) if current_row >= 0 else None
        tasks = []

        for row in range(table.rowCount()):
            task_id = self.table_ctl.task_id_by_row(row)
            if not task_id:
                continue

            task = self.task_manager.get_task(task_id)
            if not task:
                continue

            url_item = table.item(row, Col.URL)
            status_item = table.item(row, Col.Status)
            task_status = getattr(task, "status", None)
            task_result = getattr(task, "result", None)
            fallback_result = (
                self.parent.task_results.get(task_id)
                if isinstance(self.parent.task_results, dict)
                else None
            )
            result_payload = task_result if task_result is not None else fallback_result
            status_text = self._session_status_text(task_status, status_item.text() if status_item else "")

            tasks.append({
                "id": str(getattr(task, "id", task_id) or task_id),
                "url": str(getattr(task, "url", "") or (url_item.text() if url_item else "")),
                "params": self._session_task_params(task),
                "status": status_text,
                "progress": self._session_snapshot_progress(
                    getattr(task, "progress", 0),
                    status_text=status_text,
                    result=result_payload,
                    task=task,
                ),
                "created_at": getattr(task, "created_at", None),
                "result": deepcopy(result_payload) if result_payload is not None else None,
            })

        return build_scraper_session(
            tasks=tasks,
            selected_task_id=selected_task_id,
            current_row=current_row,
            annotation_store=self.parent.annotation_store,
        )

    def _session_task_params(self, task) -> dict:
        try:
            params = task.to_params()
        except Exception:
            params = getattr(task, "params", {}) or {}
        return deepcopy(dict(params or {})) if isinstance(params, dict) else {}

    def _session_status_text(self, status, fallback: str = "") -> str:
        if hasattr(status, "value"):
            return str(status.value)
        if status:
            return str(status)
        return str(fallback or "")

    def _session_progress_value(self, value) -> int:
        try:
            return max(0, min(100, int(value)))
        except Exception:
            return 0

    def _session_snapshot_progress(self, value, *, status_text: str = "", result=None, task=None) -> int:
        progress = self._session_progress_value(value)
        if progress >= 100:
            return 100

        status_key = self._session_status_key(status_text)
        if status_key in {"done", "ok", "success", "successful", "completed", "complete"}:
            return 100
        if status_key in {"pending", "stopped", "notrun", "not run", "running", "paused", "failed", "error"}:
            return progress

        if self._session_result_looks_successful(result) and getattr(task, "finished_at", None):
            return 100
        return progress

    def _session_status_key(self, status_text: str) -> str:
        text = str(status_text or "").strip()
        if text.startswith("TaskStatus."):
            text = text.split(".", 1)[1]
        text = re.sub(r"\s+\d{1,3}%?$", "", text).strip()
        return text.strip().lower().replace("_", " ")

    def _session_result_looks_successful(self, result) -> bool:
        if not result:
            return False
        if isinstance(result, dict):
            if result.get("error") or result.get("last_error"):
                return False
            status = result.get("status") or result.get("result_status")
            if status and self._session_status_key(status) in {"failed", "error", "stopped"}:
                return False
        return True

    # === SECTION === Save
    def ask_save_path(self) -> str:
        ts = QDateTime.currentDateTimeUtc().toString("yyyyMMdd_hhmmss")
        suggested = project_root() / "data" / "sessions" / f"scraper_session_{ts}.json"
        suggested.parent.mkdir(parents=True, exist_ok=True)
        path, selected_filter = QFileDialog.getSaveFileName(
            self.parent,
            "Save session",
            str(suggested),
            "JSON (*.json)",
        )
        if not path:
            return ""
        if Path(path).suffix.lower() != ".json" or "JSON" in selected_filter:
            path = str(Path(path).with_suffix(".json"))
        return path

    def on_save_clicked(self) -> None:
        path = self.ask_save_path()
        if not path:
            return

        try:
            session = self.collect_snapshot()
            if session_contains_sensitive_data(session):
                answer = QMessageBox.warning(
                    self.parent,
                    "Save Session",
                    "Session files are plaintext and may contain authentication headers, "
                    "cookies or proxy credentials. Save only to a trusted location.\n\n"
                    "Save this session with these values included?",
                    QMessageBox.Save | QMessageBox.Cancel,
                    QMessageBox.Cancel,
                )
                if answer != QMessageBox.Save:
                    return
            save_session(path, session)
        except Exception as exc:
            self.log_panel.append("ERROR", f"Save session failed: {exc}", tag="SESSION")
            QMessageBox.warning(self.parent, "Save Session", f"Failed to save session:\n{exc}")
            return

        count = len(session.get("tasks") or [])
        self.log_panel.append("INFO", f"Saved session with {count} task(s) -> {path}", tag="SESSION")
        QMessageBox.information(self.parent, "Save Session", f"Session saved:\n{path}")

    # === SECTION === Load
    def ask_load_path(self) -> str:
        suggested = project_root() / "data" / "sessions"
        path, _ = QFileDialog.getOpenFileName(
            self.parent,
            "Load session",
            str(suggested),
            "JSON (*.json)",
        )
        return path or ""

    def on_load_clicked(self) -> None:
        if self._has_active_or_running_tasks():
            QMessageBox.warning(
                self.parent,
                "Load Session",
                "Cannot load a session while tasks are running. Stop active tasks first.",
            )
            self.log_panel.append("WARN", "Load blocked because tasks are still running", tag="SESSION")
            return

        path = self.ask_load_path()
        if not path:
            return

        try:
            session = load_session(path)
            loaded_count = self.restore_snapshot(session)
        except Exception as exc:
            self.log_panel.append("ERROR", f"Load session failed: {exc}", tag="SESSION")
            QMessageBox.warning(self.parent, "Load Session", f"Failed to load session:\n{exc}")
            return

        self.log_panel.append("INFO", f"Loaded session with {loaded_count} task(s) <- {path}", tag="SESSION")
        QMessageBox.information(self.parent, "Load Session", f"Session loaded:\n{path}")

    def _has_active_or_running_tasks(self) -> bool:
        if hasattr(self.task_manager, "is_idle") and not self.task_manager.is_idle():
            return True
        active_statuses = {"running", "paused", "in progress", "in-progress"}
        for task in self.task_manager.get_all_tasks():
            if self._session_status_key(getattr(task, "status", "")) in active_statuses:
                return True
        table = self.table_ctl.table
        for row in range(table.rowCount()):
            item = table.item(row, Col.Status)
            if item and self._session_status_key(item.text()) in active_statuses:
                return True
        return False

    def restore_snapshot(self, session: dict) -> int:
        if self._has_active_or_running_tasks():
            raise ValueError("Cannot load a session while tasks are running. Stop active tasks first.")

        # Validate and construct every task before touching the current workspace.
        session = validate_session_data(session)
        prepared = self._prepare_session_tasks(session)
        annotations = extract_annotation_store(session)
        table = self.table_ctl.table
        previous = self._capture_restore_state()
        signals_blocked = table.signalsBlocked()
        updates_enabled = table.updatesEnabled()
        table.setUpdatesEnabled(False)
        table.blockSignals(True)
        try:
            table.setRowCount(0)
            self.parent._row_by_task_id.clear()
            self.parent.task_results.clear()
            self.task_manager._tasks.clear()
            self.task_manager._runnables.clear()
            self.parent.annotation_store = annotations

            for task, cached_result in prepared:
                task_id, url, params = task.id, task.url, task.params
                status_text, progress, result = task.status.value, task.progress, task.result
                self.task_manager._tasks[task_id] = task
                if result is not None:
                    self.parent.task_results[task_id] = cached_result

                row = table.rowCount()
                table.insertRow(row)
                self.parent.set_url_cell(row, url, task_id=task_id)
                status_cell = status_text
                if progress and status_text not in {"Done"}:
                    status_cell = f"{status_text} {progress}%"
                self.parent.set_status_cell(row, status_cell)
                self._restore_loaded_result_cells(row, result)
                self.parent.set_cookies_cell(row, params, url)
                params_light = {
                    k: params.get(k)
                    for k in ("method", "proxy", "user_agent", "timeout", "retries")
                    if params.get(k)
                }
                self.parent.set_params_cell(row, str(params_light) if params_light else "")
                self.parent._row_by_task_id[task_id] = row

            self._restore_session_selection(session)
            self.parent.actions.refresh_task_annotation_visuals()
            self.parent._refresh_task_inspector_for_current()
        except Exception as exc:
            # Restore original objects and cloned cells without calling failed setters.
            self._rollback_restore(previous)
            try:
                self.parent._refresh_task_inspector_for_current()
            except Exception:
                self.log_panel.append("WARN", "Workspace restored, but inspector refresh failed", tag="SESSION")
            raise RuntimeError("Could not restore session. The previous workspace was restored.") from exc
        finally:
            table.blockSignals(signals_blocked)
            table.setUpdatesEnabled(updates_enabled)

        return len(prepared)

    def _prepare_session_tasks(self, session: dict) -> list:
        prepared = []
        for index, entry in enumerate(session["tasks"], start=1):
            try:
                task = ScrapeTask(
                    id=entry["id"].strip(), url=entry["url"].strip(),
                    params=deepcopy(entry.get("params", {})),
                )
                task.status = TaskStatus(self._coerce_loaded_session_status(entry.get("status")))
                task.progress = self._session_progress_value(entry.get("progress"))
                task.result = deepcopy(entry.get("result"))
                created_at = self._parse_session_created_at(entry.get("created_at"))
                if created_at is not None:
                    task.created_at = created_at
                prepared.append((task, deepcopy(task.result)))
            except Exception as exc:
                raise ValueError(f"Invalid session task {index}: could not prepare task parameters or result.") from exc
        return prepared

    def _capture_restore_state(self) -> dict:
        table = self.table_ctl.table
        return {
            "tasks": dict(self.task_manager._tasks),
            "runnables": dict(self.task_manager._runnables),
            "results": dict(self.parent.task_results),
            "rows": dict(self.parent._row_by_task_id),
            "annotations": self.parent.annotation_store,
            "cells": [
                [table.item(row, col).clone() if table.item(row, col) is not None else None
                 for col in range(table.columnCount())]
                for row in range(table.rowCount())
            ],
            "current": (table.currentRow(), table.currentColumn()),
            "selection": [
                (r.topRow(), r.leftColumn(), r.bottomRow(), r.rightColumn())
                for r in table.selectedRanges()
            ],
        }

    def _rollback_restore(self, previous: dict) -> None:
        for target, key in (
            (self.task_manager._tasks, "tasks"),
            (self.task_manager._runnables, "runnables"),
            (self.parent.task_results, "results"),
            (self.parent._row_by_task_id, "rows"),
        ):
            target.clear()
            target.update(previous[key])
        self.parent.annotation_store = previous["annotations"]
        table = self.table_ctl.table
        table.setRowCount(0)
        table.setRowCount(len(previous["cells"]))
        for row, cells in enumerate(previous["cells"]):
            for col, item in enumerate(cells):
                if item is not None:
                    table.setItem(row, col, item)
        table.setCurrentCell(*previous["current"])
        table.clearSelection()
        for selection in previous["selection"]:
            table.setRangeSelected(QTableWidgetSelectionRange(*selection), True)

    def _restore_loaded_result_cells(self, row: int, result) -> None:
        if isinstance(result, dict) and result:
            self.parent.set_code_cell(row, result.get("status_code"))
            timings = result.get("timings", {}) or {}
            self.parent.set_time_cell(row, timings.get("request_ms"))
            self.table_ctl.set_results_cell(row=row, payload=result)
            return
        self.parent.set_code_cell(row, None)
        self.parent.set_time_cell(row, None)
        self.parent.set_results_cell(row, None)

    def _restore_session_selection(self, session: dict) -> None:
        table = self.table_ctl.table
        workspace = session.get("workspace") or {}
        row = -1
        selected_task_id = workspace.get("selected_task_id")
        if selected_task_id:
            row = self.table_ctl.row_by_task_id(str(selected_task_id))
        if row < 0:
            row = self._session_row_value(workspace.get("current_row"))
            if row >= table.rowCount():
                row = -1
        if row < 0 and table.rowCount() > 0:
            row = 0
        if row >= 0:
            table.setCurrentCell(row, Col.URL)
            table.selectRow(row)

    def _coerce_loaded_session_status(self, status) -> str:
        key = self._session_status_key(status)
        if key in {"running", "in progress", "in-progress", "paused"}:
            return TaskStatus.STOPPED.value
        if key in {"done", "complete", "completed", "success", "successful"}:
            return TaskStatus.DONE.value
        if key in {"error"}:
            return TaskStatus.ERROR.value
        if key in {"failed", "fail"}:
            return TaskStatus.FAILED.value
        if key in {"stopped", "stop"}:
            return TaskStatus.STOPPED.value
        return TaskStatus.PENDING.value

    def _parse_session_created_at(self, value):
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    def _session_row_value(self, value) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return -1
