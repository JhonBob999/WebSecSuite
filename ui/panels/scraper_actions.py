# ui/panels/scraper_actions.py
from __future__ import annotations
from typing import List, Optional
from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QAction, QCursor
from PySide6.QtWidgets import QMenu, QApplication

# Предполагаем, что у тебя есть:
# - TaskTableController со словами: selected_rows(), set_*_cell(), ...
# - task_manager с API: get_task(tid), start_task(tid), stop_task(tid), duplicate_task(tid)->new_tid, remove_task(tid)
# - log_panel с append/append_line или фасадами в ScraperTabController
# - export_bridge (необязательно). Если нет — дергаем родительский _export_mode(mode).

class ScraperActions:
    def __init__(self,
                 parent,                       # ScraperTabController
                 table_ctl,                    # TaskTableController
                 task_manager,                 # core.task_manager.TaskManager
                 log_panel=None,               # ui.log_panel.LogPanel или фасады parent.append_log_line
                 export_bridge=None):          # ui.export_bridge или fallback в parent._export_mode
        self.parent = parent
        self.table_ctl = table_ctl
        self.task_manager = task_manager
        self.log_panel = log_panel
        self.export_bridge = export_bridge

        # Готовим actions (можно переиспользовать между вызовами меню)
        self._acts = {}
        self._build_actions()

    # ---------- Public: показать контекст-меню ----------
    def on_context_menu(self, pos: QPoint):
        table = self.table_ctl.table
        if not table:
            return

        global_pos = table.viewport().mapToGlobal(pos)

        menu = QMenu(table)
        A = self._acts  # кэшированные действия, которые уже работают (Selected и пр.)

        # --- Selected group (из кэша — у тебя они уже кликаются) ---
        menu.addAction(A["start_selected"])
        menu.addAction(A["stop_selected"])
        menu.addAction(A["restart_selected"])
        menu.addSeparator()

        # --- All group (одноразовые QAction с родителем menu) ---
        act_start_all = QAction("Start All", menu)
        act_start_all.triggered.connect(lambda _=False: self._start_all_wrapper())
        menu.addAction(act_start_all)

        act_stop_all = QAction("Stop All", menu)
        act_stop_all.triggered.connect(lambda _=False: self._stop_all_wrapper())
        menu.addAction(act_stop_all)

        act_restart_all = QAction("Restart All", menu)
        act_restart_all.triggered.connect(lambda _=False: self._restart_all_wrapper())
        menu.addAction(act_restart_all)

        menu.addSeparator()

        # --- Duplicate / Remove ---
        menu.addAction(A["duplicate"])
        menu.addAction(A["remove"])
        menu.addSeparator()

        # --- View / Open / Copy ---
        menu.addAction(A["open_in_browser"])
        menu.addAction(A["copy_url"])
        menu.addAction(A["view_headers"])
        menu.addAction(A["view_cookies"])
        menu.addSeparator()

        # --- Export ---
        menu.addAction(A["export_selected"])
        menu.addAction(A["export_completed"])
        menu.addAction(A["export_all"])
        menu.addSeparator()

        # --- Clear Results ---
        menu.addAction(A["clear_results"])

        menu.exec(global_pos)


    # ---------- Actions wiring ----------
    def _build_actions(self):
        def act(text, fn):
            a = QAction(text, self.parent)
            a.triggered.connect(lambda _=False: fn())
            return a

        self._acts = {
            "start_selected":   act("Start Selected",    self.start_selected),
            "stop_selected":    act("Stop Selected",     self.stop_selected),
            "restart_selected": act("Restart Selected",  self.restart_selected),

            # ← теперь три "All" зовут делегаты на parent.*
            "start_all":        act("Start All",         self.start_all),
            "stop_all":         act("Stop All",          self.stop_all),
            "restart_all":      act("Restart All",       self.restart_all),

            "duplicate":        act("Duplicate",         self.duplicate_selected),
            "remove":           act("Remove",            self.remove_selected),

            "open_in_browser":  act("Open in Browser",   self.open_in_browser),
            "copy_url":         act("Copy URL",          self.copy_url),
            "view_headers":     act("View Headers…",     self.view_headers),
            "view_cookies":     act("View Cookies…",     self.view_cookies),

            "export_selected":  act("Export Selected…",  self.export_selected),
            "export_completed": act("Export Completed…", self.export_completed),
            "export_all":       act("Export All…",       self.export_all),

            "clear_results":    act("Clear Results",     self.clear_results),
        }

        
    def _start_all_wrapper(self):
        self._append_log("[DEBUG] Start All clicked")
        self.start_all()

    def _stop_all_wrapper(self):
        self._append_log("[DEBUG] Stop All clicked")
        self.stop_all()

    def _restart_all_wrapper(self):
        self._append_log("[DEBUG] Restart All clicked")
        self.restart_all()


    # ---------- Helpers ----------
    def _rows_to_task_ids(self, rows: Optional[List[int]] = None) -> List[str]:
        rows = rows if rows is not None else self.table_ctl.selected_rows()
        tids: List[str] = []
        for r in rows:
            tid = self.table_ctl.task_id_by_row(r)
            if tid:
                tids.append(tid)
        return tids

    def _append_log(self, msg: str):
        # Универсальный лог-вывод
        if self.log_panel and hasattr(self.log_panel, "append_line"):
            self.log_panel.append_line(msg)
        elif hasattr(self.parent, "append_log_line"):
            self.parent.append_log_line(msg)

    # ---------- Start/Stop/Restart ----------
    def start_selected(self):
        started = 0
        for tid in self._rows_to_task_ids():
            try:
                self.task_manager.start_task(tid)
                started += 1
            except Exception as e:
                self._append_log(f"[ERROR] start_task({tid[:8]}): {e}")
        self._append_log(f"[INFO] Start selected: queued {started} task(s)")

    def stop_selected(self):
        stopped = 0
        for tid in self._rows_to_task_ids():
            try:
                self.task_manager.stop_task(tid)
                stopped += 1
            except Exception as e:
                self._append_log(f"[ERROR] stop_task({tid[:8]}): {e}")
        self._append_log(f"[INFO] Stop selected: {stopped} task(s)")

    def restart_selected(self):
        # Простой вариант: stop + start
        tids = self._rows_to_task_ids()
        for tid in tids:
            try:
                self.task_manager.stop_task(tid)
            except Exception as e:
                self._append_log(f"[WARN] restart(stop) {tid[:8]}: {e}")
        for tid in tids:
            try:
                self.task_manager.start_task(tid)
            except Exception as e:
                self._append_log(f"[ERROR] restart(start) {tid[:8]}: {e}")
        self._append_log(f"[INFO] Restart selected: {len(tids)}")
        
    def _start_all_fallback(self):
        from ui.constants import TaskStatus
        started = errors = 0
        table = self.table_ctl.table
        for row in range(table.rowCount()):
            tid = self.table_ctl.task_id_by_row(row)
            if not tid:
                continue
            try:
                task = self.task_manager.get_task(tid)
                status = getattr(task, "status", TaskStatus.PENDING)
                if status != TaskStatus.RUNNING:
                    self.task_manager.start_task(tid)
                    started += 1
            except Exception as e:
                errors += 1
                self._append_log(f"[ERROR] start_all({tid[:8]}): {e}")
        self._append_log(f"[INFO] Start all: queued {started} task(s), errors {errors}")

    def _stop_all_fallback(self):
        from ui.constants import TaskStatus
        stopped = errors = 0
        table = self.table_ctl.table
        for row in range(table.rowCount()):
            tid = self.table_ctl.task_id_by_row(row)
            if not tid:
                continue
            try:
                task = self.task_manager.get_task(tid)
                status = getattr(task, "status", TaskStatus.PENDING)
                if status in {TaskStatus.RUNNING, TaskStatus.PENDING}:
                    self.task_manager.stop_task(tid)
                    stopped += 1
            except Exception as e:
                errors += 1
                self._append_log(f"[ERROR] stop_all({tid[:8]}): {e}")
        self._append_log(f"[INFO] Stop all: requested stop for {stopped} task(s), errors {errors}")

    def _restart_all_fallback(self):
        from ui.constants import TaskStatus
        restarted = errors = 0
        table = self.table_ctl.table
        for row in range(table.rowCount()):
            tid = self.table_ctl.task_id_by_row(row)
            if not tid:
                continue
            try:
                task = self.task_manager.get_task(tid)
                status = getattr(task, "status", TaskStatus.PENDING)
                if status in (TaskStatus.RUNNING, TaskStatus.PENDING):
                    self.task_manager.stop_task(tid)
                self.task_manager.start_task(tid)
                restarted += 1
            except Exception as e:
                errors += 1
                self._append_log(f"[ERROR] restart_all({tid[:8]}): {e}")
        self._append_log(f"[INFO] Restart all: requested restart for {restarted} task(s), errors {errors}")


    def start_all(self):
        # делегируем в ScraperTabController, если есть
        if hasattr(self.parent, "start_all_tasks"):
            self.parent.start_all_tasks()
            return
        # фолбэк на обход таблицы (редко понадобится)
        self._start_all_fallback()

    def stop_all(self):
        if hasattr(self.parent, "stop_all_tasks"):
            self.parent.stop_all_tasks()
            return
        self._stop_all_fallback()

    def restart_all(self):
        if hasattr(self.parent, "restart_all_tasks"):
            self.parent.restart_all_tasks()
            return
        self._restart_all_fallback()




    # ---------- Duplicate / Remove ----------
    def duplicate_selected(self):
        new_count = 0
        for tid in self._rows_to_task_ids():
            try:
                new_tid = self.task_manager.duplicate_task(tid)
                task = self.task_manager.get_task(new_tid)
                if hasattr(self.parent, "add_task_row_from_task"):
                    self.parent.add_task_row_from_task(task)
                else:
                    # фолбэк — хотя бы добавить строку по URL
                    url = getattr(task, "url", "")
                    self.parent.add_task_row(url, task_id=new_tid)
                new_count += 1
            except Exception as e:
                self._append_log(f"[ERROR] duplicate({tid[:8]}): {e}")
        self._append_log(f"[INFO] Duplicated: {new_count}")



    def remove_selected(self):
        rows = self.table_ctl.selected_rows()
        tids = self._rows_to_task_ids(rows)
        removed = 0
        for r, tid in sorted(zip(rows, tids), reverse=True):
            try:
                self.task_manager.remove_task(tid)
                if hasattr(self.table_ctl, "remove_row"):
                    self.table_ctl.remove_row(r)
                else:
                    self.table_ctl.table.removeRow(r)
                removed += 1
            except Exception as e:
                self._append_log(f"[ERROR] remove({tid[:8]}): {e}")
        self._append_log(f"[INFO] Removed: {removed}")


    # ---------- View / Open / Copy ----------
    def open_in_browser(self):
        import webbrowser
        tids = self._rows_to_task_ids()
        for tid in tids:
            task = self.task_manager.get_task(tid)
            url = getattr(task, "final_url", None) or getattr(task, "url", None)
            if url:
                webbrowser.open(url)
        self._append_log(f"[INFO] Open in browser: {len(tids)}")

    def copy_url(self):
        tids = self._rows_to_task_ids()
        urls = []
        for tid in tids:
            task = self.task_manager.get_task(tid)
            url = getattr(task, "final_url", None) or getattr(task, "url", None)
            if url:
                urls.append(url)
        if urls:
            QApplication.clipboard().setText("\n".join(urls))
            self._append_log(f"[INFO] Copied URL(s): {len(urls)}")

    def view_headers(self):
        tids = self._rows_to_task_ids()
        if hasattr(self.parent, "show_task_headers_dialog"):
            return self.parent.show_task_headers_dialog(tids)
        # фолбэк: показываем один первый
        from PySide6.QtWidgets import QMessageBox
        import json
        for tid in tids[:1]:
            task = self.task_manager.get_task(tid)
            headers = getattr(task, "result", {}) or {}
            headers = headers.get("headers")
            msg = QMessageBox(self.parent)
            msg.setWindowTitle(f"Headers — {tid[:8]}")
            if headers:
                msg.setText("Response headers (pretty-JSON):")
                msg.setDetailedText(json.dumps(headers, ensure_ascii=False, indent=2))
                msg.setIcon(QMessageBox.Information)
            else:
                msg.setText("No headers found")
                msg.setIcon(QMessageBox.Warning)
            msg.exec()

    def view_cookies(self):
        tids = self._rows_to_task_ids()
        if hasattr(self.parent, "show_task_cookies_dialog"):
            return self.parent.show_task_cookies_dialog(tids)
        # фолбэк: просто лог
        self._append_log("[WARN] No cookies dialog available.")


    # ---------- Export ----------
    def _export_by_mode(self, mode: str):
        try:
            if self.export_bridge and hasattr(self.export_bridge, "export_mode"):
                self.export_bridge.export_mode(mode)
            elif hasattr(self.parent, "_export_data"):
                self.parent._export_data(mode)    # <-- сначала пробуем это
            elif hasattr(self.parent, "_export_mode"):
                self.parent._export_mode(mode)    # <-- на всякий случай
            else:
                raise RuntimeError("No export bridge or _export_data/_export_mode")
        except Exception as e:
            self._append_log(f"[WARN] Built-in exporter failed ({mode}): {e}.")


    def export_selected(self):
        self._export_by_mode("Selected")

    def export_completed(self):
        self._export_by_mode("Completed")

    def export_all(self):
        self._export_by_mode("All")
        

    # ---------- Results ----------
    def clear_results(self):
        rows = self.table_ctl.selected_rows()
        cleared = 0
        for r in rows:
            try:
                # 1) Стираем ячейки
                if hasattr(self.table_ctl, "set_results_cell"):
                    self.table_ctl.set_results_cell(r, None)  # пустое резюме и tooltip
                if hasattr(self.table_ctl, "set_code_cell"):
                    self.table_ctl.set_code_cell(r, None)
                if hasattr(self.table_ctl, "set_time_cell"):
                    self.table_ctl.set_time_cell(r, None)

                # 2) Чистим снапшот предпросмотра, если он у тебя хранится по row
                if hasattr(self.parent, "task_results") and isinstance(self.parent.task_results, dict):
                    self.parent.task_results.pop(r, None)

                # 3) (опционально) чистим task.result, чтобы точно не путаться
                tid = self.table_ctl.task_id_by_row(r)
                if tid:
                    task = self.task_manager.get_task(tid)
                    if task and hasattr(task, "result"):
                        task.result = None

                cleared += 1
            except Exception as e:
                self._append_log(f"[ERROR] clear_results(row={r}): {e}")
        self._append_log(f"[INFO] Cleared results for {cleared} row(s)")

