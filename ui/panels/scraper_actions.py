# ui/panels/scraper_actions.py
from __future__ import annotations
from typing import List, Optional
import json
from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QAction, QCursor
from PySide6.QtWidgets import QMenu, QApplication
from PySide6.QtWidgets import QMessageBox
from dialogs.discovery_viewer_dialog import DiscoveryViewerDialog
from dialogs.forms_viewer_dialog import FormsViewerDialog
from dialogs.results_viewer_dialog import ResultsViewerDialog

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
        has_selection = bool(self._get_selected_task_ids_from_table())
        has_results = self._has_selected_results()

        A["open_results_viewer"].setEnabled(has_selection and has_results)
        A["copy_results"].setEnabled(has_selection and has_results)
        A["copy_url"].setEnabled(has_selection)
        if "copy_final_url" in A:
            A["copy_final_url"].setEnabled(has_selection)

        # --- Task actions ---
        menu.addAction(A["start_selected"])
        menu.addAction(A["stop_selected"])
        menu.addAction(A["restart_selected"])
        menu.addSeparator()

        # --- Data / View ---
        menu.addAction(A["open_results_viewer"])
        menu.addAction(A["copy_url"])
        menu.addAction(A["copy_results"])
        menu.addAction(A["copy_final_url"])
        menu.addAction(A["open_in_browser"])
        menu.addSeparator()

        # --- Analysis ---
        menu.addAction(A["discover_urls"])
        menu.addAction(A["view_discovery"]) 
        menu.addAction(A["view_forms"])
        menu.addAction(A["view_headers"])
        menu.addAction(A["view_cookies"])
        menu.addSeparator()

        # --- Other ---
        menu.addAction(A["export_selected"])
        menu.addAction(A["export_completed"])
        menu.addAction(A["export_all"])
        menu.addAction(A["clear_results"])
        menu.addAction(A["duplicate"])
        menu.addAction(A["remove"])
        menu.addSeparator()

        # --- All tasks ---
        act_start_all = QAction("Start All", menu)
        act_start_all.triggered.connect(lambda _=False: self._start_all_wrapper())
        menu.addAction(act_start_all)

        act_stop_all = QAction("Stop All", menu)
        act_stop_all.triggered.connect(lambda _=False: self._stop_all_wrapper())
        menu.addAction(act_stop_all)

        act_restart_all = QAction("Restart All", menu)
        act_restart_all.triggered.connect(lambda _=False: self._restart_all_wrapper())
        menu.addAction(act_restart_all)

        forms_available = False
        tids = self._get_selected_task_ids_from_table()
        if tids:
            payload = self._task_payload(tids[0])
            forms = self._extract_forms(payload)
            forms_available = isinstance(forms, list)
        if "view_forms" in A:
            A["view_forms"].setEnabled(bool(forms_available))

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
            "open_results_viewer": act("Open Results Viewer", self.open_results_viewer),
            "copy_url":         act("Copy URL",          self.copy_url),
            "copy_results":     act("Copy Results",      self.copy_results),
            "copy_final_url":   act("Copy Final URL",    self.copy_final_url),
            "discover_urls":    act("Discover URLs",     self.discover_urls),
            "view_discovery":  act("View Discovery…",    self.view_discovery),
            "view_forms":      act("View Forms",         self.view_forms),
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

    def _task_payload(self, task_id: str) -> dict:
        task_results = getattr(self.parent, "task_results", None)
        if task_results is None:
            task_results = getattr(getattr(self.parent, "parent", None), "task_results", None)
        if isinstance(task_results, dict):
            return dict(task_results.get(task_id) or {})
        return {}

    def _extract_forms(self, payload: dict | None):
        if not isinstance(payload, dict):
            return None
        forms = payload.get("forms")
        if isinstance(forms, list):
            return forms
        discovery = payload.get("discovery")
        if isinstance(discovery, dict):
            disc_forms = discovery.get("forms")
            if isinstance(disc_forms, list):
                return disc_forms
        return None

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

    def copy_final_url(self):
        tids = self._rows_to_task_ids()
        urls = []
        for tid in tids:
            payload = self._task_payload(tid)
            final_url = payload.get("final_url") if isinstance(payload, dict) else None
            if not final_url:
                task = self.task_manager.get_task(tid)
                final_url = getattr(task, "final_url", None)
            if final_url:
                urls.append(str(final_url))
        if urls:
            QApplication.clipboard().setText("\n".join(urls))
            self._append_log(f"[INFO] Copied final URL(s): {len(urls)}")

    def _payload_to_pretty_json(self, payload) -> str:
        if payload in (None, "", {}, []):
            return "No results available"
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                return payload
        if isinstance(payload, (dict, list)):
            try:
                return json.dumps(payload, ensure_ascii=False, indent=2)
            except Exception:
                return str(payload)
        return repr(payload)

    def _task_payload_for_row(self, row: int):
        tid = self.table_ctl.task_id_by_row(row)
        if not tid:
            return {}
        payload = self._task_payload(tid)
        if payload:
            return payload
        task = self.task_manager.get_task(tid)
        return getattr(task, "result", None) or {}

    def _has_selected_results(self) -> bool:
        for row in self.table_ctl.selected_rows():
            payload = self._task_payload_for_row(row)
            if payload not in (None, "", {}, []):
                return True
        return False

    def open_results_viewer(self):
        rows = self.table_ctl.selected_rows()
        if not rows:
            return
        row = rows[0]
        if hasattr(self.parent, "open_results_viewer_for_row"):
            self.parent.open_results_viewer_for_row(row)
            return
        payload = self._task_payload_for_row(row)
        ResultsViewerDialog(payload=payload, parent=self.parent).exec()

    def copy_results(self):
        rows = self.table_ctl.selected_rows()
        if not rows:
            return
        payload = self._task_payload_for_row(rows[0])
        text = self._payload_to_pretty_json(payload)
        QApplication.clipboard().setText(text)
        self._append_log("[INFO] Copied results payload")

    def discover_urls(self):
        if hasattr(self.parent, "discover_urls_for_selected"):
            return self.parent.discover_urls_for_selected()
        self._append_log("[WARN] Discover URLs action is unavailable")
        
    def view_discovery(self):
        # 1) сначала пытаемся получить UUID из UserRole
        task_ids = self._get_selected_task_ids_from_table()

        # 2) если не нашли UUID — берём URL из текущей строки и резолвим task_id по task_results
        if not task_ids:
            raw_ids = self._get_selected_task_ids_from_table()  # может вернуть пусто, ок
            # возьмем URL из выделенной строки (обычно колонка с http)
            table = getattr(getattr(self.parent, "table_ctl", None), "table", None)
            if table is None:
                return
            sm = table.selectionModel()
            if sm is None or not sm.selectedRows():
                return
            r = sm.selectedRows()[0].row()

            selected_url = None
            for c in range(table.columnCount()):
                it = table.item(r, c)
                if not it:
                    continue
                t = (it.text() or "").strip()
                if t.startswith("http://") or t.startswith("https://"):
                    selected_url = t
                    break

            if not selected_url:
                QMessageBox.information(self.parent, "No discovery", "Select a task row first.")
                return

            task_results = getattr(self.parent, "task_results", None)
            if not isinstance(task_results, dict):
                task_results = getattr(getattr(self.parent, "parent", None), "task_results", None)

            if not isinstance(task_results, dict):
                QMessageBox.warning(self.parent, "Error", "task_results not found.")
                return

            # ищем task_id по совпадению url/base_url внутри payload
            resolved = None
            for tid, payload in task_results.items():
                if not isinstance(payload, dict):
                    continue
                disc = payload.get("discovery")
                if isinstance(disc, dict):
                    base = disc.get("base_url")
                    if isinstance(base, str) and base.strip().rstrip("/") == selected_url.rstrip("/"):
                        resolved = tid
                        break
                u = payload.get("url")
                if isinstance(u, str) and u.strip().rstrip("/") == selected_url.rstrip("/"):
                    resolved = tid
                    break

            if resolved is None:
                QMessageBox.information(self.parent, "No discovery", "Run Discover URLs first.")
                return

            task_ids = [resolved]

        # --- обычный путь ---
        task_id = task_ids[0]

        task_results = getattr(self.parent, "task_results", None)
        if task_results is None:
            task_results = getattr(getattr(self.parent, "parent", None), "task_results", None)

        payload = task_results.get(task_id, {}) if isinstance(task_results, dict) else {}
        discovery = payload.get("discovery") if isinstance(payload, dict) else None

        if not isinstance(discovery, dict) or not discovery:
            QMessageBox.information(self.parent, "No discovery", "Run Discover URLs first.")
            return

        DiscoveryViewerDialog(discovery, parent=self.parent).exec()

    def view_forms(self):
        task_ids = self._get_selected_task_ids_from_table()
        if not task_ids:
            QMessageBox.information(self.parent, "No forms", "Select a task row first.")
            return

        task_id = task_ids[0]
        payload = self._task_payload(task_id)
        forms = self._extract_forms(payload)
        if forms is None:
            QMessageBox.information(self.parent, "No forms", "No forms available for this task.")
            return

        target_url = ""
        if isinstance(payload, dict):
            target_url = payload.get("final_url") or payload.get("url") or ""
            discovery = payload.get("discovery") if isinstance(payload.get("discovery"), dict) else None
            if discovery:
                target_url = discovery.get("base_url") or target_url

        FormsViewerDialog(self.parent, forms=forms, target_url=target_url).exec()


    def _get_selected_task_ids_from_table(self) -> list[str]:
        import re
        from PySide6.QtCore import Qt

        table = getattr(getattr(self.parent, "table_ctl", None), "table", None)
        if table is None:
            return []

        sm = table.selectionModel()
        if sm is None:
            return []

        rows = sorted({idx.row() for idx in sm.selectedRows()})
        if not rows:
            return []

        uuid_re = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

        out: list[str] = []
        for r in rows:
            found = None

            # 1) Сначала пробуем найти task_id в data(UserRole) у любой ячейки строки
            for c in range(table.columnCount()):
                it = table.item(r, c)
                if not it:
                    continue

                for role in (Qt.UserRole, Qt.UserRole + 1, Qt.UserRole + 2):
                    v = it.data(role)
                    if isinstance(v, str) and uuid_re.match(v.strip()):
                        found = v.strip()
                        break
                if found:
                    break

            # 2) Fallback: попробуем найти UUID прямо в тексте (если вдруг он видим)
            if found is None:
                for c in range(table.columnCount()):
                    it = table.item(r, c)
                    if not it:
                        continue
                    txt = (it.text() or "").strip().strip("{}")
                    if uuid_re.match(txt):
                        found = txt
                        break

            if found:
                out.append(found)

        return out





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
                    self.parent.task_results.pop(self.table_ctl.task_id_by_row(r) or r, None)

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
