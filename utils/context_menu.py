# utils/context_menu.py
from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtWidgets import QMenu

def build_task_table_menu(parent, selection_info):
    """
    selection_info: dict {
        "rows": list[int],
        "count": int,
        "has_running": bool,
        "has_stopped": bool,
        "all_running": bool,
        "all_done": bool,
        "has_params_cell": bool,
        "has_cookie_file": bool,
    }
    """
    m = QMenu(parent)

    # --- Tasks ---
    m_tasks = m.addMenu(QIcon.fromTheme("system-run"), "Tasks")
    act_start_sel = QAction("Start selected", parent); act_start_sel.setShortcut(QKeySequence("Enter"))
    act_stop_sel  = QAction("Stop selected", parent);  act_stop_sel.setShortcut(QKeySequence("Shift+S"))
    act_restart_sel = QAction("Restart selected", parent); act_restart_sel.setShortcut(QKeySequence("Ctrl+R"))
    m_tasks.addActions([act_start_sel, act_stop_sel, act_restart_sel])
    m_tasks.addSeparator()
    act_start_all = QAction("Start all", parent)
    act_stop_all  = QAction("Stop all", parent)
    act_restart_all = QAction("Restart all", parent)
    m_tasks.addActions([act_start_all, act_stop_all, act_restart_all])

    # --- Edit ---
    m_edit = m.addMenu(QIcon.fromTheme("document-edit"), "Edit")
    act_edit_params = QAction("Edit Params…", parent); act_edit_params.setShortcut(QKeySequence("Ctrl+E"))
    act_duplicate   = QAction("Duplicate task(s)", parent)
    act_remove      = QAction("Remove task(s)", parent); act_remove.setShortcut(QKeySequence("Del"))
    m_edit.addActions([act_edit_params, act_duplicate, act_remove])

    # --- Data / Export ---
    m_data = m.addMenu(QIcon.fromTheme("document-save"), "Data / Export")
    m_export = m_data.addMenu("Export")
    act_export_selected  = QAction("Selected", parent)
    act_export_completed = QAction("Completed", parent)
    act_export_all       = QAction("All", parent)
    m_export.addActions([act_export_selected, act_export_completed, act_export_all])
    act_clear_results    = QAction("Clear results (selected)", parent)
    m_data.addAction(act_clear_results)

    # --- Inspect ---
    m_inspect = m.addMenu(QIcon.fromTheme("system-search"), "Inspect")
    act_open_browser = QAction("Open in browser", parent)
    m_copy = m_inspect.addMenu("Copy")
    act_copy_url   = QAction("URL", parent)
    act_copy_furl  = QAction("Final URL", parent)
    act_copy_title = QAction("Title", parent)
    act_copy_hdrs  = QAction("Headers", parent)
    m_copy.addActions([act_copy_url, act_copy_furl, act_copy_title, act_copy_hdrs])
    act_view_headers  = QAction("View Response Headers…", parent)
    act_view_redirect = QAction("View Redirect Chain…", parent)
    m_inspect.addActions([act_open_browser, act_view_headers, act_view_redirect])

    # --- Cookies ---
    m_ck = m.addMenu(QIcon.fromTheme("preferences-web-browser-cookies"), "Cookies")
    act_view_cookies  = QAction("View Cookies…", parent)
    act_open_cookie_dir = QAction("Open cookie file location", parent)
    act_reload_cookies  = QAction("Reload cookies", parent)
    act_clear_cookies   = QAction("Clear cookies (selected)", parent)
    m_ck.addActions([act_view_cookies, act_open_cookie_dir, act_reload_cookies, act_clear_cookies])

    # ==== Enable/Disable по контексту ====
    count = selection_info.get("count", 0)
    has_running = selection_info.get("has_running", False)
    has_stopped = selection_info.get("has_stopped", False)
    all_done    = selection_info.get("all_done", False)
    has_params  = selection_info.get("has_params_cell", True)
    has_ckfile  = selection_info.get("has_cookie_file", False)

    # Доступность для пустого выбора
    for a in [act_start_sel, act_stop_sel, act_restart_sel, act_edit_params, act_duplicate,
              act_remove, act_clear_results, act_open_browser, act_copy_url, act_copy_furl,
              act_copy_title, act_copy_hdrs, act_view_headers, act_view_redirect,
              act_view_cookies, act_reload_cookies, act_clear_cookies]:
        a.setEnabled(count > 0)

    # Тонкая логика
    act_start_sel.setEnabled(count > 0 and (has_stopped or all_done))
    act_stop_sel.setEnabled(count > 0 and has_running)
    act_restart_sel.setEnabled(count > 0)

    act_edit_params.setEnabled(count == 1 and has_params)
    act_duplicate.setEnabled(count > 0)
    act_remove.setEnabled(count > 0)

    act_open_browser.setEnabled(count == 1)
    act_view_headers.setEnabled(count == 1)
    act_view_redirect.setEnabled(count == 1)

    act_open_cookie_dir.setEnabled(has_ckfile)
    # reload/clear можно всегда для выбранных, но оставим включёнными при наличии выбора
    # act_reload_cookies.setEnabled(count > 0)
    # act_clear_cookies.setEnabled(count > 0)

    # Возвращаем меню и все экшены для подключения сигналов в контроллере
    return m, {
        "start_selected": act_start_sel,
        "stop_selected": act_stop_sel,
        "restart_selected": act_restart_sel,
        "start_all": act_start_all,
        "stop_all": act_stop_all,
        "restart_all": act_restart_all,
        "edit_params": act_edit_params,
        "duplicate": act_duplicate,
        "remove": act_remove,
        "export_selected": act_export_selected,
        "export_completed": act_export_completed,
        "export_all": act_export_all,
        "clear_results": act_clear_results,
        "open_browser": act_open_browser,
        "copy_url": act_copy_url,
        "copy_final_url": act_copy_furl,
        "copy_title": act_copy_title,
        "copy_headers": act_copy_hdrs,
        "view_headers": act_view_headers,
        "view_redirect_chain": act_view_redirect,
        "view_cookies": act_view_cookies,
        "open_cookie_dir": act_open_cookie_dir,
        "reload_cookies": act_reload_cookies,
        "clear_cookies": act_clear_cookies,
    }
