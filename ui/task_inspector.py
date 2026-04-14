from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QFormLayout,
    QGroupBox,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


class TaskInspectorPanel(QWidget):
    """Read-only summary panel for selected task payload."""

    DASH = "—"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._fields: dict[str, QLabel] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        title = QLabel("Task Inspector", self)
        title.setStyleSheet("font-size: 15px; font-weight: 700;")
        root.addWidget(title)

        self.empty_label = QLabel("No task selected", self)
        self.empty_label.setWordWrap(True)
        self.empty_label.setStyleSheet("color: #9aa3ad;")
        root.addWidget(self.empty_label)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        root.addWidget(scroll, 1)

        content = QWidget(scroll)
        scroll.setWidget(content)

        self.sections_container = QVBoxLayout(content)
        self.sections_container.setContentsMargins(0, 0, 0, 0)
        self.sections_container.setSpacing(8)

        self._add_section(
            "Basic",
            [
                ("basic_url", "URL"),
                ("basic_final_url", "Final URL"),
                ("basic_status", "Status"),
                ("basic_status_code", "Status code"),
                ("basic_request_ms", "Request time"),
                ("basic_content_len", "Content length"),
            ],
        )
        self._add_section(
            "Request / Navigation",
            [
                ("nav_redirects", "Redirects"),
                ("nav_method", "Method"),
                ("nav_cookies", "Cookies"),
                ("nav_headers", "Headers present"),
            ],
        )
        self._add_section(
            "Discovery / Forms",
            [
                ("discovery_internal", "Internal URLs"),
                ("discovery_external", "External URLs"),
                ("discovery_query_params", "Query params"),
                ("discovery_forms", "Forms"),
            ],
        )
        self._add_section(
            "Fingerprint",
            [
                ("fp_top_stack", "Top stack"),
                ("fp_has_cdn", "Has CDN"),
                ("fp_has_waf_hint", "WAF hint"),
                ("fp_server", "Server"),
                ("fp_x_powered_by", "X-Powered-By"),
                ("fp_x_generator", "X-Generator"),
            ],
        )
        self._add_section(
            "JS Recon",
            [
                ("js_sources_total", "JS sources"),
                ("js_endpoint_candidates", "Endpoint candidates"),
                ("js_secret_hints", "Secret hints"),
                ("js_linkage", "Linkage total"),
                ("js_grouped_sources", "Grouped sources"),
            ],
        )
        self._add_section(
            "Candidates",
            [
                ("cand_total", "Total"),
                ("cand_xss", "XSS"),
                ("cand_sqli", "SQLi"),
                ("cand_lfi", "LFI"),
                ("cand_ssrf", "SSRF"),
                ("cand_max_conf", "Max confidence"),
                ("cand_types", "Types present"),
            ],
        )
        self.sections_container.addStretch(1)

        self.clear("No task selected")

    def _add_section(self, title: str, fields: list[tuple[str, str]]) -> None:
        box = QGroupBox(title, self)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        form = QFormLayout(box)
        form.setContentsMargins(10, 10, 10, 10)
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(6)

        for key, label_text in fields:
            value = QLabel(self.DASH, box)
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            value.setWordWrap(True)
            value.setStyleSheet("color: #d6dbe0;")
            form.addRow(label_text + ":", value)
            self._fields[key] = value

        self.sections_container.addWidget(box)

    @staticmethod
    def _as_map(value: Any) -> Mapping[str, Any]:
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _first_non_empty(*values: Any, default: Any = "") -> Any:
        for value in values:
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            return value
        return default

    @staticmethod
    def _to_bool_text(value: Any) -> str:
        return "Yes" if bool(value) else "No"

    @staticmethod
    def _safe_len(value: Any) -> int:
        if isinstance(value, (list, tuple, set, dict)):
            return len(value)
        return 0

    def clear(self, message: str = "No task selected") -> None:
        self.empty_label.setText(message)
        self.empty_label.show()
        for label in self._fields.values():
            label.setText(self.DASH)

    def update_from_payload(
        self,
        payload: Mapping[str, Any] | None,
        *,
        status_text: str = "",
        task_url: str = "",
        task_method: str = "",
        cookie_path: str = "",
    ) -> None:
        data = self._as_map(payload)
        if not data:
            self.clear("No results available for selected task")
            return

        self.empty_label.hide()

        timings = self._as_map(data.get("timings"))
        discovery = self._as_map(data.get("discovery"))
        discovery_urls = self._as_map(discovery.get("urls"))
        discovery_stats = self._as_map(discovery.get("stats"))
        forms_summary = self._as_map(data.get("forms_summary"))
        request_recipe = self._as_map(data.get("request_recipe"))
        headers = self._as_map(data.get("headers"))
        fingerprint = self._as_map(data.get("fingerprint"))
        fp_summary = self._as_map(fingerprint.get("summary"))
        js_recon = self._as_map(data.get("js_recon"))
        js_summary = self._as_map(js_recon.get("summary"))
        secret_hints = self._as_map(js_recon.get("secret_hints"))
        secret_summary = self._as_map(secret_hints.get("summary"))
        endpoint_linkage = js_recon.get("endpoint_linkage")
        linkage_summary = self._as_map(js_summary.get("endpoint_linkage"))
        candidates_summary = self._as_map(data.get("candidates_summary"))
        types_breakdown = self._as_map(candidates_summary.get("types_breakdown"))

        redirects = self._first_non_empty(
            request_recipe.get("redirects"),
            self._safe_len(data.get("redirect_chain")),
            default=0,
        )
        method_text = self._first_non_empty(
            request_recipe.get("method"),
            data.get("method"),
            task_method,
            default=self.DASH,
        )
        cookies_text = self._first_non_empty(
            request_recipe.get("cookie_path"),
            cookie_path,
            default=self.DASH,
        )

        top_stack_val = self._first_non_empty(
            fp_summary.get("top_stack"),
            fingerprint.get("top_stack"),
            default=[],
        )
        if isinstance(top_stack_val, list):
            top_stack_text = ", ".join(str(x) for x in top_stack_val[:5] if x) or self.DASH
        else:
            top_stack_text = str(top_stack_val) if top_stack_val else self.DASH

        server = self._first_non_empty(headers.get("server"), headers.get("Server"), default=self.DASH)
        x_powered = self._first_non_empty(
            headers.get("x-powered-by"), headers.get("X-Powered-By"), default=self.DASH
        )
        x_generator = self._first_non_empty(
            headers.get("x-generator"), headers.get("X-Generator"), default=self.DASH
        )

        js_grouped_sources = self._first_non_empty(
            js_summary.get("page_sources_total"),
            js_summary.get("endpoint_linkage_unique_sources"),
            default=0,
        )

        types_present = candidates_summary.get("types_present")
        if isinstance(types_present, list):
            types_present_text = ", ".join(str(t) for t in types_present if t) or self.DASH
        elif types_present:
            types_present_text = str(types_present)
        else:
            types_present_text = self.DASH

        self._set("basic_url", self._first_non_empty(data.get("url"), task_url, default=self.DASH))
        self._set("basic_final_url", self._first_non_empty(data.get("final_url"), data.get("url"), task_url, default=self.DASH))
        self._set("basic_status", self._first_non_empty(status_text, data.get("status"), default=self.DASH))
        self._set("basic_status_code", self._first_non_empty(data.get("status_code"), default=self.DASH))
        req_ms = self._first_non_empty(timings.get("request_ms"), data.get("request_ms"), data.get("time"), default=self.DASH)
        self._set("basic_request_ms", f"{req_ms} ms" if isinstance(req_ms, (int, float)) else req_ms)
        self._set("basic_content_len", self._first_non_empty(data.get("content_len"), default=self.DASH))

        self._set("nav_redirects", redirects)
        self._set("nav_method", method_text)
        self._set("nav_cookies", cookies_text)
        self._set("nav_headers", self._to_bool_text(bool(headers)))

        internal_cnt = self._first_non_empty(
            discovery_stats.get("internal"),
            self._safe_len(discovery_urls.get("internal")),
            default=0,
        )
        external_cnt = self._first_non_empty(
            discovery_stats.get("external"),
            self._safe_len(discovery_urls.get("external")),
            default=0,
        )
        params_cnt = self._first_non_empty(
            discovery_stats.get("with_params"),
            self._safe_len(discovery.get("query_params")),
            default=0,
        )
        forms_cnt = self._first_non_empty(
            forms_summary.get("forms_total"),
            self._safe_len(data.get("forms")),
            default=0,
        )
        self._set("discovery_internal", internal_cnt)
        self._set("discovery_external", external_cnt)
        self._set("discovery_query_params", params_cnt)
        self._set("discovery_forms", forms_cnt)

        self._set("fp_top_stack", top_stack_text)
        self._set("fp_has_cdn", self._to_bool_text(self._first_non_empty(fp_summary.get("has_cdn"), fingerprint.get("has_cdn"), default=False)))
        self._set(
            "fp_has_waf_hint",
            self._to_bool_text(self._first_non_empty(fp_summary.get("has_waf_hint"), fingerprint.get("has_waf_hint"), default=False)),
        )
        self._set("fp_server", server)
        self._set("fp_x_powered_by", x_powered)
        self._set("fp_x_generator", x_generator)

        js_sources_total = self._first_non_empty(
            js_summary.get("external_total"),
            self._safe_len(js_recon.get("external")) + self._safe_len(js_recon.get("inline")),
            default=0,
        )
        endpoint_candidates_total = self._first_non_empty(
            js_summary.get("endpoint_candidates_total"),
            self._safe_len(js_recon.get("endpoint_candidates")),
            default=0,
        )
        linkage_total = self._first_non_empty(
            linkage_summary.get("endpoint_linkage_total"),
            self._safe_len(endpoint_linkage),
            default=0,
        )
        secret_total = self._first_non_empty(
            secret_summary.get("total_hints"),
            self._safe_len(secret_hints.get("all")),
            default=0,
        )

        self._set("js_sources_total", js_sources_total)
        self._set("js_endpoint_candidates", endpoint_candidates_total)
        self._set("js_secret_hints", secret_total)
        self._set("js_linkage", linkage_total)
        self._set("js_grouped_sources", js_grouped_sources)

        self._set("cand_total", self._first_non_empty(candidates_summary.get("total"), default=0))
        self._set("cand_xss", self._first_non_empty(types_breakdown.get("xss_candidate"), default=0))
        self._set("cand_sqli", self._first_non_empty(types_breakdown.get("sqli_candidate"), default=0))
        self._set("cand_lfi", self._first_non_empty(types_breakdown.get("lfi_candidate"), default=0))
        self._set("cand_ssrf", self._first_non_empty(types_breakdown.get("ssrf_candidate"), default=0))
        self._set("cand_max_conf", self._first_non_empty(candidates_summary.get("max_confidence"), default=self.DASH))
        self._set("cand_types", types_present_text)

    def _set(self, key: str, value: Any) -> None:
        label = self._fields.get(key)
        if label is None:
            return
        if value is None:
            label.setText(self.DASH)
            return
        text = str(value).strip()
        label.setText(text if text else self.DASH)
