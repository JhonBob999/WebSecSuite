from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import json

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QCursor
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
from dialogs.results_viewer_dialog import UniversalViewerDialog


class InspectorValueLabel(QLabel):
    double_clicked = Signal()

    def mouseDoubleClickEvent(self, event) -> None:  # type: ignore[override]
        self.double_clicked.emit()
        super().mouseDoubleClickEvent(event)


class TaskInspectorPanel(QWidget):
    """Read-only summary panel for selected task payload."""

    DASH = "—"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._fields: dict[str, InspectorValueLabel] = {}
        self._detail_payloads: dict[str, dict[str, Any]] = {}

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
                ("cand_source_trace", "Candidate source trace"),
                ("cand_evidence_artifacts", "Evidence / Artifacts"),
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
            value = InspectorValueLabel(self.DASH, box)
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            value.setWordWrap(True)
            value.setStyleSheet("color: #d6dbe0;")
            value.double_clicked.connect(lambda _checked=False, field_key=key: self._open_detail_for_field(field_key))
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
        self._detail_payloads.clear()
        for label in self._fields.values():
            label.setText(self.DASH)
            label.setStyleSheet("color: #d6dbe0;")
            label.setCursor(QCursor(Qt.IBeamCursor))

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
        self._detail_payloads.clear()

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
        self._set_explanation_detail(
            "basic_status",
            "Status explanation",
            "Status",
            self._fields["basic_status"].text(),
            "Task status shown for the selected result.",
            "It helps distinguish completed, failed, skipped, or still-running task outcomes before reviewing deeper evidence.",
            "Taken from the selected task status text when available, otherwise from the task result payload status field.",
        )
        self._set_explanation_detail(
            "basic_status_code",
            "Status code explanation",
            "Status code",
            self._fields["basic_status_code"].text(),
            "HTTP status code returned by the target response.",
            "It helps separate successful responses, redirects, client errors, server errors, and blocked or challenged responses.",
            "Taken from the task result payload status_code field.",
        )
        self._set_explanation_detail(
            "basic_request_ms",
            "Request time explanation",
            "Request time",
            self._fields["basic_request_ms"].text(),
            "Measured request duration for the selected task result.",
            "Slow responses can help prioritize endpoints for stability review, timeout tuning, or later safe validation.",
            "Taken from timings.request_ms, request_ms, or time in the task result payload.",
        )
        self._set_explanation_detail(
            "basic_content_len",
            "Content length explanation",
            "Content length",
            self._fields["basic_content_len"].text(),
            "Reported response body length for the selected task result.",
            "Size changes can help compare responses, spot empty or unusual pages, and prepare evidence for later analysis.",
            "Taken from the task result payload content_len field.",
        )

        self._set("nav_redirects", redirects)
        self._set("nav_method", method_text)
        self._set("nav_cookies", cookies_text)
        self._set("nav_headers", self._to_bool_text(bool(headers)))
        self._set_explanation_detail(
            "nav_method",
            "Method explanation",
            "Method",
            self._fields["nav_method"].text(),
            "HTTP method used for the selected request.",
            "The method affects routing, caching, form behavior, and which endpoints are relevant for later validation.",
            "Taken from request_recipe.method, payload method, or the selected task method.",
        )

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
        has_cdn_source_available = "has_cdn" in fp_summary or "has_cdn" in fingerprint
        has_waf_source_available = "has_waf_hint" in fp_summary or "has_waf_hint" in fingerprint
        self._set("fp_has_cdn", self._to_bool_text(self._first_non_empty(fp_summary.get("has_cdn"), fingerprint.get("has_cdn"), default=False)))
        self._set(
            "fp_has_waf_hint",
            self._to_bool_text(self._first_non_empty(fp_summary.get("has_waf_hint"), fingerprint.get("has_waf_hint"), default=False)),
        )
        self._set("fp_server", server)
        self._set("fp_x_powered_by", x_powered)
        self._set("fp_x_generator", x_generator)
        top_stack_detail = top_stack_val if self._has_detail_payload(top_stack_val) else None
        self._set_fingerprint_explanation_detail(
            "fp_top_stack",
            "Top stack explanation",
            "Top stack",
            top_stack_text,
            "A compact summary of the strongest technology fingerprint signals collected for this task.",
            "It helps prioritize later technology review and keeps the likely delivery or application stack visible during recon.",
            self._fingerprint_evidence_text(fp_summary, fingerprint, "top_stack"),
            extra_detail_label="Detected stack detail",
            extra_detail=top_stack_detail,
        )
        self._set_fingerprint_explanation_detail(
            "fp_has_cdn",
            "CDN hint explanation",
            "Has CDN",
            self._fields["fp_has_cdn"].text() if has_cdn_source_available else self.DASH,
            "There may be signs of CDN or edge delivery in the fingerprint summary.",
            "CDN or edge hints can explain caching behavior, redirects, header changes, and why origin evidence may be indirect.",
            self._fingerprint_evidence_text(fp_summary, fingerprint, "has_cdn"),
        )
        self._set_fingerprint_explanation_detail(
            "fp_has_waf_hint",
            "WAF hint explanation",
            "WAF hint",
            self._fields["fp_has_waf_hint"].text() if has_waf_source_available else self.DASH,
            "There may be signs of a protection or filtering layer in the fingerprint summary.",
            "Protection-layer hints can explain challenged, filtered, or otherwise altered responses during later analysis.",
            self._fingerprint_evidence_text(fp_summary, fingerprint, "has_waf_hint"),
        )
        self._set_fingerprint_explanation_detail(
            "fp_server",
            "Server header explanation",
            "Server",
            self._fields["fp_server"].text(),
            "The Server header is a response header that may identify the HTTP server or reverse proxy.",
            "It helps understand the delivery stack and may guide later fingerprint or CVE review.",
            "Taken from the response headers server or Server field." if server != self.DASH else "No server header evidence was available in the task result payload.",
        )
        self._set_fingerprint_explanation_detail(
            "fp_x_powered_by",
            "X-Powered-By explanation",
            "X-Powered-By",
            self._fields["fp_x_powered_by"].text(),
            "The X-Powered-By header may identify an application framework, runtime, or platform component.",
            "It can guide later technology review and help connect responses to framework-specific behavior.",
            "Taken from the response headers x-powered-by or X-Powered-By field." if x_powered != self.DASH else "No X-Powered-By header evidence was available in the task result payload.",
        )
        self._set_fingerprint_explanation_detail(
            "fp_x_generator",
            "X-Generator explanation",
            "X-Generator",
            self._fields["fp_x_generator"].text(),
            "The X-Generator header may identify a CMS, site generator, framework, or publishing tool.",
            "It can help focus later fingerprint review and explain technology-specific page patterns.",
            "Taken from the response headers x-generator or X-Generator field." if x_generator != self.DASH else "No X-Generator header evidence was available in the task result payload.",
        )

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
        candidate_source_trace = self._candidate_source_trace(data.get("candidates"), candidates_summary)
        trace_entries = candidate_source_trace["summary"]["trace_entries"]
        self._set("cand_source_trace", f"{trace_entries} traces" if trace_entries else "not available")
        evidence_artifacts = {
            key: data.get(key)
            for key in (
                "discovery",
                "forms",
                "forms_summary",
                "fingerprint",
                "js_recon",
                "candidates",
                "candidates_summary",
                "request_recipe",
                "validation",
                "validation_plan",
                "replay",
                "replay_manifest",
                "evidence",
                "findings",
                "artifacts",
            )
            if key in data and self._has_detail_payload(data.get(key))
        }
        evidence_artifacts_count = len(evidence_artifacts)
        self._set(
            "cand_evidence_artifacts",
            f"{evidence_artifacts_count} sections" if evidence_artifacts_count else "none",
        )
        self._set_explanation_detail(
            "cand_max_conf",
            "Max confidence explanation",
            "Max confidence",
            self._fields["cand_max_conf"].text(),
            "Highest confidence score reported among vulnerability candidates for this result.",
            "It is a candidate ranking indicator for review priority, not proof of exploitability.",
            "Taken from the candidates_summary.max_confidence field." if candidates_summary.get("max_confidence") is not None else "No max confidence evidence was available in the task result payload.",
        )

        self._set_detail("nav_redirects", "Redirect chain", data.get("redirect_chain"))
        self._set_detail(
            "nav_cookies",
            "Cookie details",
            {
                "cookie_path": request_recipe.get("cookie_path") or cookie_path,
                "request_recipe_cookies": request_recipe.get("cookies"),
                "cookies": data.get("cookies"),
                "set_cookie": headers.get("set-cookie") or headers.get("Set-Cookie"),
            },
        )
        headers_detail = data.get("headers")
        if not self._has_detail_payload(headers_detail):
            headers_detail = request_recipe.get("headers")
        self._set_detail("nav_headers", "Headers", headers_detail)
        self._set_detail("discovery_internal", "Internal URLs", discovery_urls.get("internal"))
        self._set_detail("discovery_external", "External URLs", discovery_urls.get("external"))
        self._set_detail("discovery_query_params", "Query params", discovery.get("query_params"))
        self._set_detail("discovery_forms", "Forms", data.get("forms"))
        js_sources_detail = self._existing_detail_map(
            js_recon,
            ("external_scripts", "inline_scripts", "page_sources", "sources", "external", "inline"),
        )
        self._set_detail("js_sources_total", "JS sources", js_sources_detail)
        self._set_detail("js_endpoint_candidates", "JS endpoint candidates", js_recon.get("endpoint_candidates"))
        self._set_detail("js_secret_hints", "JS secret hints", js_recon.get("secret_hints"))
        self._set_detail("js_linkage", "JS endpoint linkage", endpoint_linkage)
        grouped_sources_detail = self._js_grouped_sources_detail(js_recon, js_summary)
        if not self._has_detail_payload(grouped_sources_detail):
            grouped_sources_detail = "Grouped source details are not available in this payload."
        self._set_detail("js_grouped_sources", "JS grouped sources", grouped_sources_detail)
        self._set_detail("cand_total", "Candidates", data.get("candidates"))
        self._set_detail("cand_xss", "XSS candidates", self._filter_candidates(data.get("candidates"), "xss"))
        self._set_detail("cand_sqli", "SQLi candidates", self._filter_candidates(data.get("candidates"), "sqli"))
        self._set_detail("cand_lfi", "LFI candidates", self._filter_candidates(data.get("candidates"), "lfi"))
        self._set_detail("cand_ssrf", "SSRF candidates", self._filter_candidates(data.get("candidates"), "ssrf"))
        self._set_detail("cand_types", "Candidate types", types_present)
        if trace_entries:
            self._set_detail("cand_source_trace", "Candidate source trace", candidate_source_trace)
        else:
            self._set_detail(
                "cand_source_trace",
                "Candidate source trace",
                "Candidate source trace is not available in this payload.\n"
                "This means the current candidates do not include "
                "source_ref/source_kind/evidence/provenance fields yet.\n"
                "Candidate generation was not changed.",
            )
        self._detail_payloads["cand_source_trace"]["save_dialog_title"] = (
            "Save Inspector Candidate Source Trace"
        )
        self._set_detail("cand_evidence_artifacts", "Evidence / Artifacts", evidence_artifacts)

    def _set(self, key: str, value: Any) -> None:
        label = self._fields.get(key)
        if label is None:
            return
        if value is None:
            label.setText(self.DASH)
            return
        text = str(value).strip()
        label.setText(text if text else self.DASH)

    @staticmethod
    def _has_detail_payload(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, Mapping):
            return any(TaskInspectorPanel._has_detail_payload(v) for v in value.values())
        if isinstance(value, (list, tuple, set)):
            return any(TaskInspectorPanel._has_detail_payload(v) for v in value)
        return True

    @staticmethod
    def _format_detail(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple, set)):
            if all(not isinstance(item, (dict, list, tuple, set)) for item in value):
                return "\n".join(str(item) for item in value)
            return json.dumps(list(value), ensure_ascii=False, indent=2)
        if isinstance(value, Mapping):
            return json.dumps(dict(value), ensure_ascii=False, indent=2)
        return str(value)

    @staticmethod
    def _filter_candidates(candidates: Any, keyword: str) -> list[Any]:
        if not isinstance(candidates, list):
            return []
        filtered: list[Any] = []
        keyword_lower = keyword.lower()
        for item in candidates:
            if not isinstance(item, Mapping):
                continue
            item_type = str(item.get("type") or item.get("category") or "").lower()
            if keyword_lower in item_type:
                filtered.append(item)
        return filtered

    @classmethod
    def _candidate_source_trace(
        cls,
        candidates: Any,
        candidates_summary: Mapping[str, Any],
    ) -> dict[str, Any]:
        trace_fields = (
            "source_ref", "source_kind", "source_priority", "source", "source_url",
            "source_id", "origin", "origin_url", "evidence", "evidence_ref",
            "evidence_refs", "linkage", "linked_source", "linked_sources", "extractor",
            "extraction_method", "rule_id", "pattern_id", "confidence",
            "confidence_reason", "type", "category", "url", "endpoint", "parameter", "value",
        )
        provenance_fields = set(trace_fields[:21])
        candidate_markers = provenance_fields | {
            "type", "category", "url", "endpoint", "parameter", "value",
        }

        def collect(value: Any) -> list[Mapping[str, Any]]:
            if isinstance(value, (list, tuple)):
                items: list[Mapping[str, Any]] = []
                for child in value:
                    items.extend(collect(child))
                return items
            if not isinstance(value, Mapping):
                return []
            if candidate_markers.intersection(value):
                return [value]
            items = []
            for child in value.values():
                items.extend(collect(child))
            return items

        candidate_items = collect(candidates)
        if not candidate_items:
            candidate_items = collect(candidates_summary)

        traces: list[dict[str, Any]] = []
        for index, item in enumerate(candidate_items):
            if not any(key in item and cls._has_detail_payload(item.get(key)) for key in provenance_fields):
                continue
            trace = {"candidate_index": index}
            trace.update(
                {
                    key: item.get(key)
                    for key in trace_fields
                    if key in item and cls._has_detail_payload(item.get(key))
                }
            )
            traces.append(trace)

        total = len(candidate_items)
        result: dict[str, Any] = {
            "summary": {
                "total_candidates_seen": total,
                "trace_entries": len(traces),
                "without_trace": max(total - len(traces), 0),
            },
            "traces": traces,
        }
        if total > len(traces):
            result["without_trace_note"] = (
                "Some candidates do not contain source/provenance fields in the current payload."
            )
        return result

    @classmethod
    def _existing_detail_map(cls, source: Mapping[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
        return {key: source.get(key) for key in keys if key in source and cls._has_detail_payload(source.get(key))}

    @classmethod
    def _js_grouped_sources_detail(
        cls,
        js_recon: Mapping[str, Any],
        js_summary: Mapping[str, Any],
    ) -> Any:
        for source in (js_recon, js_summary):
            for key in ("grouped_sources", "endpoint_linkage_grouped_sources"):
                detail = source.get(key)
                if cls._has_detail_payload(detail):
                    return detail

        return cls._existing_detail_map(
            js_recon,
            ("external_scripts", "inline_scripts", "page_sources", "sources", "external", "inline"),
        )

    @staticmethod
    def _normalize_detail_key(field_key: str) -> str:
        aliases = {
            "JS Source": "js_sources_total",
            "JS Sources": "js_sources_total",
            "JS sources": "js_sources_total",
            "js_source": "js_sources_total",
            "js_sources": "js_sources_total",
        }
        return aliases.get(field_key, field_key)

    @staticmethod
    def _detail_save_stem(field_key: str) -> str:
        stems = {
            "nav_redirects": "inspector_redirect_chain",
            "nav_cookies": "inspector_cookies",
            "nav_headers": "inspector_headers",
            "discovery_internal": "inspector_internal_urls",
            "discovery_external": "inspector_external_urls",
            "discovery_query_params": "inspector_query_params",
            "discovery_forms": "inspector_forms",
            "fp_top_stack": "inspector_top_stack_explanation",
            "js_sources_total": "inspector_js_sources",
            "js_endpoint_candidates": "inspector_js_endpoint_candidates",
            "js_secret_hints": "inspector_js_secret_hints",
            "js_linkage": "inspector_js_endpoint_linkage",
            "js_grouped_sources": "inspector_js_grouped_sources",
            "cand_total": "inspector_candidates_total",
            "cand_xss": "inspector_xss_candidates",
            "cand_sqli": "inspector_sqli_candidates",
            "cand_lfi": "inspector_lfi_candidates",
            "cand_ssrf": "inspector_ssrf_candidates",
            "basic_status": "inspector_status_explanation",
            "basic_status_code": "inspector_status_code_explanation",
            "basic_request_ms": "inspector_request_time_explanation",
            "basic_content_len": "inspector_content_length_explanation",
            "nav_method": "inspector_method_explanation",
            "fp_has_cdn": "inspector_cdn_hint_explanation",
            "fp_has_waf_hint": "inspector_waf_hint_explanation",
            "fp_server": "inspector_server_header_explanation",
            "fp_x_powered_by": "inspector_x_powered_by_explanation",
            "fp_x_generator": "inspector_x_generator_explanation",
            "cand_max_conf": "inspector_max_confidence_explanation",
            "cand_types": "inspector_candidate_types",
            "cand_source_trace": "inspector_candidate_source_trace",
            "cand_evidence_artifacts": "inspector_evidence_artifacts",
        }
        return stems.get(field_key, "inspector_detail")

    @classmethod
    def _display_value_for_explanation(cls, value: Any) -> str:
        text = str(value).strip() if value is not None else ""
        return "not detected / not available" if not text or text == cls.DASH else text

    @staticmethod
    def _fingerprint_evidence_text(
        fp_summary: Mapping[str, Any],
        fingerprint: Mapping[str, Any],
        key: str,
    ) -> str:
        if key in fp_summary:
            return f"Taken from the fingerprint summary {key} field."
        if key in fingerprint:
            return f"Taken from the fingerprint {key} field."
        return "No direct fingerprint evidence was available in the task result payload."

    def _set_explanation_detail(
        self,
        key: str,
        title: str,
        field_name: str,
        value: Any,
        meaning: str,
        why_it_matters: str,
        evidence: str,
    ) -> None:
        content = "\n".join(
            [
                f"Field: {field_name}",
                f"Value: {self._display_value_for_explanation(value)}",
                "",
                "Meaning:",
                meaning,
                "",
                "Why it matters:",
                why_it_matters,
                "",
                "Evidence:",
                evidence,
            ]
        )
        self._set_detail(key, title, content)

    def _set_fingerprint_explanation_detail(
        self,
        key: str,
        title: str,
        field_name: str,
        value: Any,
        meaning: str,
        why_it_matters: str,
        evidence: str,
        *,
        safety_note: str = "This is a fingerprint hint only. It is not proof of vulnerability or exploitability.",
        extra_detail_label: str = "",
        extra_detail: Any = None,
    ) -> None:
        lines = [
            f"Field: {field_name}",
            f"Value: {self._display_value_for_explanation(value)}",
            "",
            "Meaning:",
            meaning,
            "",
            "Why it matters:",
            why_it_matters,
            "",
            "Evidence/source:",
            evidence,
            "",
            "Safety note:",
            safety_note,
        ]
        if self._has_detail_payload(extra_detail):
            lines.extend(["", f"{extra_detail_label or 'Detail'}:", self._format_detail(extra_detail)])
        self._set_detail(key, title, "\n".join(lines))

    def _set_detail(self, key: str, title: str, data: Any) -> None:
        label = self._fields.get(key)
        if label is None:
            return
        if not self._has_detail_payload(data):
            label.setStyleSheet("color: #d6dbe0;")
            label.setCursor(QCursor(Qt.IBeamCursor))
            return

        detail: dict[str, Any] = {
            "title": title,
            "payload": None,
            "content": None,
            "default_save_stem": self._detail_save_stem(key),
            "save_dialog_title": f"Save Inspector {title}",
        }
        if isinstance(data, (dict, list)):
            detail["payload"] = data
        else:
            detail["content"] = self._format_detail(data)
        self._detail_payloads[key] = detail
        label.setStyleSheet("color: #9ecbff; text-decoration: underline;")
        label.setCursor(QCursor(Qt.PointingHandCursor))

    def _open_detail_for_field(self, field_key: str) -> None:
        field_key = self._normalize_detail_key(field_key)
        detail = self._detail_payloads.get(field_key)
        if not detail:
            return
        payload = detail.get("payload")
        content = detail.get("content")
        if not isinstance(payload, (dict, list)):
            payload = None
        if payload is None:
            content = self._format_detail(content).strip() if content is not None else ""
        if payload is None and not content:
            return
        dialog = UniversalViewerDialog(
            title=detail.get("title", "Inspector detail"),
            payload=payload,
            content=content if payload is None else None,
            parent=self,
            show_summary=False,
            save_dialog_title=detail.get("save_dialog_title", "Save Inspector Detail"),
            default_save_stem=detail.get("default_save_stem", "inspector_detail"),
        )
        dialog.exec()
