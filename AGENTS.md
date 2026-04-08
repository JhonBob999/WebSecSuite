# AGENTS.md — WebSecSuite

## Project purpose
WebSecSuite is a Python + Qt desktop application focused on recon/discovery for web security testing.
The main goal is to collect, normalize, and prioritize useful signals for later vulnerability analysis such as CVE, XSS, SQLi, LFI, SSRF, and related findings.

The scraper is not a generic marketing crawler.
Changes should improve one or more of:
- attack surface discovery
- endpoint and parameter intelligence
- technology fingerprinting
- evidence quality
- stability and scaling

---

## Environment
Primary development environment:
- Windows 11
- Visual Studio Code
- Qt Creator 17 Community
- Python project with Qt/PySide UI

---

## Repository layout
Important folders:
- `core/` — core logic, discovery, scraper, workers, storage, scanners, bot logic
- `ui/` — UI controllers and panel logic
- `dialogs/` — modal dialogs and viewers
- `utils/` — helper utilities
- `Web_Parser_Ui/` — Qt Designer `.ui` files
- `data/` — runtime data, cache, cookies, logs, results
- root files such as `main.py`, `scraper_app.py` may still exist during refactoring

When adding new logic:
- prefer putting business logic into `core/`
- keep UI glue in `ui/`
- keep dialogs isolated in `dialogs/`
- avoid pushing logic into large legacy files if it can be extracted cleanly

---

## Critical project rules
- Do not manually rewrite generated Qt UI files unless explicitly required.
- Assume UI widgets are accessed through `self.ui`.
- Preserve existing working functionality unless the task explicitly changes it.
- Do not break export, preview tables, session loading, cookies, task execution, or context menus.
- Keep changes minimal and scoped to the requested feature.
- Prefer extending existing architecture over adding parallel duplicate logic.
- Do not rename files, classes, methods, signals, or UI object names unless required.
- Do not remove existing fields from result payloads without checking downstream usage.

---

## Current architecture priorities
Priority order for new work:
1. Recon Intelligence Layer
2. Evidence and Repro Layer
3. JS / Modern Web Recon
4. Vulnerability candidate modules
5. Safe validation workflows

Current high-value directions:
- tech fingerprinting
- endpoint normalization
- parameter intelligence
- endpoint scoring / prioritization
- JS endpoint extraction
- evidence-ready request/response artifacts

---

## Coding expectations
- Prefer small, testable helpers over large monolithic methods.
- Keep parsing logic resilient: never crash on malformed HTML, missing headers, empty values, or unknown formats.
- Add safe guards and defaults where useful.
- Use explicit field names in result dictionaries.
- Preserve backward compatibility with existing result consumers when possible.
- For new parser outputs, include concise summaries if they are used by UI tables/dialogs.

---

## UI expectations
- Do not change UI layout unless the task requires it.
- If adding new data to the interface, prefer:
  - existing result payload
  - existing dialogs/viewers
  - existing context menus
- Keep text labels short and practical.
- Do not add noisy logs or message boxes unless they help debugging or workflow.

---

## Discovery / Recon expectations
For discovery-related features:
- normalize URLs carefully
- distinguish internal vs external URLs
- preserve useful query parameter data
- avoid noisy asset-only output when possible
- prefer structured evidence over raw text blobs
- store confidence/evidence for detections when possible

For fingerprinting:
- use signal-based detection, not absolute claims
- include `confidence`
- include `evidence`
- prefer reproducible detections from headers, cookies, HTML, scripts, and links

---

## Safety / scope
WebSecSuite should support recon, discovery, validation preparation, and safe analysis workflows.
Avoid implementing aggressive exploitation logic by default.
Prefer candidate generation, passive detection, response comparison, and evidence collection.

---

## Done means
A task is done when:
- code is consistent with project structure
- existing functionality still works
- new feature is integrated, not isolated
- logs/errors are understandable
- output is usable by downstream UI or analysis
- no obvious regressions are introduced

---

## Response expectations for Codex
When making changes:
- explain which files were changed
- explain why each change was made
- note any assumptions
- mention risks / follow-up work
- keep diffs minimal