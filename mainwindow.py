from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGroupBox,
    QLabel,
    QMainWindow,
    QVBoxLayout,
    QWidget,
)
from ui.main.ui_form import Ui_MainWindow

# Подключаем ScraperTabController
from ui.panels.scraper_tab import ScraperTabController


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("WebSecSuite")

        # Делаем центральный layout адаптивным вместо фиксированной геометрии.
        root_layout = QVBoxLayout(self.ui.centralwidget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(self.ui.tabWidget)

        # Добавляем вкладку Scraper
        self.scraper_tab = ScraperTabController()
        self.ui.tabWidget.addTab(self.scraper_tab, "Scraper")

        # Добавляем UI shell вкладки для будущих модулей.
        self._add_placeholder_tabs()

    def _add_placeholder_tabs(self):
        tabs = [
            (
                "Recon",
                "Discovery and recon intelligence.",
                "Discovery, endpoint normalization and recon intelligence.",
                [
                    "• Endpoint normalization",
                    "• Parameter intelligence",
                    "• Tech / fingerprint summaries",
                ],
            ),
            (
                "JS / Frontend",
                "Frontend-focused recon and JavaScript insights.",
                "JS inventory, endpoint extraction and frontend recon signals.",
                [
                    "• JS source inventory",
                    "• Endpoint extraction from JS",
                    "• Secret-ish hints and frontend tooling",
                ],
            ),
            (
                "Candidates",
                "Candidate review for potential vulnerabilities.",
                "Finding candidates, confidence and prioritization review.",
                [
                    "• XSS / SQLi / LFI / SSRF candidate review",
                    "• Confidence and priority overview",
                    "• Analyst triage workspace",
                ],
            ),
            (
                "Validation",
                "Validation planning and reproducible evidence checks.",
                "Validation planning, replay data and evidence workflows.",
                [
                    "• Replay-friendly request data",
                    "• Validator queue",
                    "• Evidence consistency checks",
                ],
            ),
            (
                "CVE / Exploits",
                "Correlation workspace for known vulnerabilities.",
                "CVE correlation, exploit notes and safe validation workflows.",
                [
                    "• CVE correlation",
                    "• Exploit notes with safe validation focus",
                    "• Future exploit workflows",
                ],
            ),
            (
                "Bots",
                "Bot orchestration and automation shell.",
                "Bot orchestration, future agent profiles and automation control.",
                [
                    "• Docker / browser / plugin agents",
                    "• Future bot lobby and profiles",
                    "• Task routing placeholder",
                ],
            ),
            (
                "Logs / Artifacts",
                "Evidence and artifact management.",
                "Logs, evidence snapshots, artifacts and exported outputs.",
                [
                    "• Logs and runtime traces",
                    "• Evidence snapshots",
                    "• Artifacts, exports, and reports",
                ],
            ),
        ]

        # Tooltip для основной рабочей вкладки.
        self.ui.tabWidget.setTabToolTip(
            0,
            "Primary task execution, collection and inspection workflow.",
        )

        for title, description, tooltip, bullets in tabs:
            tab_index = self.ui.tabWidget.addTab(
                self._create_placeholder_tab(title, description, bullets),
                title,
            )
            self.ui.tabWidget.setTabToolTip(tab_index, tooltip)

    def _create_placeholder_tab(self, title, description, bullets):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 22px; font-weight: 600; color: #e8e8e8;")
        layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #b8c1cc;")
        layout.addWidget(desc_label)

        status_label = QLabel("Coming soon • UI shell ready • Module placeholder")
        status_label.setStyleSheet("color: #9aa7b8; font-weight: 500;")
        layout.addWidget(status_label)

        card = QGroupBox("Planned scope")
        card.setStyleSheet(
            "QGroupBox {"
            "  border: 1px solid #333c45;"
            "  border-radius: 6px;"
            "  margin-top: 8px;"
            "  color: #d8dee7;"
            "}"
            "QGroupBox::title {"
            "  subcontrol-origin: margin;"
            "  left: 10px;"
            "  padding: 0 4px;"
            "}"
        )
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card_layout.setSpacing(6)

        for bullet in bullets:
            line = QLabel(bullet)
            line.setWordWrap(True)
            line.setStyleSheet("color: #d6d6d6;")
            card_layout.addWidget(line)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        divider.setStyleSheet("color: #3a3a3a;")
        card_layout.addWidget(divider)

        note = QLabel("Future module entry point • Logic not connected yet.")
        note.setStyleSheet("color: #8f8f8f;")
        note.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        card_layout.addWidget(note)

        layout.addWidget(card)

        helper = QLabel("Planned workspace for future module integration.")
        helper.setStyleSheet("color: #7d8792;")
        helper.setWordWrap(True)
        layout.addWidget(helper)

        layout.addStretch(1)
        return tab
