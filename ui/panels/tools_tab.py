"""External tool workspaces using the existing Recon controllers and state."""

from types import SimpleNamespace

from PySide6.QtWidgets import QFrame, QLabel, QScrollArea, QTabWidget, QVBoxLayout, QWidget

from ui.recon_tool_info import ToolInformationView


class ToolsTab(QWidget):
    """Host tool pages without creating runtimes or taking execution ownership."""

    def __init__(self, recon, parent=None):
        super().__init__(parent)
        self.ui = SimpleNamespace()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        self.ui.toolPages = QTabWidget()
        self.ui.toolPages.setAccessibleName("Tool workspaces")
        root.addWidget(self.ui.toolPages)

        self.ui.nmapPage = QWidget()
        self.ui.toolPages.addTab(self.ui.nmapPage, "Nmap")
        page = QVBoxLayout(self.ui.nmapPage)
        page.setContentsMargins(24, 16, 24, 16)
        title = QLabel("Tools · Nmap")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")
        page.addWidget(title)
        note = QLabel("Use checked targets from Recon → Target Manager. Results share Recon → Asset Inventory and Run / Import History.")
        note.setWordWrap(True)
        page.addWidget(note)

        self.ui.nmapScroll = QScrollArea()
        self.ui.nmapScroll.setAccessibleName("Nmap workspace controls and evidence")
        self.ui.nmapScroll.setWidgetResizable(True)
        self.ui.nmapScroll.setFrameShape(QFrame.NoFrame)
        self.ui.nmapInfo = ToolInformationView()
        self.ui.nmapScroll.setWidget(self.ui.nmapInfo)
        page.addWidget(self.ui.nmapScroll, 1)
        recon.rehost_nmap_controls(self.ui.nmapInfo)
