"""Catalog UI is passive until explicitly loaded and preserves script selection."""

from types import SimpleNamespace

from PySide6.QtCore import Qt


def test_catalog_load_filter_selection_and_risk_details(qapp):
    from ui.nmap_nse_catalog import NmapScriptCatalogWidget

    calls = []
    scripts = (
        SimpleNamespace(script_id="http-title", categories=("discovery", "safe"),
            description="Read the HTML title.", sha256="a" * 64),
        SimpleNamespace(script_id="http-brute", categories=("brute", "intrusive"),
            description="Attempt credentials.", sha256="b" * 64),
    )
    widget = NmapScriptCatalogWidget(catalog_loader=lambda: calls.append(True) or scripts)
    assert not calls
    widget.ui.load.click()
    assert calls == [True]
    widget.ui.search.setText("title")
    assert widget.ui.scripts.count() == 1
    item = widget.ui.scripts.item(0)
    item.setCheckState(Qt.Checked)
    widget.ui.scripts.setCurrentItem(item)
    assert widget.selected_ids() == ("http-title",)
    assert "Read the HTML title" in widget.ui.details.toPlainText()
    widget.ui.search.setText("brute")
    widget.ui.scripts.setCurrentRow(0)
    assert "high impact" in widget.ui.details.toPlainText().lower()
    assert widget.selected_ids() == ("http-title",)
    widget.close()


def test_catalog_failure_keeps_selection_and_disables_execution_claims(qapp):
    from ui.nmap_nse_catalog import NmapScriptCatalogWidget

    def fail():
        raise ValueError("Verify Nmap first.")

    widget = NmapScriptCatalogWidget(catalog_loader=fail)
    widget.set_selected(("http-title",))
    widget.ui.load.click()
    assert widget.selected_ids() == ("http-title",)
    assert "Verify Nmap first" in widget.ui.status.text()
    widget.close()
