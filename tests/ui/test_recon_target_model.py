import pytest
from PySide6.QtCore import Qt


@pytest.fixture
def model(qapp):
    from ui.recon_target_model import ReconTargetModel

    return ReconTargetModel()


def add_text(model, text, source="paste"):
    from core.recon.targets import parse_text

    return model.add_report(parse_text(text, source))


def test_inventory_deduplicates_across_sources_without_changing_selection(model):
    add_text(model, "EXAMPLE.test", "manual")
    report = add_text(model, "example.test\nother.test", "txt")
    assert model.rowCount() == 2
    assert report.duplicates == 1
    assert len(report.targets) == 1
    assert model.selected_count == 0
    assert model.data(model.index(0, model.SOURCE)) == "manual"
    assert model.data(model.index(1, model.SOURCE)) == "TXT"
    assert model.data(model.index(0, model.SCOPE)) == "Unreviewed"


def test_checkboxes_bulk_selection_and_remove_selected(model):
    add_text(model, "one.test\ntwo.test\nthree.test")
    assert model.setData(model.index(1, model.SELECT), Qt.Checked, Qt.CheckStateRole)
    assert model.selected_count == 1
    assert model.data(model.index(1, model.SELECT), Qt.CheckStateRole) == Qt.Checked
    assert model.data(model.index(1, model.SCOPE)) == "Unreviewed"
    model.set_all_selected(True)
    assert model.selected_count == 3
    model.set_all_selected(False)
    assert model.selected_count == 0
    model.setData(model.index(1, model.SELECT), Qt.Checked, Qt.CheckStateRole)
    assert model.remove_selected() == 1
    assert model.rowCount() == 2
    assert model.selected_count == 0
    assert [model.data(model.index(row, model.HOSTNAME)) for row in range(2)] == [
        "one.test", "three.test",
    ]
    assert len(add_text(model, "two.test").targets) == 1


def test_edits_normalize_and_revalidate_without_authorizing(model):
    add_text(model, "one.test\ntwo.test")
    model.set_all_selected(True)
    idx = model.index(0, model.HOSTNAME)
    assert model.setData(idx, " BÜCHER.de ")
    assert model.data(idx) == "xn--bcher-kva.de"
    assert model.data(model.index(0, model.VALIDATION)) == "Valid"
    assert model.selected_count == 1
    assert model.data(model.index(0, model.SCOPE)) == "Unreviewed"
    assert model.setData(idx, "https://example.test/private")
    assert "Invalid" in model.data(model.index(0, model.VALIDATION))
    assert not (model.flags(model.index(0, model.SELECT)) & Qt.ItemIsUserCheckable)
    model.set_all_selected(True)
    assert model.selected_count == 1
    assert model.setData(idx, "valid.test")
    assert model.data(model.index(0, model.VALIDATION)) == "Valid"
    assert model.data(model.index(0, model.SELECT), Qt.CheckStateRole) == Qt.Unchecked


def test_duplicate_edit_preserves_inventory_and_reports_error(model):
    add_text(model, "one.test\ntwo.test")
    errors = []
    model.editRejected.connect(errors.append)
    assert not model.setData(model.index(0, model.HOSTNAME), "TWO.test")
    assert model.data(model.index(0, model.HOSTNAME)) == "one.test"
    assert errors and "already" in errors[0].lower()


def test_large_inventory_uses_batched_model_insertions(model):
    insertions = []
    model.rowsInserted.connect(lambda parent, first, last: insertions.append((first, last)))
    add_text(model, "\n".join(f"host{i}.test" for i in range(10000)))
    assert model.rowCount() == 10000
    assert insertions == [(0, 9999)]
    model.set_all_selected(True)
    assert model.selected_count == 10000
    model.clear()
    assert model.rowCount() == model.selected_count == 0
    assert len(add_text(model, "host0.test").targets) == 1


def test_only_hostname_and_selection_are_editable(model):
    add_text(model, "example.test")
    assert model.flags(model.index(0, model.HOSTNAME)) & Qt.ItemIsEditable
    for column in (model.SOURCE, model.VALIDATION, model.SCOPE):
        assert not (model.flags(model.index(0, column)) & Qt.ItemIsEditable)
        assert not model.setData(model.index(0, column), "Authorized")
