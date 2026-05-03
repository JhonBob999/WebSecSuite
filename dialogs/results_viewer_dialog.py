from __future__ import annotations

from dialogs.universal_viewer_dialog import UniversalViewerDialog


class ResultsViewerDialog(UniversalViewerDialog):
    def __init__(self, payload=None, parent=None):
        super().__init__(
            payload=payload,
            parent=parent,
            title="Results Viewer",
            save_dialog_title="Save Results",
            pretty_default_name="results.json",
            raw_default_name="results.txt",
        )
