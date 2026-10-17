"""Qt models for imported Recon targets and the last import's rejected rows."""

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal

from core.recon.targets import ImportReport, TargetRecord, normalize_hostname


class ReconTargetModel(QAbstractTableModel):
    SELECT, HOSTNAME, SOURCE, VALIDATION, SCOPE = range(5)
    HEADERS = ("Selected", "Hostname", "Source", "Validation", "Scope")
    inventoryChanged = Signal()
    editRejected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._targets = []
        self._hostnames = set()
        self._selected_count = 0

    @property
    def selected_count(self):
        return self._selected_count

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._targets)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal and 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
            if orientation == Qt.Vertical:
                return section + 1
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._targets):
            return None
        target = self._targets[index.row()]
        column = index.column()
        if role == Qt.CheckStateRole and column == self.SELECT:
            return Qt.Checked if target.selected else Qt.Unchecked
        if role == Qt.ToolTipRole:
            if column == self.SCOPE:
                return "Scope is unreviewed. Selection does not grant authorization for active scanning."
            if column == self.VALIDATION:
                return target.validation_state
        if role in (Qt.DisplayRole, Qt.EditRole):
            return (
                None,
                target.hostname,
                {"txt": "TXT", "csv": "CSV"}.get(target.source, target.source),
                target.validation_state,
                target.scope_status,
            )[column]
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable
        if index.column() == self.HOSTNAME:
            flags |= Qt.ItemIsEditable
        if index.column() == self.SELECT and self._targets[index.row()].validation_state == "Valid":
            flags |= Qt.ItemIsUserCheckable
        return flags

    def setData(self, index, value, role=Qt.EditRole):
        if not index.isValid() or not 0 <= index.row() < len(self._targets):
            return False
        target = self._targets[index.row()]
        if index.column() == self.SELECT and role == Qt.CheckStateRole:
            if target.validation_state != "Valid":
                return False
            if value not in (Qt.Checked, Qt.Unchecked, Qt.Checked.value, Qt.Unchecked.value):
                return False
            selected = value in (Qt.Checked, Qt.Checked.value)
            self._selected_count += int(selected) - int(target.selected)
            target.selected = selected
            self.dataChanged.emit(index, index, [Qt.CheckStateRole])
            self.inventoryChanged.emit()
            return True
        if index.column() != self.HOSTNAME or role != Qt.EditRole or not isinstance(value, str):
            return False

        try:
            hostname = normalize_hostname(value)
            validation = "Valid"
        except ValueError as exc:
            hostname, validation = value.strip(), f"Invalid: {exc}"
        if validation == "Valid" and hostname in self._hostnames and hostname != target.hostname:
            self.editRejected.emit(f"{hostname} is already in the target list.")
            return False
        if hostname == target.hostname and validation == target.validation_state:
            return True
        if target.validation_state == "Valid":
            self._hostnames.discard(target.hostname)
        if validation == "Valid":
            self._hostnames.add(hostname)
        self._selected_count -= int(target.selected)
        target.hostname = hostname
        target.validation_state = validation
        target.selected = False
        target.scope_status = "Unreviewed"
        self.dataChanged.emit(self.index(index.row(), 0), self.index(index.row(), self.SCOPE))
        self.inventoryChanged.emit()
        return True

    def add_report(self, report):
        """Insert a batch, retaining first-source provenance across all imports."""
        added = []
        duplicates = report.duplicates
        for target in report.targets:
            if target.hostname in self._hostnames:
                duplicates += 1
                continue
            self._hostnames.add(target.hostname)
            added.append(TargetRecord(hostname=target.hostname, source=target.source))
        if added:
            first = len(self._targets)
            self.beginInsertRows(QModelIndex(), first, first + len(added) - 1)
            self._targets.extend(added)
            self.endInsertRows()
            self.inventoryChanged.emit()
        return ImportReport(targets=added, issues=list(report.issues), duplicates=duplicates)

    def set_all_selected(self, selected):
        for target in self._targets:
            target.selected = bool(selected) and target.validation_state == "Valid"
        self._selected_count = sum(target.selected for target in self._targets)
        if self._targets:
            self.dataChanged.emit(self.index(0, self.SELECT),
                                  self.index(len(self._targets) - 1, self.SELECT), [Qt.CheckStateRole])
        self.inventoryChanged.emit()

    def remove_selected(self):
        removed = self._selected_count
        if not removed:
            return 0
        self.beginResetModel()
        self._targets = [target for target in self._targets if not target.selected]
        self._hostnames = {target.hostname for target in self._targets if target.validation_state == "Valid"}
        self._selected_count = 0
        self.endResetModel()
        self.inventoryChanged.emit()
        return removed

    def clear(self):
        self.beginResetModel()
        self._targets.clear()
        self._hostnames.clear()
        self._selected_count = 0
        self.endResetModel()
        self.inventoryChanged.emit()


class ImportIssueModel(QAbstractTableModel):
    HEADERS = ("Row", "Input", "Reason")

    def __init__(self, parent=None):
        super().__init__(parent)
        self._issues = []

    def set_issues(self, issues):
        self.beginResetModel()
        self._issues = list(issues)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._issues)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal and 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if index.isValid() and 0 <= index.row() < len(self._issues) and role in (Qt.DisplayRole, Qt.ToolTipRole):
            issue = self._issues[index.row()]
            return (issue.row if issue.row else "File", issue.value, issue.reason)[index.column()]
        return None
