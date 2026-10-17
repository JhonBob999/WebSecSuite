"""Read-only Qt projection and filters for the offline Recon inventory."""

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt


TYPE_LABELS = {"hostname": "Hostname", "ip": "IP address", "service": "Service"}


class ReconAssetModel(QAbstractTableModel):
    ENTITY, TYPE, SERVICE, SOURCES, EVIDENCE = range(5)
    HEADERS = ("Asset / Entity", "Type", "Service / Port", "Source(s)", "Evidence count")
    AssetRole = Qt.UserRole + 1
    EntityKeyRole = Qt.UserRole + 2
    SortRole = Qt.UserRole + 3
    SearchRole = Qt.UserRole + 4

    def __init__(self, parent=None):
        super().__init__(parent)
        self._assets = ()
        self._search_text = ()

    def set_assets(self, assets):
        """Replace a validated snapshot in one batch; cache search text once."""
        assets = tuple(assets)
        search_text = tuple(" ".join((
            asset.value, TYPE_LABELS[asset.entity_type], asset.entity_type,
            asset.transport or "", str(asset.port) if asset.port is not None else "",
            *asset.service_names, *asset.sources,
        )).casefold() for asset in assets)
        self.beginResetModel()
        self._assets = assets
        self._search_text = search_text
        self.endResetModel()

    def asset_at(self, row):
        return self._assets[row] if 0 <= row < len(self._assets) else None

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._assets)

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
        if not index.isValid() or not 0 <= index.column() < len(self.HEADERS):
            return None
        asset = self.asset_at(index.row())
        if asset is None:
            return None
        if role == self.AssetRole:
            return asset
        if role == self.EntityKeyRole:
            return asset.entity_key
        if role == self.SearchRole:
            return self._search_text[index.row()]
        if role == self.SortRole:
            if index.column() == self.SERVICE:
                return asset.port if asset.port is not None else -1
            if index.column() == self.EVIDENCE:
                return asset.evidence_count
            return str(self.data(index)).casefold()
        if role == Qt.ToolTipRole:
            return asset.entity_key
        if role == Qt.DisplayRole:
            service = ""
            if asset.port is not None:
                endpoint = f"{asset.transport}/{asset.port}"
                names = ", ".join(asset.service_names)
                service = f"{names} · {endpoint}" if names else endpoint
            return (
                asset.value, TYPE_LABELS[asset.entity_type], service,
                ", ".join(asset.sources), asset.evidence_count,
            )[index.column()]
        return None

    def flags(self, index):
        if not index.isValid() or self.asset_at(index.row()) is None:
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable


class ReconAssetFilterProxy(QSortFilterProxyModel):
    """Literal text search combined with exact entity-type and source filters."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._search = ""
        self._entity_type = ""
        self._source = ""
        self.setSortRole(ReconAssetModel.SortRole)
        self.setDynamicSortFilter(True)

    def set_search_text(self, text):
        self._search = text.strip().casefold()
        self.invalidateFilter()

    def set_entity_type(self, entity_type):
        self._entity_type = entity_type
        self.invalidateFilter()

    def set_source(self, source):
        self._source = source
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        if model is None or source_parent.isValid():
            return False
        asset = model.asset_at(source_row)
        if asset is None:
            return False
        if self._entity_type and asset.entity_type != self._entity_type:
            return False
        if self._source and self._source not in asset.sources:
            return False
        return not self._search or self._search in model.data(
            model.index(source_row, 0), ReconAssetModel.SearchRole,
        )
