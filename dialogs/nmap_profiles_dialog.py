"""Offline Nmap profile editor; contains no runtime or executable integration."""

from types import SimpleNamespace

from PySide6.QtCore import QSignalBlocker, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QSpinBox,
    QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.recon.nmap_profile_store import ProfileStorageError
from core.recon.nmap_profiles import (
    BUILTIN_PROFILES, PREVIEW_NOTICE, ProfileValidationError, duplicate_profile,
    format_network_impact, format_ports, preview_arguments, profile_from_dict, profile_to_dict,
)


class NmapProfilesDialog(QDialog):
    """Edit validated configuration without changing any executable profile."""

    profilesChanged = Signal()

    def __init__(self, store, parent=None):
        super().__init__(parent)
        self.store = store
        self.ui = SimpleNamespace()
        self._original = None
        self._draft = None
        self._valid_profile = None
        self._loading = False
        self._pending = None
        self._allow_close = False
        self.setWindowTitle("Nmap Scan Profiles")
        self.resize(920, 740)
        self.setMinimumSize(700, 480)
        self._build_ui()
        self._rebuild_list(BUILTIN_PROFILES[0].profile_id)
        if store.load_error:
            self._set_storage_notice(
                f"Custom profiles unavailable: {store.load_error} "
                "The file is preserved. Built-ins and offline previews remain available."
            )

    @staticmethod
    def _label(text=""):
        label = QLabel(text)
        label.setTextFormat(Qt.PlainText)
        label.setWordWrap(True)
        policy = label.sizePolicy()
        policy.setHorizontalPolicy(QSizePolicy.Ignored)
        label.setSizePolicy(policy)
        return label

    def _build_ui(self):
        ui = self.ui
        root = QVBoxLayout(self)
        root.setSpacing(10)
        ui.configurationNotice = self._label(
            "Configuration-only editor · Run eligible Web Services and bounded saved Custom profiles "
            "from Tool Inspector. The existing Quick Network Discovery action and Local Self-Test keep their current settings. "
            "Selecting or saving a profile grants no authorization and starts no scan."
        )
        root.addWidget(ui.configurationNotice)
        ui.storageNotice = self._label()
        root.addWidget(ui.storageNotice)
        ui.storageNotice.hide()
        ui.profileSplitter = QSplitter(Qt.Horizontal)
        ui.profileSplitter.setChildrenCollapsible(False)
        root.addWidget(ui.profileSplitter, 1)
        ui.profileList = QTreeWidget()
        ui.profileList.setHeaderHidden(True)
        ui.profileList.setMinimumWidth(170)
        ui.profileList.setAccessibleName("Built-in and custom Nmap profiles")
        ui.profileSplitter.addWidget(ui.profileList)
        ui.fieldsScroll = QScrollArea()
        ui.fieldsScroll.setWidgetResizable(True)
        ui.fieldsScroll.setFrameShape(QFrame.NoFrame)
        ui.fieldsScroll.setMinimumWidth(0)
        ui.profileSplitter.addWidget(ui.fieldsScroll)
        ui.profileSplitter.setStretchFactor(0, 0)
        ui.profileSplitter.setStretchFactor(1, 1)
        ui.profileSplitter.setSizes([220, 660])
        fields = QWidget()
        layout = QVBoxLayout(fields)
        layout.setContentsMargins(10, 0, 4, 0)
        ui.profileKind = self._label()
        layout.addWidget(ui.profileKind)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        layout.addLayout(form)
        ui.nameInput = QLineEdit()
        ui.nameInput.setMaxLength(100)
        ui.descriptionInput = QPlainTextEdit()
        ui.descriptionInput.setMaximumHeight(70)
        ui.descriptionInput.setTabChangesFocus(True)
        ui.portsInput = QLineEdit()
        ui.portsInput.setMaxLength(8192)
        ui.portsInput.setPlaceholderText("80,443,8000-8005 · up to 1024 TCP ports")
        ui.techniqueInput = QComboBox()
        ui.techniqueInput.addItem("TCP connect", "tcp-connect")
        ui.maxRateInput = self._spin(1, 100, " probes/s")
        ui.maxRetriesInput = self._spin(0, 3)
        ui.hostTimeoutInput = self._spin(5, 600, " s")
        ui.executionTimeoutInput = self._spin(10, 900, " s")
        ui.versionDetection = QCheckBox("Enable service version detection")
        ui.networkImpactInput = QPlainTextEdit()
        ui.networkImpactInput.setReadOnly(True)
        ui.networkImpactInput.setMaximumHeight(70)
        ui.networkImpactInput.setTabChangesFocus(True)
        self._inputs = (
            ui.nameInput, ui.descriptionInput, ui.portsInput, ui.techniqueInput,
            ui.maxRateInput, ui.maxRetriesInput, ui.hostTimeoutInput,
            ui.executionTimeoutInput, ui.versionDetection,
        )
        self._spin_inputs = (
            ui.maxRateInput, ui.maxRetriesInput, ui.hostTimeoutInput, ui.executionTimeoutInput,
        )
        for title, widget in (
            ("Name", ui.nameInput), ("Description", ui.descriptionInput),
            ("TCP ports", ui.portsInput), ("Scan technique", ui.techniqueInput),
            ("Maximum scan rate", ui.maxRateInput), ("Maximum retries", ui.maxRetriesInput),
            ("Host timeout", ui.hostTimeoutInput), ("Overall timeout", ui.executionTimeoutInput),
            ("Version detection", ui.versionDetection), ("Network impact", ui.networkImpactInput),
        ):
            widget.setAccessibleName(title)
            form.addRow(title, widget)
        ui.versionNotice = self._label(
            "Service version detection is not executable in R7B-1. It sends additional "
            "probes; Nmap --max-rate does not constrain every "
            "service-version probe."
        )
        layout.addWidget(ui.versionNotice)
        layout.addWidget(self._label("Illustrative argument preview"))
        ui.preview = QPlainTextEdit()
        ui.preview.setReadOnly(True)
        ui.preview.setAccessibleName("Read-only illustrative Nmap arguments")
        ui.preview.setMinimumHeight(90)
        ui.preview.setMaximumHeight(130)
        layout.addWidget(ui.preview)
        ui.previewNotice = self._label(PREVIEW_NOTICE)
        layout.addWidget(ui.previewNotice)
        ui.validationLabel = self._label()
        ui.validationLabel.setAccessibleName("Profile validation error")
        layout.addWidget(ui.validationLabel)
        layout.addStretch(1)
        ui.fieldsScroll.setWidget(fields)

        ui.unsavedPrompt = QFrame()
        prompt = QVBoxLayout(ui.unsavedPrompt)
        prompt.setContentsMargins(0, 0, 0, 0)
        ui.unsavedLabel = self._label()
        prompt.addWidget(ui.unsavedLabel)
        choices = QHBoxLayout()
        ui.btnSaveEdits = QPushButton("Save and continue")
        ui.btnDiscardEdits = QPushButton("Discard and continue")
        ui.btnKeepEditing = QPushButton("Keep editing")
        for button in (ui.btnSaveEdits, ui.btnDiscardEdits, ui.btnKeepEditing):
            choices.addWidget(button)
        choices.addStretch(1)
        prompt.addLayout(choices)
        root.addWidget(ui.unsavedPrompt)
        ui.unsavedPrompt.hide()

        actions = QHBoxLayout()
        ui.btnDuplicate = QPushButton("Duplicate")
        ui.btnSave = QPushButton("Save Custom Profile")
        ui.btnDelete = QPushButton("Delete Custom Profile")
        ui.btnReset = QPushButton("Reset")
        ui.btnClose = QPushButton("Close")
        for button in (ui.btnDuplicate, ui.btnSave, ui.btnDelete, ui.btnReset, ui.btnClose):
            button.setAutoDefault(False)
            actions.addWidget(button)
        root.addLayout(actions)
        ui.profileList.currentItemChanged.connect(self._selection_changed)
        for widget in (ui.nameInput, ui.portsInput):
            widget.textChanged.connect(self._validate)
        ui.descriptionInput.textChanged.connect(self._validate)
        for widget in self._spin_inputs:
            widget.valueChanged.connect(self._validate)
            # valueChanged alone misses incomplete text that retains the old value.
            widget.lineEdit().textChanged.connect(self._validate)
        ui.techniqueInput.currentIndexChanged.connect(self._validate)
        ui.versionDetection.toggled.connect(self._validate)
        ui.btnDuplicate.clicked.connect(lambda: self._request(self._duplicate, "duplicate a profile"))
        ui.btnSave.clicked.connect(self._save)
        ui.btnDelete.clicked.connect(lambda: self._request(self._delete, "delete this custom profile"))
        ui.btnReset.clicked.connect(lambda: self._request(self._reset, "reset unsaved edits"))
        ui.btnClose.clicked.connect(self.close)
        ui.btnKeepEditing.clicked.connect(self._cancel_pending)
        ui.btnDiscardEdits.clicked.connect(self._discard_pending)
        ui.btnSaveEdits.clicked.connect(self._save_pending)

    @staticmethod
    def _spin(minimum, maximum, suffix=""):
        widget = QSpinBox()
        widget.setRange(minimum, maximum)
        widget.setSuffix(suffix)
        return widget

    def _profiles(self):
        return BUILTIN_PROFILES + self.store.profiles + ((self._draft,) if self._draft else ())

    def _rebuild_list(self, selected_id):
        with QSignalBlocker(self.ui.profileList):
            tree = self.ui.profileList
            tree.clear()
            groups = [QTreeWidgetItem(tree, [title]) for title in ("Built-in profiles", "Custom profiles")]
            for group in groups:
                group.setFlags(group.flags() & ~Qt.ItemIsSelectable)
                group.setExpanded(True)
            for profile in self._profiles():
                suffix = " (unsaved)" if self._draft and profile.profile_id == self._draft.profile_id else ""
                item = QTreeWidgetItem(groups[0 if profile.is_builtin else 1], [profile.name + suffix])
                item.setData(0, Qt.UserRole, profile.profile_id)
                item.setToolTip(0, profile.description)
                if profile.profile_id == selected_id:
                    tree.setCurrentItem(item)
        self._select(selected_id)

    def _select(self, profile_id):
        for profile in self._profiles():
            if profile.profile_id == profile_id:
                self._load_profile(profile)
                with QSignalBlocker(self.ui.profileList):
                    for group_index in range(self.ui.profileList.topLevelItemCount()):
                        group = self.ui.profileList.topLevelItem(group_index)
                        for index in range(group.childCount()):
                            item = group.child(index)
                            if item.data(0, Qt.UserRole) == profile_id:
                                self.ui.profileList.setCurrentItem(item)
                return

    def _load_profile(self, profile):
        ui = self.ui
        self._loading = True
        self._original = profile
        ui.nameInput.setText(profile.name)
        ui.descriptionInput.setPlainText(profile.description)
        ui.portsInput.setText(format_ports(profile.ports))
        ui.techniqueInput.setCurrentIndex(ui.techniqueInput.findData(profile.technique))
        ui.maxRateInput.setValue(profile.max_rate)
        ui.maxRetriesInput.setValue(profile.max_retries)
        ui.hostTimeoutInput.setValue(profile.host_timeout_seconds)
        ui.executionTimeoutInput.setValue(profile.execution_timeout_seconds)
        ui.versionDetection.setChecked(profile.version_detection)
        for widget in self._inputs:
            if isinstance(widget, (QCheckBox, QComboBox)):
                widget.setEnabled(not profile.is_builtin)
            else:
                widget.setReadOnly(profile.is_builtin)
        ui.profileKind.setText(
            "Built-in · Read-only. Duplicate to edit."
            if profile.is_builtin else "Custom · Editable · Execution eligibility is checked in Tool Inspector."
        )
        self._baseline = self._field_values()
        self._loading = False
        self._validate()

    def _field_values(self):
        ui = self.ui
        return {
            "name": ui.nameInput.text(), "description": ui.descriptionInput.toPlainText(),
            "ports": ui.portsInput.text(), "technique": ui.techniqueInput.currentData(),
            "max_rate": ui.maxRateInput.value(), "max_retries": ui.maxRetriesInput.value(),
            "host_timeout_seconds": ui.hostTimeoutInput.value(),
            "execution_timeout_seconds": ui.executionTimeoutInput.value(),
            "version_detection": ui.versionDetection.isChecked(),
        }

    def _dirty(self):
        return self._original is not None and not self._original.is_builtin and (
            self._is_draft() or self._field_values() != self._baseline
            or any(not widget.hasAcceptableInput() for widget in self._spin_inputs)
        )

    def _is_draft(self):
        return self._draft is not None and self._original.profile_id == self._draft.profile_id

    def _validate(self, *_):
        if self._loading or self._original is None:
            return
        self._valid_profile = None
        try:
            for widget in self._spin_inputs:
                if not widget.hasAcceptableInput():
                    raise ProfileValidationError(
                        f"{widget.accessibleName()} must be an integer "
                        f"from {widget.minimum()} to {widget.maximum()}."
                    )
            data = profile_to_dict(self._original)
            # Keep the legacy network_impact storage field; derive only its display.
            data.update(self._field_values())
            profile = profile_from_dict(data)
            arguments = preview_arguments(profile)
            impact = format_network_impact(profile)
        except ProfileValidationError as error:
            self.ui.validationLabel.setText(str(error))
            self.ui.preview.clear()
            self.ui.networkImpactInput.setPlainText(f"Network impact unavailable: {error}")
        else:
            self._valid_profile = profile
            self.ui.validationLabel.clear()
            self.ui.preview.setPlainText(" ".join(arguments))
            self.ui.networkImpactInput.setPlainText(impact)
        custom = not self._original.is_builtin
        can_save = custom and self._valid_profile is not None and self.store.writable
        self.ui.btnSave.setEnabled(can_save and self._dirty())
        self.ui.btnSaveEdits.setEnabled(can_save)
        self.ui.btnDelete.setEnabled(custom and not self._is_draft() and self.store.writable)
        self.ui.btnReset.setEnabled(self._dirty())

    def _selection_changed(self, current, previous):
        if current is None or self._original is None:
            return
        profile_id = current.data(0, Qt.UserRole)
        if not profile_id or profile_id == self._original.profile_id:
            return
        with QSignalBlocker(self.ui.profileList):
            self.ui.profileList.setCurrentItem(previous)
        self._request(lambda: self._select(profile_id), "select another profile")

    def _request(self, action, purpose):
        if not self._dirty():
            action()
            return
        self._pending = action
        self.ui.unsavedLabel.setText(f"Unsaved profile edits. Save or discard them to {purpose}.")
        self.ui.unsavedPrompt.show()
        self._validate()

    def _cancel_pending(self):
        self._pending = None
        self.ui.unsavedPrompt.hide()

    def _discard_pending(self):
        action = self._pending
        self._cancel_pending()
        if action is not None:
            self._load_profile(self._original)
            if self._is_draft() and action != self._reset:
                self._draft = None
                # Remove the discarded copy while retaining the original value
                # for a pending duplicate action.
                with QSignalBlocker(self.ui.profileList):
                    group = self.ui.profileList.topLevelItem(1)
                    for index in range(group.childCount()):
                        item = group.child(index)
                        if item.data(0, Qt.UserRole) == self._original.profile_id:
                            group.takeChild(index)
                            break
            action()
            if not any(profile.profile_id == self._original.profile_id for profile in self._profiles()):
                self._rebuild_list(BUILTIN_PROFILES[0].profile_id)

    def _save_pending(self):
        action = self._pending
        if self._save():
            self._cancel_pending()
            if action is not None:
                action()

    def _duplicate(self):
        self._draft = duplicate_profile(self._original)
        self._rebuild_list(self._draft.profile_id)

    def _save(self):
        self._validate()
        if self._valid_profile is None or self._original.is_builtin or not self.store.writable:
            return False
        profile = self._valid_profile
        try:
            self.store.save(profile)
        except ProfileStorageError as error:
            self._set_storage_notice(str(error))
            return False
        self._draft = None
        self._set_storage_notice("")
        self._cancel_pending()
        self._rebuild_list(profile.profile_id)
        self.profilesChanged.emit()
        return True

    def _delete(self):
        if self._original.is_builtin or self._is_draft() or not self.store.writable:
            return
        try:
            self.store.delete(self._original.profile_id)
        except ProfileStorageError as error:
            self._set_storage_notice(str(error))
            return
        self._set_storage_notice("")
        self._rebuild_list(BUILTIN_PROFILES[0].profile_id)
        self.profilesChanged.emit()

    def _set_storage_notice(self, message):
        self.ui.storageNotice.setText(message)
        self.ui.storageNotice.setVisible(bool(message))

    def _reset(self):
        self._load_profile(self._original)

    def _finish_close(self):
        self._allow_close = True
        self.close()

    def closeEvent(self, event):
        if self._dirty() and not self._allow_close:
            event.ignore()
            self._request(self._finish_close, "close the manager")
            return
        self._cancel_pending()
        super().closeEvent(event)
        self._allow_close = False

    def reject(self):
        if self._dirty() and not self._allow_close:
            self._request(self._finish_close, "close the manager")
        else:
            self._cancel_pending()
            super().reject()
