"""Offline Nmap profile editor; contains no runtime or executable integration."""

from types import SimpleNamespace

from PySide6.QtCore import QSignalBlocker, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QSpinBox,
    QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.recon.nmap_profile_store import ProfileStorageError
from core.recon.nmap_profiles import (
    BUILTIN_PROFILES, PREVIEW_NOTICE, ProfileValidationError, duplicate_profile,
    format_network_impact, format_ports, preview_arguments, profile_from_dict, profile_to_dict,
    TECHNIQUE_FLAGS, DISCOVERY_PROBE_FLAGS,
)


class NmapProfilesDialog(QDialog):
    """Edit validated configuration without changing any executable profile."""

    profilesChanged = Signal()

    def __init__(self, store, parent=None, *, catalog_loader=None):
        super().__init__(parent)
        self.store = store
        self.ui = SimpleNamespace()
        self._original = None
        self._draft = None
        self._valid_profile = None
        self._loading = False
        self._pending = None
        self._allow_close = False
        self._catalog_loader = catalog_loader
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
            "Configuration-only editor · Run supported profiles from Tools → Nmap after capability and scope checks. "
            "The existing Quick Network Discovery action and Local Self-Test keep their current settings. "
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
        ui.settingsTabs = QTabWidget()
        ui.settingsTabs.setMinimumHeight(275)
        ui.settingsTabs.setMaximumHeight(380)
        layout.addWidget(ui.settingsTabs)
        general = QWidget()
        form = QFormLayout(general)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        general_scroll = QScrollArea()
        general_scroll.setFrameShape(QFrame.NoFrame)
        general_scroll.setWidgetResizable(True)
        general_scroll.setWidget(general)
        ui.settingsTabs.addTab(general_scroll, "Scan / Ports")
        self._general_form = form
        ui.nameInput = QLineEdit()
        ui.nameInput.setMaxLength(100)
        ui.descriptionInput = QPlainTextEdit()
        ui.descriptionInput.setMaximumHeight(70)
        ui.descriptionInput.setTabChangesFocus(True)
        ui.portsInput = QLineEdit()
        ui.portsInput.setMaxLength(8192)
        ui.portsInput.setPlaceholderText("80,443,8000-8005 · up to 1024 TCP ports")
        ui.techniqueInput = QComboBox()
        for technique, flag in TECHNIQUE_FLAGS.items():
            ui.techniqueInput.addItem(f"{technique.replace('-', ' ').upper()} ({flag})", technique)
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
        self._build_extended_fields()
        ui.versionNotice = self._label(
            "R7B-2: raw-packet techniques require Windows/Npcap capability checks. Version, OS, NSE and discovery "
            "send additional probes; --max-rate does not constrain every probe. A valid configuration may be unavailable "
            "on this computer. NSE scripts run only after explicit execution approval."
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
        for widget in (ui.nameInput, ui.portsInput, ui.udpPortsInput, ui.scriptIdsInput):
            widget.textChanged.connect(self._validate)
        ui.descriptionInput.textChanged.connect(self._validate)
        ui.scriptArgumentsInput.textChanged.connect(self._validate)
        for widget in self._spin_inputs:
            widget.valueChanged.connect(self._validate)
            # valueChanged alone misses incomplete text that retains the old value.
            widget.lineEdit().textChanged.connect(self._validate)
        ui.techniqueInput.currentIndexChanged.connect(self._validate)
        ui.versionDetection.toggled.connect(self._validate)
        for widget in self._extended_checks:
            widget.toggled.connect(self._validate)
        for widget in self._extended_combos:
            widget.currentIndexChanged.connect(self._validate)
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

    def _build_extended_fields(self):
        """Keep advanced configuration in compact groups within the existing editor."""
        ui = self.ui

        def tab(title):
            page = QWidget()
            form = QFormLayout(page)
            form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
            form.setRowWrapPolicy(QFormLayout.WrapLongRows)
            scroll = QScrollArea()
            scroll.setFrameShape(QFrame.NoFrame)
            scroll.setWidgetResizable(True)
            scroll.setWidget(page)
            ui.settingsTabs.addTab(scroll, title)
            return form

        def combo(items):
            widget = QComboBox()
            for label, value in items:
                widget.addItem(label, value)
            return widget

        def add(form, label, widget, help_text=""):
            widget.setAccessibleName(label)
            if help_text:
                widget.setToolTip(help_text)
            form.addRow(label, widget)
            return widget

        def move_row(source, widget, target, label):
            row = source.takeRow(widget)
            if row.labelItem is not None:
                old_label = row.labelItem.widget()
                old_label.hide()
                old_label.deleteLater()
            add(target, label, widget)

        ports = self._general_form
        ui.udpScan = add(ports, "UDP combination", QCheckBox("Add UDP scan (-sU)"), "Combines the selected TCP technique with UDP. Requires raw-packet capabilities.")
        ui.udpPortsInput = add(ports, "UDP ports", QLineEdit())
        ui.udpPortsInput.setMaxLength(8192)
        ui.udpPortsInput.setPlaceholderText("53,123,161 · explicit UDP ports")
        ui.portModeInput = add(ports, "Port selection", combo((("Explicit ports", "explicit"), ("All ports (1–65535)", "all"), ("Most common ports", "top"))))
        ui.topPortsInput = add(ports, "Top ports per protocol", self._spin(1, 65535))
        ui.portPresetInput = add(ports, "TCP port preset", combo((("Keep current ports", ""), ("Common web", "80,443,8000,8080,8443"), ("Common services", "21-23,25,53,80,110,135,139,143,443,445,3389"), ("First 1024", "1-1024"))))
        ui.portPresetInput.currentIndexChanged.connect(self._apply_port_preset)

        discovery = tab("Discovery / DNS")
        ui.discoveryInput = add(discovery, "Discovery mode", combo((("No discovery (-Pn)", "none"), ("Default discovery", "default"), ("Host discovery only (-sn)", "only"), ("List only (-sL)", "list"))))
        ui.dnsModeInput = add(discovery, "DNS resolution", combo((("Never resolve (-n)", "never"), ("Reverse DNS (-R)", "reverse"))), "Reverse DNS names are observations. They never expand the authorized target scope.")
        ui.probeChecks = {}
        for probe, flag in DISCOVERY_PROBE_FLAGS.items():
            ui.probeChecks[probe] = add(discovery, probe.replace("-", " ").title(), QCheckBox(flag))
        discovery.addRow(self._label("Probe choices require Default discovery or Host discovery only. Defaults use Nmap's documented probe set."))

        identification = tab("Service / OS")
        # Move existing version checkbox to the identification tab.
        # takeRow preserves the existing widget and public UI object identity.
        move_row(ports, ui.versionDetection, identification, "Version detection")
        ui.versionIntensityInput = add(identification, "Version intensity", self._spin(0, 9), "0 sends the fewest version probes; 9 tries every probe.")
        ui.versionAll = add(identification, "All version probes", QCheckBox("--version-all"))
        ui.versionTrace = add(identification, "Version trace", QCheckBox("--version-trace"))
        ui.versionTimeoutInput = add(identification, "Version execution budget", self._spin(0, 900, " s"), "0 uses the overall timeout. A nonzero value limits the entire version-enabled process, not an individual service probe; Nmap has no independent version-timeout option.")
        ui.osDetection = add(identification, "OS detection", QCheckBox("Enable OS guesses (-O)"), "Requires raw-packet privileges and favorable open/closed port evidence. Output is a confidence-rated guess.")
        ui.osGuess = add(identification, "Aggressive OS guess", QCheckBox("--osscan-guess"))
        ui.osLimit = add(identification, "Limit OS attempts", QCheckBox("--osscan-limit"))

        timing = tab("Timing")
        for widget, label in ((ui.maxRateInput, "Maximum scan rate"), (ui.maxRetriesInput, "Maximum retries"),
                              (ui.hostTimeoutInput, "Host timeout"), (ui.executionTimeoutInput, "Overall timeout")):
            move_row(ports, widget, timing, label)
        ui.timingTemplateInput = add(timing, "Timing template", self._spin(0, 5), "T0–T5; higher values can be disruptive. Explicit rate, retries and timeouts remain bounded.")
        ui.minRateInput = add(timing, "Minimum rate", self._spin(0, 100, " probes/s"), "0 leaves Nmap's minimum unset. Cannot exceed maximum rate.")
        ui.minParallelismInput = add(timing, "Minimum parallel probes", self._spin(0, 64))
        ui.maxParallelismInput = add(timing, "Maximum parallel probes", self._spin(0, 64), "0 uses Nmap defaults. This is probe parallelism, not a reliable cap on every NSE/service operation.")

        nse = tab("NSE")
        from ui.nmap_nse_catalog import NmapScriptCatalogWidget
        ui.scriptCatalog = NmapScriptCatalogWidget(catalog_loader=self._catalog_loader)
        nse.addRow(ui.scriptCatalog)
        ui.scriptIdsInput = add(nse, "Selected script IDs", QLineEdit(), "Comma-separated installed script IDs. No external paths, categories, expressions or automatic script presets. Execution verifies each installed file.")
        ui.scriptIdsInput.setMaxLength(3232)
        ui.scriptArgumentsInput = add(nse, "Structured script arguments", QPlainTextEdit(), "One name=value pair per line. Only bounded simple scalar values are accepted; nested Lua syntax, external files and option injection are unsupported. Do not store secrets in profiles.")
        ui.scriptArgumentsInput.setMaximumHeight(80)
        ui.scriptTimeoutInput = add(nse, "Script timeout", self._spin(1, 600, " s"))
        nse.addRow(self._label("Potentially disruptive categories require an additional per-run confirmation. Presets never enable scripts automatically."))
        ui.scriptCatalog.selectionChanged.connect(lambda values: ui.scriptIdsInput.setText(",".join(values)))
        ui.scriptIdsInput.textChanged.connect(self._sync_script_selection)

        routing = tab("Routing / Output")
        ui.traceroute = add(routing, "Traceroute", QCheckBox("Enable --traceroute"), "Requires supported capabilities and sends probes along the route. Intermediate hops are observations and never authorized scan targets.")
        routing.addRow(self._label("Output is locked to bounded XML on stdout with no stylesheet. Runtime retains validated raw evidence and provenance. Arbitrary output paths, interfaces, source spoofing and raw expert arguments are unsupported."))

        self._extended_checks = (ui.udpScan, *ui.probeChecks.values(), ui.versionAll, ui.versionTrace,
                                 ui.osDetection, ui.osGuess, ui.osLimit, ui.traceroute)
        self._extended_combos = (ui.portModeInput, ui.discoveryInput, ui.dnsModeInput)
        extra_spins = (ui.topPortsInput, ui.timingTemplateInput, ui.minRateInput,
                       ui.minParallelismInput, ui.maxParallelismInput, ui.versionIntensityInput,
                       ui.versionTimeoutInput, ui.scriptTimeoutInput)
        self._spin_inputs += extra_spins
        self._inputs += (*self._extended_checks, *self._extended_combos, *extra_spins,
                         ui.udpPortsInput, ui.scriptIdsInput, ui.scriptArgumentsInput, ui.portPresetInput)

    def _apply_port_preset(self):
        if self._loading or self._original is None or self._original.is_builtin:
            return
        ports = self.ui.portPresetInput.currentData()
        if ports:
            self.ui.portsInput.setText(ports)
            self.ui.portPresetInput.setCurrentIndex(0)

    def _sync_script_selection(self, text):
        if not self._loading:
            self.ui.scriptCatalog.set_selected(tuple(value.strip() for value in text.split(",") if value.strip()))

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
        ui.udpPortsInput.setText(format_ports(profile.udp_ports) if profile.udp_ports else "")
        ui.udpScan.setChecked(profile.udp_scan)
        for widget, value in ((ui.portModeInput, profile.port_mode), (ui.discoveryInput, profile.discovery),
                              (ui.dnsModeInput, profile.dns_mode)):
            widget.setCurrentIndex(widget.findData(value))
        ui.portPresetInput.setCurrentIndex(0)
        for probe, widget in ui.probeChecks.items():
            widget.setChecked(probe in profile.discovery_probes)
        for widget, value in (
            (ui.topPortsInput, profile.top_ports), (ui.timingTemplateInput, profile.timing_template),
            (ui.minRateInput, profile.min_rate), (ui.minParallelismInput, profile.min_parallelism),
            (ui.maxParallelismInput, profile.max_parallelism), (ui.versionIntensityInput, profile.version_intensity),
            (ui.versionTimeoutInput, profile.version_timeout_seconds), (ui.scriptTimeoutInput, profile.script_timeout_seconds),
        ):
            widget.setValue(value)
        for widget, value in ((ui.versionAll, profile.version_all), (ui.versionTrace, profile.version_trace),
                              (ui.osDetection, profile.os_detection), (ui.osGuess, profile.os_guess),
                              (ui.osLimit, profile.os_limit), (ui.traceroute, profile.traceroute)):
            widget.setChecked(value)
        ui.scriptIdsInput.setText(",".join(profile.script_ids))
        ui.scriptArgumentsInput.setPlainText("\n".join(f"{name}={value}" for name, value in profile.script_arguments))
        ui.scriptCatalog.set_selected(profile.script_ids)
        ui.scriptCatalog.setEnabled(not profile.is_builtin)
        for widget in self._inputs:
            if isinstance(widget, (QCheckBox, QComboBox)):
                widget.setEnabled(not profile.is_builtin)
            else:
                widget.setReadOnly(profile.is_builtin)
        ui.profileKind.setText(
            "Built-in · Read-only. Duplicate to edit."
            if profile.is_builtin else "Custom · Editable · Execution eligibility is checked in Tools → Nmap."
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
            "udp_ports": ui.udpPortsInput.text(), "udp_scan": ui.udpScan.isChecked(),
            "port_mode": ui.portModeInput.currentData(), "top_ports": ui.topPortsInput.value(),
            "discovery": ui.discoveryInput.currentData(),
            "discovery_probes": [probe for probe, widget in ui.probeChecks.items() if widget.isChecked()],
            "dns_mode": ui.dnsModeInput.currentData(), "timing_template": ui.timingTemplateInput.value(),
            "min_rate": ui.minRateInput.value(), "min_parallelism": ui.minParallelismInput.value(),
            "max_parallelism": ui.maxParallelismInput.value(), "version_intensity": ui.versionIntensityInput.value(),
            "version_all": ui.versionAll.isChecked(), "version_trace": ui.versionTrace.isChecked(),
            "os_detection": ui.osDetection.isChecked(), "os_guess": ui.osGuess.isChecked(),
            "os_limit": ui.osLimit.isChecked(), "traceroute": ui.traceroute.isChecked(),
            "script_ids": [value.strip() for value in ui.scriptIdsInput.text().split(",")] if ui.scriptIdsInput.text() else [],
            "script_arguments": [line.split("=", 1) for line in ui.scriptArgumentsInput.toPlainText().splitlines() if line],
            "script_timeout_seconds": ui.scriptTimeoutInput.value(),
            "version_timeout_seconds": ui.versionTimeoutInput.value(),
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
