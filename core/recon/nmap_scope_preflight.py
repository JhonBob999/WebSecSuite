"""Asynchronous Qt DNS preflight; it never grants permission or launches Nmap."""

import ipaddress
import re

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QDnsLookup

from core.recon.nmap_scope import MAX_INPUTS, resolve_scope, scope_is_fresh
from core.recon.targets import normalize_hostname


class NmapScopePreflight(QObject):
    changed = Signal()

    def __init__(self, parent=None, *, lookup_factory=QDnsLookup):
        super().__init__(parent)
        self._factory = lookup_factory
        self._lookups = []
        self._revision = 0
        self._inputs = ()
        self._family = 4
        self._answers = {}
        self.scope = None
        self.busy = False
        self.status = "Preflight required. Target selections and DNS answers grant no scan authorization."
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(10_000)
        self._timer.timeout.connect(self._timeout)
        self._expiry_timer = QTimer(self)
        self._expiry_timer.setInterval(1000)
        self._expiry_timer.timeout.connect(self._expire)

    def clear(self):
        self._revision += 1
        self._timer.stop()
        self._expiry_timer.stop()
        lookups, self._lookups = self._lookups, []
        for lookup in lookups:
            lookup.abort()
            lookup.deleteLater()
        self.scope = None
        self.busy = False
        self.status = "Scope changed; preflight and explicitly authorize every concrete address again."
        self.changed.emit()

    def start(self, inputs, *, family=4):
        self.clear()
        try:
            if type(inputs) not in (tuple, list) or not 1 <= len(inputs) <= MAX_INPUTS:
                raise ValueError("Select 1–64 explicit targets.")
            if family not in (4, 6):
                raise ValueError("Select IPv4 or IPv6 for this run.")
            names = []
            for value in inputs:
                if type(value) is not str or not value or len(value) > 253:
                    raise ValueError("Use bounded target identities.")
                try:
                    ipaddress.ip_address(value)
                    continue
                except ValueError:
                    pass
                if "/" in value or ":" in value or re.fullmatch(r"[0-9.]+-[0-9.]+", value):
                    continue
                name = normalize_hostname(value)
                if name not in names:
                    names.append(name)
            self._inputs, self._family, self._answers = tuple(inputs), family, {name: [] for name in names}
            if not names:
                self._complete()
                return
            self.busy = True
            revision = self._revision
            # Collect both families for provenance; the explicit family selector
            # controls which numeric addresses may enter the execution scope.
            for name in names:
                for kind in (QDnsLookup.A, QDnsLookup.AAAA):
                    lookup = self._factory(self)
                    lookup.setType(kind)
                    lookup.setName(name)
                    lookup.finished.connect(lambda query=lookup, host=name, rev=revision: self._finished(query, host, rev))
                    self._lookups.append(lookup)
            self.status = "Resolving explicit hostnames; DNS remains an observation."
            self._timer.start()
            self.changed.emit()
            for lookup in tuple(self._lookups):
                lookup.lookup()
        except (ValueError, RuntimeError) as error:
            self.clear()
            self.status = f"Preflight rejected: {error}"
            self.changed.emit()

    def _finished(self, lookup, name, revision):
        if revision != self._revision or lookup not in self._lookups:
            return
        self._lookups.remove(lookup)
        error = lookup.error()
        if error == QDnsLookup.NoError:
            self._answers[name].extend(record.value().toString() for record in lookup.hostAddressRecords())
        lookup.deleteLater()
        if error not in (QDnsLookup.NoError, QDnsLookup.NotFoundError):
            self.clear()
            self.status = "DNS preflight failed; incomplete DNS observations cannot define authorized scope."
            self.changed.emit()
            return
        if not self._lookups:
            self._timer.stop()
            self._complete()

    def _complete(self):
        self.busy = False
        try:
            self.scope = resolve_scope(self._inputs, resolver=lambda name: self._answers[name], family=self._family)
        except (ValueError, OSError) as error:
            self.scope = None
            self.status = f"Preflight rejected: {error}"
        else:
            self.status = f"Preflight: {self.scope.target_count} concrete IPv{self.scope.family} addresses. Authorization required."
            self._expiry_timer.start()
        self.changed.emit()

    def _timeout(self):
        self.clear()
        self.status = "DNS preflight timed out; no scope was approved."
        self.changed.emit()

    def _expire(self):
        if self.scope is not None and not scope_is_fresh(self.scope):
            self.clear()
            self.status = "Scope expired or consumed; preflight and authorize a new run."
            self.changed.emit()
