import copy
import json
import re
from pathlib import Path

from PyQt6.QtCore import QFileSystemWatcher, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import SegmentedWidget

XRAY_DOMAIN_STRATEGIES  = ["AsIs", "IPIfNonMatch", "IPOnDemand"]
XRAY_DEFAULT_STRATEGY   = "AsIs"
SINGBOX_DEFAULT_RESOLVER = ""

XRAY_PROTOCOLS  = ["http", "tls", "quic", "bittorrent", "dtls", "wireguard"]
XRAY_NETWORKS   = ["", "tcp", "udp", "tcp,udp"]
XRAY_OUTBOUNDS  = ["proxy", "direct", "block"]

SINGBOX_ACTIONS  = ["", "route", "sniff", "hijack-dns", "reject", "return"]
SINGBOX_PROTOCOLS = ["dns", "quic", "http", "tls", "bittorrent"]

X_COL_ENABLED  = 0
X_COL_NUM      = 1
X_COL_REMARKS  = 2
X_COL_OUTBOUND = 3
X_COL_ACTION   = 4
X_COL_PORT     = 5
X_COL_PROTOCOL = 6
X_COL_NETWORK  = 7
X_COL_DOMAIN   = 8
X_COL_IP       = 9
X_COL_PROCESS  = 10

XRAY_COLUMNS = ["✓", "#", "remarks", "outbound", "action",
                "port", "protocol", "network", "domain", "ip", "process"]

S_COL_NUM      = 0
S_COL_OUTBOUND = 1
S_COL_ACTION   = 2
S_COL_PORT     = 3
S_COL_PROTOCOL = 4
S_COL_NETWORK  = 5
S_COL_DOMAIN   = 6
S_COL_IP       = 7
S_COL_PROCESS  = 8

SINGBOX_COLUMNS = ["#", "outbound", "action", "port", "protocol",
                   "network", "domain", "ip", "process"]


def _join(val) -> str:
    if not val:
        return ""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    return str(val)


def _parse_entries(text: str) -> list[str]:
    entries = re.split(r"[,\s\n]+", text.strip())
    return sorted(set(e.strip() for e in entries if e.strip()))


def _extract_rule_fields(rule: dict) -> tuple:
    enabled  = bool(rule.get("enabled", True))
    remarks  = rule.get("remarks", "")
    outbound = rule.get("outbound", rule.get("outboundTag", ""))
    action   = rule.get("action", "")
    port     = str(rule.get("port", ""))

    raw_proto = rule.get("protocol", [])
    protocol  = _join(raw_proto) if raw_proto else ""
    network   = rule.get("network", "")

    domain_parts: list[str] = []
    for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
        v = rule.get(key)
        if v:
            domain_parts.extend(v if isinstance(v, list) else [str(v)])
    domain = ", ".join(domain_parts)

    ip_parts: list[str] = []
    for key in ("ip", "ip_cidr", "source_ip_cidr", "geoip"):
        v = rule.get(key)
        if v:
            ip_parts.extend(v if isinstance(v, list) else [str(v)])
    if rule.get("ip_is_private"):
        ip_parts.append("ip_is_private")
    ip = ", ".join(ip_parts)

    process_parts: list[str] = []
    for key in ("process", "process_name"):
        v = rule.get(key)
        if v:
            process_parts.extend(v if isinstance(v, list) else [str(v)])
    process = ", ".join(process_parts)

    return enabled, remarks, outbound, action, port, protocol, network, domain, ip, process


def _load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


CHECKBOX_STYLE = """
QCheckBox { spacing: 0px; }
QCheckBox::indicator {
    width: 15px; height: 15px;
    border: 1px solid #666666; border-radius: 3px; background: #2b2b2b;
}
QCheckBox::indicator:checked {
    background-color: #0e639c; border: 1px solid #0e639c;
}
QCheckBox::indicator:hover { border-color: #0e639c; }
"""


class _CheckCell(QWidget):
    def __init__(self, checked: bool, on_changed=None, parent=None):
        super().__init__(parent)
        self.setAutoFillBackground(False)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._cb = QCheckBox()
        self._cb.setChecked(checked)
        self._cb.setStyleSheet(CHECKBOX_STYLE)
        if on_changed:
            self._cb.stateChanged.connect(on_changed)
        lay.addWidget(self._cb)

    def is_checked(self) -> bool:
        return self._cb.isChecked()


SHARED_STYLE = """
QDialog, QWidget {
    background-color: #1e1e1e;
    color: #ffffff;
}
QLabel { color: #ffffff; }
QLineEdit, QTextEdit {
    background-color: #2b2b2b;
    color: #ffffff;
    border: 1px solid #444444;
    border-radius: 3px;
    padding: 4px 6px;
    font-size: 13px;
    selection-background-color: #0e639c;
}
QLineEdit:focus, QTextEdit:focus { border-color: #0e639c; }
QComboBox {
    background-color: #2b2b2b;
    color: #ffffff;
    border: 1px solid #555555;
    border-radius: 3px;
    padding: 3px 8px;
    font-size: 12px;
    min-width: 130px;
}
QComboBox:hover { border-color: #0e639c; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox::down-arrow { width: 10px; height: 10px; }
QComboBox QAbstractItemView {
    background-color: #252526;
    color: #ffffff;
    selection-background-color: #2d4a6e;
    selection-color: #ffffff;
    border: 1px solid #4a4a4a;
    outline: none;
    padding: 2px;
}
QComboBox QAbstractItemView::item {
    padding: 5px 10px;
    min-height: 24px;
}
QComboBox QAbstractItemView::item:hover {
    background-color: #2d4a6e;
}
QComboBox QAbstractItemView::item:selected {
    background-color: #2d4a6e;
}
QTableWidget {
    background-color: #2b2b2b;
    color: #ffffff;
    gridline-color: #3a3a3a;
    border: none;
    font-size: 13px;
    alternate-background-color: #272727;
    selection-background-color: #2d4a6e;
    selection-color: #ffffff;
}
QTableWidget::item {
    padding: 6px 10px;
    border-bottom: 1px solid #3a3a3a;
}
QTableWidget::item:selected {
    background-color: #2d4a6e;
    color: #ffffff;
}
QTableWidget::item:hover {
    background-color: #2d4a6e;
}
QHeaderView { background-color: #252526; }
QHeaderView::section {
    background-color: #252526;
    color: #cccccc;
    padding: 6px 10px;
    border: none;
    border-right: 1px solid #4a4a4a;
    border-bottom: 2px solid #4a4a4a;
    font-weight: bold;
    font-size: 12px;
}
QHeaderView::section:last { border-right: none; }
QScrollBar:vertical { background: #2b2b2b; width: 8px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #555555; border-radius: 4px; }
QScrollBar:horizontal { background: #2b2b2b; height: 8px; border-radius: 4px; }
QScrollBar::handle:horizontal { background: #555555; border-radius: 4px; }
QPushButton#confirmBtn {
    background-color: #0e639c; color: #ffffff;
    border: none; padding: 6px 24px; border-radius: 3px;
    font-size: 13px; min-width: 90px;
}
QPushButton#confirmBtn:hover { background-color: #1177bb; }
QPushButton#cancelBtn {
    background-color: #3a3a3a; color: #cccccc;
    border: none; padding: 6px 24px; border-radius: 3px;
    font-size: 13px; min-width: 90px;
}
QPushButton#cancelBtn:hover { background-color: #4a4a4a; }
QPushButton.tag {
    background-color: #333333; color: #cccccc;
    border: 1px solid #555555; border-radius: 12px;
    padding: 3px 12px; font-size: 12px;
}
QPushButton.tag:checked {
    background-color: #0e639c; color: #ffffff;
    border-color: #0e639c;
}
QPushButton.tag:hover { border-color: #0e639c; }
"""


class _TagButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setProperty("class", "tag")
        self.setStyleSheet("""
            QPushButton {
                background-color: #333333; color: #cccccc;
                border: 1px solid #555555; border-radius: 12px;
                padding: 3px 12px; font-size: 12px;
            }
            QPushButton:checked {
                background-color: #0e639c; color: #ffffff;
                border-color: #0e639c;
            }
            QPushButton:hover { border-color: #0e639c; }
        """)


class _SectionLabel(QLabel):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(
            "font-size: 11px; font-weight: bold; color: #7ec8e3;"
            "padding: 4px 0 2px 0; background: transparent;"
        )


class RuleEditDialog(QDialog):
    def __init__(self, rule: dict, core: str, file_path: Path,
                 rule_index: int, parent=None):
        super().__init__(parent)
        self._rule        = copy.deepcopy(rule)
        self._core        = core
        self._file_path   = file_path
        self._rule_index  = rule_index

        self.setWindowTitle("Routing Rule Details Setting")
        self.resize(860, 620)
        self.setModal(True)
        self.setStyleSheet(SHARED_STYLE)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(10)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        row = 0

        if core == "xray":
            enabled_val = bool(rule.get("enabled", True))
            grid.addWidget(QLabel("Remarks"), row, 0)
            self._remarks_edit = QLineEdit(rule.get("remarks", ""))
            self._remarks_edit.setPlaceholderText("Remarks")
            self._enabled_cb = QCheckBox()
            self._enabled_cb.setChecked(enabled_val)
            self._enabled_cb.setStyleSheet(CHECKBOX_STYLE)
            remarks_row = QHBoxLayout()
            remarks_row.addWidget(self._remarks_edit)
            remarks_row.addWidget(self._enabled_cb)
            grid.addLayout(remarks_row, row, 1)
            row += 1

            grid.addWidget(QLabel("outboundTag"), row, 0)
            self._outbound_combo = QComboBox()
            self._outbound_combo.setEditable(True)
            for o in XRAY_OUTBOUNDS:
                self._outbound_combo.addItem(o)
            self._outbound_combo.setCurrentText(
                rule.get("outboundTag", rule.get("outbound", ""))
            )
            grid.addWidget(self._outbound_combo, row, 1)
            row += 1

            grid.addWidget(QLabel("port"), row, 0)
            self._port_edit = QLineEdit(str(rule.get("port", "")))
            self._port_edit.setPlaceholderText("e.g. 80  or  1000-2000")
            grid.addWidget(self._port_edit, row, 1)
            row += 1

            grid.addWidget(QLabel("protocol"), row, 0)
            proto_row = QHBoxLayout()
            proto_row.setSpacing(6)
            self._proto_btns: dict[str, _TagButton] = {}
            current_protos = rule.get("protocol", [])
            if isinstance(current_protos, str):
                current_protos = [current_protos]
            for p in XRAY_PROTOCOLS:
                btn = _TagButton(p)
                btn.setChecked(p in current_protos)
                self._proto_btns[p] = btn
                proto_row.addWidget(btn)
            proto_row.addStretch()
            grid.addLayout(proto_row, row, 1)
            row += 1

            grid.addWidget(QLabel("network"), row, 0)
            self._network_combo = QComboBox()
            for n in XRAY_NETWORKS:
                self._network_combo.addItem(n)
            self._network_combo.setCurrentText(rule.get("network", ""))
            grid.addWidget(self._network_combo, row, 1)
            row += 1

            grid.addWidget(QLabel("inboundTag"), row, 0)
            inbound_row = QHBoxLayout()
            inbound_row.setSpacing(6)
            self._inbound_btns: dict[str, _TagButton] = {}
            current_inbounds = rule.get("inboundTag", [])
            if isinstance(current_inbounds, str):
                current_inbounds = [current_inbounds]
            for tag in ("socks", "socks2", "socks3", "http", "api"):
                btn = _TagButton(tag)
                btn.setChecked(tag in current_inbounds)
                self._inbound_btns[tag] = btn
                inbound_row.addWidget(btn)
            inbound_row.addStretch()
            grid.addLayout(inbound_row, row, 1)
            row += 1

        else:
            grid.addWidget(QLabel("outbound"), row, 0)
            self._outbound_combo = QComboBox()
            self._outbound_combo.setEditable(True)
            for o in XRAY_OUTBOUNDS:
                self._outbound_combo.addItem(o)
            self._outbound_combo.setCurrentText(
                rule.get("outbound", rule.get("outboundTag", ""))
            )
            grid.addWidget(self._outbound_combo, row, 1)
            row += 1

            grid.addWidget(QLabel("action"), row, 0)
            self._action_combo = QComboBox()
            for a in SINGBOX_ACTIONS:
                self._action_combo.addItem(a)
            self._action_combo.setCurrentText(rule.get("action", ""))
            grid.addWidget(self._action_combo, row, 1)
            row += 1

            grid.addWidget(QLabel("port"), row, 0)
            self._port_edit = QLineEdit(str(rule.get("port", "")))
            self._port_edit.setPlaceholderText("e.g. 80  or  1000-2000")
            grid.addWidget(self._port_edit, row, 1)
            row += 1

            grid.addWidget(QLabel("protocol"), row, 0)
            proto_row = QHBoxLayout()
            proto_row.setSpacing(6)
            self._proto_btns: dict[str, _TagButton] = {}
            current_protos = rule.get("protocol", [])
            if isinstance(current_protos, str):
                current_protos = [current_protos]
            for p in SINGBOX_PROTOCOLS:
                btn = _TagButton(p)
                btn.setChecked(p in current_protos)
                self._proto_btns[p] = btn
                proto_row.addWidget(btn)
            proto_row.addStretch()
            grid.addLayout(proto_row, row, 1)
            row += 1

            grid.addWidget(QLabel("network"), row, 0)
            self._network_combo = QComboBox()
            for n in XRAY_NETWORKS:
                self._network_combo.addItem(n)
            self._network_combo.setCurrentText(rule.get("network", ""))
            grid.addWidget(self._network_combo, row, 1)
            row += 1

        root.addLayout(grid)

        text_row = QHBoxLayout()
        text_row.setSpacing(10)

        domain_col = QVBoxLayout()
        domain_col.addWidget(_SectionLabel("Domain"))
        self._domain_edit = QTextEdit()
        self._domain_edit.setPlaceholderText("one per line, or comma/space separated")
        domain_vals = []
        for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
            v = rule.get(key)
            if v:
                domain_vals.extend(v if isinstance(v, list) else [str(v)])
        self._domain_edit.setPlainText("\n".join(domain_vals))
        domain_col.addWidget(self._domain_edit)
        text_row.addLayout(domain_col)

        ip_col = QVBoxLayout()
        ip_col.addWidget(_SectionLabel("IP or IP CIDR"))
        self._ip_edit = QTextEdit()
        self._ip_edit.setPlaceholderText("one per line, or comma/space separated")
        ip_vals = []
        for key in ("ip", "ip_cidr", "source_ip_cidr", "geoip"):
            v = rule.get(key)
            if v:
                ip_vals.extend(v if isinstance(v, list) else [str(v)])
        if rule.get("ip_is_private"):
            ip_vals.append("ip_is_private")
        self._ip_edit.setPlainText("\n".join(ip_vals))
        ip_col.addWidget(self._ip_edit)
        text_row.addLayout(ip_col)

        proc_col = QVBoxLayout()
        proc_col.addWidget(_SectionLabel("Process (Linux/Windows)"))
        self._process_edit = QTextEdit()
        self._process_edit.setPlaceholderText("one per line, or comma/space separated")
        proc_vals = []
        for key in ("process", "process_name"):
            v = rule.get(key)
            if v:
                proc_vals.extend(v if isinstance(v, list) else [str(v)])
        self._process_edit.setPlainText("\n".join(proc_vals))
        proc_col.addWidget(self._process_edit)
        text_row.addLayout(proc_col)

        root.addLayout(text_row)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._confirm_btn = QPushButton("Confirm")
        self._confirm_btn.setObjectName("confirmBtn")
        self._confirm_btn.clicked.connect(self._on_confirm)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("cancelBtn")
        self._cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(self._confirm_btn)
        btn_row.addWidget(self._cancel_btn)
        root.addLayout(btn_row)

    def _build_updated_rule(self) -> dict:
        rule = copy.deepcopy(self._rule)

        if self._core == "xray":
            remarks = self._remarks_edit.text().strip()
            if remarks:
                rule["remarks"] = remarks
            else:
                rule.pop("remarks", None)

            enabled = self._enabled_cb.isChecked()
            if enabled:
                rule.pop("enabled", None)
            else:
                rule["enabled"] = False

            outbound = self._outbound_combo.currentText().strip()
            if outbound:
                rule["outboundTag"] = outbound
            else:
                rule.pop("outboundTag", None)
            rule.pop("outbound", None)
        else:
            outbound = self._outbound_combo.currentText().strip()
            if outbound:
                rule["outbound"] = outbound
            else:
                rule.pop("outbound", None)
            rule.pop("outboundTag", None)

            action = self._action_combo.currentText().strip()
            if action:
                rule["action"] = action
            else:
                rule.pop("action", None)

        port = self._port_edit.text().strip()
        if port:
            rule["port"] = port
        else:
            rule.pop("port", None)

        network = self._network_combo.currentText().strip()
        if network:
            rule["network"] = network
        else:
            rule.pop("network", None)

        selected_protos = sorted(
            p for p, btn in self._proto_btns.items() if btn.isChecked()
        )
        if self._core == "xray":
            if selected_protos:
                rule["protocol"] = selected_protos
            else:
                rule.pop("protocol", None)
        else:
            if len(selected_protos) == 1:
                rule["protocol"] = selected_protos[0]
            elif selected_protos:
                rule["protocol"] = selected_protos
            else:
                rule.pop("protocol", None)

        domain_entries = _parse_entries(self._domain_edit.toPlainText())
        for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
            rule.pop(key, None)
        if domain_entries:
            rule["domain"] = domain_entries

        ip_entries = _parse_entries(self._ip_edit.toPlainText())
        for key in ("ip", "ip_cidr", "source_ip_cidr", "geoip"):
            rule.pop(key, None)
        rule.pop("ip_is_private", None)
        if ip_entries:
            rule["ip"] = ip_entries

        process_entries = _parse_entries(self._process_edit.toPlainText())
        for key in ("process", "process_name"):
            rule.pop(key, None)
        if self._core == "xray":
            if process_entries:
                rule["process"] = process_entries
        else:
            if process_entries:
                rule["process_name"] = process_entries

        if self._core == "xray" and hasattr(self, "_inbound_btns"):
            selected_inbounds = [t for t, b in self._inbound_btns.items() if b.isChecked()]
            if selected_inbounds:
                rule["inboundTag"] = selected_inbounds
            else:
                rule.pop("inboundTag", None)

        return rule

    def _on_confirm(self):
        updated_rule = self._build_updated_rule()
        try:
            data = _load_json(self._file_path)
            if self._core == "xray":
                rules = data.get("routing", {}).get("rules", [])
            else:
                rules = data.get("route", {}).get("rules", [])

            if self._rule_index < len(rules):
                rules[self._rule_index] = updated_rule

            _save_json(self._file_path, data)
        except Exception as e:
            print(f"[routing] save rule failed: {e}")
            return
        self.accept()


class RuleDetailDialog(QDialog):
    file_saved = pyqtSignal(str, str)

    def __init__(self, config_name: str, file_path: Path, core: str, parent=None):
        super().__init__(parent)

        self._file_path   = file_path
        self._core        = core
        self._config_name = config_name
        self._pending_enabled: dict[int, bool] = {}
        self._pending_strategy: str | None     = None
        self._original_data: dict = {}

        self.setWindowTitle(f"Rule Settings — {config_name}")
        self.resize(1300, 660)
        self.setModal(True)
        self.setStyleSheet(SHARED_STYLE)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self._header_label = QLabel()
        self._header_label.setStyleSheet(
            "font-size: 14px; color: #cccccc; padding-bottom: 2px;"
        )
        layout.addWidget(self._header_label)

        strategy_row = QHBoxLayout()
        strategy_row.setSpacing(8)

        if self._core == "xray":
            strategy_row.addWidget(QLabel("domainStrategy:"))
            self._strategy_combo = QComboBox()
            for s in XRAY_DOMAIN_STRATEGIES:
                self._strategy_combo.addItem(s)
            self._strategy_combo.currentTextChanged.connect(self._on_strategy_changed)
            strategy_row.addWidget(self._strategy_combo)
        else:
            strategy_row.addWidget(QLabel("default_domain_resolver:"))
            self._strategy_combo = QComboBox()
            self._strategy_combo.setEditable(True)
            self._strategy_combo.currentTextChanged.connect(self._on_strategy_changed)
            strategy_row.addWidget(self._strategy_combo)

        strategy_row.addStretch()
        layout.addLayout(strategy_row)

        self._table = QTableWidget()
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)
        self._table.cellDoubleClicked.connect(self._on_row_double_clicked)

        self._setup_columns()
        layout.addWidget(self._table)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._confirm_btn = QPushButton("Confirm")
        self._confirm_btn.setObjectName("confirmBtn")
        self._confirm_btn.clicked.connect(self._on_confirm)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("cancelBtn")
        self._cancel_btn.clicked.connect(self._on_cancel)
        btn_row.addWidget(self._confirm_btn)
        btn_row.addWidget(self._cancel_btn)
        layout.addLayout(btn_row)

        self._watcher = QFileSystemWatcher(self)
        self._watcher.addPath(str(file_path))
        self._watcher.fileChanged.connect(self._on_file_changed)

        self._populate()

    def _setup_columns(self):
        is_xray = (self._core == "xray")
        columns = XRAY_COLUMNS if is_xray else SINGBOX_COLUMNS

        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)

        hv = self._table.horizontalHeader()
        hv.setHighlightSections(False)
        hv.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        hv.setMinimumSectionSize(30)

        last = len(columns) - 1
        for col in range(len(columns)):
            mode = QHeaderView.ResizeMode.Stretch if col == last \
                   else QHeaderView.ResizeMode.Interactive
            hv.setSectionResizeMode(col, mode)

        if is_xray:
            self._table.setColumnWidth(X_COL_ENABLED,  36)
            self._table.setColumnWidth(X_COL_NUM,       40)
            self._table.setColumnWidth(X_COL_REMARKS,  160)
            self._table.setColumnWidth(X_COL_OUTBOUND,  90)
            self._table.setColumnWidth(X_COL_ACTION,    80)
            self._table.setColumnWidth(X_COL_PORT,      80)
            self._table.setColumnWidth(X_COL_PROTOCOL, 100)
            self._table.setColumnWidth(X_COL_NETWORK,   80)
            self._table.setColumnWidth(X_COL_DOMAIN,   220)
            self._table.setColumnWidth(X_COL_IP,       180)
        else:
            self._table.setColumnWidth(S_COL_NUM,       40)
            self._table.setColumnWidth(S_COL_OUTBOUND,  90)
            self._table.setColumnWidth(S_COL_ACTION,    90)
            self._table.setColumnWidth(S_COL_PORT,      80)
            self._table.setColumnWidth(S_COL_PROTOCOL, 100)
            self._table.setColumnWidth(S_COL_NETWORK,   80)
            self._table.setColumnWidth(S_COL_DOMAIN,   240)
            self._table.setColumnWidth(S_COL_IP,       200)

    def _load_data(self) -> dict:
        try:
            return _load_json(self._file_path)
        except Exception:
            return {}

    def _get_routing_block(self, data: dict) -> dict:
        if self._core == "xray":
            return data.get("routing", {})
        return data.get("route", {})

    def _get_rules_and_strategy(self, data: dict) -> tuple[list, str]:
        block = self._get_routing_block(data)
        rules = block.get("rules", [])
        if self._core == "xray":
            strategy = block.get("domainStrategy", XRAY_DEFAULT_STRATEGY)
        else:
            strategy = block.get("default_domain_resolver", SINGBOX_DEFAULT_RESOLVER)
        return rules, strategy

    def _populate(self):
        self._pending_enabled.clear()
        self._pending_strategy = None

        data = self._load_data()
        self._original_data = copy.deepcopy(data)

        rules, strategy = self._get_rules_and_strategy(data)

        self._header_label.setText(
            f"<b>{self._config_name}</b>"
            f" &nbsp;·&nbsp; {len(rules)} rules"
            f" &nbsp;·&nbsp; core: {self._core}"
        )

        self._strategy_combo.blockSignals(True)
        if self._core == "xray":
            idx = self._strategy_combo.findText(strategy)
            self._strategy_combo.setCurrentIndex(idx if idx >= 0 else 0)
        else:
            self._strategy_combo.setCurrentText(strategy)
        self._strategy_combo.blockSignals(False)

        self._fill_table(rules)

    def _fill_table(self, rules: list):
        is_xray = (self._core == "xray")
        self._table.setRowCount(0)
        self._table.setRowCount(len(rules))

        for i, rule in enumerate(rules):
            (enabled, remarks, outbound, action,
             port, protocol, network, domain, ip, process) = _extract_rule_fields(rule)

            if i in self._pending_enabled:
                enabled = self._pending_enabled[i]

            if is_xray:
                cb = _CheckCell(
                    enabled,
                    on_changed=lambda state, r=i: self._on_checkbox_changed(r, state),
                )
                self._table.setCellWidget(i, X_COL_ENABLED, cb)
                self._set_item(i, X_COL_NUM,      str(i + 1))
                self._set_item(i, X_COL_REMARKS,  remarks)
                self._set_item(i, X_COL_OUTBOUND, outbound)
                self._set_item(i, X_COL_ACTION,   action)
                self._set_item(i, X_COL_PORT,     port)
                self._set_item(i, X_COL_PROTOCOL, protocol)
                self._set_item(i, X_COL_NETWORK,  network)
                self._set_item(i, X_COL_DOMAIN,   domain)
                self._set_item(i, X_COL_IP,       ip)
                self._set_item(i, X_COL_PROCESS,  process)
                if not enabled:
                    for col in range(1, self._table.columnCount()):
                        item = self._table.item(i, col)
                        if item:
                            item.setForeground(QColor("#606060"))
            else:
                self._set_item(i, S_COL_NUM,      str(i + 1))
                self._set_item(i, S_COL_OUTBOUND, outbound)
                self._set_item(i, S_COL_ACTION,   action)
                self._set_item(i, S_COL_PORT,     port)
                self._set_item(i, S_COL_PROTOCOL, protocol)
                self._set_item(i, S_COL_NETWORK,  network)
                self._set_item(i, S_COL_DOMAIN,   domain)
                self._set_item(i, S_COL_IP,       ip)
                self._set_item(i, S_COL_PROCESS,  process)

    def _set_item(self, row: int, col: int, value: str):
        item = QTableWidgetItem(value)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, col, item)

    def _on_checkbox_changed(self, row: int, state: int):
        checked = (state == Qt.CheckState.Checked.value)
        self._pending_enabled[row] = checked
        color = QColor("#ffffff") if checked else QColor("#606060")
        for col in range(1, self._table.columnCount()):
            item = self._table.item(row, col)
            if item:
                item.setForeground(color)

    def _on_strategy_changed(self, text: str):
        self._pending_strategy = text

    def _on_row_double_clicked(self, row: int, col: int):
        if self._core == "xray" and col == X_COL_ENABLED:
            return
        data = self._load_data()
        if self._core == "xray":
            rules = data.get("routing", {}).get("rules", [])
        else:
            rules = data.get("route", {}).get("rules", [])
        if row >= len(rules):
            return
        rule = rules[row]
        dlg = RuleEditDialog(rule, self._core, self._file_path, row, parent=self)
        if dlg.exec():
            self._populate()
            self.file_saved.emit(self._core, str(self._file_path))

    def _on_confirm(self):
        if not self._pending_enabled and self._pending_strategy is None:
            self.accept()
            return

        try:
            data = _load_json(self._file_path)
        except Exception as e:
            print(f"[routing] Failed to read JSON for saving: {e}")
            return

        changed = False

        if self._pending_strategy is not None:
            if self._core == "xray":
                routing = data.setdefault("routing", {})
                if routing.get("domainStrategy") != self._pending_strategy:
                    routing["domainStrategy"] = self._pending_strategy
                    changed = True
            else:
                route = data.setdefault("route", {})
                if route.get("default_domain_resolver") != self._pending_strategy:
                    if self._pending_strategy:
                        route["default_domain_resolver"] = self._pending_strategy
                    else:
                        route.pop("default_domain_resolver", None)
                    changed = True

        if self._pending_enabled:
            if self._core == "xray":
                rules = data.get("routing", {}).get("rules", [])
            else:
                rules = data.get("route", {}).get("rules", [])

            for row_idx, enabled_val in self._pending_enabled.items():
                if row_idx < len(rules):
                    rule = rules[row_idx]
                    current = bool(rule.get("enabled", True))
                    if current != enabled_val:
                        if enabled_val:
                            rule.pop("enabled", None)
                        else:
                            rule["enabled"] = False
                        changed = True

        if changed:
            try:
                self._watcher.removePath(str(self._file_path))
                _save_json(self._file_path, data)
                self._watcher.addPath(str(self._file_path))
                self._original_data = copy.deepcopy(data)
            except Exception as e:
                print(f"[routing] Failed to save JSON: {e}")
                return

        self._pending_enabled.clear()
        self._pending_strategy = None
        self.file_saved.emit(self._core, str(self._file_path))
        self.accept()

    def _on_cancel(self):
        self._pending_enabled.clear()
        self._pending_strategy = None
        self.reject()

    def _on_file_changed(self, path: str):
        if path not in self._watcher.files():
            self._watcher.addPath(path)
        if not self._pending_enabled and self._pending_strategy is None:
            self._populate()


class RoutingPage(QWidget):
    file_saved = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("routing")

        self.core_dirs = {"singbox": "sing-box", "xray": "xray"}
        self.base_path = Path("data/configs")
        self._file_paths: dict[QTableWidget, list[Path | None]] = {}

        root = QVBoxLayout(self)

        self.segmented = SegmentedWidget(self)
        self.segmented.addItem("singbox", "sing-box")
        self.segmented.addItem("xray", "xray")
        root.addWidget(self.segmented)

        self.stack = QStackedWidget(self)
        root.addWidget(self.stack)

        self.singbox_table = QTableWidget()
        self.xray_table    = QTableWidget()

        self._file_paths[self.singbox_table] = []
        self._file_paths[self.xray_table]    = []

        self.stack.addWidget(self.singbox_table)
        self.stack.addWidget(self.xray_table)

        self.segmented.currentItemChanged.connect(self._on_tab_changed)

        self.watcher = QFileSystemWatcher(self)
        self._setup_watcher()

        self._setup_table(self.singbox_table)
        self._setup_table(self.xray_table)

        self.singbox_table.cellDoubleClicked.connect(
            lambda row, _col: self._open_rule_detail(self.singbox_table, row, "singbox")
        )
        self.xray_table.cellDoubleClicked.connect(
            lambda row, _col: self._open_rule_detail(self.xray_table, row, "xray")
        )

        self.refresh()
        QTimer.singleShot(0, lambda: self.set_current("singbox"))

    def _setup_table(self, table: QTableWidget):
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Name", "Rules"])

        body_font = QFont("Arial", 15)
        table.setFont(body_font)

        hdr_font = QFont("Arial", 11)
        hdr_font.setBold(True)

        hdr = table.horizontalHeader()
        hdr.setFont(hdr_font)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hdr.setHighlightSections(False)
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)

        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.setStyleSheet(SHARED_STYLE)

    def _on_tab_changed(self, key: str):
        self.stack.setCurrentIndex(0 if key == "singbox" else 1)

    def set_current(self, key: str):
        self.segmented.setCurrentItem(key)
        self.stack.setCurrentIndex(0 if key == "singbox" else 1)

    def _setup_watcher(self):
        for core in self.core_dirs:
            path = self.base_path / self.core_dirs[core]
            path.mkdir(parents=True, exist_ok=True)
            self.watcher.addPath(str(path))
        self.watcher.directoryChanged.connect(self.refresh)

    def _get_rules(self, file_path: Path, core: str) -> list:
        try:
            data = _load_json(file_path)
            if core == "xray":
                return data.get("routing", {}).get("rules", [])
            if core == "singbox":
                return data.get("route", {}).get("rules", [])
        except Exception:
            pass
        return []

    def refresh(self):
        self._load_core("singbox", self.singbox_table)
        self._load_core("xray",    self.xray_table)

    def _load_core(self, core: str, table: QTableWidget):
        folder = self.core_dirs.get(core, core)
        path   = self.base_path / folder

        table.setRowCount(0)
        self._file_paths[table] = []

        if not path.exists():
            self._add_row(table, "(папка не найдена)", "-")
            self._file_paths[table].append(None)
            return

        files = sorted(path.rglob("*.json"))

        if not files:
            self._add_row(table, "(нет json файлов)", "-")
            self._file_paths[table].append(None)
            return

        for f in files:
            name  = f.relative_to(path).as_posix().replace(".json", "")
            count = len(self._get_rules(f, core))
            self._add_row(table, name, str(count))
            self._file_paths[table].append(f)

    def _add_row(self, table: QTableWidget, name: str, rules: str):
        row = table.rowCount()
        table.insertRow(row)
        table.setItem(row, 0, QTableWidgetItem(name))
        table.setItem(row, 1, QTableWidgetItem(rules))

    def _open_rule_detail(self, table: QTableWidget, row: int, core: str):
        paths = self._file_paths.get(table, [])
        if row >= len(paths) or paths[row] is None:
            return

        file_path   = paths[row]
        folder      = self.core_dirs.get(core, core)
        config_name = file_path.relative_to(
            self.base_path / folder
        ).as_posix().replace(".json", "")

        dialog = RuleDetailDialog(config_name, file_path, core, parent=self)
        dialog.file_saved.connect(self.file_saved)
        dialog.exec()