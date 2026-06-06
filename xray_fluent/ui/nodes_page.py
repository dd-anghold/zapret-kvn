from __future__ import annotations

from typing import cast

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QSize, QItemSelectionModel
from PyQt6.QtGui import QCursor, QKeyEvent, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QHBoxLayout, QHeaderView,
    QScrollArea, QSizePolicy, QStackedWidget, QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    ComboBox,
    FluentIcon as FIF,
    IndeterminateProgressRing,
    LineEdit,
    ProgressBar,
    PrimaryToolButton,
    SearchLineEdit,
    SubtitleLabel,
    TableView,
    ToolButton,
    TransparentToolButton,
    VerticalSeparator,
)
from qfluentwidgets import RoundMenu, Action, MessageBox

from ..models import Node, Subscription
from .node_detail_widget import NodeDetailWidget
from .nodes_table_model import NodesTableModel

_COLUMN_WIDTHS = {
    0: 200,  # Имя
    1: 96,   # Тип
    2: 200,  # Сервер
    3: 84,   # Порт
    4: 140,  # Группа
    5: 160,  # Теги
    6: 92,   # Пинг
    7: 110,  # Скорость
    8: 84,   # Статус
    9: 156,  # Последнее использование
}

class _BidirectionalHeaderView(QHeaderView):
    """QHeaderView that lets you resize a column from its LEFT edge as well as its right.

    Standard Qt behaviour: dragging the boundary between columns A and B always
    resizes column A (the one to the left).  This subclass adds a second "left-edge"
    hit zone (the first few pixels *inside* each column's header area).  Dragging
    there resizes *that* column while the neighbour to the left absorbs the delta.
    """

    _HANDLE_PX = 6  # hit-zone width in pixels from the left edge of a section

    def __init__(self, parent=None):
        super().__init__(Qt.Orientation.Horizontal, parent)
        self._left_drag_active = False
        self._left_drag_section = -1
        self._left_drag_prev = -1
        self._left_drag_start_x = 0
        self._left_drag_sec_w0 = 0
        self._left_drag_prev_w0 = 0
        self.setMouseTracking(True)

    def _left_edge_hit(self, x: int) -> tuple[int, int]:
        """Return (section, prev_section) when x falls in the left-edge zone of a section.

        Zone is (left_edge, left_edge + HANDLE_PX] — strictly inside this section so
        it doesn't overlap with Qt's own right-edge zone of the previous section.
        """
        for i in range(1, self.count()):
            if self.isSectionHidden(i):
                continue
            le = self.sectionViewportPosition(i)
            if le < x <= le + self._HANDLE_PX:
                prev = i - 1
                while prev >= 0 and self.isSectionHidden(prev):
                    prev -= 1
                if prev >= 0:
                    return i, prev
        return -1, -1

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            sec, prev = self._left_edge_hit(event.pos().x())
            if sec >= 0:
                self._left_drag_active = True
                self._left_drag_section = sec
                self._left_drag_prev = prev
                self._left_drag_start_x = event.pos().x()
                self._left_drag_sec_w0 = self.sectionSize(sec)
                self._left_drag_prev_w0 = self.sectionSize(prev)
                self.setCursor(Qt.CursorShape.SplitHCursor)
                return  # suppress Qt default (which would resize the prev column)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._left_drag_active:
            delta = event.pos().x() - self._left_drag_start_x
            min_w = max(self.minimumSectionSize(), 20)
            # Clamp so neither column goes below min_w
            delta = max(-(self._left_drag_sec_w0 - min_w),
                        min(self._left_drag_prev_w0 - min_w, delta))
            self.resizeSection(self._left_drag_section, self._left_drag_sec_w0 - delta)
            self.resizeSection(self._left_drag_prev, self._left_drag_prev_w0 + delta)
            return
        # Cursor feedback for left-edge zones
        sec, _ = self._left_edge_hit(event.pos().x())
        if sec >= 0:
            self.setCursor(Qt.CursorShape.SplitHCursor)
        else:
            self.unsetCursor()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._left_drag_active and event.button() == Qt.MouseButton.LeftButton:
            self._left_drag_active = False
            self._left_drag_section = -1
            self.unsetCursor()
            return
        super().mouseReleaseEvent(event)


_SORT_KEYS = ["Вручную", "Имя", "Группа", "Тип", "Пинг", "Скорость", "Последнее использование"]

_COLUMN_SORT_MAP = {
    0: "Имя",
    1: "Тип",
    4: "Группа",
    6: "Пинг",
    7: "Скорость",
    9: "Последнее использование",
}


class NodesPage(QWidget):
    import_clipboard_requested = pyqtSignal()
    delete_requested = pyqtSignal(object)          # emits set[str] of node IDs
    ping_requested = pyqtSignal(object)             # emits set[str] or empty set
    speed_test_requested = pyqtSignal(object)       # emits set[str] of node IDs (or empty set for all)
    cancel_speed_test_requested = pyqtSignal()
    export_outbound_json_requested = pyqtSignal(str)
    export_runtime_json_requested = pyqtSignal(str)
    selected_node_changed = pyqtSignal(str)
    edit_node_requested = pyqtSignal(str)           # node_id
    bulk_edit_requested = pyqtSignal(object)        # set[str] of node_ids
    copy_link_requested = pyqtSignal(str)           # node_id
    reorder_requested = pyqtSignal(str, str)        # node_id, direction
    import_subscription_requested = pyqtSignal(str, str)   # url, name
    update_subscription_requested = pyqtSignal(str)        # sub_id
    remove_subscription_requested = pyqtSignal(str)        # sub_id
    rename_subscription_requested = pyqtSignal(str, str)   # sub_id, new_name
    column_widths_changed = pyqtSignal(dict)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("nodes")

        self._nodes: list[Node] = []
        self._subscriptions: list[Subscription] = []
        self._active_sub_id: str | None = None   # None = show all
        self._visible_node_ids: list[str] = []
        self._id_to_node: dict[str, Node] = {}
        self._search_haystacks: dict[str, str] = {}
        self._sort_ascending = True
        self._cached_groups: frozenset[str] = frozenset()
        self._cached_tags: frozenset[str] = frozenset()
        self._pending_ping_ids: set[str] = set()
        self._active_speed_progress: dict[str, int] = {}
        self._speed_test_running = False
        self._speed_test_stopping = False
        self._in_reload = False
        self._active_node_id: str | None = None  # which node is the VPN endpoint
        self._applying_column_widths = False

        # Stack: page 0 = server list, page 1 = node detail
        self._stack = QStackedWidget(self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._stack)

        # --- Page 0: Server list ---
        list_page = QWidget()
        root = QVBoxLayout(list_page)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        title = SubtitleLabel("Серверы", self)
        root.addWidget(title)

        # --- Subscription chips row ---
        sub_scroll = QScrollArea(self)
        sub_scroll.setObjectName("subScrollArea")
        sub_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        sub_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sub_scroll.setWidgetResizable(True)
        sub_scroll.setFixedHeight(40)
        sub_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        sub_scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        self._sub_chips_container = QWidget()
        self._sub_chips_container.setStyleSheet("background: transparent;")
        self._sub_chips_layout = QHBoxLayout(self._sub_chips_container)
        self._sub_chips_layout.setContentsMargins(0, 0, 0, 0)
        self._sub_chips_layout.setSpacing(6)
        self._sub_chips_layout.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        sub_scroll.setWidget(self._sub_chips_container)
        root.addWidget(sub_scroll)
        self._sub_scroll = sub_scroll

        # --- Filter row ---
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        self.search_edit = SearchLineEdit(self)
        self.search_edit.setPlaceholderText("Поиск серверов")
        filter_row.addWidget(self.search_edit, 1)

        self.group_filter = ComboBox(self)
        self.group_filter.setMinimumWidth(120)
        self.group_filter.addItem("Все группы")
        filter_row.addWidget(self.group_filter)

        self.tag_filter = ComboBox(self)
        self.tag_filter.setMinimumWidth(120)
        self.tag_filter.addItem("Все теги")
        filter_row.addWidget(self.tag_filter)

        filter_row.addWidget(VerticalSeparator(self))

        self.sort_combo = ComboBox(self)
        self.sort_combo.setMinimumWidth(110)
        for key in _SORT_KEYS:
            self.sort_combo.addItem(key)
        filter_row.addWidget(self.sort_combo)

        self.sort_order_btn = TransparentToolButton(FIF.UP, self)
        self.sort_order_btn.setToolTip("Порядок сортировки")
        filter_row.addWidget(self.sort_order_btn)

        root.addLayout(filter_row)

        # --- Action toolbar ---
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self.import_btn = PrimaryToolButton(FIF.ADD, self)
        self.import_btn.setToolTip("Импорт из буфера (Ctrl+V)")
        toolbar.addWidget(self.import_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.edit_btn = TransparentToolButton(FIF.EDIT, self)
        self.edit_btn.setToolTip("Редактировать")
        toolbar.addWidget(self.edit_btn)

        self.bulk_edit_btn = TransparentToolButton(FIF.CHECKBOX, self)
        self.bulk_edit_btn.setToolTip("Массовое редактирование")
        self.bulk_edit_btn.setVisible(False)
        toolbar.addWidget(self.bulk_edit_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.ping_btn = TransparentToolButton(FIF.SEND, self)
        self.ping_btn.setToolTip("Пинг выбранных")
        toolbar.addWidget(self.ping_btn)

        self.ping_all_btn = TransparentToolButton(FIF.SYNC, self)
        self.ping_all_btn.setToolTip("Пинг всех")
        toolbar.addWidget(self.ping_all_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.speed_test_btn = TransparentToolButton(FIF.SPEED_HIGH, self)
        self.speed_test_btn.setToolTip("Тест скорости выбранных")
        toolbar.addWidget(self.speed_test_btn)

        self.speed_test_all_btn = TransparentToolButton(FIF.SPEED_MEDIUM, self)
        self.speed_test_all_btn.setToolTip("Тест скорости всех")
        toolbar.addWidget(self.speed_test_all_btn)

        self.stop_speed_test_btn = TransparentToolButton(FIF.PAUSE_BOLD, self)
        self.stop_speed_test_btn.setToolTip("Остановить тест скорости")
        self.stop_speed_test_btn.setVisible(False)
        toolbar.addWidget(self.stop_speed_test_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.export_outbound_btn = TransparentToolButton(FIF.SAVE_AS, self)
        self.export_outbound_btn.setToolTip("Экспорт outbound JSON")
        toolbar.addWidget(self.export_outbound_btn)

        self.export_runtime_btn = TransparentToolButton(FIF.CODE, self)
        self.export_runtime_btn.setToolTip("Экспорт runtime конфига")
        toolbar.addWidget(self.export_runtime_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.delete_btn = TransparentToolButton(FIF.DELETE, self)
        self.delete_btn.setToolTip("Удалить выбранные")
        toolbar.addWidget(self.delete_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.move_up_btn = TransparentToolButton(FIF.UP, self)
        self.move_up_btn.setToolTip("Переместить вверх")
        self.move_up_btn.setEnabled(False)
        toolbar.addWidget(self.move_up_btn)

        self.move_down_btn = TransparentToolButton(FIF.DOWN, self)
        self.move_down_btn.setToolTip("Переместить вниз")
        self.move_down_btn.setEnabled(False)
        toolbar.addWidget(self.move_down_btn)

        toolbar.addStretch()

        root.addLayout(toolbar)

        # --- Table ---
        self.table = TableView(self)
        self._table_model = NodesTableModel(self)
        self.table.setModel(self._table_model)
        vertical_header = cast(QHeaderView, self.table.verticalHeader())
        vertical_header.setVisible(False)

        _bidi_header = _BidirectionalHeaderView(self.table)
        self.table.setHorizontalHeader(_bidi_header)
        _bidi_header.setHighlightSections(False)

        horizontal_header = _bidi_header
        horizontal_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for col, width in _COLUMN_WIDTHS.items():
            self.table.setColumnWidth(col, width)
        horizontal_header.setSectionsClickable(True)
        horizontal_header.sectionClicked.connect(self._on_header_clicked)

        self._col_resize_timer = QTimer(self)
        self._col_resize_timer.setSingleShot(True)
        self._col_resize_timer.setInterval(400)
        self._col_resize_timer.timeout.connect(self._emit_column_widths)
        horizontal_header.sectionResized.connect(self._on_section_resized)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.setIconSize(QSize(20, 14))

        # Prevent deselection on empty area click
        orig_mouse_press = self.table.mousePressEvent

        def _no_deselect_mouse_press(event):
            if event.button() == Qt.MouseButton.LeftButton:
                index = self.table.indexAt(event.pos())
                if not index.isValid():
                    return
            orig_mouse_press(event)

        self.table.mousePressEvent = _no_deselect_mouse_press

        root.addWidget(self.table, 1)

        self._stack.addWidget(list_page)

        # --- Page 1: Node detail ---
        self._detail_widget = NodeDetailWidget(self)
        self._detail_widget.back_requested.connect(self._show_list)
        self._detail_widget.ping_node_requested.connect(lambda nid: self.ping_requested.emit({nid}))
        self._detail_widget.speed_test_node_requested.connect(lambda nid: self.speed_test_requested.emit({nid}))
        self._detail_widget.cancel_speed_test_requested.connect(self.cancel_speed_test_requested.emit)
        self._stack.addWidget(self._detail_widget)

        # --- Search debounce ---
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(300)
        self._search_timer.timeout.connect(self._reload)

        # --- Connections ---
        self.search_edit.textChanged.connect(self._search_timer.start)
        self.group_filter.currentIndexChanged.connect(self._reload)
        self.tag_filter.currentIndexChanged.connect(self._reload)
        self.sort_combo.currentIndexChanged.connect(self._reload)
        self.sort_order_btn.clicked.connect(self._toggle_sort_order)
        self.import_btn.clicked.connect(self.import_clipboard_requested)
        self.edit_btn.clicked.connect(self._on_edit)
        self.bulk_edit_btn.clicked.connect(self._on_bulk_edit)
        self.ping_btn.clicked.connect(self._on_ping_selected)
        self.ping_all_btn.clicked.connect(self._on_ping_all)
        self.export_outbound_btn.clicked.connect(self._on_export_outbound)
        self.export_runtime_btn.clicked.connect(self._on_export_runtime)
        self.speed_test_btn.clicked.connect(self._on_speed_test_selected)
        self.speed_test_all_btn.clicked.connect(self._on_speed_test_all)
        self.stop_speed_test_btn.clicked.connect(self.cancel_speed_test_requested.emit)
        self.delete_btn.clicked.connect(self._on_delete_selected)
        self.move_up_btn.clicked.connect(self._on_move_up)
        self.move_down_btn.clicked.connect(self._on_move_down)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._emit_selection())
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.customContextMenuRequested.connect(self._on_context_menu)

        # --- Keyboard shortcuts ---
        paste_shortcut = QShortcut(QKeySequence.StandardKey.Paste, self)
        paste_shortcut.activated.connect(self.import_clipboard_requested)

        # Build initial (empty) chip row
        self._rebuild_sub_chips()

    # ── Public API ──

    def apply_column_widths(self, widths: dict[int, int]) -> None:
        if not widths:
            return
        self._applying_column_widths = True
        try:
            for col, width in widths.items():
                if width > 0:
                    self.table.setColumnWidth(int(col), width)
        finally:
            self._applying_column_widths = False

    def set_subscriptions(self, subscriptions: list[Subscription]) -> None:
        self._subscriptions = list(subscriptions)
        if self._active_sub_id and not any(s.id == self._active_sub_id for s in self._subscriptions):
            self._active_sub_id = None
        self._rebuild_sub_chips()
        self._reload()

    def set_nodes(self, nodes: list[Node], selected_id: str | None = None) -> None:
        self._nodes = list(nodes)
        self._id_to_node = {node.id: node for node in self._nodes}
        self._search_haystacks = {
            node.id: " ".join([node.name, node.scheme, node.server, node.group, " ".join(node.tags)]).lower()
            for node in self._nodes
        }
        if selected_id is not None:
            self._active_node_id = selected_id
        self._rebuild_filter_combos()
        self._reload()

    def update_ping(self, node_id: str, ping_ms: int | None) -> None:
        self._pending_ping_ids.discard(node_id)
        self._table_model.set_ping_busy(node_id, False)
        self._table_model.refresh_ping(node_id)
        self._apply_activity_widgets()

    def update_speed(self, node_id: str, speed_mbps: float | None) -> None:
        self._active_speed_progress.pop(node_id, None)
        self._table_model.set_speed_busy(node_id, False)
        self._table_model.refresh_speed(node_id)
        self._apply_activity_widgets()

    def update_alive_status(self, node_id: str, is_alive: bool | None) -> None:
        self._table_model.refresh_alive_status(node_id)

    def refresh_detail(self) -> None:
        """Refresh detail view if it is currently visible."""
        if self._stack.currentIndex() == 1:
            self._detail_widget.refresh()

    # ── Subscription chips ──

    _CHIP_BASE = (
        "QPushButton {"
        "  border: 1px solid #555;"
        "  border-radius: 12px;"
        "  padding: 2px 14px;"
        "  background: transparent;"
        "  color: palette(text);"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover { background: rgba(255,255,255,0.06); }"
        "QPushButton:checked {"
        "  background: #0078D4;"
        "  border-color: #0078D4;"
        "  color: white;"
        "}"
    )

    def _rebuild_sub_chips(self) -> None:
        layout = self._sub_chips_layout
        while layout.count():
            item = layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

        all_btn = self._make_chip("Все", None)
        all_btn.setChecked(self._active_sub_id is None)
        layout.addWidget(all_btn)

        for sub in self._subscriptions:
            btn = self._make_chip(sub.name or sub.url, sub.id)
            btn.setChecked(self._active_sub_id == sub.id)
            btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            btn.customContextMenuRequested.connect(
                lambda pos, sid=sub.id: self._on_sub_chip_context(sid)
            )
            layout.addWidget(btn)

        add_btn = TransparentToolButton(FIF.ADD, self._sub_chips_container)
        add_btn.setFixedSize(28, 28)
        add_btn.setToolTip("Добавить подписку")
        add_btn.clicked.connect(self._on_add_subscription)
        layout.addWidget(add_btn)

        layout.addStretch()

        # Hide entire row when no subscriptions and chips would be trivial
        self._sub_scroll.setVisible(True)

    def _make_chip(self, label: str, sub_id: str | None) -> "QPushButton":
        from PyQt6.QtWidgets import QPushButton
        btn = QPushButton(label, self._sub_chips_container)
        btn.setCheckable(True)
        btn.setFixedHeight(28)
        btn.setStyleSheet(self._CHIP_BASE)
        btn.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        btn.clicked.connect(lambda checked, sid=sub_id: self._on_sub_chip_clicked(sid))
        return btn

    def _on_sub_chip_clicked(self, sub_id: str | None) -> None:
        self._active_sub_id = sub_id
        self._rebuild_sub_chips()
        self._reload()

    def _on_sub_chip_context(self, sub_id: str) -> None:
        sub = next((s for s in self._subscriptions if s.id == sub_id), None)
        if sub is None:
            return
        menu = RoundMenu(parent=self)
        update_action = Action("Обновить", self)
        update_action.triggered.connect(lambda: self.update_subscription_requested.emit(sub_id))
        menu.addAction(update_action)
        rename_action = Action("Переименовать", self)
        rename_action.triggered.connect(lambda: self._on_rename_subscription(sub_id, sub.name))
        menu.addAction(rename_action)
        menu.addSeparator()
        delete_action = Action("Удалить подписку", self)
        delete_action.triggered.connect(lambda: self._on_delete_subscription(sub_id, sub.name))
        menu.addAction(delete_action)
        menu.exec(QCursor.pos())

    def _on_add_subscription_prefilled(self, url: str) -> None:
        self._on_add_subscription(prefill_url=url)

    def _on_add_subscription(self, *, prefill_url: str = "") -> None:
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout, QLabel
        dlg = QDialog(self.window())
        dlg.setWindowTitle("Добавить подписку")
        dlg.setMinimumWidth(420)
        form = QFormLayout(dlg)
        form.setSpacing(10)
        form.setContentsMargins(16, 16, 16, 16)
        url_edit = LineEdit(dlg)
        url_edit.setPlaceholderText("https://example.com/sub/token")
        if prefill_url:
            url_edit.setText(prefill_url)
        name_edit = LineEdit(dlg)
        name_edit.setPlaceholderText("Моя подписка")
        form.addRow(QLabel("URL подписки:"), url_edit)
        form.addRow(QLabel("Название:"), name_edit)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, dlg
        )
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        url = url_edit.text().strip()
        name = name_edit.text().strip()
        if not url:
            return
        if not name:
            from urllib.parse import urlsplit
            name = urlsplit(url).netloc or url[:40]
        self.import_subscription_requested.emit(url, name)

    def _on_rename_subscription(self, sub_id: str, current_name: str) -> None:
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout, QLabel
        dlg = QDialog(self.window())
        dlg.setWindowTitle("Переименовать подписку")
        dlg.setMinimumWidth(320)
        form = QFormLayout(dlg)
        form.setSpacing(10)
        form.setContentsMargins(16, 16, 16, 16)
        name_edit = LineEdit(dlg)
        name_edit.setText(current_name)
        form.addRow(QLabel("Новое название:"), name_edit)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, dlg
        )
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        new_name = name_edit.text().strip()
        if new_name and new_name != current_name:
            self.rename_subscription_requested.emit(sub_id, new_name)

    def _on_delete_subscription(self, sub_id: str, name: str) -> None:
        box = MessageBox(
            "Удалить подписку",
            f"Удалить подписку «{name}» и все её серверы?",
            self.window(),
        )
        box.yesButton.setText("Удалить")
        box.cancelButton.setText("Отмена")
        if box.exec():
            if self._active_sub_id == sub_id:
                self._active_sub_id = None
            self.remove_subscription_requested.emit(sub_id)

    # ── Filter combos ──

    def _rebuild_filter_combos(self) -> None:
        new_groups = frozenset(n.group for n in self._nodes if n.group)
        new_tags: set[str] = set()
        for n in self._nodes:
            new_tags.update(n.tags)
        new_tags_frozen = frozenset(new_tags)

        if new_groups == self._cached_groups and new_tags_frozen == self._cached_tags:
            return
        self._cached_groups = new_groups
        self._cached_tags = new_tags_frozen

        prev_group = self.group_filter.currentText()
        prev_tag = self.tag_filter.currentText()

        self.group_filter.blockSignals(True)
        self.group_filter.clear()
        self.group_filter.addItem("Все группы")
        for g in sorted(new_groups):
            self.group_filter.addItem(g)
        idx = self.group_filter.findText(prev_group)
        self.group_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.group_filter.blockSignals(False)

        self.tag_filter.blockSignals(True)
        self.tag_filter.clear()
        self.tag_filter.addItem("Все теги")
        for t in sorted(new_tags_frozen):
            self.tag_filter.addItem(t)
        idx = self.tag_filter.findText(prev_tag)
        self.tag_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.tag_filter.blockSignals(False)

    # ── Reload / filter / sort ──

    def _reload(self) -> None:
        query = self.search_edit.text().strip().lower()
        group_filter = self.group_filter.currentText()
        tag_filter = self.tag_filter.currentText()

        filtered = []
        for node in self._nodes:
            if self._active_sub_id is not None and node.subscription_id != self._active_sub_id:
                continue
            if group_filter != "Все группы" and node.group != group_filter:
                continue
            if tag_filter != "Все теги" and tag_filter not in node.tags:
                continue
            if query:
                haystack = self._search_haystacks.get(node.id, "")
                if query not in haystack:
                    continue
            filtered.append(node)

        sort_key = self.sort_combo.currentText()
        filtered = self._sort_nodes(filtered, sort_key, self._sort_ascending)

        self._visible_node_ids = [node.id for node in filtered]

        self._in_reload = True
        self.table.setUpdatesEnabled(False)
        try:
            self._table_model.set_nodes(filtered)
            selection_model = self.table.selectionModel()
            if selection_model is not None:
                selection_model.clearSelection()
                selection_model.clearCurrentIndex()
                # Restore selection based on the actual active VPN node, not
                # previous click position — avoids wrong-row highlight when
                # the user switches subscription tabs.
                if self._active_node_id and self._active_node_id in self._visible_node_ids:
                    row = self._visible_node_ids.index(self._active_node_id)
                    index = self._table_model.index(row, 0)
                    if index.isValid():
                        selection_model.select(
                            index,
                            QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
                        )
        finally:
            self.table.setUpdatesEnabled(True)
            self.table.viewport().update()
            self._in_reload = False

        self._apply_activity_widgets()
        self._emit_selection()

    def start_ping_activity(self, node_ids: set[str] | None = None) -> None:
        targets = set(node_ids) if node_ids else {node.id for node in self._nodes}
        if not targets:
            return
        self._pending_ping_ids.clear()
        self._table_model.clear_ping_busy()
        self._pending_ping_ids = targets
        for node_id in targets:
            self._table_model.set_ping_busy(node_id, True)
        self._apply_activity_widgets()

    def start_speed_activity(self) -> None:
        self._active_speed_progress.clear()
        self._table_model.clear_speed_busy()
        self._speed_test_running = True
        self._speed_test_stopping = False
        self._sync_speed_test_controls()
        self._apply_activity_widgets()

    def update_speed_progress(self, node_id: str, percent: int) -> None:
        self._active_speed_progress[node_id] = max(0, min(100, int(percent)))
        self._table_model.set_speed_busy(node_id, True)
        self._apply_activity_widgets()

    def finish_ping_activity(self) -> None:
        if not self._pending_ping_ids:
            return
        self._pending_ping_ids.clear()
        self._table_model.clear_ping_busy()
        self._apply_activity_widgets()

    def finish_speed_activity(self) -> None:
        self._active_speed_progress.clear()
        self._table_model.clear_speed_busy()
        self._speed_test_running = False
        self._speed_test_stopping = False
        self._sync_speed_test_controls()
        self._apply_activity_widgets()

    def mark_speed_test_stopping(self) -> None:
        if not self._speed_test_running:
            return
        self._speed_test_stopping = True
        self._sync_speed_test_controls()

    def _apply_activity_widgets(self) -> None:
        for row, node_id in enumerate(self._visible_node_ids):
            self._sync_activity_widget(row, 6, node_id in self._pending_ping_ids)
            self._sync_speed_widget(row, node_id)

    def _sync_speed_test_controls(self) -> None:
        running = self._speed_test_running
        stopping = self._speed_test_stopping
        self.speed_test_btn.setEnabled(not running)
        self.speed_test_all_btn.setEnabled(not running)
        self.stop_speed_test_btn.setVisible(running)
        self.stop_speed_test_btn.setEnabled(running and not stopping)
        self._detail_widget.set_speed_test_running(running, stopping=stopping)

    def _sync_activity_widget(self, row: int, column: int, active: bool) -> None:
        index = self._table_model.index(row, column)
        if not index.isValid():
            return

        existing = self.table.indexWidget(index)
        if not active:
            if existing is not None:
                self.table.setIndexWidget(index, None)
                existing.deleteLater()
            return

        if existing is not None:
            return

        container = QWidget(self.table)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        ring = IndeterminateProgressRing(container)
        ring.setFixedSize(16, 16)
        ring.setStrokeWidth(3)
        ring.setCustomBackgroundColor("transparent", "transparent")
        layout.addStretch(1)
        layout.addWidget(ring)
        layout.addStretch(1)
        self.table.setIndexWidget(index, container)

    def _sync_speed_widget(self, row: int, node_id: str) -> None:
        index = self._table_model.index(row, 7)
        if not index.isValid():
            return

        percent = self._active_speed_progress.get(node_id)
        existing = self.table.indexWidget(index)
        if percent is None:
            if existing is not None:
                self.table.setIndexWidget(index, None)
                existing.deleteLater()
            return

        if existing is None:
            container = QWidget(self.table)
            layout = QHBoxLayout(container)
            layout.setContentsMargins(6, 0, 6, 0)
            layout.setSpacing(0)
            bar = ProgressBar(container)
            bar.setRange(0, 100)
            bar.setValue(percent)
            bar.setTextVisible(False)
            bar.setFixedHeight(6)
            layout.addWidget(bar, 1)
            container.setProperty("progressBar", bar)
            self.table.setIndexWidget(index, container)
            return

        bar = existing.property("progressBar")
        if isinstance(bar, ProgressBar):
            bar.setValue(percent)

    @staticmethod
    def _sort_nodes(nodes: list[Node], key: str, ascending: bool) -> list[Node]:
        if key == "Вручную":
            return sorted(nodes, key=lambda n: n.sort_order, reverse=not ascending)
        if key == "Имя":
            return sorted(nodes, key=lambda n: n.name.lower(), reverse=not ascending)
        if key == "Группа":
            return sorted(nodes, key=lambda n: n.group.lower(), reverse=not ascending)
        if key == "Тип":
            return sorted(nodes, key=lambda n: n.scheme.lower(), reverse=not ascending)
        if key == "Пинг":
            none_val = float("inf") if ascending else float("-inf")
            return sorted(
                nodes,
                key=lambda n: n.ping_ms if n.ping_ms is not None else none_val,
                reverse=not ascending,
            )
        if key == "Скорость":
            none_val = float("inf") if ascending else float("-inf")
            return sorted(
                nodes,
                key=lambda n: n.speed_mbps if n.speed_mbps is not None else none_val,
                reverse=not ascending,
            )
        if key == "Последнее использование":
            return sorted(nodes, key=lambda n: n.last_used_at or "", reverse=not ascending)
        return nodes

    def _toggle_sort_order(self) -> None:
        self._sort_ascending = not self._sort_ascending
        self.sort_order_btn.setIcon(FIF.UP if self._sort_ascending else FIF.DOWN)
        self._reload()

    def _on_header_clicked(self, logical_index: int) -> None:
        sort_key = _COLUMN_SORT_MAP.get(logical_index)
        if sort_key is None:
            return
        idx = self.sort_combo.findText(sort_key)
        if idx < 0:
            return
        if self.sort_combo.currentIndex() == idx:
            self._sort_ascending = not self._sort_ascending
            self.sort_order_btn.setIcon(FIF.UP if self._sort_ascending else FIF.DOWN)
            self._reload()
        else:
            self._sort_ascending = True
            self.sort_order_btn.setIcon(FIF.UP)
            self.sort_combo.setCurrentIndex(idx)

    # ── Selection helpers ──

    def _selected_ids(self) -> set[str]:
        model = self.table.selectionModel()
        if model is None:
            return set()
        ids: set[str] = set()
        for index in model.selectedRows():
            row = index.row()
            if 0 <= row < len(self._visible_node_ids):
                ids.add(self._visible_node_ids[row])
        return ids

    def _select_node(self, node_id: str) -> None:
        row = self._table_model.row_for_node(node_id)
        if row is not None:
            self.table.selectRow(row)

    def _emit_selection(self) -> None:
        if self._in_reload:
            return
        ids = self._selected_ids()
        self.bulk_edit_btn.setVisible(len(ids) > 1)
        is_manual = self.sort_combo.currentText() == "Вручную"
        self.move_up_btn.setEnabled(is_manual and len(ids) == 1)
        self.move_down_btn.setEnabled(is_manual and len(ids) == 1)
        if len(ids) == 1:
            node_id = next(iter(ids))
            self._active_node_id = node_id  # track user click → drives selection on reload
            self.selected_node_changed.emit(node_id)

    # ── Button handlers ──

    def _on_move_up(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.reorder_requested.emit(next(iter(ids)), "up")

    def _on_move_down(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.reorder_requested.emit(next(iter(ids)), "down")

    def _on_edit(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.edit_node_requested.emit(next(iter(ids)))

    def _on_bulk_edit(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.bulk_edit_requested.emit(ids)

    def _on_ping_selected(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.ping_requested.emit(ids)

    def _on_ping_all(self) -> None:
        self.ping_requested.emit(set())

    def _on_speed_test_selected(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.speed_test_requested.emit(ids)

    def _on_speed_test_all(self) -> None:
        self.speed_test_requested.emit(set())

    def _on_delete_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        from qfluentwidgets import MessageBox
        count = len(ids)
        title = "Удаление серверов" if count > 1 else "Удаление сервера"
        msg = f"Удалить {count} серверов?" if count > 1 else "Удалить выбранный сервер?"
        box = MessageBox(title, msg, self.window())
        box.yesButton.setText("Удалить")
        box.cancelButton.setText("Отмена")
        if box.exec():
            self.delete_requested.emit(ids)

    def _on_export_outbound(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 1:
            return
        self.export_outbound_json_requested.emit(next(iter(ids)))

    def _on_export_runtime(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 1:
            return
        self.export_runtime_json_requested.emit(next(iter(ids)))

    # ── Double-click / context menu ──

    def _on_double_click(self, index) -> None:
        row = index.row()
        if 0 <= row < len(self._visible_node_ids):
            node_id = self._visible_node_ids[row]
            node = self._id_to_node.get(node_id)
            if node:
                self._show_detail(node)

    def _on_context_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        clicked_row = index.row()
        if clicked_row < 0 or clicked_row >= len(self._visible_node_ids):
            return

        clicked_id = self._visible_node_ids[clicked_row]
        current_ids = self._selected_ids()
        if clicked_id not in current_ids:
            self.table.clearSelection()
            self.table.selectRow(clicked_row)
            ids = {clicked_id}
        else:
            ids = current_ids

        menu = RoundMenu(parent=self)
        count = len(ids)

        if count == 1:
            node_id = next(iter(ids))
            edit_action = Action("Редактировать", self)
            edit_action.triggered.connect(lambda: self.edit_node_requested.emit(node_id))
            menu.addAction(edit_action)

            copy_action = Action("Копировать ссылку", self)
            copy_action.triggered.connect(lambda: self._copy_node_link(node_id))
            menu.addAction(copy_action)
        else:
            copy_action = Action(f"Копировать {count} ссылок", self)
            copy_action.triggered.connect(lambda: self._copy_multiple_links(ids))
            menu.addAction(copy_action)

        bulk_action = Action("Массовое редактирование", self)
        bulk_action.triggered.connect(lambda: self.bulk_edit_requested.emit(ids))
        menu.addAction(bulk_action)

        menu.addSeparator()

        ping_action = Action(f"Пинг ({count})" if count > 1 else "Пинг", self)
        ping_action.triggered.connect(lambda: self.ping_requested.emit(ids))
        menu.addAction(ping_action)

        speed_action = Action(f"Тест скорости ({count})" if count > 1 else "Тест скорости", self)
        speed_action.triggered.connect(lambda: self.speed_test_requested.emit(ids))
        menu.addAction(speed_action)

        menu.addSeparator()

        delete_label = f"Удалить {count} серверов" if count > 1 else "Удалить"
        delete_action = Action(delete_label, self)
        delete_action.triggered.connect(lambda: self.delete_requested.emit(ids))
        menu.addAction(delete_action)

        if count == 1 and self.sort_combo.currentText() == "Вручную":
            node_id = next(iter(ids))
            menu.addSeparator()
            move_top = Action("В начало списка", self)
            move_top.triggered.connect(lambda: self.reorder_requested.emit(node_id, "top"))
            menu.addAction(move_top)
            move_bottom = Action("В конец списка", self)
            move_bottom.triggered.connect(lambda: self.reorder_requested.emit(node_id, "bottom"))
            menu.addAction(move_bottom)

        menu.exec(QCursor.pos())

    # ── Navigation (list / detail) ──

    def _show_detail(self, node: Node) -> None:
        self._detail_widget.set_node(node)
        self._stack.setCurrentIndex(1)

    def _show_list(self) -> None:
        self._stack.setCurrentIndex(0)

    # ── Utilities ──

    def _copy_node_link(self, node_id: str) -> None:
        node = self._id_to_node.get(node_id)
        if node and node.link:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(node.link)

    def _copy_multiple_links(self, node_ids: set[str]) -> None:
        links: list[str] = []
        for vid in self._visible_node_ids:
            if vid in node_ids:
                node = self._id_to_node.get(vid)
                if node and node.link:
                    links.append(node.link)
        if links:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText("\n".join(links))

    def _on_section_resized(self, logical_index: int, old_size: int, new_size: int) -> None:
        if not self._applying_column_widths:
            self._col_resize_timer.start()

    def _emit_column_widths(self) -> None:
        header = cast(QHeaderView, self.table.horizontalHeader())
        widths = {col: header.sectionSize(col) for col in range(self._table_model.columnCount())}
        self.column_widths_changed.emit(widths)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Delete:
            self._on_delete_selected()
            return
        if event.matches(QKeySequence.StandardKey.Copy):
            ids = self._selected_ids()
            if ids:
                if len(ids) == 1:
                    self._copy_node_link(next(iter(ids)))
                else:
                    self._copy_multiple_links(ids)
            return
        super().keyPressEvent(event)
