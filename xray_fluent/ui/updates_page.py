from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    PrimaryPushButton,
    ProgressBar,
    PushButton,
    SubtitleLabel,
    SwitchButton,
    TitleLabel,
)

from ..constants import APP_VERSION


class UpdatesPage(QWidget):
    check_app_requested = pyqtSignal()
    check_xray_requested = pyqtSignal()
    update_xray_requested = pyqtSignal()
    check_geo_requested = pyqtSignal()
    update_geo_requested = pyqtSignal()
    check_singbox_requested = pyqtSignal()
    update_singbox_requested = pyqtSignal()
    prerelease_toggled = pyqtSignal(bool)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("updates")
        self._neutral_status_style = "color: #888;"
        self._success_status_style = "color: #4CAF50; font-weight: bold;"
        self._error_status_style = "color: #E57373; font-weight: bold;"

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 28)
        root.setSpacing(20)

        title = SubtitleLabel("Обновления", self)
        root.addWidget(title)

        # ── Pre-release toggle ──
        prerelease_row = QHBoxLayout()
        prerelease_row.setSpacing(10)
        prerelease_label = BodyLabel("Включить pre-release обновления", self)
        self.prerelease_switch = SwitchButton(self)
        prerelease_row.addWidget(prerelease_label)
        prerelease_row.addWidget(self.prerelease_switch)
        prerelease_row.addStretch()
        root.addLayout(prerelease_row)

        root.addWidget(self._make_separator())

        # ── App version info ──
        app_box = QVBoxLayout()
        app_box.setSpacing(6)
        app_title = BodyLabel("zapret kvn", self)
        app_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        app_box.addWidget(app_title)

        self._app_version_label = BodyLabel(f"Текущая версия: v{APP_VERSION}", self)
        app_box.addWidget(self._app_version_label)

        self._app_status = CaptionLabel("", self)
        self._app_status.setStyleSheet(self._neutral_status_style)
        app_box.addWidget(self._app_status)

        self._app_progress = ProgressBar(self)
        self._app_progress.setFixedHeight(4)
        self._app_progress.setValue(0)
        self._app_progress.hide()
        app_box.addWidget(self._app_progress)

        self._app_spinner = IndeterminateProgressBar(self)
        self._app_spinner.setFixedHeight(4)
        self._app_spinner.hide()
        app_box.addWidget(self._app_spinner)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.check_app_btn = PrimaryPushButton(FIF.SYNC, "Проверить обновления", self)
        self.download_btn = PushButton(FIF.DOWNLOAD, "Скачать и установить", self)
        self.download_btn.hide()
        btn_row.addWidget(self.check_app_btn)
        btn_row.addWidget(self.download_btn)
        btn_row.addStretch()
        app_box.addLayout(btn_row)

        root.addLayout(app_box)

        root.addWidget(self._make_separator())

        # ── Xray core ──
        xray_box = QVBoxLayout()
        xray_box.setSpacing(6)
        xray_title = BodyLabel("Xray Core", self)
        xray_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        xray_box.addWidget(xray_title)

        self._xray_version_label = BodyLabel("Версия: загрузка...", self)
        xray_box.addWidget(self._xray_version_label)

        self._xray_status = CaptionLabel("", self)
        self._xray_status.setStyleSheet(self._neutral_status_style)
        xray_box.addWidget(self._xray_status)

        self._xray_progress = ProgressBar(self)
        self._xray_progress.setFixedHeight(4)
        self._xray_progress.setValue(0)
        self._xray_progress.hide()
        xray_box.addWidget(self._xray_progress)

        xray_btn_row = QHBoxLayout()
        xray_btn_row.setSpacing(10)
        self.check_xray_btn = PushButton(FIF.SYNC, "Проверить", self)
        self.update_xray_btn = PrimaryPushButton(FIF.DOWNLOAD, "Обновить Xray", self)
        self.update_xray_btn.hide()
        xray_btn_row.addWidget(self.check_xray_btn)
        xray_btn_row.addWidget(self.update_xray_btn)
        xray_btn_row.addStretch()
        xray_box.addLayout(xray_btn_row)

        root.addLayout(xray_box)

        root.addWidget(self._make_separator())

        # ── Geo files ──
        geo_box = QVBoxLayout()
        geo_box.setSpacing(6)
        geo_title = BodyLabel("Geo-файлы (runetfreedom/russia-v2ray-rules-dat)", self)
        geo_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        geo_box.addWidget(geo_title)

        self._geo_version_label = BodyLabel("Установленная версия: неизвестна", self)
        geo_box.addWidget(self._geo_version_label)

        self._geo_status = CaptionLabel("", self)
        self._geo_status.setStyleSheet(self._neutral_status_style)
        geo_box.addWidget(self._geo_status)

        self._geo_progress = ProgressBar(self)
        self._geo_progress.setFixedHeight(4)
        self._geo_progress.setValue(0)
        self._geo_progress.hide()
        geo_box.addWidget(self._geo_progress)

        geo_btn_row = QHBoxLayout()
        geo_btn_row.setSpacing(10)
        self.check_geo_btn = PushButton(FIF.SYNC, "Проверить", self)
        self.update_geo_btn = PrimaryPushButton(FIF.DOWNLOAD, "Обновить geo", self)
        self.update_geo_btn.hide()
        geo_btn_row.addWidget(self.check_geo_btn)
        geo_btn_row.addWidget(self.update_geo_btn)
        geo_btn_row.addStretch()
        geo_box.addLayout(geo_btn_row)

        root.addLayout(geo_box)

        root.addWidget(self._make_separator())

        # ── Sing-box-extended ──
        sb_box = QVBoxLayout()
        sb_box.setSpacing(6)
        sb_title = BodyLabel("sing-box-extended (shtorm-7/sing-box-extended)", self)
        sb_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        sb_box.addWidget(sb_title)

        self._singbox_version_label = BodyLabel("Версия: загрузка...", self)
        sb_box.addWidget(self._singbox_version_label)

        self._singbox_status = CaptionLabel("", self)
        self._singbox_status.setStyleSheet(self._neutral_status_style)
        sb_box.addWidget(self._singbox_status)

        self._singbox_progress = ProgressBar(self)
        self._singbox_progress.setFixedHeight(4)
        self._singbox_progress.setValue(0)
        self._singbox_progress.hide()
        sb_box.addWidget(self._singbox_progress)

        sb_btn_row = QHBoxLayout()
        sb_btn_row.setSpacing(10)
        self.check_singbox_btn = PushButton(FIF.SYNC, "Проверить", self)
        self.update_singbox_btn = PrimaryPushButton(FIF.DOWNLOAD, "Обновить sing-box", self)
        self.update_singbox_btn.hide()
        sb_btn_row.addWidget(self.check_singbox_btn)
        sb_btn_row.addWidget(self.update_singbox_btn)
        sb_btn_row.addStretch()
        sb_box.addLayout(sb_btn_row)

        root.addLayout(sb_box)

        root.addStretch()

        # ── Connections ──
        self.check_app_btn.clicked.connect(self.check_app_requested)
        self.check_xray_btn.clicked.connect(self.check_xray_requested)
        self.update_xray_btn.clicked.connect(self.update_xray_requested)
        self.check_geo_btn.clicked.connect(self.check_geo_requested)
        self.update_geo_btn.clicked.connect(self.update_geo_requested)
        self.check_singbox_btn.clicked.connect(self.check_singbox_requested)
        self.update_singbox_btn.clicked.connect(self.update_singbox_requested)
        self.prerelease_switch.checkedChanged.connect(self.prerelease_toggled)

    # ── helpers ──

    def _make_separator(self) -> QWidget:
        sep = QWidget(self)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: rgba(128,128,128,0.3);")
        return sep

    # ── Public API: app ──

    def set_app_status(self, text: str) -> None:
        self._app_status.setStyleSheet(self._neutral_status_style)
        self._app_status.setText(text)

    def set_app_error(self, text: str) -> None:
        self._app_status.setStyleSheet(self._error_status_style)
        self._app_status.setText(text)

    def show_checking(self) -> None:
        self._app_progress.hide()
        self._app_spinner.show()
        self._app_spinner.start()
        self.check_app_btn.setEnabled(False)
        self._app_status.setStyleSheet(self._neutral_status_style)
        self._app_status.setText("Проверка обновлений...")

    def show_download_progress(self, percent: int) -> None:
        self._app_spinner.hide()
        self._app_progress.show()
        self._app_progress.setValue(percent)
        self._app_status.setStyleSheet(self._neutral_status_style)
        self._app_status.setText(f"Загрузка: {percent}%")
        self.check_app_btn.setEnabled(False)
        self.download_btn.setEnabled(False)

    def show_idle(self) -> None:
        self._app_spinner.stop()
        self._app_spinner.hide()
        self._app_progress.hide()
        self._app_progress.setValue(0)
        self.check_app_btn.setEnabled(True)
        self.download_btn.hide()

    def show_update_available(self, version: str) -> None:
        self._app_spinner.stop()
        self._app_spinner.hide()
        self.check_app_btn.setEnabled(True)
        self._app_status.setText(f"Доступна новая версия: v{version}")
        self._app_status.setStyleSheet(self._success_status_style)
        self.download_btn.show()
        self.download_btn.setEnabled(True)
        self.download_btn.setText(f"Скачать v{version} и установить")

    def show_up_to_date(self) -> None:
        self.show_idle()
        self._app_status.setText("У вас последняя версия")
        self._app_status.setStyleSheet(self._success_status_style)

    # ── Public API: xray ──

    def set_xray_version(self, version: str) -> None:
        self._xray_version_label.setText(f"Версия: {version}" if version else "Версия: не найдена")

    def set_xray_status(self, text: str) -> None:
        self._xray_status.setStyleSheet(self._neutral_status_style)
        self._xray_status.setText(text)
        self.update_xray_btn.hide()

    def set_xray_error(self, text: str) -> None:
        self._xray_status.setStyleSheet(self._error_status_style)
        self._xray_status.setText(text)
        self.update_xray_btn.hide()

    def set_xray_success(self, text: str) -> None:
        self._xray_status.setStyleSheet(self._success_status_style)
        self._xray_status.setText(text)
        self.update_xray_btn.hide()

    def set_xray_update_available(self, latest_version: str) -> None:
        self._xray_status.setStyleSheet(self._success_status_style)
        self._xray_status.setText(f"Доступно обновление: {latest_version}")
        self.update_xray_btn.show()
        self.check_xray_btn.setEnabled(True)

    def set_xray_progress(self, percent: int) -> None:
        self._xray_progress.show()
        self._xray_progress.setValue(percent)

    def hide_xray_progress(self) -> None:
        self._xray_progress.hide()
        self._xray_progress.setValue(0)

    # ── Public API: geo ──

    def set_geo_version(self, version: str) -> None:
        if version:
            self._geo_version_label.setText(f"Установленная версия: {version}")
        else:
            self._geo_version_label.setText("Установленная версия: неизвестна")

    def set_geo_status(self, text: str) -> None:
        self._geo_status.setStyleSheet(self._neutral_status_style)
        self._geo_status.setText(text)
        self.update_geo_btn.hide()

    def set_geo_error(self, text: str) -> None:
        self._geo_status.setStyleSheet(self._error_status_style)
        self._geo_status.setText(text)
        self.update_geo_btn.hide()

    def set_geo_success(self, text: str) -> None:
        self._geo_status.setStyleSheet(self._success_status_style)
        self._geo_status.setText(text)
        self.update_geo_btn.hide()

    def set_geo_update_available(self, latest_version: str) -> None:
        self._geo_status.setStyleSheet(self._success_status_style)
        self._geo_status.setText(f"Доступно обновление: {latest_version}")
        self.update_geo_btn.show()
        self.check_geo_btn.setEnabled(True)

    def set_geo_progress(self, percent: int) -> None:
        self._geo_progress.show()
        self._geo_progress.setValue(percent)

    def hide_geo_progress(self) -> None:
        self._geo_progress.hide()
        self._geo_progress.setValue(0)

    def set_geo_busy(self, busy: bool) -> None:
        self.check_geo_btn.setEnabled(not busy)
        self.update_geo_btn.setEnabled(not busy)

    # ── Public API: singbox ──

    def set_singbox_version(self, version: str) -> None:
        self._singbox_version_label.setText(f"Версия: {version}" if version else "Версия: не найдена")

    def set_singbox_status(self, text: str) -> None:
        self._singbox_status.setStyleSheet(self._neutral_status_style)
        self._singbox_status.setText(text)
        self.update_singbox_btn.hide()

    def set_singbox_error(self, text: str) -> None:
        self._singbox_status.setStyleSheet(self._error_status_style)
        self._singbox_status.setText(text)
        self.update_singbox_btn.hide()

    def set_singbox_success(self, text: str) -> None:
        self._singbox_status.setStyleSheet(self._success_status_style)
        self._singbox_status.setText(text)
        self.update_singbox_btn.hide()

    def set_singbox_update_available(self, latest_version: str) -> None:
        self._singbox_status.setStyleSheet(self._success_status_style)
        self._singbox_status.setText(f"Доступно обновление: {latest_version}")
        self.update_singbox_btn.show()
        self.check_singbox_btn.setEnabled(True)

    def set_singbox_progress(self, percent: int) -> None:
        self._singbox_progress.show()
        self._singbox_progress.setValue(percent)

    def hide_singbox_progress(self) -> None:
        self._singbox_progress.hide()
        self._singbox_progress.setValue(0)

    def set_singbox_busy(self, busy: bool) -> None:
        self.check_singbox_btn.setEnabled(not busy)
        self.update_singbox_btn.setEnabled(not busy)

    # ── Public API: prerelease ──

    def set_prerelease(self, enabled: bool) -> None:
        self.prerelease_switch.setChecked(enabled)
