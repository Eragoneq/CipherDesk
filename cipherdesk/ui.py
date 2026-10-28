"""CipherDesk's native desktop interface. No key material is stored here."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from string import Template
import sys
from typing import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Qt, Signal, Slot, QTimer
from PySide6.QtGui import QColor, QDesktopServices, QFont, QIcon, QPainter, QPalette, QPen, QPixmap
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QCheckBox, QComboBox, QFileDialog,
    QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMessageBox, QProgressBar, QPushButton,
    QSizePolicy, QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem, QScrollArea, QLayout,
    QVBoxLayout, QWidget, QHeaderView,
)

from .crypto import GPGBackend
from .store import GroupStore


COLORS = {
    "canvas": "#3d4a56", "surface": "#4b5b68", "header": "#303e49",
    "text": "#e6edf1", "muted": "#cbd5dd", "header_caption": "#c7d7df",
    "border": "#9aafbd", "separator": "#748896",
    "tab": "#374550", "tab_hover": "#435765", "tab_text": "#b7dfe0",
    "hover": "#566875", "pressed": "#3d5260",
    "selected": "#3c6d79", "selected_text": "#eef7f8", "alternate": "#455562",
    "primary": "#91c4c4", "primary_text": "#20383d",
    "primary_hover": "#a8d1cf", "primary_pressed": "#7db6b7", "focus": "#b7dfe0",
    "disabled": "#414f5b", "disabled_text": "#bac7d1",
    "header_button": "#425663", "header_button_hover": "#536c79",
    "notice": "#65573d", "notice_text": "#fae3af",
    "success": "#3c5c50", "success_text": "#d5f0df",
    "error": "#6b4b4e", "error_text": "#ffe0de", "error_detail": "#ffe0de",
}

# A medium slate palette reduces glare without using near-black surfaces.
# Qt's native controls use the same roles through apply_theme(), below.
STYLE = Template("""
QMainWindow, QDialog { background: $canvas; }
QWidget { font-family: 'Segoe UI'; font-size: 13px; color: $text; }
QLabel { background: transparent; }
QFrame#header { background: $header; border: none; }
QLabel#brand { font-size: 25px; font-weight: 600; color: $text; }
QLabel#tagline { color: $header_caption; font-size: 12px; }
QLabel#heading { font-size: 23px; font-weight: 600; color: $text; }
QLabel#section { font-size: 14px; font-weight: 600; }
QLabel#muted { color: $muted; }
QLabel#notice { color: $notice_text; background: $notice; padding: 10px; border-radius: 5px; }
QLabel#success { color: $success_text; background: $success; padding: 10px; border-radius: 5px; }
QLabel#error { color: $error_text; background: $error; padding: 10px; border-radius: 5px; }
QTabWidget::pane { background: $canvas; border: 1px solid $separator; top: -1px; }
QScrollArea, QScrollArea > QWidget > QWidget { background: $canvas; }
QTabBar::tab { background: $tab; padding: 12px 23px; border: 1px solid $separator; border-bottom: none; min-width: 95px; }
QTabBar::tab:selected { background: $canvas; color: $tab_text; font-weight: 600; }
QTabBar::tab:hover:!selected { background: $tab_hover; }
QPushButton { background: $surface; border: 1px solid $border; border-radius: 5px; padding: 8px 13px; min-height: 18px; }
QPushButton:hover { background: $hover; border-color: $focus; }
QPushButton:pressed { background: $pressed; }
QPushButton:focus { border: 2px solid $focus; padding: 7px 12px; }
QPushButton:disabled { color: $disabled_text; background: $disabled; border-color: $separator; }
QPushButton#primary { color: $primary_text; background: $primary; border-color: $primary; font-weight: 600; padding: 10px 20px; }
QPushButton#primary:hover { background: $primary_hover; }
QPushButton#primary:pressed { background: $primary_pressed; }
QPushButton#primary:focus { border: 2px solid $text; padding: 9px 19px; }
QPushButton#primary:disabled { color: $disabled_text; background: $disabled; border-color: $separator; }
QPushButton#headerButton { color: $text; background: $header_button; border-color: $border; }
QPushButton#headerButton:hover { background: $header_button_hover; }
QPushButton#headerButton:disabled { color: $disabled_text; background: $disabled; }
QLineEdit, QComboBox { padding: 8px; background: $surface; border: 1px solid $border; border-radius: 4px; min-height: 18px; selection-background-color: $selected; selection-color: $selected_text; placeholder-text-color: $muted; }
QLineEdit:focus, QComboBox:focus { border: 2px solid $focus; padding: 7px; }
QLineEdit:disabled, QComboBox:disabled { background: $disabled; color: $disabled_text; }
QComboBox::drop-down { border: none; width: 25px; }
QComboBox QAbstractItemView { background: $surface; color: $text; selection-background-color: $selected; selection-color: $selected_text; }
QListWidget, QTreeWidget { background: $surface; border: 1px solid $border; border-radius: 4px; alternate-background-color: $alternate; selection-background-color: $selected; selection-color: $selected_text; }
QListWidget::item { padding: 9px 7px; }
QTreeWidget::item { padding: 7px 4px; }
QListWidget::item:hover, QTreeWidget::item:hover { background: $hover; }
QListWidget::item:selected, QTreeWidget::item:selected { background: $selected; color: $selected_text; }
QHeaderView::section { background: $tab; color: $text; padding: 8px; border: none; border-right: 1px solid $separator; font-weight: 600; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 17px; height: 17px; }
QSplitter::handle { background: $canvas; width: 1px; }
QProgressBar { background: $disabled; border: none; border-radius: 3px; min-height: 5px; max-height: 5px; }
QProgressBar::chunk { background: $primary; }
QStatusBar { background: $canvas; color: $muted; }
QScrollBar::handle { background: $border; border: 2px solid $canvas; border-radius: 5px; }
QScrollBar::handle:vertical { min-height: 28px; }
QScrollBar::handle:horizontal { min-width: 28px; }
QToolTip { color: $text; background: $header; border: 1px solid $border; padding: 6px; }
""").substitute(COLORS)


def apply_theme(application):
    """Apply the same medium-slate colors to QSS and native Fusion controls."""
    application.setStyle("Fusion")
    application.setFont(QFont("Segoe UI", 10))
    palette = QPalette()
    roles = {
        "Window": "canvas", "WindowText": "text", "Base": "surface",
        "AlternateBase": "alternate", "ToolTipBase": "header", "ToolTipText": "text",
        "Text": "text", "Button": "surface", "ButtonText": "text", "BrightText": "error_detail",
        "Highlight": "selected", "HighlightedText": "selected_text", "Link": "focus",
        "Light": "border", "Midlight": "separator", "Dark": "border", "Mid": "separator",
        "Shadow": "border", "PlaceholderText": "muted",
    }
    for role, token in roles.items():
        palette.setColor(getattr(QPalette.ColorRole, role), QColor(COLORS[token]))
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(COLORS["disabled_text"]))
    application.setPalette(palette)
    application.setStyleSheet(STYLE)


def label(text: str, kind: str = "", wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if kind:
        widget.setObjectName(kind)
    widget.setWordWrap(wrap)
    return widget


def button(text: str, action: Callable, primary: bool = False) -> QPushButton:
    widget = QPushButton(text)
    if primary:
        widget.setObjectName("primary")
    widget.clicked.connect(action)
    return widget


def fingerprint_text(value: str) -> str:
    return " ".join(value[i:i + 4] for i in range(0, len(value), 4))


def key_title(key) -> str:
    return key.name or key.email or key.fingerprint[-16:]


def key_reason(key) -> str:
    return getattr(key, "reason", "") or ("Available" if key.can_encrypt else "Cannot encrypt")


def key_usable(key) -> bool:
    return bool(key.can_encrypt and key.trusted)


def key_status(key) -> str:
    if key_usable(key):
        return "Ready"
    return {"r": "Revoked", "e": "Expired", "d": "Disabled", "i": "Invalid"}.get(
        key.validity, "Certify in Kleopatra" if key.can_encrypt else "No encryption key")


class FileList(QListWidget):
    files_dropped = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setMinimumHeight(132)
        self.setAccessibleName("Selected files; drag and drop local files here")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and any(u.isLocalFile() for u in event.mimeData().urls()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        self.dragEnterEvent(event)

    def dropEvent(self, event):
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        self.files_dropped.emit(paths)
        event.acceptProposedAction()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.count() == 0:
            painter = QPainter(self.viewport())
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(self.viewport().rect().adjusted(18, 12, -18, -12),
                             Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                             "Drop files here, or choose Add files.\nYour original files stay unchanged.")
            painter.end()

    def paths(self) -> list[Path]:
        return [Path(self.item(i).data(Qt.ItemDataRole.UserRole)) for i in range(self.count())]

    def add_paths(self, paths):
        existing = {str(p.resolve()).casefold() for p in self.paths()}
        skipped = []
        for raw in paths:
            path = Path(raw).expanduser()
            if not path.is_file() or path.is_symlink():
                skipped.append(str(path))
                continue
            resolved = path.resolve()
            identity = str(resolved).casefold()
            if identity in existing:
                continue
            existing.add(identity)
            item = QListWidgetItem(f"{path.name}    ·    {self._size(path.stat().st_size)}")
            item.setData(Qt.ItemDataRole.UserRole, str(resolved))
            item.setToolTip(str(resolved))
            self.addItem(item)
        self.viewport().update()
        return skipped

    @staticmethod
    def _size(size):
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024

    def remove_selected(self):
        for item in self.selectedItems():
            self.takeItem(self.row(item))
        self.viewport().update()


class WorkerSignals(QObject):
    progress = Signal(str)
    finished = Signal(object)
    failed = Signal(str)


class Worker(QRunnable):
    def __init__(self, function):
        super().__init__()
        self.function = function
        self.signals = WorkerSignals()

    @Slot()
    def run(self):
        try:
            result = self.function(self.signals.progress.emit)
        except Exception as exc:
            self.signals.failed.emit(str(exc) or type(exc).__name__)
        else:
            self.signals.finished.emit(result)


@dataclass
class BatchResult:
    completed: list
    failures: list[tuple[str, str]]


class MainWindow(QMainWindow):
    def __init__(self, store=None, backend=None, auto_refresh=True):
        super().__init__()
        self.setWindowTitle("CipherDesk — PGP file sharing")
        self.resize(1140, 900)
        self.setMinimumSize(960, 760)
        self.store = store if store is not None else GroupStore()
        self.backend = backend
        self.keys = []
        self.key_map = {}
        self.groups = []
        self._editing_group = None
        self._busy = False
        self._worker = None
        self._recipient_error = ""
        self._effective_recipients = []
        self._last_output = None
        self._settings = self.store.get_settings()
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)
        self._build()
        self._reload_groups()
        self._update_recipients()
        if auto_refresh:
            QTimer.singleShot(0, self.refresh_keys)

    def _build(self):
        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        header = QFrame()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(26, 18, 26, 18)
        brand = QVBoxLayout()
        brand.setSpacing(3)
        brand.addWidget(label("CipherDesk", "brand"))
        brand.addWidget(label("PGP files · contact groups · keys managed in Kleopatra", "tagline"))
        header_layout.addLayout(brand)
        header_layout.addStretch()
        self.kleopatra_button = button("Open Kleopatra", self.open_kleopatra)
        self.kleopatra_button.setObjectName("headerButton")
        self.refresh_button = button("Refresh keys", self.refresh_keys)
        self.refresh_button.setObjectName("headerButton")
        header_layout.addWidget(self.kleopatra_button)
        header_layout.addWidget(self.refresh_button)
        outer.addWidget(header)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(24, 18, 24, 10)
        body_layout.setSpacing(10)
        self.key_status = label("Reading your GnuPG keyring…", "muted", True)
        body_layout.addWidget(self.key_status)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._scroll_page(self._build_encrypt()), "Encrypt files")
        self.tabs.addTab(self._scroll_page(self._build_decrypt()), "Decrypt files")
        self.tabs.addTab(self._scroll_page(self._build_groups()), "Contact groups")
        body_layout.addWidget(self.tabs, 1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        body_layout.addWidget(self.progress_bar)
        self.result_banner = label("", "success", True)
        self.result_banner.hide()
        self.result_banner.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body_layout.addWidget(self.result_banner)
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["File", "Result / signature"])
        self.results_tree.setRootIsDecorated(False)
        self.results_tree.setMaximumHeight(130)
        self.results_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.results_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_tree.hide()
        body_layout.addWidget(self.results_tree)
        self.open_output_button = button("Open output folder", self.open_output_folder)
        self.open_output_button.hide()
        footer = QHBoxLayout()
        footer.addWidget(label("Local processing. Only encrypted copies belong in your shared folder.", "muted", True), 1)
        footer.addWidget(self.open_output_button)
        body_layout.addLayout(footer)
        outer.addWidget(body, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage("Ready")

    def _page(self, title, description):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        layout.addWidget(label(title, "heading"))
        layout.addWidget(label(description, "muted", True))
        return page, layout

    @staticmethod
    def _scroll_page(page):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        return scroll

    def _build_encrypt(self):
        page, layout = self._page("Encrypt for your contacts", "Select one or more groups. Review the combined recipients before saving encrypted copies.")
        split = QWidget()
        split_layout = QHBoxLayout(split)
        split_layout.setContentsMargins(0, 0, 0, 0)
        split_layout.setSpacing(0)
        groups_panel = QWidget()
        groups_panel.setFixedWidth(245)
        group_layout = QVBoxLayout(groups_panel)
        group_layout.setContentsMargins(0, 0, 14, 0)
        group_layout.setSpacing(8)
        group_layout.addWidget(label("Recipient groups", "section"))
        self.send_groups = QListWidget()
        self.send_groups.setAccessibleName("Recipient groups to encrypt for")
        self.send_groups.setMinimumWidth(200)
        self.send_groups.setMinimumHeight(96)
        self.send_groups.itemChanged.connect(self._update_recipients)
        group_layout.addWidget(self.send_groups, 1)
        self.group_hint = label("Create a group in Contact groups to get started.", "muted", True)
        group_layout.addWidget(self.group_hint)
        group_layout.addWidget(button("Manage contact groups", lambda: self.tabs.setCurrentIndex(2)))
        split_layout.addWidget(groups_panel)
        files_panel = QWidget()
        files_layout = QVBoxLayout(files_panel)
        files_layout.setContentsMargins(8, 0, 0, 0)
        files_layout.setSpacing(8)
        row = QHBoxLayout()
        row.addWidget(label("Files to encrypt", "section"))
        row.addStretch()
        row.addWidget(button("Add files", lambda: self._choose_files(self.encrypt_files)))
        row.addWidget(button("Remove selected", lambda: self._remove_files(self.encrypt_files)))
        files_layout.addLayout(row)
        self.encrypt_files = FileList()
        self.encrypt_files.files_dropped.connect(lambda paths: self._add_files(self.encrypt_files, paths))
        files_layout.addWidget(self.encrypt_files, 1)
        self.file_count = label("No files selected", "muted")
        files_layout.addWidget(self.file_count)
        split_layout.addWidget(files_panel, 1)
        split.setFixedHeight(216)
        layout.addWidget(split, 2)
        self.recipient_heading = label("Recipients · 0", "section")
        layout.addWidget(self.recipient_heading)
        self.recipient_tree = QTreeWidget()
        self.recipient_tree.setHeaderLabels(["Contact", "Email", "Key fingerprint", "Status"])
        self.recipient_tree.setRootIsDecorated(False)
        self.recipient_tree.setAlternatingRowColors(True)
        self.recipient_tree.setMinimumHeight(126)
        self.recipient_tree.setMaximumHeight(140)
        self.recipient_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.recipient_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.recipient_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.recipient_tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.recipient_tree, 1)
        identity = QHBoxLayout()
        self.include_self = QCheckBox("Also encrypt for me")
        self.include_self.setToolTip("Adds your public key so you can decrypt your own sent copy.")
        self.own_key = QComboBox()
        self.own_key.setMinimumWidth(230)
        self.own_key.setAccessibleName("Your key for decrypting sent copies")
        self.sign_files = QCheckBox("Sign files")
        self.signer_key = QComboBox()
        self.signer_key.setAccessibleName("Signing key")
        self.signer_key.setMinimumWidth(230)
        identity.addWidget(self.include_self)
        identity.addWidget(self.own_key, 1)
        identity.addSpacing(12)
        identity.addWidget(self.sign_files)
        identity.addWidget(self.signer_key, 1)
        layout.addLayout(identity)
        self.include_self.toggled.connect(self._update_recipients)
        self.own_key.currentIndexChanged.connect(self._update_recipients)
        self.sign_files.toggled.connect(self._update_recipients)
        self.signer_key.currentIndexChanged.connect(self._update_recipients)
        self.encrypt_output, output_row = self._output_row("Encrypted output", self._settings.get("encrypt_output", str(Path.home() / "Documents" / "CipherDesk" / "Encrypted")))
        layout.addLayout(output_row)
        bottom = QHBoxLayout()
        self.encrypt_hint = label("Choose files and at least one recipient group.", "muted", True)
        bottom.addWidget(self.encrypt_hint, 1)
        self.encrypt_button = button("Encrypt files", self.encrypt, True)
        bottom.addWidget(self.encrypt_button)
        layout.addLayout(bottom)
        self.encrypt_output.textChanged.connect(self._update_actions)
        return page

    def _build_decrypt(self):
        page, layout = self._page("Decrypt received files", "GnuPG will use your local private key. A passphrase prompt may appear in a separate Pinentry window.")
        row = QHBoxLayout()
        row.addWidget(label("Encrypted files", "section"))
        row.addStretch()
        row.addWidget(button("Add files", lambda: self._choose_files(self.decrypt_files, decrypt=True)))
        row.addWidget(button("Remove selected", lambda: self._remove_files(self.decrypt_files)))
        layout.addLayout(row)
        self.decrypt_files = FileList()
        self.decrypt_files.files_dropped.connect(lambda paths: self._add_files(self.decrypt_files, paths))
        layout.addWidget(self.decrypt_files, 1)
        layout.addWidget(label("Decrypted copies contain readable document contents. Save them outside synced SharePoint or OneDrive folders.", "notice", True))
        self.decrypt_output, output_row = self._output_row("Decrypted output", self._settings.get("decrypt_output", str(Path.home() / "Documents" / "CipherDesk" / "Decrypted")))
        layout.addLayout(output_row)
        self.require_signature = QCheckBox("Require a valid signature from a trusted key")
        self.require_signature.setChecked(bool(self._settings.get("require_signature", False)))
        self.require_signature.setToolTip("Reject unsigned files and signatures from untrusted or unknown keys before publishing a decrypted copy.")
        layout.addWidget(self.require_signature)
        bottom = QHBoxLayout()
        self.decrypt_hint = label("Signature status is shown for every file. Originals stay unchanged.", "muted", True)
        bottom.addWidget(self.decrypt_hint, 1)
        self.decrypt_button = button("Decrypt files", self.decrypt, True)
        bottom.addWidget(self.decrypt_button)
        layout.addLayout(bottom)
        self.decrypt_output.textChanged.connect(self._update_actions)
        return page

    def _build_groups(self):
        page, layout = self._page("Contact groups", "Build reusable groups from your Kleopatra public keys. Groups stay on this computer and contain no private keys.")
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        sidebar = QWidget()
        left = QVBoxLayout(sidebar)
        left.setContentsMargins(0, 0, 14, 0)
        left.setSpacing(8)
        left.addWidget(label("Saved groups", "section"))
        self.group_list = QListWidget()
        self.group_list.setAccessibleName("Saved contact groups")
        self.group_list.currentItemChanged.connect(self._edit_selected_group)
        left.addWidget(self.group_list, 1)
        left.addWidget(button("New group", self.new_group))
        self.delete_group_button = button("Delete group", self.delete_group)
        left.addWidget(self.delete_group_button)
        splitter.addWidget(sidebar)
        editor = QWidget()
        form = QVBoxLayout(editor)
        form.setContentsMargins(8, 0, 0, 0)
        form.setSpacing(10)
        form.addWidget(label("Group name", "section"))
        self.group_name = QLineEdit()
        self.group_name.setPlaceholderText("For example, Finance team")
        self.group_name.setMaxLength(80)
        self.group_name.setAccessibleName("Group name")
        form.addWidget(self.group_name)
        self.contact_search = QLineEdit()
        self.contact_search.setPlaceholderText("Find contacts by name, email, or fingerprint")
        self.contact_search.setClearButtonEnabled(True)
        self.contact_search.setAccessibleName("Search available contacts")
        self.contact_search.textChanged.connect(self._filter_contacts)
        form.addWidget(self.contact_search)
        self.contact_tree = QTreeWidget()
        self.contact_tree.setHeaderLabels(["Contact", "Email", "Fingerprint", "Status"])
        self.contact_tree.setRootIsDecorated(False)
        self.contact_tree.setAlternatingRowColors(True)
        self.contact_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.contact_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.contact_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.contact_tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.contact_tree.itemChanged.connect(self._contact_count_changed)
        form.addWidget(self.contact_tree, 1)
        self.contact_count = label("0 contacts selected", "muted", True)
        form.addWidget(self.contact_count)
        self.group_message = label("Create or import keys in Kleopatra, verify their fingerprints, then choose Refresh keys.", "muted", True)
        form.addWidget(self.group_message)
        row = QHBoxLayout()
        row.addStretch()
        self.save_group_button = button("Save group", self.save_group, True)
        row.addWidget(self.save_group_button)
        form.addLayout(row)
        splitter.addWidget(editor)
        splitter.setSizes([235, 760])
        layout.addWidget(splitter, 1)
        return page

    def _output_row(self, title, value):
        row = QHBoxLayout()
        title_label = label(title, "section")
        title_label.setMinimumWidth(120)
        row.addWidget(title_label)
        field = QLineEdit(value)
        field.setAccessibleName(title + " folder")
        title_label.setBuddy(field)
        row.addWidget(field, 1)
        row.addWidget(button("Browse…", lambda: self._browse_output(field)))
        return field, row

    def _browse_output(self, field):
        folder = QFileDialog.getExistingDirectory(self, "Choose output folder", field.text())
        if folder:
            field.setText(folder)

    def _choose_files(self, target, decrypt=False):
        filters = "PGP files (*.gpg *.pgp *.asc);;All files (*)" if decrypt else "All files (*)"
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose encrypted files" if decrypt else "Choose files to encrypt", "", filters)
        self._add_files(target, paths)

    def _add_files(self, target, paths):
        skipped = target.add_paths(paths)
        if skipped:
            self._show_result("Some paths were skipped. Choose regular files, not folders or symbolic links.", error=True)
        self._update_actions()

    def _remove_files(self, target):
        target.remove_selected()
        self._update_actions()

    def _checked_group_names(self):
        return {self.send_groups.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.send_groups.count())
                if self.send_groups.item(i).checkState() == Qt.CheckState.Checked}

    def _reload_groups(self, select_name=None):
        checked = self._checked_group_names()
        self.groups = self.store.list_groups()
        self.send_groups.blockSignals(True)
        self.group_list.blockSignals(True)
        self.send_groups.clear()
        self.group_list.clear()
        selected_row = -1
        for index, group in enumerate(self.groups):
            count = len(group.fingerprints)
            send_item = QListWidgetItem(f"{group.name}\n{count} contact{'s' if count != 1 else ''}")
            send_item.setFlags(send_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            send_item.setData(Qt.ItemDataRole.UserRole, group.name)
            send_item.setCheckState(Qt.CheckState.Checked if group.name in checked else Qt.CheckState.Unchecked)
            self.send_groups.addItem(send_item)
            item = QListWidgetItem(f"{group.name}   ({count})")
            item.setData(Qt.ItemDataRole.UserRole, group.name)
            self.group_list.addItem(item)
            if group.name == select_name:
                selected_row = index
        self.send_groups.blockSignals(False)
        self.group_list.blockSignals(False)
        self.group_hint.setText("Select multiple groups to combine their contacts." if self.groups else "Create a group in Contact groups to get started.")
        self.delete_group_button.setEnabled(bool(self._editing_group) and not self._busy)
        if selected_row >= 0:
            self.group_list.setCurrentRow(selected_row)
        self._update_recipients()

    def _fill_key_choices(self):
        own_selected = self.own_key.currentData() or self._settings.get("own_key", "")
        signer_selected = self.signer_key.currentData() or self._settings.get("signer_key", "")
        self.own_key.blockSignals(True)
        self.signer_key.blockSignals(True)
        self.own_key.clear()
        self.signer_key.clear()
        self.own_key.addItem("Choose your encryption key", "")
        self.signer_key.addItem("Choose a signing key", "")
        for key in self.keys:
            if key.has_secret and key_usable(key) and key.can_decrypt_secret:
                self.own_key.addItem(f"{key_title(key)} · {key.fingerprint[-8:]}", key.fingerprint)
            if key.has_secret and key.can_sign_secret:
                self.signer_key.addItem(f"{key_title(key)} · {key.fingerprint[-8:]}", key.fingerprint)
        own_index = self.own_key.findData(own_selected)
        sign_index = self.signer_key.findData(signer_selected)
        self.own_key.setCurrentIndex(max(0, own_index))
        self.signer_key.setCurrentIndex(max(0, sign_index))
        self.own_key.blockSignals(False)
        self.signer_key.blockSignals(False)
        if own_index > 0:
            self.include_self.setChecked(bool(self._settings.get("include_self", True)))
        if sign_index > 0:
            self.sign_files.setChecked(bool(self._settings.get("sign_files", False)))
        selected = self._selected_contacts()
        self._populate_contacts(selected)

    def _selected_contacts(self):
        return [self.contact_tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)
                for i in range(self.contact_tree.topLevelItemCount())
                if self.contact_tree.topLevelItem(i).checkState(0) == Qt.CheckState.Checked]

    def _populate_contacts(self, selected=()):
        selected = set(selected)
        self.contact_tree.blockSignals(True)
        self.contact_tree.clear()
        for key in self.keys:
            item = QTreeWidgetItem([key_title(key), key.email, key.fingerprint[-16:], key_status(key)])
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Checked if key.fingerprint in selected else Qt.CheckState.Unchecked)
            item.setData(0, Qt.ItemDataRole.UserRole, key.fingerprint)
            item.setToolTip(2, fingerprint_text(key.fingerprint))
            item.setToolTip(3, key_reason(key))
            if not key_usable(key):
                item.setForeground(3, QColor(COLORS["error_detail"]))
            self.contact_tree.addTopLevelItem(item)
        for fingerprint in sorted(selected - self.key_map.keys()):
            item = QTreeWidgetItem(["Missing public key", "", fingerprint[-16:], "Not in keyring"])
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Checked)
            item.setData(0, Qt.ItemDataRole.UserRole, fingerprint)
            item.setToolTip(2, fingerprint_text(fingerprint))
            item.setForeground(3, QColor(COLORS["error_detail"]))
            self.contact_tree.addTopLevelItem(item)
        self.contact_tree.blockSignals(False)
        self._filter_contacts()
        self._contact_count_changed()

    def _filter_contacts(self):
        query = self.contact_search.text().strip().casefold()
        for index in range(self.contact_tree.topLevelItemCount()):
            item = self.contact_tree.topLevelItem(index)
            haystack = " ".join(item.text(c) for c in range(4)) + " " + item.data(0, Qt.ItemDataRole.UserRole)
            item.setHidden(bool(query) and query not in haystack.casefold())

    def _contact_count_changed(self, *_):
        selected = self._selected_contacts()
        unusable = [f for f in selected if f not in self.key_map or not key_usable(self.key_map[f])]
        self.contact_count.setText(f"{len(selected)} contact{'s' if len(selected) != 1 else ''} selected" +
                                   (f" · {len(unusable)} unavailable; this group cannot be used until fixed" if unusable else ""))

    def _edit_selected_group(self, current, previous=None):
        if current is None:
            return
        name = current.data(Qt.ItemDataRole.UserRole)
        group = next((g for g in self.groups if g.name == name), None)
        if group:
            self._editing_group = group.name
            self.group_name.setText(group.name)
            self._populate_contacts(group.fingerprints)
            self.group_message.setText("Select contacts, then save. Refresh keys after making changes in Kleopatra.")
            self.delete_group_button.setEnabled(not self._busy)

    def new_group(self):
        self._editing_group = None
        self.group_list.clearSelection()
        self.group_list.setCurrentRow(-1)
        self.group_name.clear()
        self.contact_search.clear()
        self._populate_contacts()
        self.group_message.setText("Choose a name and select the contacts who should be able to decrypt.")
        self.delete_group_button.setEnabled(False)
        self.group_name.setFocus()

    def save_group(self):
        try:
            name = self.group_name.text().strip()
            self.store.save_group(name, self._selected_contacts(), original_name=self._editing_group)
        except Exception as exc:
            self.group_message.setText(str(exc))
            self.group_message.setObjectName("error")
        else:
            self._editing_group = name
            self._reload_groups(select_name=name)
            self.group_message.setText(f"Saved {name}. Select it in Encrypt files when you are ready to send.")
            self.group_message.setObjectName("success")
        self.group_message.style().unpolish(self.group_message)
        self.group_message.style().polish(self.group_message)

    def delete_group(self):
        if not self._editing_group:
            return
        name = self._editing_group
        answer = QMessageBox.question(self, "Delete contact group", f'Delete the group “{name}”?\n\nKeys and files will remain unchanged.',
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.store.delete_group(name)
        except Exception as exc:
            self._show_result(str(exc), error=True)
            return
        self.new_group()
        self._reload_groups()

    def _update_recipients(self, *_):
        if not hasattr(self, "recipient_tree"):
            return
        checked = self._checked_group_names()
        fingerprints = []
        errors = []
        for group in self.groups:
            if group.name not in checked:
                continue
            for fpr in group.fingerprints:
                if fpr not in fingerprints:
                    fingerprints.append(fpr)
        if hasattr(self, "include_self") and self.include_self.isChecked():
            own = self.own_key.currentData()
            if not own:
                errors.append("Choose your encryption key, or turn off Also encrypt for me.")
            elif own not in fingerprints:
                fingerprints.append(own)
        self.recipient_tree.clear()
        for fpr in fingerprints:
            key = self.key_map.get(fpr)
            if key:
                item = QTreeWidgetItem([key_title(key), key.email, fpr[-16:], key_status(key)])
                item.setToolTip(3, key_reason(key))
                if not key_usable(key):
                    errors.append(f"{key_title(key)}: {key_reason(key)}.")
            else:
                item = QTreeWidgetItem(["Missing public key", "", fpr[-16:], "Import in Kleopatra"])
                errors.append(f"Public key {fpr[-16:]} is missing. Import it in Kleopatra, then refresh keys.")
            item.setToolTip(2, fingerprint_text(fpr))
            if not key or not key_usable(key):
                item.setForeground(3, QColor(COLORS["error_detail"]))
            self.recipient_tree.addTopLevelItem(item)
        if hasattr(self, "sign_files") and self.sign_files.isChecked() and not self.signer_key.currentData():
            errors.append("Choose a signing key, or turn off Sign files.")
        self._effective_recipients = fingerprints
        self._recipient_error = " ".join(errors)
        self.recipient_heading.setText(f"Recipients · {len(fingerprints)} unique contact{'s' if len(fingerprints) != 1 else ''}")
        self._update_actions()

    def _update_actions(self, *_):
        if not hasattr(self, "encrypt_button") or not hasattr(self, "decrypt_button"):
            return
        count = self.encrypt_files.count()
        self.file_count.setText(f"{count} file{'s' if count != 1 else ''} selected" if count else "No files selected")
        if self._recipient_error:
            hint = self._recipient_error
        elif not self.backend:
            hint = "GnuPG is not available. Install Gpg4win, then refresh keys."
        elif not self._checked_group_names():
            hint = "Select at least one recipient group."
        elif not count:
            hint = "Add the files you want to encrypt."
        else:
            hint = f"{count} file{'s' if count != 1 else ''} · {len(self._effective_recipients)} recipients. Original files stay unchanged."
        self.encrypt_hint.setText(hint)
        enabled = bool(self.backend and count and self._checked_group_names() and self._effective_recipients
                       and not self._recipient_error and self.encrypt_output.text().strip() and not self._busy)
        self.encrypt_button.setEnabled(enabled)
        self.decrypt_button.setEnabled(bool(self.backend and self.decrypt_files.count()
                                           and self.decrypt_output.text().strip() and not self._busy))
        self.own_key.setEnabled(not self._busy and self.include_self.isChecked())
        self.signer_key.setEnabled(not self._busy and self.sign_files.isChecked())

    def _set_busy(self, busy, message="Ready"):
        self._busy = busy
        self.tabs.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy)
        self.kleopatra_button.setEnabled(not busy)
        self.progress_bar.setVisible(busy)
        self.statusBar().showMessage(message)
        self._update_actions()

    def _run_worker(self, function, finished, message):
        if self._busy:
            return
        self._set_busy(True, message)
        worker = Worker(function)
        self._worker = worker
        self._completion = finished
        worker.signals.progress.connect(self.statusBar().showMessage)
        worker.signals.finished.connect(self._worker_done)
        worker.signals.failed.connect(self._worker_failed)
        self.pool.start(worker)

    @Slot(object)
    def _worker_done(self, result):
        self._set_busy(False)
        self._worker = None
        self._completion(result)

    @Slot(str)
    def _worker_failed(self, message):
        self._set_busy(False, "Operation failed")
        self._worker = None
        if not self.keys:
            self.key_status.setText("Keyring not available. Check Gpg4win, then choose Refresh keys.")
        self._show_result(message, error=True)

    def refresh_keys(self):
        def work(progress):
            backend = self.backend if self.backend is not None else GPGBackend()
            return backend, backend.list_keys()
        def done(result):
            self.backend, keys = result
            self.set_keys(keys)
        self._run_worker(work, done, "Reading Kleopatra's GnuPG keyring…")

    def set_keys(self, keys):
        self.keys = sorted(keys, key=lambda k: (key_title(k).casefold(), k.fingerprint))
        self.key_map = {k.fingerprint: k for k in self.keys}
        self._fill_key_choices()
        usable = sum(1 for k in self.keys if key_usable(k))
        self.key_status.setText(f"{len(self.keys)} public keys · {usable} usable for encryption · shared GnuPG keyring" if self.keys
                                else "No public keys found. Open Kleopatra to create your key and import contacts, then refresh keys.")
        self._update_recipients()

    def open_kleopatra(self):
        try:
            backend = self.backend if self.backend is not None else GPGBackend()
            backend.open_kleopatra()
        except Exception as exc:
            self._show_result(str(exc), error=True)

    def _save_settings(self):
        self.store.update_settings(encrypt_output=self.encrypt_output.text().strip(),
                                   decrypt_output=self.decrypt_output.text().strip(),
                                   own_key=self.own_key.currentData() or "",
                                   signer_key=self.signer_key.currentData() or "",
                                   include_self=self.include_self.isChecked(),
                                   sign_files=self.sign_files.isChecked(),
                                   require_signature=self.require_signature.isChecked())

    def encrypt(self):
        self._update_recipients()
        if not self.encrypt_button.isEnabled():
            return
        paths = self.encrypt_files.paths()
        output = Path(self.encrypt_output.text().strip()).expanduser()
        recipients = tuple(self._effective_recipients)
        signer = self.signer_key.currentData() if self.sign_files.isChecked() else None
        self_recipient = self.own_key.currentData() if self.include_self.isChecked() else None
        try:
            self._save_settings()
        except Exception as exc:
            self._show_result(str(exc), error=True)
            return
        def work(progress):
            completed, failures = [], []
            for index, path in enumerate(paths, start=1):
                progress(f"Encrypting {index} of {len(paths)}: {path.name}. Complete Pinentry if prompted.")
                try:
                    completed.append(self.backend.encrypt_file(path, output, recipients,
                                                              signer_fingerprint=signer,
                                                              include_self_fingerprint=self_recipient))
                except Exception as exc:
                    failures.append((path.name, str(exc)))
            return BatchResult(completed, failures)
        self._clear_results()
        self._run_worker(work, lambda result: self._batch_done(result, "Encrypted", output), "Encrypting files…")

    def decrypt(self):
        if not self.decrypt_button.isEnabled():
            return
        paths = self.decrypt_files.paths()
        output = Path(self.decrypt_output.text().strip()).expanduser()
        require_signature = self.require_signature.isChecked()
        try:
            self._save_settings()
        except Exception as exc:
            self._show_result(str(exc), error=True)
            return
        def work(progress):
            completed, failures = [], []
            for index, path in enumerate(paths, start=1):
                progress(f"Decrypting {index} of {len(paths)}: {path.name}. Complete Pinentry if prompted.")
                try:
                    completed.append(self.backend.decrypt_file(path, output, require_signature=require_signature))
                except Exception as exc:
                    failures.append((path.name, str(exc)))
            return BatchResult(completed, failures)
        self._clear_results()
        self._run_worker(work, lambda result: self._batch_done(result, "Decrypted", output), "Decrypting files…")

    def _clear_results(self):
        self.result_banner.hide()
        self.results_tree.clear()
        self.results_tree.hide()
        self.open_output_button.hide()

    @staticmethod
    def _signature_text(report):
        signatures = getattr(report, "signatures", ())
        if getattr(report, "unsigned", False) or not signatures:
            return "Unsigned — sender not authenticated"
        result = []
        for signature in signatures:
            if signature.valid:
                status = "Valid signature" if signature.trusted else "Valid signature; identity not trusted"
            else:
                status = getattr(signature, "status", "Signature not verified")
            name = getattr(signature, "name", "") or getattr(signature, "fingerprint", "")[-16:]
            result.append(f"{status}" + (f" · {name}" if name else ""))
        return "; ".join(result)

    def _batch_done(self, result, verb, output):
        for report in result.completed:
            path = Path(report.output_path)
            detail = "Encrypted copy saved"
            if verb == "Decrypted":
                detail = self._signature_text(report)
            elif getattr(report, "signed", False):
                detail = "Signed and encrypted copy saved"
            item = QTreeWidgetItem([path.name, detail])
            item.setToolTip(0, str(path))
            item.setToolTip(1, detail)
            self.results_tree.addTopLevelItem(item)
        for filename, error in result.failures:
            item = QTreeWidgetItem([filename, "Failed: " + error])
            item.setForeground(1, QColor(COLORS["error_detail"]))
            item.setToolTip(1, error)
            self.results_tree.addTopLevelItem(item)
        self.results_tree.setVisible(bool(result.completed or result.failures))
        count = len(result.completed)
        message = f"{verb} {count} file{'s' if count != 1 else ''}."
        if result.failures:
            message += f" {len(result.failures)} failed; see the results below."
        elif verb == "Encrypted":
            message += " Saved locally; SharePoint / OneDrive synchronization is handled separately."
        else:
            message += " Check each file's signature status before relying on the sender's identity."
        self._show_result(message, error=bool(result.failures))
        if count:
            self._last_output = output
            self.open_output_button.show()
        self.statusBar().showMessage("Completed" if not result.failures else "Completed with errors")

    def _show_result(self, message, error=False):
        self.result_banner.setText(message)
        self.result_banner.setObjectName("error" if error else "success")
        self.result_banner.style().unpolish(self.result_banner)
        self.result_banner.style().polish(self.result_banner)
        self.result_banner.show()

    def open_output_folder(self):
        if self._last_output:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._last_output.resolve())))

    def closeEvent(self, event):
        if self._busy:
            self.statusBar().showMessage("Wait for the current operation or dismiss its Pinentry prompt before closing.")
            event.ignore()
        else:
            event.accept()


def application_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(COLORS["header"]))
    painter.drawRoundedRect(1, 1, 62, 62, 12, 12)
    painter.setPen(QPen(QColor(COLORS["text"]), 3))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawRoundedRect(16, 15, 32, 35, 3, 3)
    painter.drawLine(23, 25, 41, 25)
    painter.drawLine(23, 33, 37, 33)
    painter.drawLine(23, 41, 33, 41)
    painter.end()
    return QIcon(pixmap)


def main(argv=None):
    parser = argparse.ArgumentParser(description="CipherDesk — local PGP file sharing with Kleopatra contact keys")
    parser.add_argument("--data-dir", type=Path, help="Override the local groups/settings directory")
    parser.add_argument("--gpg-home", type=Path, help="Use an alternate GnuPG home, e.g. for isolated tests")
    parser.add_argument("--gpg-path", type=Path, help="Path to the GnuPG executable")
    parser.add_argument("--no-key-refresh", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    application = QApplication.instance() or QApplication(sys.argv[:1])
    application.setApplicationName("CipherDesk")
    application.setOrganizationName("CipherDesk")
    apply_theme(application)
    application.setWindowIcon(application_icon())
    try:
        store = GroupStore(data_dir=args.data_dir)
        backend = None
        startup_error = None
        if args.gpg_path or args.gpg_home:
            try:
                backend = GPGBackend(gpg_path=args.gpg_path, homedir=args.gpg_home)
            except Exception as exc:
                startup_error = str(exc)
        window = MainWindow(store=store, backend=backend, auto_refresh=not args.no_key_refresh and not startup_error)
        if startup_error:
            window._show_result(startup_error, error=True)
        window.show()
    except Exception as exc:
        QMessageBox.critical(None, "CipherDesk could not start", str(exc) + "\n\nNo keys or documents were changed.")
        return 1
    return application.exec()
