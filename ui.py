"""
ui.py
=====
PySide6 graphical user interface for the Encryptor application.

Architecture:
  - MainWindow          : top-level QMainWindow with tab bar
  - FileTab             : drag-and-drop file encryption/decryption
  - TextTab             : in-memory text encryption/decryption
  - PasswordField       : reusable password input with strength indicator
  - WorkerThread        : off-thread crypto work to keep the UI responsive
"""

import os
from typing import Callable

from PySide6.QtCore import (
    Qt, QThread, Signal, QMimeData, QSize, QTimer
)
from PySide6.QtGui import (
    QColor, QDragEnterEvent, QDropEvent, QFont, QIcon,
    QPainter, QPalette, QPixmap
)
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QSizePolicy, QSplitter,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget, QCheckBox,
    QGraphicsOpacityEffect
)

import crypto_core
import utils


# ── Colour Palette ─────────────────────────────────────────────────────────────
PALETTE = {
    "bg":          "#0d1117",   # Deep dark background
    "surface":     "#161b22",   # Card / widget surface
    "surface2":    "#21262d",   # Slightly lighter surface
    "border":      "#30363d",   # Subtle border
    "accent":      "#58a6ff",   # Primary blue accent
    "accent_dark": "#1f6feb",   # Darker blue for hover
    "success":     "#3fb950",   # Green
    "warning":     "#d29922",   # Amber
    "danger":      "#f85149",   # Red
    "text":        "#e6edf3",   # Primary text
    "text_dim":    "#8b949e",   # Muted text
    "strength": [
        "#f85149",   # 0 – Very Weak
        "#e09b2a",   # 1 – Weak
        "#d2a42d",   # 2 – Fair
        "#3fb950",   # 3 – Strong
        "#58a6ff",   # 4 – Very Strong
    ],
}

BASE_STYLESHEET = f"""
QMainWindow, QDialog {{
    background-color: {PALETTE['bg']};
}}

QWidget {{
    background-color: {PALETTE['bg']};
    color: {PALETTE['text']};
    font-family: 'Segoe UI', 'SF Pro Display', 'Inter', sans-serif;
    font-size: 13px;
}}

QTabWidget::pane {{
    border: 1px solid {PALETTE['border']};
    border-radius: 8px;
    background-color: {PALETTE['surface']};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {PALETTE['surface2']};
    color: {PALETTE['text_dim']};
    padding: 10px 28px;
    border: 1px solid {PALETTE['border']};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 4px;
    font-weight: 500;
    font-size: 13px;
}}

QTabBar::tab:selected {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
    border-bottom: 2px solid {PALETTE['accent']};
}}

QTabBar::tab:hover:!selected {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
}}

QLineEdit, QTextEdit {{
    background-color: {PALETTE['surface2']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 8px 12px;
    selection-background-color: {PALETTE['accent_dark']};
}}

QLineEdit:focus, QTextEdit:focus {{
    border: 1px solid {PALETTE['accent']};
}}

QPushButton {{
    background-color: {PALETTE['surface2']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {PALETTE['surface']};
    border-color: {PALETTE['accent']};
}}

QPushButton:pressed {{
    background-color: {PALETTE['accent_dark']};
    border-color: {PALETTE['accent']};
}}

QPushButton:disabled {{
    color: {PALETTE['text_dim']};
    border-color: {PALETTE['border']};
}}

QPushButton#primary {{
    background-color: {PALETTE['accent_dark']};
    color: white;
    border: none;
}}

QPushButton#primary:hover {{
    background-color: {PALETTE['accent']};
}}

QPushButton#primary:disabled {{
    background-color: {PALETTE['surface2']};
    color: {PALETTE['text_dim']};
}}

QPushButton#danger {{
    background-color: #3d1f1f;
    color: {PALETTE['danger']};
    border: 1px solid {PALETTE['danger']};
}}

QPushButton#danger:hover {{
    background-color: {PALETTE['danger']};
    color: white;
}}

QProgressBar {{
    background-color: {PALETTE['surface2']};
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {PALETTE['accent']};
    border-radius: 4px;
}}

QLabel#sectionTitle {{
    font-size: 11px;
    font-weight: 600;
    color: {PALETTE['text_dim']};
    text-transform: uppercase;
    letter-spacing: 1px;
}}

QLabel#statusLabel {{
    color: {PALETTE['text_dim']};
    font-size: 12px;
}}

QLabel#errorLabel {{
    color: {PALETTE['danger']};
    font-size: 12px;
}}

QLabel#successLabel {{
    color: {PALETTE['success']};
    font-size: 12px;
}}

QCheckBox {{
    color: {PALETTE['text_dim']};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid {PALETTE['border']};
    background: {PALETTE['surface2']};
}}

QCheckBox::indicator:checked {{
    background-color: {PALETTE['accent_dark']};
    border-color: {PALETTE['accent']};
}}

QScrollBar:vertical {{
    background: {PALETTE['surface']};
    width: 8px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical {{
    background: {PALETTE['border']};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
"""


# ── Worker Thread ──────────────────────────────────────────────────────────────

class WorkerThread(QThread):
    """Runs a blocking crypto function on a background thread."""
    progress = Signal(int)
    finished = Signal()
    error = Signal(str)

    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            self._fn(*self._args, progress_callback=self.progress.emit, **self._kwargs)
            self.finished.emit()
        except Exception as exc:
            self.error.emit(str(exc))


# ── Password Field with Strength Indicator ─────────────────────────────────────

class PasswordField(QWidget):
    """
    Composite widget: QLineEdit (password mode) + strength bar + label.
    """
    def __init__(self, placeholder="Enter password…", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Password input row
        row = QHBoxLayout()
        row.setSpacing(6)

        self.line_edit = QLineEdit()
        self.line_edit.setPlaceholderText(placeholder)
        self.line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.line_edit.textChanged.connect(self._update_strength)
        row.addWidget(self.line_edit)

        # Eye toggle button
        self.toggle_btn = QPushButton("👁")
        self.toggle_btn.setFixedSize(36, 36)
        self.toggle_btn.setToolTip("Show / hide password")
        self.toggle_btn.clicked.connect(self._toggle_visibility)
        row.addWidget(self.toggle_btn)

        layout.addLayout(row)

        # Strength bar
        self.bar = QProgressBar()
        self.bar.setRange(0, 4)
        self.bar.setValue(0)
        self.bar.setFixedHeight(6)
        self.bar.setTextVisible(False)
        layout.addWidget(self.bar)

        # Strength label
        self.strength_label = QLabel("No password")
        self.strength_label.setObjectName("statusLabel")
        layout.addWidget(self.strength_label)

    def _toggle_visibility(self):
        if self.line_edit.echoMode() == QLineEdit.EchoMode.Password:
            self.line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("🙈")
        else:
            self.line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("👁")

    def _update_strength(self, text: str):
        score, label = crypto_core.password_strength(text)
        self.bar.setValue(score)
        self.strength_label.setText(label)
        color = PALETTE["strength"][score]
        self.bar.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 4px; }}"
        )

    def text(self) -> str:
        return self.line_edit.text()

    def clear(self):
        self.line_edit.clear()


# ── Drop Zone ──────────────────────────────────────────────────────────────────

class DropZone(QFrame):
    """
    A labelled rectangular area that accepts file drag-and-drop.
    Emits file_dropped(path) when a single file is dropped.
    """
    file_dropped = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(130)
        self._apply_style(hover=False)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.icon_label = QLabel("📂")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setStyleSheet("font-size: 36px; background: transparent;")
        layout.addWidget(self.icon_label)

        self.hint_label = QLabel("Drag & drop a file here\nor click Browse to select")
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint_label.setStyleSheet(
            f"color: {PALETTE['text_dim']}; background: transparent; font-size: 13px;"
        )
        layout.addWidget(self.hint_label)

        self.file_label = QLabel("")
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_label.setWordWrap(True)
        self.file_label.setStyleSheet(
            f"color: {PALETTE['accent']}; background: transparent; font-size: 12px; "
            f"font-weight: 600;"
        )
        layout.addWidget(self.file_label)

    def _apply_style(self, hover: bool):
        border_color = PALETTE["accent"] if hover else PALETTE["border"]
        bg = PALETTE["surface2"] if hover else PALETTE["surface"]
        self.setStyleSheet(
            f"""
            DropZone {{
                border: 2px dashed {border_color};
                border-radius: 10px;
                background-color: {bg};
            }}
            """
        )

    def set_file(self, path: str):
        name = os.path.basename(path)
        size = utils.human_readable_size(os.path.getsize(path))
        self.file_label.setText(f"{name}  ({size})")
        self.hint_label.setText("File selected — ready to encrypt / decrypt")
        self.icon_label.setText("📄")

    def clear(self):
        self.file_label.setText("")
        self.hint_label.setText("Drag & drop a file here\nor click Browse to select")
        self.icon_label.setText("📂")

    # ── drag/drop events ──
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._apply_style(hover=True)

    def dragLeaveEvent(self, event):
        self._apply_style(hover=False)

    def dropEvent(self, event: QDropEvent):
        self._apply_style(hover=False)
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.file_dropped.emit(path)


# ── Status Banner ──────────────────────────────────────────────────────────────

class StatusBanner(QLabel):
    """Temporary coloured banner that auto-hides after a few seconds."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWordWrap(True)
        self.hide()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_message(self, text: str, kind: str = "info", duration_ms: int = 5000):
        colours = {
            "success": (PALETTE["success"], "#1a3a1f"),
            "error":   (PALETTE["danger"],  "#3d1515"),
            "info":    (PALETTE["accent"],  "#192440"),
            "warning": (PALETTE["warning"], "#3a2e10"),
        }
        fg, bg = colours.get(kind, colours["info"])
        self.setStyleSheet(
            f"color: {fg}; background-color: {bg}; border-radius: 6px; "
            f"padding: 10px 14px; font-size: 13px;"
        )
        self.setText(text)
        self.show()
        self._timer.start(duration_ms)


# ── File Tab ───────────────────────────────────────────────────────────────────

class FileTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._file_path: str = ""
        self._worker: WorkerThread | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Drop zone ──
        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self._on_file_dropped)
        root.addWidget(self.drop_zone)

        # ── Browse button ──
        browse_row = QHBoxLayout()
        self.browse_btn = QPushButton("📁  Browse File…")
        self.browse_btn.clicked.connect(self._browse_file)
        self.clear_btn = QPushButton("✕  Clear")
        self.clear_btn.clicked.connect(self._clear_file)
        browse_row.addWidget(self.browse_btn)
        browse_row.addWidget(self.clear_btn)
        browse_row.addStretch()
        root.addLayout(browse_row)

        # ── Password field ──
        pw_title = QLabel("PASSWORD")
        pw_title.setObjectName("sectionTitle")
        root.addWidget(pw_title)
        self.password_field = PasswordField()
        root.addWidget(self.password_field)

        # ── Options ──
        self.compress_check = QCheckBox("Compress before encrypting (recommended for text/code files)")
        self.compress_check.setChecked(True)
        root.addWidget(self.compress_check)

        # ── Action buttons ──
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.encrypt_btn = QPushButton("🔒  Encrypt File")
        self.encrypt_btn.setObjectName("primary")
        self.encrypt_btn.setMinimumHeight(40)
        self.decrypt_btn = QPushButton("🔓  Decrypt File")
        self.decrypt_btn.setMinimumHeight(40)
        self.encrypt_btn.clicked.connect(self._encrypt)
        self.decrypt_btn.clicked.connect(self._decrypt)
        btn_row.addWidget(self.encrypt_btn)
        btn_row.addWidget(self.decrypt_btn)
        root.addLayout(btn_row)

        # ── Progress bar ──
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedHeight(8)
        root.addWidget(self.progress)

        # ── Status banner ──
        self.banner = StatusBanner()
        root.addWidget(self.banner)

        root.addStretch()

    # ── File selection helpers ──

    def _on_file_dropped(self, path: str):
        self._set_file(path)

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a file")
        if path:
            self._set_file(path)

    def _set_file(self, path: str):
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            self.banner.show_message(f"Cannot access file: {exc}", "error")
            return
        if size > crypto_core.MAX_FILE_BYTES:
            self.banner.show_message(
                f"File is too large ({utils.human_readable_size(size)}). "
                f"Maximum allowed is 100 MB.", "error"
            )
            return
        self._file_path = path
        self.drop_zone.set_file(path)

    def _clear_file(self):
        self._file_path = ""
        self.drop_zone.clear()
        self.progress.setValue(0)

    # ── Crypto actions ──

    def _validate_inputs(self) -> bool:
        if not self._file_path:
            self.banner.show_message("Please select a file first.", "warning")
            return False
        if not self.password_field.text():
            self.banner.show_message("Please enter a password.", "warning")
            return False
        return True

    def _encrypt(self):
        if not self._validate_inputs():
            return
        out_path = utils.encrypted_output_path(self._file_path)
        self._run_worker(
            crypto_core.encrypt_file,
            self._file_path,
            out_path,
            self.password_field.text(),
            compress=self.compress_check.isChecked(),
            success_msg=f"✅  Encrypted file saved as:\n{os.path.basename(out_path)}",
        )

    def _decrypt(self):
        if not self._validate_inputs():
            return
        out_path = utils.decrypted_output_path(self._file_path)
        self._run_worker(
            crypto_core.decrypt_file,
            self._file_path,
            out_path,
            self.password_field.text(),
            success_msg=f"✅  Decrypted file saved as:\n{os.path.basename(out_path)}",
        )

    def _run_worker(self, fn, input_path, output_path, password,
                    success_msg, compress=None):
        self._set_busy(True)
        self.progress.setValue(0)

        kwargs = {}
        if compress is not None:
            kwargs["compress"] = compress

        self._worker = WorkerThread(fn, input_path, output_path, password, **kwargs)
        self._worker.progress.connect(self.progress.setValue)
        self._worker.finished.connect(lambda: self._on_done(success_msg))
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_done(self, msg: str):
        self._set_busy(False)
        self.progress.setValue(100)
        self.banner.show_message(msg, "success", duration_ms=8000)

    def _on_error(self, msg: str):
        self._set_busy(False)
        self.progress.setValue(0)
        self.banner.show_message(f"❌  {msg}", "error", duration_ms=10000)

    def _set_busy(self, busy: bool):
        self.encrypt_btn.setEnabled(not busy)
        self.decrypt_btn.setEnabled(not busy)
        self.browse_btn.setEnabled(not busy)


# ── Text Tab ───────────────────────────────────────────────────────────────────

class TextTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        # ── Input pane ──
        input_pane = QWidget()
        in_layout = QVBoxLayout(input_pane)
        in_layout.setContentsMargins(0, 0, 0, 0)
        in_layout.setSpacing(6)

        in_title = QLabel("INPUT TEXT")
        in_title.setObjectName("sectionTitle")
        in_layout.addWidget(in_title)

        self.input_box = QTextEdit()
        self.input_box.setPlaceholderText(
            "Paste your plaintext or encrypted token here…"
        )
        self.input_box.setMinimumHeight(120)
        in_layout.addWidget(self.input_box)

        splitter.addWidget(input_pane)

        # ── Output pane ──
        output_pane = QWidget()
        out_layout = QVBoxLayout(output_pane)
        out_layout.setContentsMargins(0, 0, 0, 0)
        out_layout.setSpacing(6)

        out_title_row = QHBoxLayout()
        out_title = QLabel("OUTPUT TEXT")
        out_title.setObjectName("sectionTitle")
        out_title_row.addWidget(out_title)
        out_title_row.addStretch()
        self.copy_btn = QPushButton("📋  Copy")
        self.copy_btn.setFixedHeight(28)
        self.copy_btn.clicked.connect(self._copy_output)
        out_title_row.addWidget(self.copy_btn)
        out_layout.addLayout(out_title_row)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setPlaceholderText("Result will appear here…")
        self.output_box.setMinimumHeight(120)
        out_layout.addWidget(self.output_box)

        splitter.addWidget(output_pane)
        root.addWidget(splitter, stretch=1)

        # ── Password ──
        pw_title = QLabel("PASSWORD")
        pw_title.setObjectName("sectionTitle")
        root.addWidget(pw_title)
        self.password_field = PasswordField()
        root.addWidget(self.password_field)

        # ── Action buttons ──
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.encrypt_btn = QPushButton("🔒  Encrypt Text")
        self.encrypt_btn.setObjectName("primary")
        self.encrypt_btn.setMinimumHeight(40)
        self.decrypt_btn = QPushButton("🔓  Decrypt Text")
        self.decrypt_btn.setMinimumHeight(40)
        self.clear_btn = QPushButton("✕  Clear All")
        self.encrypt_btn.clicked.connect(self._encrypt)
        self.decrypt_btn.clicked.connect(self._decrypt)
        self.clear_btn.clicked.connect(self._clear_all)
        btn_row.addWidget(self.encrypt_btn)
        btn_row.addWidget(self.decrypt_btn)
        btn_row.addWidget(self.clear_btn)
        root.addLayout(btn_row)

        # ── Status ──
        self.banner = StatusBanner()
        root.addWidget(self.banner)

    def _encrypt(self):
        text = self.input_box.toPlainText()
        password = self.password_field.text()
        if not text.strip():
            self.banner.show_message("Please enter some text to encrypt.", "warning")
            return
        if not password:
            self.banner.show_message("Please enter a password.", "warning")
            return
        try:
            result = crypto_core.encrypt_text(text, password)
            self.output_box.setPlainText(result)
            self.banner.show_message("✅  Text encrypted successfully.", "success")
        except Exception as exc:
            self.banner.show_message(f"❌  {exc}", "error")

    def _decrypt(self):
        text = self.input_box.toPlainText()
        password = self.password_field.text()
        if not text.strip():
            self.banner.show_message("Please enter the encrypted token.", "warning")
            return
        if not password:
            self.banner.show_message("Please enter a password.", "warning")
            return
        try:
            result = crypto_core.decrypt_text(text, password)
            self.output_box.setPlainText(result)
            self.banner.show_message("✅  Text decrypted successfully.", "success")
        except Exception as exc:
            self.banner.show_message(f"❌  {exc}", "error")

    def _copy_output(self):
        text = self.output_box.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.banner.show_message("Copied to clipboard.", "info", duration_ms=3000)

    def _clear_all(self):
        self.input_box.clear()
        self.output_box.clear()
        self.password_field.clear()
        self.banner.hide()


# ── Main Window ────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryptor — Secure File & Text Encryption")
        self.setMinimumSize(600, 640)
        self.resize(680, 720)

        # Load window icon if available
        icon_path = utils.resource_path(os.path.join("assets", "icon.png"))
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setStyleSheet(BASE_STYLESHEET)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # ── Header ──
        header = self._build_header()
        main_layout.addWidget(header)

        # ── Tab widget ──
        self.tabs = QTabWidget()
        self.file_tab = FileTab()
        self.text_tab = TextTab()
        self.tabs.addTab(self.file_tab, "🗂  File Mode")
        self.tabs.addTab(self.text_tab, "📝  Text Mode")
        main_layout.addWidget(self.tabs, stretch=1)

        # ── Footer ──
        footer = QLabel(
            "AES (Fernet) · PBKDF2-SHA256 · 200k iterations · Offline only"
        )
        footer.setObjectName("statusLabel")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(footer)

    def _build_header(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(
            f"background-color: {PALETTE['surface']}; border-radius: 10px;"
        )
        layout = QHBoxLayout(w)
        layout.setContentsMargins(20, 14, 20, 14)

        title = QLabel("🔐  Encryptor")
        title.setStyleSheet(
            f"font-size: 22px; font-weight: 700; color: {PALETTE['text']}; "
            f"background: transparent;"
        )
        subtitle = QLabel("Secure offline encryption for files and text")
        subtitle.setStyleSheet(
            f"font-size: 12px; color: {PALETTE['text_dim']}; background: transparent;"
        )

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        text_col.addWidget(title)
        text_col.addWidget(subtitle)
        layout.addLayout(text_col)
        layout.addStretch()
        return w
