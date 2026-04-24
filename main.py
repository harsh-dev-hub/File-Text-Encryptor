"""
main.py
=======
Entry point for the Encryptor desktop application.

Usage:
  python main.py               # Launch the GUI
  python main.py --version     # Print version and exit
"""

import sys
import os

__version__ = "1.0.0"
__app_name__ = "Encryptor"


def main():
    # ── Optional CLI flags before importing Qt (faster --version check) ──────
    if "--version" in sys.argv or "-v" in sys.argv:
        print(f"{__app_name__} v{__version__}")
        sys.exit(0)

    # ── PySide6 high-DPI setup (must happen before QApplication) ─────────────
    # Qt 6 enables high-DPI scaling by default, but we set the attribute
    # explicitly so the behaviour is clear and portable.
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont

    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("Encryptor Project")

    # Use a clean sans-serif base font
    font = QFont("Segoe UI", 10)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)

    # Import here so Qt is already initialised
    from ui import MainWindow

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
