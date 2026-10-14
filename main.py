import sys
import traceback
from tkinter import messagebox

from gui.dashboard import AntivirusApp
from utils.logger import logger


def report_crash(exc_type, exc, tb):
    """Log unexpected errors and tell the user. A --noconsole app has no terminal."""
    if sys.stderr:                       # still print tracebacks while developing
        traceback.print_exception(exc_type, exc, tb)

    logger.critical("Unhandled error", exc_info=(exc_type, exc, tb))

    try:
        messagebox.showerror(
            "CyberScan",
            f"CyberScan hit an unexpected error:\n\n{exc}\n\n"
            "Details were saved to the log file."
        )
    except Exception:
        pass


if __name__ == "__main__":
    sys.excepthook = report_crash

    app = AntivirusApp()
    app.report_callback_exception = report_crash    # errors inside clicks and timers
    app.mainloop()