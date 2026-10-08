import json
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

import customtkinter as ctk

from utils.logger import logger

class HistoryTab(ctk.CTkFrame):
    """Table of past scans, newest first, read from scan_history.json."""

    def __init__(self, parent, history_file, on_change=None):
        super().__init__(parent, fg_color="transparent")

        self.history_file = Path(history_file)
        self.on_change = on_change

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.build_header()
        self.build_table()
        self.refresh()


    # ---------- UI ----------

    def build_header(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(
            frame,
            text="SCAN HISTORY",
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left")

        ctk.CTkButton(
            frame,
            text="Clear History",
            width=120,
            fg_color="#b33a3a",
            hover_color="#8f2d2d",
            command=self.clear
        ).pack(side="right")

        ctk.CTkButton(
            frame, text="Refresh", width=100, command=self.refresh
        ).pack(side="right", padx=(0, 10))

        self.summary = ctk.CTkLabel(frame, text="")
        self.summary.pack(side="right", padx=20)

    def build_table(self):
        # "Results.Treeview" is styled by the dashboard, so we reuse it.
        frame = ctk.CTkFrame(self, corner_radius=12)
        frame.grid(row=1, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            frame,
            columns=("date", "files", "threats", "result"),
            show="headings",
            selectmode="browse",
            style="Results.Treeview"
        )

        for column, title, width, stretch in (
            ("date", "DATE", 220, False),
            ("files", "FILES SCANNED", 150, False),
            ("threats", "THREATS", 110, False),
            ("result", "RESULT", 250, True),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=80, stretch=stretch)

        self.tree.tag_configure("bad", foreground="#ff6b6b")
        self.tree.tag_configure("good", foreground="#5fd38d")

        scrollbar = ctk.CTkScrollbar(frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=8)

    # ---------- Data ----------

    def load(self):
        """Return the saved scans as a list. Never raises: bad data means empty."""
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

        if not isinstance(data, list):
            return []

        return [entry for entry in data if isinstance(entry, dict)]

    @staticmethod
    def pretty_date(iso):
        try:
            return datetime.fromisoformat(iso).strftime("%b %d, %Y  %H:%M")
        except (TypeError, ValueError):
            return "unknown"

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        history = self.load()

        total_files = 0
        total_threats = 0

        for entry in reversed(history):          # newest first
            files = entry.get("files_scanned", 0)
            threats = entry.get("threats", 0)

            total_files += files
            total_threats += threats

            self.tree.insert(
                "",
                "end",
                values=(
                    self.pretty_date(entry.get("date")),
                    f"{files:,}",
                    threats,
                    "Threats found" if threats else "Clean"
                ),
                tags=("bad" if threats else "good",)
            )

        if history:
            self.summary.configure(
                text=f"{len(history)} scans  |  {total_files:,} files  |  "
                     f"{total_threats} threats"
            )
        else:
            self.summary.configure(text="No scans recorded yet")

    def clear(self):
        if not self.load():
            messagebox.showinfo("Scan History", "History is already empty.")
            return

        if not messagebox.askyesno(
            "Clear History",
            "Permanently delete all scan history?\nThis cannot be undone."
        ):
            return

        try:
            self.history_file.write_text("[]", encoding="utf-8")
            logger.warning("Scan history cleared")

        except OSError as exc:
            logger.error("Could not clear history: %s", exc)
            messagebox.showerror("Scan History", str(exc))
            return

        self.refresh()

        if self.on_change:
            self.on_change()
