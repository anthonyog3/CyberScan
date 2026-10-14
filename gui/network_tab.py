from tkinter import ttk

import customtkinter as ctk

from security.network_check import run_network_check
from utils.logger import logger

THREATS = frozenset({"HIGH", "CRITICAL"})


class NetworkTab(ctk.CTkFrame):
    """Open ports and outgoing connections, with the program behind each."""

    def __init__(self, parent, app, on_change=None):
        super().__init__(parent, fg_color="transparent")

        self.app = app
        self.on_change = on_change

        self.items = []
        self.loaded = False
        self.warning_count = 0
        self.threat_count = 0

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.build_header()
        self.build_table()
        self.build_details()

    # ---------- UI ----------

    def build_header(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(
            frame,
            text="NETWORK ACTIVITY",
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left")

        ctk.CTkButton(
            frame, text="Check Again", width=120, command=self.scan
        ).pack(side="right")

        self.summary = ctk.CTkLabel(frame, text="")
        self.summary.pack(side="right", padx=20)

    def build_table(self):
        frame = ctk.CTkFrame(self, corner_radius=12)
        frame.grid(row=1, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            frame,
            columns=("risk", "kind", "process", "local", "remote"),
            show="headings",
            selectmode="browse",
            style="Results.Treeview"
        )

        for column, title, width, stretch in (
            ("risk", "STATUS", 80, False),
            ("kind", "TYPE", 90, False),
            ("process", "PROGRAM", 170, False),
            ("local", "LOCAL ADDRESS", 190, False),
            ("remote", "REMOTE ADDRESS", 260, True),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=70, stretch=stretch)

        self.tree.tag_configure("bad", foreground="#ff6b6b")
        self.tree.tag_configure("good", foreground="#5fd38d")
        self.tree.tag_configure("warn", foreground="#f5c542")

        scrollbar = ctk.CTkScrollbar(frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=8)

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

    def build_details(self):
        self.details = ctk.CTkTextbox(
            self, height=130, corner_radius=8, wrap="word", state="disabled"
        )
        self.details.grid(row=2, column=0, sticky="ew", pady=(10, 0))

    # ---------- Behaviour ----------

    def ensure_loaded(self):
        if not self.loaded:
            self.scan()

    def scan(self):
        if self.app.busy:
            return

        self.loaded = True
        self.summary.configure(text="Checking network activity...")
        self.app.status_text("Checking network activity...")

        self.app.run_in_background(run_network_check, self.finish, self.fail)

    def finish(self, items):
        self.items = items
        self.tree.delete(*self.tree.get_children())
        self.set_details("")

        for index, item in enumerate(items):
            risk = item["risk"]
            tag = "bad" if risk in THREATS else "warn" if risk == "WARNING" else "good"

            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    "OK" if risk == "SAFE" else risk,
                    item["kind"],
                    item["process"],
                    item["local"],
                    item["remote"]
                ),
                tags=(tag,)
            )

        self.threat_count = sum(1 for i in items if i["risk"] in THREATS)
        self.warning_count = sum(1 for i in items if i["risk"] != "SAFE")

        self.summary.configure(
            text=f"{len(items)} connections  |  {self.warning_count} need review"
        )
        self.app.status_text(
            f"Network check complete - {self.warning_count} need review"
        )
        logger.info(
            "Network check: %d connections, %d need review, %d threats",
            len(items), self.warning_count, self.threat_count
        )

        if self.on_change:
            self.on_change()

    def fail(self, exc):
        self.summary.configure(text="Check failed")
        self.app.status_text("Network check failed")
        self.set_details(f"Error: {exc}")
        logger.error("Network check failed: %s", exc)

    def on_select(self, _event=None):
        selection = self.tree.selection()

        if not selection:
            return

        item = self.items[int(selection[0])]
        lines = [
            f"Program: {item['process']} (PID {item['pid']})",
            f"File: {item['path'] or 'Unknown (Windows denied access)'}",
            f"Type: {item['kind']}  |  Reachable from: {item['scope']}",
            f"Local: {item['local']}  |  Remote: {item['remote']}",
        ]

        if item["service"]:
            lines.append(f"Service: {item['service']}")

        if item["sha256"]:
            lines.append(f"SHA-256: {item['sha256']}")

        lines.extend(f"• {reason}" for reason in item["reasons"])

        if not item["reasons"]:
            lines.append("No problems found.")

        self.set_details("\n".join(lines))

    def set_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")