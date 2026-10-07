from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from core.quarantine import quarantine_file
from utils.logger import logger

THREATS = frozenset({"HIGH", "CRITICAL"})
FEED_LIMIT = 500


class RealTimeWindow(ctk.CTkToplevel):
    """Control panel + live activity feed for Real-Time Protection."""

    def __init__(self, app):
        super().__init__(app)

        self.app = app
        self.title("Real-Time Protection")
        self.geometry("900x620")
        self.minsize(720, 520)
        self.transient(app)

        self.rows = {}        # feed iid -> entry dict
        self._next_id = 0

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.build_header()
        self.build_folders()
        self.build_feed()
        self.build_buttons()

        self.refresh_folders()

        for entry in app.rt_events:       # oldest first; each insert goes on top
            self.add_entry(entry)

        self.after(150, self.focus)

    # ---------- UI ----------

    def build_header(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            frame,
            text="REAL-TIME PROTECTION",
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left")

        self.switch = ctk.CTkSwitch(
            frame, text="Protection enabled", command=self.toggle
        )
        self.switch.pack(side="right")
        self.sync_switch()

    def build_folders(self):
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="PROTECTED FOLDERS",
            font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=15, pady=(12, 6))

        self.folder_tree = ttk.Treeview(
            frame,
            columns=("path",),
            show="headings",
            selectmode="browse",
            height=3,
            style="Results.Treeview"
        )
        self.folder_tree.heading("path", text="FOLDER")
        self.folder_tree.column("path", stretch=True)
        self.folder_tree.grid(
            row=1, column=0, sticky="ew", padx=(15, 10), pady=(0, 12)
        )

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.grid(row=1, column=1, padx=(0, 15), pady=(0, 12), sticky="n")

        ctk.CTkButton(
            buttons, text="Add Folder", width=120, command=self.add_folder
        ).pack(pady=(0, 6))
        ctk.CTkButton(
            buttons, text="Remove", width=120, command=self.remove_folder
        ).pack()

    def build_feed(self):
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 10))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            frame,
            columns=("time", "risk", "name", "path"),
            show="headings",
            selectmode="browse",
            style="Results.Treeview"
        )
        for column, title, width, stretch in (
            ("time", "TIME", 80, False),
            ("risk", "RISK", 110, False),
            ("name", "FILE", 200, False),
            ("path", "LOCATION", 400, True),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=60, stretch=stretch)

        self.tree.tag_configure("bad", foreground="#ff6b6b")
        self.tree.tag_configure("good", foreground="#5fd38d")
        self.tree.tag_configure("warn", foreground="#f5c542")

        scrollbar = ctk.CTkScrollbar(frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 4), pady=4)

    def build_buttons(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))

        ctk.CTkButton(
            frame, text="Quarantine Selected Threat", width=200,
            command=self.quarantine
        ).pack(side="left")

        ctk.CTkButton(
            frame, text="Clear Feed", width=110, command=self.clear_feed
        ).pack(side="right")

    # ---------- Protection switch ----------

    def toggle(self):
        self.app.set_realtime(bool(self.switch.get()))
        self.sync_switch()      # show the real state if starting failed

    def sync_switch(self):
        if self.app.monitor.running:
            self.switch.select()
        else:
            self.switch.deselect()

    # ---------- Folders ----------

    def refresh_folders(self):
        self.folder_tree.delete(*self.folder_tree.get_children())

        for i, folder in enumerate(self.app.settings["protected_folders"] or []):
            self.folder_tree.insert("", "end", iid=str(i), values=(folder,))

    def apply_folders(self, folders):
        self.app.set_folders(folders)
        self.refresh_folders()
        self.sync_switch()

    def add_folder(self):
        folder = filedialog.askdirectory(
            title="Choose a folder to protect", parent=self
        )

        if not folder:
            return

        folder = str(Path(folder))      # turns C:/x into C:\x
        folders = list(self.app.settings["protected_folders"] or [])

        if folder.lower() in (f.lower() for f in folders):
            return

        folders.append(folder)
        self.apply_folders(folders)

    def remove_folder(self):
        selection = self.folder_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Real-Time Protection", "Select a folder first.", parent=self
            )
            return

        folders = list(self.app.settings["protected_folders"])
        folders.pop(int(selection[0]))
        self.apply_folders(folders)

    # ---------- Activity feed ----------

    @staticmethod
    def row_values(entry):
        status = "QUARANTINED" if entry["quarantined"] else entry["risk"]
        return (
            entry["time"],
            status,
            Path(entry["path"]).name,
            entry["path"]
        )

    @staticmethod
    def row_tag(entry):
        if entry["quarantined"]:
            return "warn"
        if entry["risk"] in THREATS or entry["risk"] == "ERROR":
            return "bad"
        if entry["risk"] == "SAFE":
            return "good"
        return ""

    def add_entry(self, entry):
        iid = str(self._next_id)
        self._next_id += 1

        self.tree.insert(
            "", 0, iid=iid,
            values=self.row_values(entry),
            tags=(self.row_tag(entry),)
        )
        self.rows[iid] = entry

        if len(self.rows) > FEED_LIMIT:
            oldest = self.tree.get_children()[-1]
            self.tree.delete(oldest)
            self.rows.pop(oldest, None)

    def clear_feed(self):
        self.app.rt_events.clear()
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()

    def quarantine(self):
        selection = self.tree.selection()

        if not selection:
            messagebox.showinfo(
                "Quarantine", "Select a threat in the feed first.", parent=self
            )
            return

        iid = selection[0]
        entry = self.rows[iid]
        result = entry["result"]

        if result is None or entry["risk"] not in THREATS:
            messagebox.showinfo(
                "Quarantine",
                "Only HIGH or CRITICAL threats can be quarantined.",
                parent=self
            )
            return

        if entry["quarantined"]:
            messagebox.showinfo(
                "Quarantine", "This file is already quarantined.", parent=self
            )
            return

        if not messagebox.askyesno(
            "Quarantine",
            f"Move this file to quarantine?\n\n{result.path}",
            parent=self
        ):
            return

        try:
            qid = quarantine_file(result.path, result.sha256)

        except Exception as exc:
            logger.error("Quarantine failed for %s: %s", result.path, exc)
            messagebox.showerror("Quarantine Error", str(exc), parent=self)
            return

        entry["quarantined"] = True
        self.app.refresh_home()
        self.tree.item(
            iid, values=self.row_values(entry), tags=(self.row_tag(entry),)
        )
        logger.warning("Quarantined %s as %s", result.path, qid)
        messagebox.showinfo(
            "Quarantined", f"File quarantined.\n\nID: {qid}", parent=self
        )