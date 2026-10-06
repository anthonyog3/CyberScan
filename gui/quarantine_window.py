from pathlib import Path
from tkinter import messagebox, ttk

import customtkinter as ctk

from core.quarantine import delete_quarantined, list_quarantined, restore_file
from utils.logger import logger


class QuarantineWindow(ctk.CTkToplevel):
    """Pop-up window to review, restore, or permanently delete quarantined files."""

    def __init__(self, parent):
        super().__init__(parent)

        self.title("Quarantine Manager")
        self.geometry("820x460")
        self.minsize(640, 340)
        self.transient(parent)

        self.items = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.build_header()
        self.build_tree()
        self.build_buttons()

        self.refresh()
        self.after(150, self.focus)  # CTkToplevel can open behind the main window

    # ---------- UI ----------

    def build_header(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            frame,
            text="QUARANTINED FILES",
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left")

        self.count_label = ctk.CTkLabel(frame, text="")
        self.count_label.pack(side="right")

    def build_tree(self):
        # "Results.Treeview" was already styled by the dashboard, so we reuse it.
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 10))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            frame,
            columns=("date", "name", "path"),
            show="headings",
            selectmode="browse",
            style="Results.Treeview"
        )
        self.tree.heading("date", text="QUARANTINED")
        self.tree.heading("name", text="NAME")
        self.tree.heading("path", text="ORIGINAL LOCATION")
        self.tree.column("date", width=150, minwidth=120, stretch=False)
        self.tree.column("name", width=200, minwidth=100, stretch=False)
        self.tree.column("path", width=380, minwidth=150, stretch=True)

        scrollbar = ctk.CTkScrollbar(frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 4), pady=4)

    def build_buttons(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))

        ctk.CTkButton(
            frame, text="Restore", width=130, command=self.restore
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            frame,
            text="Delete Permanently",
            width=160,
            fg_color="#b33a3a",
            hover_color="#8f2d2d",
            command=self.delete
        ).pack(side="left")

        ctk.CTkButton(
            frame, text="Refresh", width=100, command=self.refresh
        ).pack(side="right")

    # ---------- Data ----------

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        self.items = list_quarantined()

        # Newest first. Old entries without a date sort to the bottom.
        ordered = sorted(
            self.items.items(),
            key=lambda pair: pair[1].get("quarantined_at", ""),
            reverse=True
        )

        for qid, item in ordered:
            original = item.get("original_path", "")
            name = item.get("name") or Path(original).name

            self.tree.insert(
                "",
                "end",
                iid=qid,
                values=(item.get("quarantined_at", "unknown"), name, original)
            )

        self.count_label.configure(text=f"{len(self.items)} file(s)")

    def selected(self):
        selection = self.tree.selection()
        if selection:
            return selection[0]

        messagebox.showinfo(
            "Quarantine Manager", "Select a file first.", parent=self
        )
        return None

    # ---------- Actions ----------

    def restore(self):
        qid = self.selected()
        if qid is None:
            return

        original = self.items[qid].get("original_path", "")

        if not messagebox.askyesno(
            "Restore",
            f"Restore this file to its original location?\n\n{original}\n\n"
            "Only do this if you are sure the file is safe.",
            parent=self
        ):
            return

        try:
            try:
                restored = restore_file(qid)
            except FileExistsError:
                if not messagebox.askyesno(
                    "File exists",
                    "A file already exists at that location.\nOverwrite it?",
                    parent=self
                ):
                    return
                restored = restore_file(qid, overwrite=True)

            logger.warning("Restored %s from quarantine (%s)", restored, qid)
            messagebox.showinfo(
                "Restored", f"File restored to:\n{restored}", parent=self
            )

        except Exception as exc:
            logger.error("Restore failed for %s: %s", qid, exc)
            messagebox.showerror("Restore Error", str(exc), parent=self)

        self.refresh()

    def delete(self):
        qid = self.selected()
        if qid is None:
            return

        if not messagebox.askyesno(
            "Delete Permanently",
            "Permanently delete this file?\nThis cannot be undone.",
            icon="warning",
            parent=self
        ):
            return

        try:
            delete_quarantined(qid)
            logger.warning("Permanently deleted quarantined item %s", qid)

        except Exception as exc:
            logger.error("Delete failed for %s: %s", qid, exc)
            messagebox.showerror("Delete Error", str(exc), parent=self)

        self.refresh()