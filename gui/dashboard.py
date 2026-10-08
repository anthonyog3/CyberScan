import json
import os
import queue
import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from core.scanner import scan_path
from core.quarantine import quarantine_file, list_quarantined
from gui.quarantine_window import QuarantineWindow
from core.monitor import RealTimeMonitor
from core.settings import load_settings, save_settings
from gui.realtime_window import RealTimeWindow
from gui.history_tab import HistoryTab
from security.system_audit import run_security_audit
from utils.logger import logger


HISTORY = Path("database/scan_history.json")
HISTORY_LIMIT = 50

THREATS = frozenset({"HIGH", "CRITICAL"})
SAFE_RISKS = frozenset({"SAFE", "Secure"})
NO_BADGE = frozenset({"INFO", ""})
BAD_TAGS = THREATS | {"ERROR"}

POLL_MS = 100        # how often the UI thread checks the worker
INSERT_BATCH = 500   # tree rows inserted per UI tick
RT_POLL_MS = 500     # how often the UI drains real-time events
RT_FEED_LIMIT = 500  # activity entries kept in memory
STALE_DAYS = 7       # warn when the last scan is older than this

ICONS = {"good": "✓", "warn": "●", "bad": "⚠"}
TEXT_COLORS = {"good": "#5fd38d", "warn": "#f5c542", "bad": "#ff6b6b"}
BANNER_COLORS = {"good": "#1e5a3a", "warn": "#6b5a1a", "bad": "#7a2a2a"}


def normalize(path):
    """Normalize a path so dialog output and scanner output compare equal."""
    return os.path.normcase(os.path.normpath(str(path)))


class AntivirusApp(ctk.CTk):
    def __init__(self):
        # Theme must be set before the window is created to avoid a re-style flash.
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        super().__init__()

        self.title("CyberScan")
        self.geometry("1100x840")          # CHANGE (was 1100x780)
        self.minsize(900, 760)             # CHANGE (was 900, 700)

        self.results = []
        self.threats = {}          # normalized path -> result (HIGH / CRITICAL only)
        self.buttons = []
        self.busy = False

        self._quarantine_window = None

        self._events = queue.Queue()   # worker -> UI thread
        self._progress = None          # latest (index, total) from the worker
        self._shown_progress = None
        self._render_job = None

        self._row_data = {}            # tree iid -> ScanResult or details string
        self._row_count = 0
        self.settings = load_settings()
        self.monitor = RealTimeMonitor(
            exclude=("quarantine", "logs", "database")
        )
        self.rt_events = []        # activity feed, oldest first
        self.rt_scanned = 0
        self.rt_threats = 0
        self._rt_window = None

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.last_scan = self.load_last_scan()
        self.build_ui()
        self.init_realtime()               # ADD (right after build_ui)

        self.last_scan = self.load_last_scan()     # ADD (above self.build_ui())

    # ---------- UI ----------

    def build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.build_header()
        self.build_status()
        self.build_tabs()

    def build_header(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", padx=30, pady=(25, 5))

        self.label(frame, "CyberScan", 30).pack(side="left")

        ctk.CTkLabel(
            frame,
            text="Windows Security Center",
            font=ctk.CTkFont(size=13)
        ).pack(side="left", padx=15, pady=(8, 0))

    def build_status(self):
        frame = ctk.CTkFrame(self, corner_radius=12)
        frame.grid(row=1, column=0, sticky="ew", padx=30, pady=10)

        self.status_label = self.label(frame, "●  System ready", 14)
        self.status_label.pack(side="left", padx=20, pady=14)
        self.rt_label = self.label(frame, "", 12)
        self.rt_label.pack(side="right", padx=20)

    def build_stats(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))

        for i in range(3):
            frame.grid_columnconfigure(i, weight=1)

        self.files_stat = self.stat_card(frame, "FILES SCANNED", "0", 0)
        self.threats_stat = self.stat_card(frame, "THREATS FOUND", "0", 1)
        self.score_stat = self.stat_card(frame, "SECURITY SCORE", "--", 2)

    def stat_card(self, parent, title, value, column):
        card = ctk.CTkFrame(parent, corner_radius=12)
        card.grid(row=0, column=column, sticky="ew", padx=5)

        self.label(card, title, 11).pack(pady=(12, 2))

        label = self.label(card, value, 24)
        label.pack(pady=(0, 12))

        return label

    def build_main(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=1, column=-0, sticky="nsew", pady=(10, 0))

        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        self.build_controls(frame)
        self.build_results(frame)

    def build_tabs(self):
        self.tabs = ctk.CTkTabview(
            self, corner_radius=12, command=self.on_tab_change
        )
        self.tabs.grid(row=2, column=0, sticky="nsew", padx=30, pady=(5, 25))

        home = self.tabs.add("Home")
        scanner = self.tabs.add("Scanner")
        history = self.tabs.add("History")

        for tab in (home, scanner, history):
            tab.grid_columnconfigure(0, weight=1)

        scanner.grid_rowconfigure(1, weight=1)
        history.grid_rowconfigure(0, weight=1)

        self.build_home(home)
        self.build_stats(scanner)
        self.build_main(scanner)

        self.history_tab = HistoryTab(
            history, HISTORY, on_change=self.on_history_cleared
        )
        self.history_tab.grid(row=0, column=0, sticky="nsew")

        # Show the saved audit score in the Scanner tab's card too.
        audit = self.settings.get("last_audit")

        if audit:
            self.score_stat.configure(text=f"{audit.get('score', 0)}/100")

    def on_tab_change(self):
        tab = self.tabs.get()

        if tab == "Home":
            self.refresh_home()
        elif tab == "History":
            self.history_tab.refresh()


    def build_home(self, parent):
        parent.grid_rowconfigure(2, weight=1)

        # Banner: the one-glance verdict.
        self.banner = ctk.CTkFrame(parent, corner_radius=12)
        self.banner.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        self.banner_title = self.label(self.banner, "", 22)
        self.banner_title.pack(anchor="w", padx=25, pady=(16, 2))

        self.banner_sub = ctk.CTkLabel(self.banner, text="")
        self.banner_sub.pack(anchor="w", padx=25, pady=(0, 16))

        # Four status cards.
        cards = ctk.CTkFrame(parent, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=5)

        for i in range(4):
            cards.grid_columnconfigure(i, weight=1, uniform="cards")

        _, self.home_score, self.home_score_note = self.home_card(
            cards, "SECURITY SCORE", 0
        )
        rt_card, self.home_rt, self.home_rt_note = self.home_card(
            cards, "REAL-TIME PROTECTION", 1
        )
        _, self.home_scan, self.home_scan_note = self.home_card(
            cards, "LAST SCAN", 2
        )
        _, self.home_quar, self.home_quar_note = self.home_card(
            cards, "QUARANTINE", 3
        )

        self.home_switch = ctk.CTkSwitch(
            rt_card, text="Enabled", command=self.toggle_realtime_home
        )
        self.home_switch.pack(pady=(0, 12))

        # Recommendations + quick actions.
        bottom = ctk.CTkFrame(parent, fg_color="transparent")
        bottom.grid(row=2, column=0, sticky="nsew", pady=(5, 0))
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_rowconfigure(0, weight=1)

        recs = ctk.CTkFrame(bottom, corner_radius=12)
        recs.grid(row=0, column=0, sticky="nsew", padx=5)

        self.label(recs, "RECOMMENDATIONS", 13).pack(
            anchor="w", padx=20, pady=(16, 8)
        )
        self.rec_frame = ctk.CTkFrame(recs, fg_color="transparent")
        self.rec_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        actions = ctk.CTkFrame(bottom, corner_radius=12)
        actions.grid(row=0, column=1, sticky="ns", padx=5)

        self.label(actions, "QUICK ACTIONS", 13).pack(padx=20, pady=(16, 8))

        for text, command in (
            ("Quick Scan", self.quick_scan),
            ("Security Audit", self.security_audit),
            ("Real-Time Protection", self.open_realtime),
            ("Quarantine Manager", self.open_quarantine_manager),
        ):
            self.add_button(actions, text, command)

    def home_card(self, parent, title, column):
        card = ctk.CTkFrame(parent, corner_radius=12)
        card.grid(row=0, column=column, sticky="nsew", padx=5)

        self.label(card, title, 11).pack(pady=(12, 2))

        value = self.label(card, "--", 22)
        value.pack()

        note = ctk.CTkLabel(card, text="", wraplength=190)
        note.pack(pady=(2, 12), padx=10)

        return card, value, note


    def build_controls(self, parent):
        frame = ctk.CTkFrame(parent, corner_radius=12)
        frame.grid(row=0, column=0, sticky="ns")

        self.label(frame, "PROTECTION", 13).pack(padx=20, pady=(20, 15))

        for text, command in (
            ("Quick Scan", self.quick_scan),
            ("Custom Scan", self.custom_scan),
            ("Security Audit", self.security_audit),
            ("Real-Time Protection", self.open_realtime),
        ):
            self.add_button(frame, text, command)

        self.label(frame, "ACTIONS", 11).pack(padx=20, pady=(25, 10))

        self.add_button(frame, "Quarantine Selected", self.quarantine_selected)
        self.add_button(frame, "Quarantine Manager", self.open_quarantine_manager)

        self.progress = ctk.CTkProgressBar(frame)
        self.progress.pack(fill="x", padx=20, pady=(25, 5))
        self.progress.set(0)

    @staticmethod
    def label(parent, text, size):
        return ctk.CTkLabel(
            parent,
            text=text,
            font=ctk.CTkFont(size=size, weight="bold")
        )

    def add_button(self, parent, text, command):
        button = ctk.CTkButton(
            parent,
            text=text,
            width=190,
            height=40,
            command=command
        )
        button.pack(padx=20, pady=5)
        self.buttons.append(button)

    def build_results(self, parent):
        frame = ctk.CTkFrame(parent, corner_radius=12)
        frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=15)

        self.label(header, "SCAN RESULTS", 15).pack(side="left")

        self.results_status = ctk.CTkLabel(header, text="Ready")
        self.results_status.pack(side="right")

        # Row 1: either the results tree or the "System ready" placeholder.
        self.build_tree(frame)
        self.build_empty_state(frame)

        # Row 2: full details of the selected row.
        self.details_box = ctk.CTkTextbox(
            frame,
            height=130,
            corner_radius=8,
            wrap="word",
            state="disabled"
        )
        self.details_box.grid(
            row=2,
            column=0,
            sticky="ew",
            padx=15,
            pady=(0, 15)
        )

        self.empty_results()

    def build_tree(self, parent):
        """A Treeview only draws visible rows, so it stays fast with 100k+ results
        (the old one-widget-per-result list froze and crashed on large scans)."""
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Results.Treeview",
            background="#2b2b2b",
            fieldbackground="#2b2b2b",
            foreground="#e6e6e6",
            rowheight=30,
            borderwidth=0
        )
        style.map(
            "Results.Treeview",
            background=[("selected", "#1f6aa5")],
            foreground=[("selected", "#ffffff")]
        )
        style.configure(
            "Results.Treeview.Heading",
            background="#333333",
            foreground="#e6e6e6",
            relief="flat",
            font=("Segoe UI", 10, "bold")
        )
        style.map(
            "Results.Treeview.Heading",
            background=[("active", "#3d3d3d")]
        )

        self.tree_frame = ctk.CTkFrame(parent, corner_radius=8)
        self.tree_frame.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=15,
            pady=(0, 10)
        )
        self.tree_frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=("risk", "name", "summary"),
            show="headings",
            selectmode="browse",
            style="Results.Treeview"
        )
        self.tree.heading("risk", text="RISK")
        self.tree.heading("name", text="NAME")
        self.tree.heading("summary", text="DETAILS")
        self.tree.column("risk", width=90, minwidth=70, stretch=False)
        self.tree.column("name", width=240, minwidth=120, stretch=False)
        self.tree.column("summary", width=400, minwidth=150, stretch=True)

        self.tree.tag_configure("bad", foreground="#ff6b6b")
        self.tree.tag_configure("good", foreground="#5fd38d")
        self.tree.tag_configure("warn", foreground="#f5c542")

        scrollbar = ctk.CTkScrollbar(
            self.tree_frame,
            command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 4), pady=4)

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

    def build_empty_state(self, parent):
        self.empty_frame = ctk.CTkFrame(parent, corner_radius=8)
        self.empty_frame.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=15,
            pady=(0, 10)
        )

        ctk.CTkLabel(
            self.empty_frame,
            text="✓",
            font=ctk.CTkFont(size=42, weight="bold")
        ).pack(pady=(70, 5))

        self.label(self.empty_frame, "System ready", 18).pack()

        ctk.CTkLabel(
            self.empty_frame,
            text="Choose a scan from the left to begin."
        ).pack(pady=5)

    # ---------- Helpers ----------

    def _show_empty(self, empty):
        if empty:
            self.tree_frame.grid_remove()
            self.empty_frame.grid()
        else:
            self.empty_frame.grid_remove()
            self.tree_frame.grid()

    def clear_results(self):
        self._cancel_render()

        self.tree.delete(*self.tree.get_children())
        self._row_data.clear()
        self._row_count = 0

        self.set_details("")
        self._show_empty(False)

    def empty_results(self):
        self.clear_results()
        self._show_empty(True)

    def show(self, text=""):
        self.clear_results()

        if text:
            self.result_card("INFO", text)

    def add(self, text):
        self.result_card("INFO", text)

    def status_text(self, text):
        self.status_label.configure(text=f"●  {text}")

    def set_buttons(self, enabled):
        state = "normal" if enabled else "disabled"

        for button in self.buttons:
            button.configure(state=state)

    def set_details(self, text):
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert("1.0", text)
        self.details_box.configure(state="disabled")

    @staticmethod
    def risk_tag(risk):
        if risk in BAD_TAGS:
            return "bad"
        if risk in SAFE_RISKS:
            return "good"
        if risk == "WARNING":
            return "warn"
        return ""

    def add_row(self, risk, title, summary, data):
        """Insert one row. `data` is a ScanResult or a details string, shown on select."""
        if risk in THREATS:
            icon = "⚠"
        elif risk in SAFE_RISKS:
            icon = "✓"
        else:
            icon = "●"

        badge = "" if risk in NO_BADGE else risk
        iid = str(self._row_count)
        self._row_count += 1

        self.tree.insert(
            "",
            "end",
            iid=iid,
            values=(badge, f"{icon}  {title}", summary),
            tags=(self.risk_tag(risk),)
        )
        self._row_data[iid] = data

    def result_card(self, risk, title, details=""):
        """Add an info / audit / error row (details shown when selected)."""
        summary = details.split("\n", 1)[0] if details else ""
        self.add_row(risk, title, summary, details or title)

    def on_select(self, _event=None):
        selection = self.tree.selection()

        if not selection:
            return

        data = self._row_data.get(selection[0])

        if data is None:
            return

        self.set_details(
            data if isinstance(data, str) else self.result_details(data)
        )

    # ---------- Background work ----------
    #
    # Worker threads never touch Tk. They only put results on a queue (or
    # overwrite a "latest progress" value); the UI thread polls both.

    def run_in_background(self, func, on_done, on_error):
        self.busy = True
        self.set_buttons(False)

        def worker():
            try:
                self._events.put((on_done, func()))
            except Exception as exc:
                self._events.put((on_error, exc))

        threading.Thread(target=worker, daemon=True).start()
        self.after(POLL_MS, self._poll)

    def _poll(self):
        try:
            handler, payload = self._events.get_nowait()
        except queue.Empty:
            self._show_progress()
            self.after(POLL_MS, self._poll)
            return

        self.busy = False
        self.set_buttons(True)
        handler(payload)

    def progress_callback(self, index, total, path, result):
        # Runs on the worker thread: just record the latest value.
        if index != "done":
            self._progress = (index, total)

    def _show_progress(self):
        current = self._progress

        if current is None or current == self._shown_progress:
            return

        self._shown_progress = current
        index, total = current

        self.progress.set(index / total if total else 0)
        self.status_text(f"Scanning {index}/{total}")

    # ---------- Scanning ----------

    def quick_scan(self):
        home = Path.home()
        targets = [
            p for p in (home / "Downloads", home / "Desktop") if p.exists()
        ]

        if not targets:
            messagebox.showwarning(
                "Quick Scan",
                "No Desktop or Downloads folder was found."
            )
            return

        self.start_scan(targets)

    def custom_scan(self):
        target = filedialog.askdirectory(title="Choose a folder to scan")

        if target:
            self.start_scan([Path(target)])

    def start_scan(self, targets):
        if self.busy:
            return

        self.tabs.set("Scanner")

        self.results = []
        self._progress = None
        self._shown_progress = None

        self.progress.set(0)
        self.clear_results()
        self.results_status.configure(text="Scanning...")
        self.status_text("Scanning...")

        def scan():
            results = []

            for target in targets:
                results.extend(
                    scan_path(str(target), callback=self.progress_callback)
                )

            return results

        self.run_in_background(scan, self.finish_scan, self.scan_error)

    def finish_scan(self, results):
        self.results = results
        self.threats = {
            normalize(r.path): r for r in results if r.risk in THREATS
        }
        threat_count = len(self.threats)

        self.files_stat.configure(text=str(len(results)))
        self.threats_stat.configure(text=str(threat_count))
        self.results_status.configure(text=f"{threat_count} threats")

        self.progress.set(1)
        self.status_text(
            f"{threat_count} threat(s) detected"
            if threat_count
            else "Scan complete - system looks safe"
        )

        if not results:
            self.empty_results()
            self.refresh_home()
            return

        self.save_history(len(results), threat_count)
        self.refresh_home()
        self.render_results(results)

        logger.info(
            "Scan complete: %d files, %d threats",
            len(results),
            threat_count
        )

    def scan_error(self, exc):
        self.progress.set(0)

        self.status_text("Scan failed")
        self.results_status.configure(text="Error")

        self.clear_results()
        self.result_card("ERROR", "Scan error", str(exc))

        logger.error("Scan failed: %s", exc)

    # ---------- Result rendering (batched) ----------

    @staticmethod
    def result_details(result):
        details = [f"Path: {result.path}"]

        if result.sha256:
            details.append(f"SHA-256: {result.sha256}")

        details.extend(f"• {reason}" for reason in result.reasons)

        if result.error:
            details.append(f"Error: {result.error}")

        return "\n".join(details)

    def render_results(self, results):
        """Insert rows in batches so the window never stalls on huge scans."""
        self.clear_results()
        self._insert_batch(results, 0)

    def _insert_batch(self, results, start):
        end = min(start + INSERT_BATCH, len(results))

        for result in results[start:end]:
            self.add_row(
                result.risk or "SAFE",
                Path(result.path).name,
                str(result.path),
                result
            )

        self._render_job = (
            self.after(1, self._insert_batch, results, end)
            if end < len(results)
            else None
        )

    def _cancel_render(self):
        if self._render_job is not None:
            self.after_cancel(self._render_job)
            self._render_job = None

    # ---------- History ----------

    def save_history(self, scanned, threats):
        entry = {
            "date": datetime.now().isoformat(timespec="seconds"),
            "files_scanned": scanned,
            "threats": threats
            
        }
        self.last_scan = entry

        try:
            history = (
                json.loads(HISTORY.read_text(encoding="utf-8"))
                if HISTORY .exists()
                else[]
            )


            history.append(entry)

            HISTORY.parent.mkdir(parents=True, exist_ok=True)
            HISTORY.write_text(
                json.dumps(history[-HISTORY_LIMIT:], indent=2),
                encoding="utf-8"
            )

        except Exception as exc:
            logger.error("Could not save history: %s", exc)
    @staticmethod
    def load_last_scan():
        try:
            history = json.loads(HISTORY.read_text(encoding="utf-8"))
            return history[-1] if history else None
        except (OSError, json.JSONDecodeError):
            return None

    def on_history_cleared(self):
        self.last_scan = self.load_last_scan()   #None once the file is empty
        self.refresh_home()

    # ---------- Quarantine ----------

    def selected_threat(self):
        """The threat currently selected in the results list, if any."""
        for iid in self.tree.selection():
            data = self._row_data.get(iid)

            if data is not None and not isinstance(data, str):
                return self.threats.get(normalize(data.path))

        return None

    def quarantine_selected(self):
        if not self.threats:
            messagebox.showinfo("Quarantine", "No HIGH or CRITICAL results.")
            return

        result = self.selected_threat()

        if result is None:
            if len(self.threats) == 1:
                result = next(iter(self.threats.values()))
            else:
                path = filedialog.askopenfilename(
                    title="Select threat to quarantine"
                )

                if not path:
                    return

                result = self.threats.get(normalize(path))

                if not result:
                    messagebox.showerror(
                        "Quarantine",
                        "Threat could not be found."
                    )
                    return

        if not messagebox.askyesno(
            "Quarantine",
            f"Move this file to quarantine?\n\n{result.path}"
        ):
            return

        try:
            qid = quarantine_file(result.path, result.sha256)

            self.threats.pop(normalize(result.path), None)
            self.threats_stat.configure(text=str(len(self.threats)))
            self.refresh_home()

            messagebox.showinfo("Quarantined", f"File quarantined. \n\nID: {qid}")
            logger.warning("Quarantined %s as %s", result.path, qid)

        except Exception as exc:
            messagebox.showerror("Quarantine Error", str(exc))

    def open_quarantine_manager(self):
        window = self._quarantine_window

        # Reuse the open window instead of stacking duplicates.
        if window is not None and window.winfo_exists():
            window.focus()
            return

        self._quarantine_window = QuarantineWindow(self, on_change=self.refresh_home)        

    # ---------- Security Audit ----------

    def security_audit(self):
        if self.busy:
            return

        self.tabs.set("Scanner")

        self.status_text("Running security audit...")
        self.results_status.configure(text="Auditing...")
        self.clear_results()

        self.run_in_background(
            run_security_audit,
            self.finish_audit,
            self.audit_error
        )

    def finish_audit(self, audit):
        score = audit["score"]
        checks = audit["checks"]

        level = (
            "EXCELLENT" if score >= 90
            else "GOOD" if score >= 75
            else "WARNING" if score >= 50
            else "CRITICAL"
        )

        self.score_stat.configure(text=f"{score}/100")
        self.files_stat.configure(text=str(len(checks)))
        self.threats_stat.configure(text="0")

        self.result_card(
            "INFO"
            f"Security Score: {score}/100",
            f"Overall security status: {level}"
        )

        for check in checks:
            self.result_card(
                check.get("status", "Unknown"),
                check.get("name", "Unknown Check"),
                f"Score: {check.get('score', 0)}/20\n{check.get('details', '')}"
            )

        self.status_text(f"Security audit complete - {score}/100")
        logger.info("Security audit complete: %d/100", score)

        self.settings["last_audit"] = {
            "score": score,
            "level": level,
            "date": datetime.now() .isoformat(timespec="seconds")
        }
        save_settings(self.settings)
        self.refresh_home()

    def audit_error(self, exc):
        self.status_text("Security audit failed")
        self.results_status.configure(text="Error")

        self.result_card("ERROR", "Security audit error", str(exc))
        logger.error("Security audit failed: %s", exc)

    # ---------- Real-Time Protection ----------

    def init_realtime(self):
        if self.settings["protected_folders"] is None:
            downloads = Path.home() / "Downloads"
            self.settings["protected_folders"] = (
                [str(downloads)] if downloads.is_dir() else []
            )
            save_settings(self.settings)

        if self.settings["realtime_enabled"]:
            self.set_realtime(True, quiet=True)

        self.update_rt_status()
        self.refresh_home()
        self.after(RT_POLL_MS, self._poll_realtime)

    def set_realtime(self, enabled, quiet=False):
        try:
            if enabled:
                self.monitor.start(self.settings["protected_folders"])
            else:
                self.monitor.stop()

        except Exception as exc:
            logger.error("Real-time protection error: %s", exc)

            if not quiet:
                messagebox.showerror("Real-Time Protection", str(exc))

        self.settings["realtime_enabled"] = self.monitor.running

        if not quiet:
            save_settings(self.settings)

        self.update_rt_status()
        self.refresh_home()
        logger.info(
            "Real-time protection %s",
            "enabled" if self.monitor.running else "disabled"
        )

    def set_folders(self, folders):
        self.settings["protected_folders"] = folders
        save_settings(self.settings)

        if self.monitor.running:        # restart so the new list takes effect
            self.set_realtime(False)

            if folders:
                self.set_realtime(True)

    def update_rt_status(self):
        if self.monitor.running:
            text = (
                f"●  Real-time protection ON  "
                f"({self.rt_scanned} scanned, {self.rt_threats} threats)"
            )
            color = "#ff6b6b" if self.rt_threats else "#5fd38d"
        else:
            text, color = "●  Real-time protection OFF", "#f5c542"

        self.rt_label.configure(text=text, text_color=color)
        self.update_home_rt()

    def _poll_realtime(self):
        handled = False

        for _ in range(100):            # cap per tick so the UI never stalls
            try:
                event = self.monitor.events.get_nowait()
            except queue.Empty:
                break

            self.handle_rt_event(event)
            handled = True

        if handled:
            self.update_rt_status()

        self.after(RT_POLL_MS, self._poll_realtime)

    def handle_rt_event(self, event):
        result = event.result

        if event.kind == "error":
            risk, details = "ERROR", event.error
        else:
            risk = result.risk or "SAFE"
            details = self.result_details(result)

        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "risk": risk,
            "path": event.path,
            "result": result,
            "details": details,
            "quarantined": False,
        }

        self.rt_scanned += 1
        self.rt_events.append(entry)

        if len(self.rt_events) > RT_FEED_LIMIT:
            self.rt_events.pop(0)

        if risk in THREATS:
            self.rt_threats += 1
            self.status_text(f"Real-time: threat detected - {Path(event.path).name}")
            logger.warning("Real-time threat (%s): %s", risk, event.path)

        window = self._rt_window

        if window is not None and window.winfo_exists():
            window.add_entry(entry)

    def open_realtime(self):
        window = self._rt_window

        if window is not None and window.winfo_exists():
            window.focus()
            return

        self._rt_window = RealTimeWindow(self)

    def on_close(self):
        self.monitor.stop()     # stop watching, but keep the saved on/off choice
        self.destroy()    


    # ---------- Home dashboard ----------

    def refresh_home(self):
        """Redraw the whole Home tab from current state. Safe to call anytime."""
        audit = self.settings.get("last_audit")

        if audit:
            self.home_score.configure(text=f"{audit.get('score', 0)}/100")
            self.home_score_note.configure(
                text=f"{audit.get('level', '')} - {self.ago(audit.get('date'))}"
            )
        else:
            self.home_score.configure(text="--")
            self.home_score_note.configure(text="Run a Security Audit")

        scan = self.last_scan

        if scan:
            self.home_scan.configure(text=self.ago(scan.get("date")))
            self.home_scan_note.configure(
                text=f"{scan.get('files_scanned', 0)} files, "
                     f"{scan.get('threats', 0)} threats"
            )
        else:
            self.home_scan.configure(text="Never")
            self.home_scan_note.configure(text="Run a Quick Scan")

        count = self.quarantine_count()
        self.home_quar.configure(text=str(count))
        self.home_quar_note.configure(
            text="file(s) isolated" if count else "Nothing in quarantine"
        )

        self.update_home_rt()
        self.render_recommendations()

    def update_home_rt(self):
        if self.monitor.running:
            self.home_switch.select()
            self.home_rt.configure(text="ON", text_color=TEXT_COLORS["good"])
            self.home_rt_note.configure(
                text=f"{self.rt_scanned} scanned, {self.rt_threats} threats"
            )
        else:
            self.home_switch.deselect()
            self.home_rt.configure(text="OFF", text_color=TEXT_COLORS["warn"])
            self.home_rt_note.configure(text="New files are not scanned")

    def toggle_realtime_home(self):
        self.set_realtime(bool(self.home_switch.get()))

        window = self._rt_window      # keep the pop-up's switch in sync

        if window is not None and window.winfo_exists():
            window.sync_switch()

    def home_issues(self):
        """Everything needing attention, as (severity, message) pairs."""
        issues = []

        unresolved = sum(
            1 for e in self.rt_events
            if e["risk"] in THREATS and not e["quarantined"]
        )
        active = len(self.threats) + unresolved

        if active:
            issues.append((
                "bad",
                f"{active} active threat(s) detected. Quarantine them to stay safe."
            ))

        if not self.monitor.running:
            issues.append((
                "warn",
                "Real-time protection is off. Turn it on to scan new files automatically."
            ))

        audit = self.settings.get("last_audit")
        score = audit.get("score", 0) if audit else None

        if score is None:
            issues.append((
                "warn",
                "No security audit yet. Run one to check your Windows settings."
            ))
        elif score < 50:
            issues.append(("bad", f"Security score is {score}/100. Review the failed checks."))
        elif score < 75:
            issues.append(("warn", f"Security score is {score}/100. Review the failed checks."))

        scan = self.last_scan

        if scan is None:
            issues.append(("warn", "You haven't scanned yet. Try a Quick Scan."))
        else:
            try:
                age = datetime.now() - datetime.fromisoformat(scan["date"])

                if age.days >= STALE_DAYS:
                    issues.append((
                        "warn",
                        f"Your last scan was {age.days} days ago. Run a new scan."
                    ))
            except (KeyError, TypeError, ValueError):
                pass

        return issues

    def render_recommendations(self):
        issues = self.home_issues()
        severities = {severity for severity, _ in issues}

        if "bad" in severities:
            level, title = "bad", "Action required"
        elif "warn" in severities:
            level, title = "warn", "Attention needed"
        else:
            level, title = "good", "You're protected"

        if level == "good":
            subtitle = "Your PC looks healthy."
            issues = [(
                "good",
                "Everything looks good. Keep real-time protection on and scan regularly."
            )]
        else:
            subtitle = f"{len(issues)} item(s) to review."

        self.banner.configure(fg_color=BANNER_COLORS[level])
        self.banner_title.configure(text=f"{ICONS[level]}  {title}")
        self.banner_sub.configure(text=subtitle)

        for widget in self.rec_frame.winfo_children():
            widget.destroy()

        for severity, text in issues:
            ctk.CTkLabel(
                self.rec_frame,
                text=f"{ICONS[severity]}  {text}",
                text_color=TEXT_COLORS[severity],
                anchor="w",
                justify="left",
                wraplength=520
            ).pack(fill="x", pady=4)

    @staticmethod
    def quarantine_count():
        try:
            return len(list_quarantined())
        except Exception:
            return 0

    @staticmethod
    def ago(iso):
        try:
            delta = datetime.now() - datetime.fromisoformat(iso)
        except (TypeError, ValueError):
            return "unknown"

        seconds = int(delta.total_seconds())

        if seconds < 60:
            return "just now"
        if seconds < 3600:
            return f"{seconds // 60} min ago"
        if seconds < 86400:
            return f"{seconds // 3600} h ago"
        return f"{seconds // 86400} d ago"    