
import json
import threading
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.scanner import scan_path, ScanResult
from core.quarantine import quarantine_file
from security.system_audit import run_security_audit
from utils.logger import logger


HISTORY = Path("database/scan_history.json")
THREATS = {"HIGH", "CRITICAL"}


class AntivirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CyberScan")
        self.geometry("1100x720")
        self.minsize(900, 620)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.results: list[ScanResult] = []
        self.scanning = False
        self.buttons = []

        self.build_ui()

    # =========================
    # UI
    # =========================

    def build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.build_header()
        self.build_status()
        self.build_stats()
        self.build_main()

    def build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(25, 5))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="CyberScan",
            font=ctk.CTkFont(size=32, weight="bold")
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="Windows Security & Malware Protection"
        ).grid(row=1, column=0, sticky="w")

        self.protection = ctk.CTkLabel(
            header,
            text="● PROTECTION READY",
            text_color="#4ade80",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.protection.grid(row=0, column=1, rowspan=2)

    def build_status(self):
        frame = ctk.CTkFrame(self, corner_radius=12)
        frame.grid(row=1, column=0, sticky="ew", padx=30, pady=15)
        frame.grid_columnconfigure(0, weight=1)

        self.status = ctk.CTkLabel(
            frame,
            text="Your system is ready to scan",
            font=ctk.CTkFont(size=17, weight="bold")
        )
        self.status.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 3))

        self.progress = ctk.CTkProgressBar(frame)
        self.progress.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        self.progress.set(0)

        self.progress_text = ctk.CTkLabel(
            frame,
            text="Ready"
        )
        self.progress_text.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 15))

    def build_stats(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="ew", padx=30, pady=5)

        for i in range(3):
            frame.grid_columnconfigure(i, weight=1)

        self.files_stat = self.stat_card(frame, "FILES SCANNED", "0", 0)
        self.threats_stat = self.stat_card(frame, "THREATS FOUND", "0", 1)
        self.score_stat = self.stat_card(frame, "SECURITY SCORE", "--", 2)

    def stat_card(self, parent, title, value, column):
        card = ctk.CTkFrame(parent, corner_radius=12)
        card.grid(row=0, column=column, sticky="ew", padx=5)

        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(pady=(12, 2))

        label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=24, weight="bold")
        )
        label.pack(pady=(0, 12))

        return label

    def build_main(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="nsew", padx=30, pady=(10, 25))

        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        self.build_controls(frame)
        self.build_results(frame)

    def build_controls(self, parent):
        controls = ctk.CTkFrame(parent, corner_radius=12)
        controls.grid(row=0, column=0, sticky="ns", padx=(0, 15))

        ctk.CTkLabel(
            controls,
            text="SCAN CENTER",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(pady=(20, 15))

        for text, command, width in [
            ("Quick Scan", self.quick_scan, 190),
            ("Custom Scan", self.custom_scan, 190),
            ("Security Audit", self.security_audit, 190),
            ("Quarantine Selected", self.quarantine_selected, 190)
        ]:
            button = ctk.CTkButton(
                controls,
                text=text,
                width=width,
                height=42,
                command=command
            )
            button.pack(padx=20, pady=6)
            self.buttons.append(button)

        ctk.CTkLabel(
            controls,
            text="THREAT SELECTION",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(25, 8))

        self.threats = ctk.CTkComboBox(
            controls,
            values=["No threats detected"],
            width=190
        )
        self.threats.pack(padx=20, pady=(0, 20))

    def build_results(self, parent):
        frame = ctk.CTkFrame(parent, corner_radius=12)
        frame.grid(row=0, column=1, sticky="nsew")

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            frame,
            text="SCAN RESULTS",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=20, pady=18)

        self.output = ctk.CTkTextbox(
            frame,
            wrap="word",
            font=("Consolas", 12),
            corner_radius=8
        )
        self.output.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=15,
            pady=(0, 15)
        )

        self.show(
            "============================================\n"
            "              CYBERSCAN\n"
            "        SECURITY PROTECTION CENTER\n"
            "============================================\n\n"
            "System ready.\n\n"
            "Choose a scan from the left to begin."
        )

    # =========================
    # Helpers
    # =========================

    def show(self, text):
        self.output.delete("1.0", "end")
        self.output.insert("end", text)
        self.output.see("end")

    def add(self, text):
        self.output.insert("end", text)
        self.output.see("end")

    def status_text(self, text):
        self.status.configure(text=text)

    def set_buttons(self, enabled):
        state = "normal" if enabled else "disabled"
        for button in self.buttons:
            button.configure(state=state)

    # =========================
    # Scanning
    # =========================

    def quick_scan(self):
        home = Path.home()
        targets = [
            p for p in (
                home / "Downloads",
                home / "Desktop"
            ) if p.exists()
        ]

        if not targets:
            messagebox.showwarning(
                "Quick Scan",
                "No Desktop or Downloads folder was found."
            )
            return

        self.start_scan(targets)

    def custom_scan(self):
        folder = filedialog.askdirectory(
            title="Choose a folder to scan"
        )

        if folder:
            self.start_scan([Path(folder)])

    def start_scan(self, targets):
        if self.scanning:
            return

        self.scanning = True
        self.set_buttons(False)
        self.progress.set(0)
        self.progress_text.configure(text="Starting scan...")
        self.status_text("Scanning your system...")

        self.protection.configure(
            text="● SCAN IN PROGRESS",
            text_color="#60a5fa"
        )

        self.show("Scanning...\n\n")

        def worker():
            try:
                results = []

                for target in targets:
                    results.extend(
                        scan_path(
                            str(target),
                            callback=self.progress_callback
                        )
                    )

                self.after(0, lambda: self.finish_scan(results))

            except Exception as exc:
                self.after(0, lambda: self.scan_error(exc))

        threading.Thread(target=worker, daemon=True).start()

    def progress_callback(self, index, total, path, result):
        if index == "done":
            return

        progress = index / total if total else 0

        self.after(
            0,
            lambda: self.update_progress(
                progress, index, total, path
            )
        )

    def update_progress(self, progress, index, total, path):
        self.progress.set(progress)
        self.progress_text.configure(
            text=f"{index}/{total} • {Path(str(path)).name}"
        )
        self.status_text(
            f"Scanning file {index} of {total}"
        )

    def finish_scan(self, results):
        self.scanning = False
        self.set_buttons(True)
        self.progress.set(1)
        self.progress_text.configure(text="Scan complete")

        self.results = results
        threats = [r for r in results if r.risk in THREATS]

        self.files_stat.configure(text=str(len(results)))
        self.threats_stat.configure(text=str(len(threats)))

        paths = [r.path for r in threats] or ["No threats detected"]
        self.threats.configure(values=paths)
        self.threats.set(paths[0])

        self.protection.configure(
            text="● PROTECTION READY",
            text_color="#4ade80"
        )

        self.status_text("Scan completed successfully")

        self.show(
            "============================================\n"
            "             CYBERSCAN RESULTS\n"
            "============================================\n\n"
            f"Files scanned : {len(results)}\n"
            f"Threats found : {len(threats)}\n\n"
        )

        if not threats:
            self.add("✓ NO HIGH OR CRITICAL THREATS DETECTED\n\n")
        else:
            self.add("⚠ THREATS DETECTED\n\n")

        for result in results:
            self.add(f"[{result.risk}] {result.path}\n")

            if result.sha256:
                self.add(f"  SHA-256: {result.sha256}\n")

            for reason in result.reasons:
                self.add(f"  - {reason}\n")

            if result.error:
                self.add(f"  ERROR: {result.error}\n")

            self.add("\n")

        self.save_history(len(results), len(threats))

        logger.info(
            "Scan complete: %d files, %d threats",
            len(results),
            len(threats)
        )

    def scan_error(self, exc):
        self.scanning = False
        self.set_buttons(True)

        self.progress_text.configure(text="Scan failed")
        self.status_text("Scan failed")

        self.protection.configure(
            text="● SCAN ERROR",
            text_color="#f87171"
        )

        self.show(f"Scan error:\n\n{exc}")

        logger.error("Scan failed: %s", exc)

    # =========================
    # History
    # =========================

    def save_history(self, scanned, threats):
        try:
            history = []

            if HISTORY.exists():
                history = json.loads(
                    HISTORY.read_text(encoding="utf-8")
                )

            history.append({
                "timestamp": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "files_scanned": scanned,
                "threats": threats
            })

            HISTORY.parent.mkdir(parents=True, exist_ok=True)

            HISTORY.write_text(
                json.dumps(history[-50:], indent=2),
                encoding="utf-8"
            )

        except Exception as exc:
            logger.error("Could not save history: %s", exc)

    # =========================
    # Quarantine
    # =========================

    def quarantine_selected(self):
        path = self.threats.get()

        if path == "No threats detected":
            messagebox.showinfo(
                "Quarantine",
                "No HIGH or CRITICAL results."
            )
            return

        result = next(
            (r for r in self.results if r.path == path),
            None
        )

        if not result:
            messagebox.showerror(
                "Quarantine",
                "Threat could not be found."
            )
            return

        if not messagebox.askyesno(
            "Quarantine",
            f"Move this file to quarantine?\n\n{path}"
        ):
            return

        try:
            qid = quarantine_file(
                result,
                path,
                result.sha256
            )

            messagebox.showinfo(
                "Quarantined",
                f"File quarantined.\n\nID: {qid}"
            )

            logger.warning(
                "Quarantined %s as %s",
                path,
                qid
            )

        except Exception as exc:
            messagebox.showerror(
                "Quarantine Error",
                str(exc)
            )

    # =========================
    # Security Audit
    # =========================

    def security_audit(self):
        self.status_text("Running security audit...")
        self.show("")

        try:
            audit = run_security_audit()
            score = audit["score"]
            checks = audit["checks"]

            self.score_stat.configure(text=f"{score}/100")


            self.score_stat.configure(text=f"{score}/100")

            level = (
                "EXCELLENT" if score >= 90 else
                "GOOD" if score >= 75 else
                "WARNING" if score>= 50 else
                "CRITICAL"
            )

            self.add(
                "CYBERSCAN SECURITY AUDIT\n"
                "========================\n\n"
                f"Security Score: {score}/100\n"
                f"Status: {level}\n\n"
                "SECURITY CHECKS\n"
                "------------------------"
            )

            for check in checks:
                self.add(
                    f"{check['name']}\n"
                    f"Status: {check['score']}/20\n"
                    f"{check['details']}\n\n"
                )

            self.add(
                "========================\n"
                f"FINAL SCORE: {score}/100\n"
            )

            self.status_text(f"Security audit complete - {score}/100")
            logger.info("Security audit complete: %d/100", score)

        except Exception as exc:
            self.status_text("Security audit failed")
            self.add(f"Security audit error: \n{exc}\n")
            logger.error("Security audit failed: %s", exc)
            messagebox.showerror("Security Audit Error", str(exc))        
