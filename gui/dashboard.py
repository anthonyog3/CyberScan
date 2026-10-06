import json
import threading
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.scanner import scan_path, ScanResult
from core.quarantine import quarantine_file
from security.system_audit import run_security_audit
from utils.logger import logger


HISTORY = Path("database/scan_history.json")
THREAT_LEVELS = {"HIGH", "CRITICAL"}


class AntivirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CyberScan")
        self.geometry("900x650")
        self.minsize(760, 540)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.results: list[ScanResult] = []
        self._build_ui()

    # =========================
    # UI
    # =========================

    def _build_ui(self):
        ctk.CTkLabel(
            self,
            text="CyberScan",
            font=ctk.CTkFont(size=30, weight="bold")
        ).pack(pady=(25, 5))

        ctk.CTkLabel(
            self,
            text="Windows Security & Malware Scanner",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 5))

        self.status = ctk.CTkLabel(
            self,
            text="Ready to scan",
            font=ctk.CTkFont(size=15)
        )
        self.status.pack(pady=5)

        self.progress = ctk.CTkProgressBar(self)
        self.progress.pack(fill="x", padx=40, pady=15)
        self.progress.set(0)

        buttons = ctk.CTkFrame(self)
        buttons.pack(pady=5)

        button_data = [
            ("Quick Scan", self.quick_scan, 130),
            ("Custom Scan", self.custom_scan, 130),
            ("Security Audit", self.security_audit, 130),
            ("Quarantine Selected", self.quarantine_selected, 150),
        ]

        for column, (text, command, width) in enumerate(button_data):
            ctk.CTkButton(
                buttons,
                text=text,
                width=width,
                command=command
            ).grid(row=0, column=column, padx=6)

        self.stats = ctk.CTkLabel(
            self,
            text="Files scanned: 0 | Threats: 0",
            font=ctk.CTkFont(size=14)
        )
        self.stats.pack(pady=10)

        self.threats = ctk.CTkComboBox(
            self,
            values=["No threats detected"],
            width=500,
        )
        self.threats.pack(pady=5)

        self.results_box = ctk.CTkTextbox(
            self,
            wrap="word",
            font=("Consolas", 12)
        )
        self.results_box.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(5, 30)
        )

    def _output(self, text):
        self.results_box.insert("end", text)

    def _clear_output(self):
        self.results_box.delete("1.0", "end")

    def _set_status(self, text):
        self.status.configure(text=text)

    # =========================
    # SCANNING
    # =========================

    def quick_scan(self):
        home = Path.home()
        targets = [
            path for path in (
                home / "Downloads",
                home / "Desktop"
            )
            if path.exists()
        ]

        if not targets:
            messagebox.showwarning(
                "Quick Scan",
                "No Desktop or Downloads folder was found."
            )
            return

        self.start_scan(targets)

    def custom_scan(self):
        target = filedialog.askdirectory(
            title="Choose a folder to scan"
        )

        if target:
            self.start_scan([Path(target)])

    def start_scan(self, targets):
        self._clear_output()
        self.results = []
        self.progress.set(0)
        self._set_status("Scanning...")

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

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def progress_callback(self, index, total, path, result):
        if index == "done":
            return

        progress = index / total if total else 0

        self.after(
            0,
            lambda: (
                self.progress.set(progress),
                self.set_status(f"Scanning {index}/{total}: {path}"),
            )
        )

    def finish_scan(self, results):
        self.results = results
        threats = [r for r in results if r.risk in THREAT_LEVELS]

        self.threats.configure(
            values=[r.path for r in threats] or ["No threats detected"]
        )
        self.threats.set(
            threats[0].path if threats else "No threats detected"
        )

        self.stats.configure(
            text=f"Files scanned: {len(results)} | Threats: {len(threats)}"
        )
        self._set_status("Scan complete")
        self.progress.set(1)
        self._clear_output()

        if not results:
            self._output("\nNo files were scanned.\n")
            return

        self._output(
            "========================================\n"
            "          CYBERSCAN SCAN RESULTS\n"
            "========================================\n\n"
        )

        for result in results:
            self._output(f"[{result.risk}] {result.path}\n")

            if result.sha256:
                self._output(f"  SHA-256: {result.sha256}\n")

            for reason in result.reasons:
                self._output(f"  - {reason}\n")

            if result.error:
                self._output(f"  ERROR: {result.error}\n")

            self._output("\n")

        self.save_history(len(results), len(threats))
        logger.info(
            "Scan complete: %d files, %d threats",
            len(results),
            len(threats)
        )

    def scan_error(self, exc):
        self._set_status("Scan failed")
        self._output(f"Scan error:\n{exc}\n")
        logger.error("Scan failed: %s", exc)

    # =========================
    # HISTORY
    # =========================

    def save_history(self, scanned, threats):
        try:
            history = []

            if HISTORY.exists():
                history = json.loads(
                    HISTORY.read_text(encoding="utf-8")
                )

            history.append({
                "files_scanned": scanned,
                "threats": threats
            })

            HISTORY.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            HISTORY.write_text(
                json.dumps(history[-50:], indent=2),
                encoding="utf-8"
            )

        except Exception as exc:
            logger.error(
                "Could not save history: %s",
                exc
            )

    # =========================
    # QUARANTINE
    # =========================

    def quarantine_selected(self):
        path = self.threats.get()

        if path == "No threats detected":
            messagebox.showinfo("Quarantine", "No HIGH or CRITICAL results.")
            return

        result = next((r for r in self.results if r.path == path), None)

        if not result:
            messagebox.showerror("Quarantine", "Threat could not be found.")
            return

        if not messagebox.askyesno(
            "Quarantine",
            f"Move this file to quarantine?\n\n{result.path}"
        ):
            return

        try:
            qid = quarantine_file(result,path, result.sha256)

            messagebox.showinfo(
                "Quarantined",
                f"File quarantined.\n\nID: {qid}"
            )

            logger.warning("Quarantines %s as %s", result.path, qid)

        except Exception as exc:
            messagebox.showerror("Quarantine Error",str(exc))    

    # =========================
    # SECURITY AUDIT
    # =========================

    def security_audit(self):
        self._set_status("Running security audit...")
        self._clear_output()

        try:
            audit = run_security_audit()
            score = audit.get("score", 0)
            checks = audit.get("checks", [])

            level = (
                "EXCELLENT" if score >= 90 else
                "GOOD" if score >= 75 else
                "WARNING" if score >= 50 else
                "CRITICAL"
            )

            self._output(
                "\n"
                "========================================\n"
                "           CYBERSCAN SECURITY\n"
                "              SYSTEM AUDIT\n"
                "========================================\n\n"
                f"              {score}/100\n"
                f"        SECURITY: {level}\n\n"
                "----------------------------------------\n"
                "SECURITY CHECKS\n"
                "----------------------------------------\n\n"
            )

            for check in checks:
                status = check.get("status", "Unknown")
                icon = {
                    "Secure": "[+]",
                    "Warning": "[!]"
                }.get(status, "[?]")

                self._output(
                    f"{icon} {check.get('name', 'Unknown Check')}\n"
                    f"    Status: {status}\n"
                    f"    Score: {check.get('score', 0)}/20\n"
                    f"    {check.get('details', 'No details available.')}\n\n"
                )

            self._output(
                "========================================\n"
                f"FINAL SECURITY SCORE: {score}/100\n"
                "========================================\n"
            )

            self._set_status(
                f"Security audit complete - {score}/100"
            )

            logger.info(
                "Security audit complete: %d/100",
                score
            )

        except Exception as exc:
            self._set_status("Security audit failed")
            self._output(f"Security audit error:\n{exc}\n")
            logger.error(
                "Security audit failed: %s",
                exc
            )