#!/usr/bin/env python3
# Psychopomp Packages Tools
# GUI package fetcher for Debian 13 (Trixie)
# Author: PsychopompOS Project
# License: GPLv3

import csv
import json
import queue
import shutil
import threading
import subprocess
import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
import glob
import time
import os

APP_NAME = "Psychopomp Packages Tools"
TARGET_RELEASE = "Debian 13 (Trixie)"
BASE_DIR = Path(__file__).resolve().parent
PKG_JSON = BASE_DIR / "packages.json"     # Provided separately
CONFIG_FILE = BASE_DIR / "config.json"
LOGS_DIR = BASE_DIR / "logs"

DEFAULT_MAX_WORKERS = 4
APT_TIMEOUT_SEC = 300
RETRY_ON_FAILURE = 1  # retry once on transient failure

# -----------------------------
# Config
# -----------------------------
class Config:
    def __init__(self):
        # Defaults: repo_root/packages + workers
        self.base_dir = str((BASE_DIR.parent / "packages").resolve())
        self.max_workers = DEFAULT_MAX_WORKERS
        self.load()

    def load(self):
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                self.base_dir = data.get("base_dir", self.base_dir)
                self.max_workers = int(data.get("max_workers", self.max_workers))
            except Exception:
                pass

    def save(self):
        data = {"base_dir": self.base_dir, "max_workers": self.max_workers}
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @property
    def deb_dir(self) -> Path:
        return Path(self.base_dir) / "deb"

    @property
    def src_dir(self) -> Path:
        return Path(self.base_dir) / "source"

    def ensure_dirs(self):
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)
        self.deb_dir.mkdir(parents=True, exist_ok=True)
        self.src_dir.mkdir(parents=True, exist_ok=True)


# -----------------------------
# Helpers
# -----------------------------
def has_deb_src_enabled() -> bool:
    candidates = [Path("/etc/apt/sources.list")] + list(Path("/etc/apt/sources.list.d").glob("*.list"))
    for p in candidates:
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s and not s.startswith("#") and s.startswith("deb-src "):
                    return True
        except Exception:
            continue
    return False

def apt_lists_age_days() -> int | None:
    # Return age in days of the newest list file, or None if not found
    lists_dir = Path("/var/lib/apt/lists")
    if not lists_dir.exists():
        return None
    mtimes = [f.stat().st_mtime for f in lists_dir.glob("*") if f.is_file()]
    if not mtimes:
        return None
    newest = max(mtimes)
    age_days = int((time.time() - newest) / 86400)
    return age_days

def open_folder(path: Path):
    try:
        if os.name == "posix":
            subprocess.Popen(["xdg-open", str(path)])
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore
        else:
            subprocess.Popen(["open", str(path)])
    except Exception:
        # ignore
        pass


# -----------------------------
# Package Manager (APT)
# -----------------------------
class PackageManager:
    def __init__(self, cfg: Config, enqueue_log):
        self.cfg = cfg
        self.enqueue_log = enqueue_log
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self.run_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = LOGS_DIR / f"download_{self.run_ts}.log"
        # Maintain a "latest" symlink for convenience (best-effort)
        try:
            latest = LOGS_DIR / "latest.log"
            if latest.exists() or latest.is_symlink():
                latest.unlink()
            latest.symlink_to(self.log_file.name)
        except Exception:
            pass

    def log(self, msg, level="INFO"):
        line = f"[{datetime.datetime.now().isoformat(timespec='seconds')}] [{level}] {msg}"
        self.enqueue_log(("log", line))
        with self.log_file.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def run_cmd(self, cmd, cwd=None, timeout=APT_TIMEOUT_SEC):
        # Execute with timeout and capture output
        try:
            res = subprocess.run(
                cmd, check=True, text=True, capture_output=True, cwd=cwd, timeout=timeout
            )
            return True, res.stdout.strip()
        except subprocess.TimeoutExpired as e:
            return False, f"Timeout after {timeout}s: {e}"
        except subprocess.CalledProcessError as e:
            return False, (e.stderr or e.stdout or "").strip()

    def run_cmd_with_retry(self, cmd, cwd=None, what="command"):
        ok, out = self.run_cmd(cmd, cwd=cwd)
        if ok:
            return ok, out
        self.log(f"{what} failed: {out}. Retrying once...", level="WARN")
        time.sleep(2)
        return self.run_cmd(cmd, cwd=cwd)

    def check_tools(self):
        for tool in ("apt-get", "apt-cache"):
            ok, _ = self.run_cmd(["which", tool], timeout=10)
            if not ok:
                self.log(f"Required tool not found: {tool}", level="ERROR")
                return False
        return True

    def package_exists(self, name: str, version: str | None = None) -> bool:
        ok, out = self.run_cmd(["apt-cache", "show", name])
        if not ok or not out:
            return False
        if not version:
            return True
        ok2, mad = self.run_cmd(["apt-cache", "madison", name])
        if not ok2 or not mad:
            return False
        for line in mad.splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2 and parts[1] == version:
                return True
        return False

    def _parse_downloaded_filename(self, stdout_text: str) -> str | None:
        # apt-get download often prints the filename at the end or as a "Get:" line
        # Fallback: glob by name in deb_dir
        for line in stdout_text.splitlines():
            line = line.strip()
            if line.endswith(".deb") and Path(line).name.endswith(".deb"):
                candidate = Path(line)
                if candidate.exists():
                    return str(candidate)
        return None

    def _latest_deb_for(self, name: str, directory: Path) -> str | None:
        pattern = str(directory / f"{name}_*.deb")
        candidates = glob.glob(pattern)
        if not candidates:
            return None
        candidates.sort(key=lambda p: Path(p).stat().st_mtime, reverse=True)
        return candidates[0]

    def download_deb(self, name: str, version: str | None = None) -> tuple[bool, str | None, str]:
        self.cfg.ensure_dirs()
        cmd = ["apt-get", "download", name] if not version else ["apt-get", "download", f"{name}={version}"]
        self.log(f"Downloading .deb: {' '.join(cmd)}")
        ok, out = self.run_cmd_with_retry(cmd, cwd=self.cfg.deb_dir, what=f"apt-get download {name}")
        # Try to detect file reliably
        deb_path = None
        if ok:
            detected = self._parse_downloaded_filename(out)
            if detected and Path(detected).exists():
                deb_path = detected
            else:
                time.sleep(0.1)
                deb_path = self._latest_deb_for(name, self.cfg.deb_dir)
        if ok and deb_path:
            self.log(f".deb ready: {deb_path}")
        else:
            hint = ""
            if "E: Unable to locate package" in out:
                hint = " (Check that main/contrib/non-free components are enabled in your sources.list)"
            self.log(f"Failed to download .deb for {name}: {out}{hint}", level="ERROR")
        return ok, deb_path, out

    def download_source(self, name: str, version: str | None = None) -> tuple[bool, str]:
        self.cfg.ensure_dirs()
        cmd = ["apt-get", "source", name] if not version else ["apt-get", "source", f"{name}={version}"]
        self.log(f"Downloading source: {' '.join(cmd)}")
        ok, out = self.run_cmd_with_retry(cmd, cwd=self.cfg.src_dir, what=f"apt-get source {name}")
        if ok:
            self.log(f"Source fetched for {name} → {self.cfg.src_dir}")
        else:
            hint = ""
            if "You must put some 'source' URIs" in out:
                hint = " (Enable deb-src entries in /etc/apt/sources.list and run: sudo apt update)"
            self.log(f"Failed to download source for {name}: {out}{hint}", level="ERROR")
        return ok, out


# -----------------------------
# GUI
# -----------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — {TARGET_RELEASE}")
        self.geometry("1140x820")
        self.minsize(1024, 720)

        self.log_queue: queue.Queue = queue.Queue()

        self.cfg = Config()
        self.pm = PackageManager(self.cfg, self.enqueue)

        self.data = self.load_packages()
        self.filtered = list(self.data.get("packages", []))
        self.stop_flag = threading.Event()
        self.sources_enabled_warned = False
        self.current_results = []
        self.run_start = None

        self.create_widgets()
        self.refresh_list()

        if not self.pm.check_tools():
            messagebox.showerror(APP_NAME, "Required APT tools not found. Please ensure apt-get and apt-cache are installed.")
            self.destroy()
            return

        # Warn if apt lists are stale
        age = apt_lists_age_days()
        if age is not None and age > 7:
            self.pm.log(f"APT lists are {age} days old. Consider running: sudo apt update", level="WARN")

        self.after(100, self.process_queue)

    # --------- Queue bridge ---------
    def enqueue(self, item):
        self.log_queue.put(item)

    def process_queue(self):
        try:
            while True:
                kind, payload = self.log_queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "progress":
                    self.progress["value"] = payload
                elif kind == "status":
                    self.status_var.set(payload)
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    # --------- Data loading ---------
    def load_packages(self):
        if not PKG_JSON.exists():
            messagebox.showerror("Error", f"packages.json not found at {PKG_JSON}")
            self.destroy()
            raise SystemExit(1)
        try:
            data = json.loads(PKG_JSON.read_text(encoding="utf-8"))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse packages.json: {e}")
            self.destroy()
            raise SystemExit(1)
        if "packages" not in data or not isinstance(data["packages"], list):
            messagebox.showerror("Error", "packages.json is missing a 'packages' list.")
            self.destroy()
            raise SystemExit(1)
        return data

    # --------- UI ---------
    def create_widgets(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Menu
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Export Last Summary CSV", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=False)
        tools_menu.add_command(label="Open DEB Folder", command=lambda: open_folder(self.cfg.deb_dir))
        tools_menu.add_command(label="Open Source Folder", command=lambda: open_folder(self.cfg.src_dir))
        tools_menu.add_command(label="Open Logs Folder", command=lambda: open_folder(LOGS_DIR))
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(
            label="Requirements",
            command=lambda: messagebox.showinfo(
                "Requirements",
                "• Debian 13 (Trixie) with apt configured\n"
                "• For sources: enable deb-src in /etc/apt/sources.list (or *.list) and run: sudo apt update\n"
                "• Ensure components main/contrib/non-free(-firmware) are enabled if needed\n"
                "• Recommended: sudo apt update && sudo apt install apt-utils dpkg-dev python3-tk\n"
            ),
        )
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo(APP_NAME, f"{APP_NAME}\nTarget: {TARGET_RELEASE}\n© PsychopompOS Project"))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

        # Base path
        paths = ttk.LabelFrame(self, text="Base Download Directory (creates subfolders: packages/deb, packages/source)")
        paths.pack(fill="x", padx=12, pady=8)

        ttk.Label(paths, text="Base path:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.base_var = tk.StringVar(value=self.cfg.base_dir)
        base_entry = ttk.Entry(paths, textvariable=self.base_var, width=80)
        base_entry.grid(row=0, column=1, padx=6, pady=6, sticky="we")
        ttk.Button(paths, text="Browse", command=self.pick_base_dir).grid(row=0, column=2, padx=6, pady=6)
        ttk.Button(paths, text="Save Path", command=self.save_path).grid(row=0, column=3, padx=6, pady=6)

        # Concurrency
        conc = ttk.LabelFrame(self, text="Parallel Downloads")
        conc.pack(fill="x", padx=12, pady=6)
        ttk.Label(conc, text="Max workers:").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.workers_var = tk.IntVar(value=self.cfg.max_workers)
        workers = ttk.Combobox(conc, state="readonly", values=[1,2,3,4,5,6,7,8], textvariable=self.workers_var, width=5)
        workers.grid(row=0, column=1, padx=6, pady=6, sticky="w")
        ttk.Button(conc, text="Apply", command=self.apply_workers).grid(row=0, column=2, padx=6, pady=6)

        # Filters
        filters = ttk.LabelFrame(self, text="Filter & Search")
        filters.pack(fill="x", padx=12, pady=6)

        ttk.Label(filters, text="Category:").grid(row=0, column=0, padx=6, pady=6)
        cats = ["all"] + self.data.get("categories", [])
        self.category_var = tk.StringVar(value="all")
        cat_combo = ttk.Combobox(filters, textvariable=self.category_var, values=cats, state="readonly", width=22)
        cat_combo.grid(row=0, column=1, padx=6, pady=6)

        ttk.Label(filters, text="Search:").grid(row=0, column=2, padx=6, pady=6)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filters, textvariable=self.search_var, width=44)
        search_entry.grid(row=0, column=3, padx=6, pady=6)
        search_entry.bind("<Return>", lambda e: self.apply_filters())

        ttk.Button(filters, text="Apply", command=self.apply_filters).grid(row=0, column=4, padx=6, pady=6)
        ttk.Button(filters, text="Clear", command=self.clear_filters).grid(row=0, column=5, padx=6, pady=6)

        # Table
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=12, pady=6)

        cols = ("name", "category", "description")
        self.table = ttk.Treeview(table_frame, columns=cols, show="headings", height=16, selectmode="extended")
        self.table.heading("name", text="Name")
        self.table.heading("category", text="Category")
        self.table.heading("description", text="Description")

        self.table.column("name", anchor="w", width=220)
        self.table.column("category", anchor="w", width=170)
        self.table.column("description", anchor="w", width=660)

        self.table.pack(side="left", fill="both", expand=True)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        vsb.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=vsb.set)

        # Selection helpers
        sel = ttk.Frame(self)
        sel.pack(fill="x", padx=12, pady=4)
        ttk.Button(sel, text="Select All", command=lambda: self.table.selection_set(self.table.get_children())).pack(side="left", padx=4)
        ttk.Button(sel, text="Clear Selection", command=lambda: self.table.selection_remove(self.table.get_children())).pack(side="left", padx=4)

        # Download options
        opts = ttk.LabelFrame(self, text="Download Options")
        opts.pack(fill="x", padx=12, pady=6)
        self.opt_deb = tk.BooleanVar(value=True)
        self.opt_src = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Download .deb", variable=self.opt_deb).grid(row=0, column=0, padx=10, pady=8)
        ttk.Checkbutton(opts, text="Download source", variable=self.opt_src).grid(row=0, column=1, padx=10, pady=8)

        # Actions
        actions = ttk.Frame(self)
        actions.pack(fill="x", padx=12, pady=6)
        ttk.Button(actions, text="Download Selected", command=self.download_selected).pack(side="left", padx=6)
        ttk.Button(actions, text="Download All (filtered)", command=self.download_all_filtered).pack(side="left", padx=6)
        ttk.Button(actions, text="Stop", command=self.stop_downloads).pack(side="left", padx=6)

        self.progress = ttk.Progressbar(actions, mode="determinate")
        self.progress.pack(side="right", fill="x", expand=True, padx=6)

        # Log
        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill="both", expand=False, padx=12, pady=10)
        self.log_text = tk.Text(log_frame, height=12, wrap="word")
        self.log_text.pack(fill="both", expand=True)

        # Status
        self.status_var = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status_bar.pack(fill="x", side="bottom", padx=8, pady=4)

    # --------- UI helpers ---------
    def pick_base_dir(self):
        d = filedialog.askdirectory(title="Select base download directory", initialdir=self.base_var.get())
        if d:
            self.base_var.set(d)

    def save_path(self):
        self.cfg.base_dir = self.base_var.get().strip()
        self.cfg.ensure_dirs()
        self.cfg.save()
        messagebox.showinfo(APP_NAME, f"Base path saved.\n\n.deb → {self.cfg.deb_dir}\nsource → {self.cfg.src_dir}")

    def apply_workers(self):
        try:
            self.cfg.max_workers = int(self.workers_var.get())
            self.cfg.save()
            messagebox.showinfo(APP_NAME, f"Max workers set to {self.cfg.max_workers}.")
        except Exception:
            messagebox.showerror(APP_NAME, "Invalid workers value.")

    def _append_log(self, line):
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")

    def apply_filters(self):
        cat = self.category_var.get()
        q = self.search_var.get().lower().strip()
        out = []
        for p in self.data.get("packages", []):
            if cat != "all" and p.get("category") != cat:
                continue
            if q and (q not in p.get("name", "").lower() and q not in p.get("description", "").lower()):
                continue
            out.append(p)
        self.filtered = out
        self.refresh_list()

    def clear_filters(self):
        self.category_var.set("all")
        self.search_var.set("")
        self.filtered = list(self.data.get("packages", []))
        self.refresh_list()

    def refresh_list(self):
        for row in self.table.get_children():
            self.table.delete(row)
        for p in self.filtered:
            self.table.insert("", "end", values=(p.get("name", ""), p.get("category", ""), p.get("description", "")))
        self.status_var.set(f"{len(self.filtered)} package(s) listed.")

    def get_selected_packages(self):
        items = self.table.selection()
        selected_names = []
        for it in items:
            vals = self.table.item(it, "values")
            if not vals:
                continue
            selected_names.append(vals[0])
        selected = [p for p in self.filtered if p.get("name") in selected_names]
        return selected

    def stop_downloads(self):
        self.pm.log("Stop requested by user.", level="WARN")
        self.stop_flag.set()

    # --------- Preflight ---------
    def preflight(self, want_src: bool) -> bool:
        # Disk space check (warn if less than 1 GB free)
        total, used, free = shutil.disk_usage(self.cfg.base_dir if self.cfg.base_dir else "/")
        if free < 1_000_000_000:
            if not messagebox.askyesno(APP_NAME, "Less than 1 GB free on target disk. Continue anyway?"):
                return False

        # deb-src warning
        if want_src and not self.sources_enabled_warned and not has_deb_src_enabled():
            self.pm.log("Warning: deb-src entries are not enabled; source downloads may fail.", level="WARN")
            self.sources_enabled_warned = True
            messagebox.showwarning(
                APP_NAME,
                "deb-src entries are not enabled.\n\nEnable them in /etc/apt/sources.list (or /etc/apt/sources.list.d/*.list)\nthen run: sudo apt update"
            )
        return True

    # --------- Download orchestration ---------
    def _download_one(self, pkg, want_deb: bool, want_src: bool):
        name = pkg.get("name")
        version = pkg.get("version")  # optional
        result = {
            "name": name or "",
            "version": version or "",
            "deb_ok": "",
            "src_ok": "",
            "deb_path": "",
            "notes": ""
        }
        if not name:
            result["notes"] = "Invalid package entry"
            return result

        if self.stop_flag.is_set():
            result["notes"] = "Skipped (stopped)"
            return result

        # Existence check
        if not self.pm.package_exists(name, version):
            msg = f"Package not found: {name}" if not version else f"Package/version not found: {name}={version}"
            self.pm.log(msg, level="ERROR")
            result["deb_ok"] = "no" if want_deb else ""
            result["src_ok"] = "no" if want_src else ""
            result["notes"] = "Not in repositories"
            return result

        ok_all = True

        if want_deb:
            ok_deb, deb_path, _ = self.pm.download_deb(name, version)
            result["deb_ok"] = "yes" if ok_deb else "no"
            result["deb_path"] = deb_path or ""
            if not ok_deb:
                ok_all = False

        if want_src:
            ok_src, _ = self.pm.download_source(name, version)
            result["src_ok"] = "yes" if ok_src else "no"
            if not ok_src:
                ok_all = False

        result["notes"] = "ok" if ok_all else "errors"
        return result

    def _export_csv_internal(self):
        if not self.current_results:
            return None
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        csv_path = LOGS_DIR / f"summary_{self.pm.run_ts}.csv"
        fields = ["name", "version", "deb_ok", "src_ok", "deb_path", "notes"]
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for row in self.current_results:
                writer.writerow(row)
        self.pm.log(f"CSV summary exported: {csv_path}")
        return csv_path

    def _run_downloads(self, pkgs, want_deb: bool, want_src: bool):
        self.stop_flag.clear()
        total = len(pkgs)
        self.progress["value"] = 0
        self.progress["maximum"] = max(1, total)
        self.enqueue(("status", "Downloading..."))
        self.current_results = []
        self.run_start = time.time()

        # Ensure dirs
        self.cfg.ensure_dirs()

        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as executor:
            future_map = {executor.submit(self._download_one, p, want_deb, want_src): p for p in pkgs}
            completed = 0
            for fut in as_completed(future_map):
                if self.stop_flag.is_set():
                    break
                res = fut.result()
                self.current_results.append(res)
                completed += 1
                self.enqueue(("progress", completed))

        duration = time.time() - self.run_start if self.run_start else 0
        ok_count = sum(1 for r in self.current_results if r.get("notes") == "ok")
        err_count = len(self.current_results) - ok_count

        if self.stop_flag.is_set():
            self.pm.log("Stopped by user.", level="WARN")
            self.enqueue(("status", "Stopped."))
        else:
            self.pm.log(f"All tasks finished. Success: {ok_count}, Errors: {err_count}, Duration: {int(duration)}s")
            self.enqueue(("status", "Done."))

        csv_path = None
        try:
            csv_path = self._export_csv_internal()
        except Exception as e:
            self.pm.log(f"Failed to export CSV summary: {e}", level="ERROR")

        # End-of-run dialog
        msg = f"Completed.\n\nSuccess: {ok_count}\nErrors: {err_count}\nDuration: {int(duration)}s"
        if messagebox.askyesno(APP_NAME, msg + "\n\nOpen logs folder?"):
            open_folder(LOGS_DIR)
        elif csv_path and messagebox.askyesno(APP_NAME, "Open CSV summary?"):
            try:
                open_folder(csv_path.parent)
            except Exception:
                pass

    def download_selected(self):
        pkgs = self.get_selected_packages()
        if not pkgs:
            messagebox.showwarning(APP_NAME, "No packages selected.")
            return
        want_deb = self.opt_deb.get()
        want_src = self.opt_src.get()
        if not want_deb and not want_src:
            messagebox.showwarning(APP_NAME, "Please select at least one option: Download .deb and/or Download source.")
            return
        self.save_path()
        if not self.preflight(want_src):
            return
        threading.Thread(target=self._run_downloads, args=(pkgs, want_deb, want_src), daemon=True).start()

    def download_all_filtered(self):
        if not self.filtered:
            messagebox.showwarning(APP_NAME, "No packages to download in current filter.")
            return
        want_deb = self.opt_deb.get()
        want_src = self.opt_src.get()
        if not want_deb and not want_src:
            messagebox.showwarning(APP_NAME, "Please select at least one option: Download .deb and/or Download source.")
            return
        self.save_path()
        if not self.preflight(want_src):
            return
        threading.Thread(target=self._run_downloads, args=(self.filtered, want_deb, want_src), daemon=True).start()


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    try:
        app = App()
        app.mainloop()
    except KeyboardInterrupt:
        pass
