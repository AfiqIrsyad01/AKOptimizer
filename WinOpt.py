#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AKOptimizer - Windows 10/11 PC optimizer for low-end systems
Single-file PyQt6 app, works with Python 3.10+ (tested on Python 3.13)

Required pip packages:
  pip install psutil wmi pywin32 PyQt6 qdarkstyle

To run:
  python optimizer.py

To package as .exe (one file, no console):
  pyinstaller --onefile --noconsole optimizer.py

Notes:
- Some features require Administrator privileges (e.g., services, winsock reset, defrag, startup registry).
- The app will warn if not running as admin. Use the "Relaunch as Admin" button to elevate.
- All actions log output in the bottom log panel.
"""

import os
import sys
import re
import time
import ctypes
import shutil
import traceback
import subprocess
import threading
from pathlib import Path

def resource_path(relative_path):
    """
    Get the absolute path to a resource, works for dev and for PyInstaller.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Third-party
try:
    import psutil
except Exception as e:
    print("Missing dependency: psutil")
    raise

# Try to import wmi and pywin32; if not available, app will still start but some features will be limited.
try:
    import wmi as wmi_module
except Exception:
    wmi_module = None

try:
    import win32api
    import win32con
    import win32serviceutil
except Exception:
    win32api = None
    win32con = None
    win32serviceutil = None

try:
    import qdarkstyle
except Exception:
    qdarkstyle = None

# PyQt6
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter, QListWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QProgressBar, QTextEdit,
    QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QLineEdit, QComboBox, QGroupBox, QFormLayout, QCheckBox
)
from PyQt6.QtGui import QIcon


# --------------------- Utilities ---------------------

def is_user_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    try:
        if win32api is not None:
            # Use pywin32 for elevation
            params = " ".join(f'"{a}"' if " " in a else a for a in sys.argv)
            win32api.ShellExecute(0, "runas", sys.executable, params, None, 1)
        else:
            # Fallback using ctypes ShellExecute
            ShellExecuteW = ctypes.windll.shell32.ShellExecuteW
            params = " ".join(f'"{a}"' if " " in a else a for a in sys.argv)
            ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        # Show message box if we can't elevate
        QMessageBox.critical(None, "Elevation failed", f"Could not relaunch as admin:\n{e}")


def format_bytes(n: int) -> str:
    # Human-readable bytes
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def run_cmd(cmd, timeout=None):
    try:
        cp = subprocess.run(
            cmd, shell=True, timeout=timeout, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        out = cp.stdout.strip()
        err = cp.stderr.strip()
        return cp.returncode, out, err
    except Exception as e:
        return -1, "", f"Exception running {cmd!r}: {e}"


def confirm(parent, title, text) -> bool:
    return QMessageBox.question(parent, title, text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes


def delete_folder_contents(path: Path):
    # Deletes contents of a directory but keeps the directory
    if not path.exists() or not path.is_dir():
        return 0, 0
    deleted_files = 0
    deleted_bytes = 0
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            p = Path(root) / name
            try:
                sz = p.stat().st_size
            except Exception:
                sz = 0
            try:
                p.unlink(missing_ok=True)
                deleted_files += 1
                deleted_bytes += sz
            except Exception:
                pass
        for name in dirs:
            p = Path(root) / name
            try:
                if not any(p.iterdir()):
                    p.rmdir()
            except Exception:
                pass
    return deleted_files, deleted_bytes


def SHEmptyRecycleBin():
    # Empty Recycle Bin using Windows API (no UI, no sound, no confirm)
    # Flags: 0x1 no confirmation, 0x2 no progress UI, 0x4 no sound
    SHERB_NOCONFIRMATION = 0x00000001
    SHERB_NOPROGRESSUI = 0x00000002
    SHERB_NOSOUND = 0x00000004
    try:
        shell32 = ctypes.windll.shell32
        res = shell32.SHEmptyRecycleBinW(None, None, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
        return res == 0, None if res == 0 else f"SHEmptyRecycleBinW returned {res}"
    except Exception as e:
        return False, str(e)


def drive_letter_from_mountpoint(mp: str) -> str:
    # From "C:\" get "C:"
    if mp and len(mp) >= 2 and mp[1] == ":":
        return mp[:2]
    return ""


def get_fixed_drives():
    # Returns list of drive letters for fixed drives (e.g., ["C:", "D:"])
    drives = []
    try:
        parts = psutil.disk_partitions(all=False)
        for p in parts:
            opts = (p.opts or "").lower()
            if "fixed" in opts:
                dl = drive_letter_from_mountpoint(p.device)
                if dl and dl not in drives:
                    drives.append(dl)
    except Exception:
        pass
    # Always try to include C:
    if "C:" not in drives:
        drives.insert(0, "C:")
    return drives


def detect_drive_is_ssd(drive_letter: str) -> str:
    # Robust detection using IOCTL_STORAGE_QUERY_PROPERTY (StorageDeviceSeekPenaltyProperty)
    # If IncursSeekPenalty == False => SSD, True => HDD
    # drive_letter like "C:"
    try:
        path = f"\\\\.\\{drive_letter}"
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3

        handle = ctypes.windll.kernel32.CreateFileW(
            path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
        )
        if handle == ctypes.c_void_p(-1).value:
            # Try with read access
            handle = ctypes.windll.kernel32.CreateFileW(
                path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
            )
        if handle == ctypes.c_void_p(-1).value:
            return "Unknown"

        IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400
        StorageDeviceSeekPenaltyProperty = 7
        PropertyStandardQuery = 0

        class STORAGE_PROPERTY_QUERY(ctypes.Structure):
            _fields_ = [
                ("PropertyId", ctypes.c_int),
                ("QueryType", ctypes.c_int),
                ("AdditionalParameters", ctypes.c_byte * 1),
            ]

        class DEVICE_SEEK_PENALTY_DESCRIPTOR(ctypes.Structure):
            _fields_ = [
                ("Version", ctypes.c_uint),
                ("Size", ctypes.c_uint),
                ("IncursSeekPenalty", ctypes.c_byte),
            ]

        query = STORAGE_PROPERTY_QUERY()
        query.PropertyId = StorageDeviceSeekPenaltyProperty
        query.QueryType = PropertyStandardQuery
        query.AdditionalParameters = (ctypes.c_byte * 1)(0)

        desc = DEVICE_SEEK_PENALTY_DESCRIPTOR()
        bytes_returned = ctypes.c_ulong(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            ctypes.byref(query),
            ctypes.sizeof(query),
            ctypes.byref(desc),
            ctypes.sizeof(desc),
            ctypes.byref(bytes_returned),
            None
        )
        ctypes.windll.kernel32.CloseHandle(handle)
        if ok and bytes_returned.value >= ctypes.sizeof(desc):
            # False => No seek penalty => SSD; True => HDD
            return "SSD" if not bool(desc.IncursSeekPenalty) else "HDD"
        return "Unknown"
    except Exception:
        return "Unknown"


def parse_power_plans():
    # Returns dict: {friendly_name_lower: (GUID, is_active)}
    plans = {}
    rc, out, err = run_cmd("powercfg /list")
    if rc != 0:
        return plans
    # Lines like: "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *"
    pattern = re.compile(r"Power Scheme GUID:\s+([0-9a-fA-F\-]+)\s+KATEX_INLINE_OPEN(.+?)KATEX_INLINE_CLOSE(\s+\*)?$")
    for line in out.splitlines():
        m = pattern.search(line.strip())
        if m:
            guid = m.group(1).strip().lower()
            name = m.group(2).strip()
            active = bool(m.group(3))
            plans[name.lower()] = (guid, active)
    return plans


def get_active_power_plan_name():
    rc, out, err = run_cmd("powercfg /getactivescheme")
    if rc != 0:
        return "Unknown"
    m = re.search(r"Power Scheme GUID:\s+([0-9a-fA-F\-]+)\s+KATEX_INLINE_OPEN(.+?)KATEX_INLINE_CLOSE", out)
    if m:
        return m.group(2).strip()
    return "Unknown"


def set_power_plan_by_name(name: str):
    plans = parse_power_plans()
    # Map common synonyms
    name_l = name.strip().lower()
    name_candidates = [name_l]
    if name_l in ["balanced", "balance"]:
        name_candidates += ["balanced"]
    if name_l in ["high performance", "high-performance", "highperformance", "game mode", "game", "performance"]:
        name_candidates += ["high performance", "ultimate performance"]
    if name_l in ["battery saver", "power saver", "powersaver", "battery"]:
        name_candidates += ["power saver"]
    # Try to find matching plan
    for n in name_candidates:
        for plan_name, (guid, _) in plans.items():
            if n == plan_name or n in plan_name:
                rc, out, err = run_cmd(f"powercfg /setactive {guid}")
                return rc == 0, out if rc == 0 else err or out
    return False, "Requested power plan not found on this system."


def clear_browser_cache_for_dir(path: Path):
    # Remove contents if directory exists
    if path.exists():
        return delete_folder_contents(path)
    return 0, 0


def trim_working_sets(log_callback):
    # Try to reduce processes' working sets using EmptyWorkingSet
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_SET_QUOTA = 0x0100
    OpenProcess = ctypes.windll.kernel32.OpenProcess
    CloseHandle = ctypes.windll.kernel32.CloseHandle
    EmptyWorkingSet = ctypes.windll.psapi.EmptyWorkingSet

    before = psutil.virtual_memory().used
    n_ok = 0
    n_fail = 0
    for p in psutil.process_iter(attrs=["pid", "name"]):
        pid = p.info.get("pid")
        try:
            h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid)
            if h:
                try:
                    res = EmptyWorkingSet(h)
                    if res:
                        n_ok += 1
                    else:
                        n_fail += 1
                finally:
                    CloseHandle(h)
        except Exception:
            n_fail += 1
    after = psutil.virtual_memory().used
    freed = before - after
    log_callback(f"Trimmed working sets: success={n_ok}, failed={n_fail}, freed approx={format_bytes(max(freed,0))}")


# --------------------- GUI App ---------------------

class LogEmitter(QObject):
    message = pyqtSignal(str)


class PyOptimizer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AKOptimizer")
        self.setMinimumSize(1100, 700)
        try:
            self.setWindowIcon(QIcon(resource_path("opt.ico")))
        except Exception:
            pass

        self.is_admin = is_user_admin()

        # WMI client
        self.wmi = None
        if wmi_module is not None:
            try:
                self.wmi = wmi_module.WMI()
            except Exception:
                self.wmi = None

        # Logging
        self.log_emitter = LogEmitter()
        self.log_emitter.message.connect(self.append_log)

        # Build UI
        self._build_ui()

        # Timers
        self._start_timers()

        # Initial log + admin warning
        if not self.is_admin:
            self.append_log("Warning: Not running as Administrator. Some features may fail.")
        else:
            self.append_log("Running as Administrator.")

        # Populate initial data
        self.refresh_dashboard()
        self.refresh_services()
        self.refresh_startup()
        self.refresh_processes()
        self.refresh_power_tab()
        self.refresh_disk_tab()

    def _build_ui(self):
        main = QWidget()
        main_layout = QHBoxLayout(main)
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(6)
        self.setCentralWidget(main)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # Left nav
        self.nav = QListWidget()
        self.nav.addItems([
            "Dashboard", "Cleaner", "Services", "RAM", "Power", "Startup", "Processes", "Disk", "Network"
        ])
        self.nav.setFixedWidth(180)
        splitter.addWidget(self.nav)

        # Right content
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        splitter.addWidget(right_container)

        # Top admin bar
        top_bar = QHBoxLayout()
        self.admin_label = QLabel("Admin: YES" if self.is_admin else "Admin: NO")
        self.btn_elevate = QPushButton("Relaunch as Admin")
        self.btn_elevate.clicked.connect(self._on_elevate_clicked)
        top_bar.addWidget(self.admin_label)
        top_bar.addStretch(1)
        top_bar.addWidget(self.btn_elevate)
        right_layout.addLayout(top_bar)

        # Pages
        self.pages = QStackedWidget()
        right_layout.addWidget(self.pages, 1)

        # Global Log
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(160)
        right_layout.addWidget(self.log, 0)

        # Create pages
        self._build_page_dashboard()
        self._build_page_cleaner()
        self._build_page_services()
        self._build_page_ram()
        self._build_page_power()
        self._build_page_startup()
        self._build_page_processes()
        self._build_page_disk()
        self._build_page_network()

        # Signals
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(0)

    def _start_timers(self):
        # Dashboard refresh
        self.timer_dashboard = QTimer(self)
        self.timer_dashboard.timeout.connect(self.refresh_dashboard)
        self.timer_dashboard.start(1500)

        # Processes refresh
        self.timer_processes = QTimer(self)
        self.timer_processes.timeout.connect(self.refresh_processes)
        self.timer_processes.start(3000)

    def append_log(self, msg: str):
        # Timestamped message
        ts = time.strftime("%H:%M:%S")
        self.log.append(f"[{ts}] {msg}")
        self.log.moveCursor(self.log.textCursor().End)

    def emit_log(self, msg: str):
        self.log_emitter.message.emit(msg)

    def run_in_thread(self, func, *args, **kwargs):
        def wrapper():
            try:
                func(*args, **kwargs)
            except Exception as e:
                self.emit_log(f"Error: {e}\n{traceback.format_exc()}")
        t = threading.Thread(target=wrapper, daemon=True)
        t.start()
        return t

    # ------------------ Dashboard ------------------
    def _build_page_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        # CPU
        self.cpu_label = QLabel("CPU Usage: 0%")
        self.cpu_bar = QProgressBar()
        self.cpu_bar.setRange(0, 100)
        layout.addWidget(self.cpu_label)
        layout.addWidget(self.cpu_bar)

        # RAM
        self.ram_label = QLabel("RAM Usage: 0% (0/0)")
        self.ram_bar = QProgressBar()
        self.ram_bar.setRange(0, 100)
        layout.addWidget(self.ram_label)
        layout.addWidget(self.ram_bar)

        # Disk usage (C:)
        self.disk_label = QLabel("Disk C: Usage: 0% (0/0)")
        self.disk_bar = QProgressBar()
        self.disk_bar.setRange(0, 100)
        layout.addWidget(self.disk_label)
        layout.addWidget(self.disk_bar)

        # Power plan
        self.power_label = QLabel("Active Power Plan: Unknown")
        layout.addWidget(self.power_label)
        layout.addStretch(1)

        self.pages.addWidget(page)

    def refresh_dashboard(self):
        try:
            cpu = psutil.cpu_percent(interval=0.0)
            self.cpu_bar.setValue(int(cpu))
            self.cpu_label.setText(f"CPU Usage: {cpu:.1f}%")
        except Exception:
            pass
        try:
            vm = psutil.virtual_memory()
            used = vm.total - vm.available
            perc = vm.percent
            self.ram_bar.setValue(int(perc))
            self.ram_label.setText(f"RAM Usage: {perc:.1f}% ({format_bytes(used)}/{format_bytes(vm.total)})")
        except Exception:
            pass
        try:
            du = psutil.disk_usage("C:\\")
            self.disk_bar.setValue(int(du.percent))
            self.disk_label.setText(f"Disk C: Usage: {du.percent:.1f}% ({format_bytes(du.used)}/{format_bytes(du.total)})")
        except Exception:
            pass
        try:
            name = get_active_power_plan_name()
            self.power_label.setText(f"Active Power Plan: {name}")
        except Exception:
            pass

    # ------------------ Cleaner ------------------
    def _build_page_cleaner(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Cache Cleaner"))

        # Checkboxes
        self.chk_temp = QCheckBox("Clear %TEMP%")
        self.chk_wintemp = QCheckBox("Clear C:\\Windows\\Temp")
        self.chk_recycle = QCheckBox("Empty Recycle Bin")
        self.chk_chrome = QCheckBox("Clear Chrome cache (if found)")
        self.chk_edge = QCheckBox("Clear Edge cache (if found)")
        self.chk_firefox = QCheckBox("Clear Firefox cache (if found)")

        for w in [self.chk_temp, self.chk_wintemp, self.chk_recycle, self.chk_chrome, self.chk_edge, self.chk_firefox]:
            w.setChecked(True)
            layout.addWidget(w)

        self.btn_clean = QPushButton("Run Cleaner")
        self.btn_clean.clicked.connect(self._on_run_cleaner)
        layout.addWidget(self.btn_clean)
        layout.addStretch(1)

        self.pages.addWidget(page)

    def _on_run_cleaner(self):
        def task():
            total_files = 0
            total_bytes = 0

            # %TEMP%
            if self.chk_temp.isChecked():
                temp_path = Path(os.environ.get("TEMP") or os.environ.get("TMP") or "")
                f, b = delete_folder_contents(temp_path)
                total_files += f
                total_bytes += b
                self.emit_log(f"Cleared %TEMP%: files={f}, bytes={format_bytes(b)}")
            # C:\Windows\Temp
            if self.chk_wintemp.isChecked():
                f, b = delete_folder_contents(Path("C:\\Windows\\Temp"))
                total_files += f
                total_bytes += b
                self.emit_log(f"Cleared C:\\Windows\\Temp: files={f}, bytes={format_bytes(b)}")
            # Recycle Bin
            if self.chk_recycle.isChecked():
                ok, err = SHEmptyRecycleBin()
                if ok:
                    self.emit_log("Recycle Bin emptied.")
                else:
                    self.emit_log(f"Failed to empty Recycle Bin: {err or 'Unknown error'}")
            # Chrome
            if self.chk_chrome.isChecked():
                base = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"
                count_f = 0
                count_b = 0
                if base.exists():
                    for profile in base.glob("*"):
                        for sub in ["Cache", "Code Cache", "GPUCache"]:
                            p = profile / sub
                            f, b = clear_browser_cache_for_dir(p)
                            count_f += f
                            count_b += b
                    self.emit_log(f"Cleared Chrome caches: files={count_f}, bytes={format_bytes(count_b)}")
            # Edge
            if self.chk_edge.isChecked():
                base = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data"
                count_f = 0
                count_b = 0
                if base.exists():
                    for profile in base.glob("*"):
                        for sub in ["Cache", "Code Cache", "GPUCache"]:
                            p = profile / sub
                            f, b = clear_browser_cache_for_dir(p)
                            count_f += f
                            count_b += b
                    self.emit_log(f"Cleared Edge caches: files={count_f}, bytes={format_bytes(count_b)}")
            # Firefox
            if self.chk_firefox.isChecked():
                ff_base = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles"
                count_f = 0
                count_b = 0
                if ff_base.exists():
                    for prof in ff_base.glob("*.default*"):
                        p = prof / "cache2"
                        f, b = clear_browser_cache_for_dir(p)
                        count_f += f
                        count_b += b
                    self.emit_log(f"Cleared Firefox caches: files={count_f}, bytes={format_bytes(count_b)}")

            self.emit_log(f"Cleaner finished: total files removed={total_files}, total bytes={format_bytes(total_bytes)}")

        self.run_in_thread(task)

    # ------------------ Services ------------------
    def _build_page_services(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Services Optimizer"))
        self.table_services = QTableWidget(0, 4)
        self.table_services.setHorizontalHeaderLabels(["Name", "Display Name", "Status", "Start Mode"])
        self.table_services.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_services)

        btns = QHBoxLayout()
        self.btn_refresh_services = QPushButton("Refresh")
        self.btn_start_service = QPushButton("Start")
        self.btn_stop_service = QPushButton("Stop")
        self.btn_refresh_services.clicked.connect(self.refresh_services)
        self.btn_start_service.clicked.connect(self._on_start_service)
        self.btn_stop_service.clicked.connect(self._on_stop_service)
        for b in [self.btn_refresh_services, self.btn_start_service, self.btn_stop_service]:
            btns.addWidget(b)
        btns.addStretch(1)
        layout.addLayout(btns)

        layout.addStretch(1)
        self.pages.addWidget(page)

    def refresh_services(self):
        self.table_services.setRowCount(0)
        if self.wmi is None and win32serviceutil is None:
            self.append_log("WMI/pywin32 not available: cannot list services.")
            return
        try:
            rows = []
            if self.wmi is not None:
                for s in self.wmi.Win32_Service():
                    rows.append((s.Name or "", s.DisplayName or "", s.State or "", s.StartMode or ""))
            else:
                # Fallback using pywin32 service utils: only get names; state info limited
                # We'll try to get service names from win32serviceutil.EnumServicesStatus
                try:
                    import win32service
                    hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
                    statuses = win32service.EnumServicesStatus(hscm)
                    for (name, display, status) in statuses:
                        state = str(status[1])
                        rows.append((name, display, state, ""))
                except Exception as e:
                    self.append_log(f"Error listing services: {e}")
            for r in rows:
                row = self.table_services.rowCount()
                self.table_services.insertRow(row)
                for i, v in enumerate(r):
                    self.table_services.setItem(row, i, QTableWidgetItem(str(v)))
        except Exception as e:
            self.append_log(f"Failed to refresh services: {e}")

    def _selected_service_name(self):
        row = self.table_services.currentRow()
        if row < 0:
            return None
        item = self.table_services.item(row, 0)
        if not item:
            return None
        return item.text().strip()

    def _on_start_service(self):
        name = self._selected_service_name()
        if not name:
            QMessageBox.information(self, "Service", "Select a service first.")
            return
        if not confirm(self, "Confirm", f"Start service '{name}'?"):
            return

        def task():
            ok = False
            err = None
            if self.wmi is not None:
                try:
                    svc = self.wmi.Win32_Service(Name=name)
                    if svc:
                        rc, out = svc[0].StartService()
                        ok = (rc == 0)
                        err = f"WMI error code={rc}" if rc != 0 else None
                except Exception as e:
                    err = str(e)
            if (not ok) and (win32serviceutil is not None):
                try:
                    win32serviceutil.StartService(name)
                    ok = True
                except Exception as e:
                    err = str(e)
            if ok:
                self.emit_log(f"Service '{name}' started.")
            else:
                self.emit_log(f"Failed to start '{name}': {err or 'Unknown error'}")
            self.refresh_services()

        self.run_in_thread(task)

    def _on_stop_service(self):
        name = self._selected_service_name()
        if not name:
            QMessageBox.information(self, "Service", "Select a service first.")
            return
        if not confirm(self, "Confirm", f"Stop service '{name}'?"):
            return

        def task():
            ok = False
            err = None
            if self.wmi is not None:
                try:
                    svc = self.wmi.Win32_Service(Name=name)
                    if svc:
                        rc, out = svc[0].StopService()
                        ok = (rc == 0)
                        err = f"WMI error code={rc}" if rc != 0 else None
                except Exception as e:
                    err = str(e)
            if (not ok) and (win32serviceutil is not None):
                try:
                    win32serviceutil.StopService(name)
                    ok = True
                except Exception as e:
                    err = str(e)
            if ok:
                self.emit_log(f"Service '{name}' stopped.")
            else:
                self.emit_log(f"Failed to stop '{name}': {err or 'Unknown error'}")
            self.refresh_services()

        self.run_in_thread(task)

    # ------------------ RAM ------------------
    def _build_page_ram(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        self.ram_info_label = QLabel("RAM: Unknown")
        layout.addWidget(self.ram_info_label)

        self.btn_trim_ram = QPushButton("Trim Working Sets (Free RAM)")
        self.btn_trim_ram.clicked.connect(self._on_trim_ram)
        layout.addWidget(self.btn_trim_ram)

        layout.addStretch(1)
        self.pages.addWidget(page)

    def _on_trim_ram(self):
        if not confirm(self, "Confirm", "Trim working sets of background processes?\nThis may reduce RAM usage temporarily."):
            return

        def task():
            vm_before = psutil.virtual_memory()
            self.emit_log(f"RAM before: {format_bytes(vm_before.used)}/{format_bytes(vm_before.total)} used")
            try:
                trim_working_sets(self.emit_log)
            except Exception as e:
                self.emit_log(f"Trimming failed: {e}")
            vm_after = psutil.virtual_memory()
            freed = (vm_before.used - vm_after.used)
            self.emit_log(f"RAM after: {format_bytes(vm_after.used)}/{format_bytes(vm_after.total)} used; Freed approx {format_bytes(max(freed,0))}")

        self.run_in_thread(task)

        # Update small RAM info immediately
        vm = psutil.virtual_memory()
        self.ram_info_label.setText(f"RAM: {vm.percent:.1f}% used ({format_bytes(vm.used)}/{format_bytes(vm.total)})")

    # ------------------ Power ------------------
    def _build_page_power(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        self.power_current_label = QLabel("Active plan: Unknown")
        layout.addWidget(self.power_current_label)

        btns = QHBoxLayout()
        self.btn_power_balanced = QPushButton("Balanced")
        self.btn_power_high = QPushButton("High Performance")
        self.btn_power_saver = QPushButton("Battery Saver")
        for b in [self.btn_power_balanced, self.btn_power_high, self.btn_power_saver]:
            btns.addWidget(b)
        btns.addStretch(1)
        layout.addLayout(btns)

        self.btn_power_balanced.clicked.connect(lambda: self._on_switch_power("Balanced"))
        self.btn_power_high.clicked.connect(lambda: self._on_switch_power("High Performance"))
        self.btn_power_saver.clicked.connect(lambda: self._on_switch_power("Battery Saver"))

        self.power_plans_label = QLabel("Available plans: -")
        layout.addWidget(self.power_plans_label)
        layout.addStretch(1)

        self.pages.addWidget(page)

    def refresh_power_tab(self):
        try:
            active = get_active_power_plan_name()
            self.power_current_label.setText(f"Active plan: {active}")
            plans = parse_power_plans()
            names = [n.title() + (" [Active]" if a else "") for n, (_, a) in plans.items()]
            self.power_plans_label.setText("Available plans: " + ", ".join(names) if names else "Available plans: (none)")
        except Exception as e:
            self.append_log(f"Failed to refresh power plans: {e}")

    def _on_switch_power(self, plan_name: str):
        if not confirm(self, "Confirm", f"Switch power plan to '{plan_name}'?"):
            return

        def task():
            ok, msg = set_power_plan_by_name(plan_name)
            if ok:
                self.emit_log(f"Power plan switched to {plan_name}.")
            else:
                self.emit_log(f"Failed to switch power plan: {msg}")
            self.refresh_power_tab()
            self.refresh_dashboard()

        self.run_in_thread(task)

    # ------------------ Startup ------------------
    def _build_page_startup(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Startup Manager (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)"))
        layout.addWidget(QLabel("We move disabled items to 'RunDisabled' under the same path."))

        tables = QHBoxLayout()

        self.table_startup_enabled = QTableWidget(0, 2)
        self.table_startup_enabled.setHorizontalHeaderLabels(["Name", "Command"])
        self.table_startup_enabled.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tables.addWidget(self.table_startup_enabled)

        self.table_startup_disabled = QTableWidget(0, 2)
        self.table_startup_disabled.setHorizontalHeaderLabels(["Name", "Command"])
        self.table_startup_disabled.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tables.addWidget(self.table_startup_disabled)

        layout.addLayout(tables)

        # Controls
        form = QFormLayout()
        self.input_startup_name = QLineEdit()
        self.input_startup_cmd = QLineEdit()
        form.addRow("New Entry Name:", self.input_startup_name)
        form.addRow("Command (full path or command line):", self.input_startup_cmd)
        layout.addLayout(form)

        btns = QHBoxLayout()
        self.btn_startup_add = QPushButton("Add")
        self.btn_startup_disable = QPushButton("Disable Selected")
        self.btn_startup_enable = QPushButton("Enable Selected")
        self.btn_startup_delete = QPushButton("Delete Selected")
        self.btn_startup_refresh = QPushButton("Refresh")
        for b in [self.btn_startup_add, self.btn_startup_disable, self.btn_startup_enable, self.btn_startup_delete, self.btn_startup_refresh]:
            btns.addWidget(b)
        btns.addStretch(1)
        layout.addLayout(btns)

        self.btn_startup_add.clicked.connect(self._on_startup_add)
        self.btn_startup_disable.clicked.connect(self._on_startup_disable)
        self.btn_startup_enable.clicked.connect(self._on_startup_enable)
        self.btn_startup_delete.clicked.connect(self._on_startup_delete)
        self.btn_startup_refresh.clicked.connect(self.refresh_startup)

        layout.addStretch(1)
        self.pages.addWidget(page)

    def _reg_keys(self):
        # Return (enabled_key, disabled_key)
        import winreg
        base = r"Software\Microsoft\Windows\CurrentVersion"
        run = base + r"\Run"
        run_disabled = base + r"\RunDisabled"
        return winreg.HKEY_CURRENT_USER, run, run_disabled

    def refresh_startup(self):
        import winreg
        self.table_startup_enabled.setRowCount(0)
        self.table_startup_disabled.setRowCount(0)
        try:
            hroot, run_sub, run_disabled_sub = self._reg_keys()
            # Enabled
            try:
                rk = winreg.OpenKey(hroot, run_sub, 0, winreg.KEY_READ)
            except FileNotFoundError:
                rk = None
            if rk:
                try:
                    i = 0
                    while True:
                        name, val, typ = winreg.EnumValue(rk, i)
                        row = self.table_startup_enabled.rowCount()
                        self.table_startup_enabled.insertRow(row)
                        self.table_startup_enabled.setItem(row, 0, QTableWidgetItem(name))
                        self.table_startup_enabled.setItem(row, 1, QTableWidgetItem(str(val)))
                        i += 1
                except OSError:
                    pass
                finally:
                    rk.Close()
            # Disabled
            try:
                rk2 = winreg.OpenKey(hroot, run_disabled_sub, 0, winreg.KEY_READ)
            except FileNotFoundError:
                rk2 = None
            if rk2:
                try:
                    i = 0
                    while True:
                        name, val, typ = winreg.EnumValue(rk2, i)
                        row = self.table_startup_disabled.rowCount()
                        self.table_startup_disabled.insertRow(row)
                        self.table_startup_disabled.setItem(row, 0, QTableWidgetItem(name))
                        self.table_startup_disabled.setItem(row, 1, QTableWidgetItem(str(val)))
                        i += 1
                except OSError:
                    pass
                finally:
                    rk2.Close()
        except Exception as e:
            self.append_log(f"Startup refresh failed: {e}")

    def _on_startup_add(self):
        import winreg
        name = self.input_startup_name.text().strip()
        cmd = self.input_startup_cmd.text().strip()
        if not name or not cmd:
            QMessageBox.information(self, "Startup", "Please fill both Name and Command.")
            return
        if not confirm(self, "Confirm", f"Add startup entry '{name}'?"):
            return
        try:
            hroot, run_sub, _ = self._reg_keys()
            rk = winreg.CreateKeyEx(hroot, run_sub, 0, winreg.KEY_WRITE)
            with rk:
                winreg.SetValueEx(rk, name, 0, winreg.REG_SZ, cmd)
            self.append_log(f"Startup added: {name} -> {cmd}")
            self.refresh_startup()
        except Exception as e:
            self.append_log(f"Failed to add startup: {e}")

    def _on_startup_disable(self):
        import winreg
        row = self.table_startup_enabled.currentRow()
        if row < 0:
            QMessageBox.information(self, "Startup", "Select an enabled entry to disable.")
            return
        name = self.table_startup_enabled.item(row, 0).text().strip()
        cmd = self.table_startup_enabled.item(row, 1).text().strip()
        if not confirm(self, "Confirm", f"Disable startup '{name}'?"):
            return
        try:
            hroot, run_sub, run_disabled_sub = self._reg_keys()
            # Create disabled key if missing
            winreg.CreateKeyEx(hroot, run_disabled_sub, 0, winreg.KEY_WRITE).Close()
            # Move value
            with winreg.OpenKey(hroot, run_disabled_sub, 0, winreg.KEY_WRITE) as dst:
                winreg.SetValueEx(dst, name, 0, winreg.REG_SZ, cmd)
            with winreg.OpenKey(hroot, run_sub, 0, winreg.KEY_SET_VALUE) as src:
                try:
                    winreg.DeleteValue(src, name)
                except FileNotFoundError:
                    pass
            self.append_log(f"Disabled startup: {name}")
            self.refresh_startup()
        except Exception as e:
            self.append_log(f"Failed to disable startup: {e}")

    def _on_startup_enable(self):
        import winreg
        row = self.table_startup_disabled.currentRow()
        if row < 0:
            QMessageBox.information(self, "Startup", "Select a disabled entry to enable.")
            return
        name = self.table_startup_disabled.item(row, 0).text().strip()
        cmd = self.table_startup_disabled.item(row, 1).text().strip()
        if not confirm(self, "Confirm", f"Enable startup '{name}'?"):
            return
        try:
            hroot, run_sub, run_disabled_sub = self._reg_keys()
            with winreg.OpenKey(hroot, run_sub, 0, winreg.KEY_WRITE) as dst:
                winreg.SetValueEx(dst, name, 0, winreg.REG_SZ, cmd)
            with winreg.OpenKey(hroot, run_disabled_sub, 0, winreg.KEY_SET_VALUE) as src:
                try:
                    winreg.DeleteValue(src, name)
                except FileNotFoundError:
                    pass
            self.append_log(f"Enabled startup: {name}")
            self.refresh_startup()
        except Exception as e:
            self.append_log(f"Failed to enable startup: {e}")

    def _on_startup_delete(self):
        import winreg
        # Prefer delete from currently selected table
        def delete_from_table(table, run_sub):
            row = table.currentRow()
            if row < 0:
                return False
            name = table.item(row, 0).text().strip()
            if not confirm(self, "Confirm", f"Delete startup entry '{name}'? This cannot be undone."):
                return True  # considered handled
            try:
                hroot, run_real, run_disabled_sub = self._reg_keys()
                target = run_sub
                with winreg.OpenKey(hroot, target, 0, winreg.KEY_SET_VALUE) as key:
                    try:
                        winreg.DeleteValue(key, name)
                        self.append_log(f"Deleted startup entry: {name} from {target}")
                    except FileNotFoundError:
                        self.append_log(f"Startup entry not found: {name}")
                self.refresh_startup()
            except Exception as e:
                self.append_log(f"Failed to delete: {e}")
            return True

        import winreg
        hroot, run_sub, run_disabled_sub = self._reg_keys()
        # Try enabled table first; if nothing selected, try disabled
        if self.table_startup_enabled.currentRow() >= 0:
            delete_from_table(self.table_startup_enabled, run_sub)
        elif self.table_startup_disabled.currentRow() >= 0:
            delete_from_table(self.table_startup_disabled, run_disabled_sub)
        else:
            QMessageBox.information(self, "Startup", "Select an entry (enabled or disabled) to delete.")

    # ------------------ Processes ------------------
    def _build_page_processes(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Background Apps Killer"))

        self.table_procs = QTableWidget(0, 4)
        self.table_procs.setHorizontalHeaderLabels(["Name", "PID", "CPU %", "Memory (MB)"])
        self.table_procs.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_procs)

        btns = QHBoxLayout()
        self.btn_procs_refresh = QPushButton("Refresh")
        self.btn_procs_kill = QPushButton("End Task")
        btns.addWidget(self.btn_procs_refresh)
        btns.addWidget(self.btn_procs_kill)
        btns.addStretch(1)
        layout.addLayout(btns)

        self.btn_procs_refresh.clicked.connect(self.refresh_processes)
        self.btn_procs_kill.clicked.connect(self._on_kill_process)

        layout.addStretch(1)
        self.pages.addWidget(page)

    def refresh_processes(self):
        try:
            procs = []
            for p in psutil.process_iter(attrs=["pid", "name", "memory_info"]):
                try:
                    name = p.info["name"] or "?"
                    pid = p.info["pid"]
                    mem = p.info["memory_info"].rss if p.info["memory_info"] else 0
                    cpu = p.cpu_percent(interval=0.0)  # next refresh shows more accurate
                    procs.append((name, pid, cpu, mem))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            # Sort by memory desc
            procs.sort(key=lambda x: x[3], reverse=True)

            self.table_procs.setRowCount(0)
            for name, pid, cpu, mem in procs[:200]:  # limit to keep UI snappy
                row = self.table_procs.rowCount()
                self.table_procs.insertRow(row)
                self.table_procs.setItem(row, 0, QTableWidgetItem(str(name)))
                self.table_procs.setItem(row, 1, QTableWidgetItem(str(pid)))
                self.table_procs.setItem(row, 2, QTableWidgetItem(f"{cpu:.1f}"))
                self.table_procs.setItem(row, 3, QTableWidgetItem(f"{mem/1024/1024:.1f}"))
        except Exception as e:
            self.append_log(f"Failed to refresh processes: {e}")

    def _on_kill_process(self):
        row = self.table_procs.currentRow()
        if row < 0:
            QMessageBox.information(self, "Processes", "Select a process to end.")
            return
        name = self.table_procs.item(row, 0).text()
        pid = int(self.table_procs.item(row, 1).text())

        # Warn for critical/system processes
        critical_names = {
            "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe"
        }
        extra_warn = ""
        if name.lower() in {n.lower() for n in critical_names}:
            extra_warn = "\nWARNING: This looks like a system-critical process!"
        if not confirm(self, "Confirm", f"End task '{name}' (PID {pid})?{extra_warn}"):
            return

        def task():
            try:
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(3)
                    self.emit_log(f"Process {name} (PID {pid}) terminated.")
                except psutil.TimeoutExpired:
                    p.kill()
                    self.emit_log(f"Process {name} (PID {pid}) killed.")
            except Exception as e:
                self.emit_log(f"Failed to end {name} (PID {pid}): {e}")
            self.refresh_processes()

        self.run_in_thread(task)

    # ------------------ Disk ------------------
    def _build_page_disk(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Disk Optimizer"))

        hl = QHBoxLayout()
        hl.addWidget(QLabel("Drive:"))
        self.combo_drive = QComboBox()
        for d in get_fixed_drives():
            self.combo_drive.addItem(d)
        hl.addWidget(self.combo_drive)
        hl.addStretch(1)
        layout.addLayout(hl)

        self.disk_type_label = QLabel("Type: Unknown")
        layout.addWidget(self.disk_type_label)

        btns = QHBoxLayout()
        self.btn_disk_analyze = QPushButton("Analyze Drive Type")
        self.btn_disk_optimize = QPushButton("Optimize (Defrag for HDD)")
        self.btn_disk_trim_status = QPushButton("Query TRIM status")
        btns.addWidget(self.btn_disk_analyze)
        btns.addWidget(self.btn_disk_optimize)
        btns.addWidget(self.btn_disk_trim_status)
        btns.addStretch(1)
        layout.addLayout(btns)

        self.btn_disk_analyze.clicked.connect(self._on_disk_analyze)
        self.btn_disk_optimize.clicked.connect(self._on_disk_optimize)
        self.btn_disk_trim_status.clicked.connect(self._on_disk_trim_status)

        layout.addStretch(1)
        self.pages.addWidget(page)

    def refresh_disk_tab(self):
        # Auto detect on current selection
        self._on_disk_analyze()

    def _on_disk_analyze(self):
        drive = self.combo_drive.currentText()
        def task():
            dtype = detect_drive_is_ssd(drive)
            self.disk_type_label.setText(f"Type: {dtype}")
            self.emit_log(f"Drive {drive} detected as: {dtype}")
        self.run_in_thread(task)

    def _on_disk_optimize(self):
        drive = self.combo_drive.currentText()
        dtype = self.disk_type_label.text().replace("Type:", "").strip().upper()
        if dtype not in ["HDD", "SSD", "UNKNOWN"]:
            dtype = "UNKNOWN"
        if dtype == "SSD":
            if not confirm(self, "Confirm", f"{drive} appears to be SSD. TRIM is used instead of defrag. Run defrag anyway?"):
                return
        if not confirm(self, "Confirm", f"Optimize {drive} now? This may take a while."):
            return
        def task():
            rc, out, err = run_cmd(f"defrag {drive} /O")
            if rc == 0:
                self.emit_log(f"Defrag/Optimize {drive} completed:\n{out}")
            else:
                self.emit_log(f"Defrag/Optimize {drive} failed (rc={rc}):\n{err or out}")
        self.run_in_thread(task)

    def _on_disk_trim_status(self):
        # 'fsutil behavior query DisableDeleteNotify'
        def task():
            rc, out, err = run_cmd("fsutil behavior query DisableDeleteNotify")
            if rc == 0:
                self.emit_log("TRIM status:\n" + out)
            else:
                self.emit_log(f"TRIM query failed (rc={rc}):\n{err or out}")
        self.run_in_thread(task)

    # ------------------ Network ------------------
    def _build_page_network(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Network Optimizer"))

        btns = QHBoxLayout()
        self.btn_flush_dns = QPushButton("Flush DNS")
        self.btn_reset_winsock = QPushButton("Reset Winsock")
        btns.addWidget(self.btn_flush_dns)
        btns.addWidget(self.btn_reset_winsock)
        btns.addStretch(1)
        layout.addLayout(btns)

        self.btn_flush_dns.clicked.connect(self._on_flush_dns)
        self.btn_reset_winsock.clicked.connect(self._on_reset_winsock)

        layout.addStretch(1)
        self.pages.addWidget(page)

    def _on_flush_dns(self):
        def task():
            rc, out, err = run_cmd("ipconfig /flushdns")
            if rc == 0:
                self.emit_log("DNS cache flushed:\n" + out)
            else:
                self.emit_log(f"Failed to flush DNS (rc={rc}):\n{err or out}")
        self.run_in_thread(task)

    def _on_reset_winsock(self):
        if not confirm(self, "Confirm", "Reset Winsock? You may need to restart your PC afterwards."):
            return
        def task():
            rc, out, err = run_cmd("netsh winsock reset")
            if rc == 0:
                self.emit_log("Winsock reset completed:\n" + out)
            else:
                self.emit_log(f"Winsock reset failed (rc={rc}):\n{err or out}")
        self.run_in_thread(task)

    # ------------------ Admin Button ------------------
    def _on_elevate_clicked(self):
        if self.is_admin:
            QMessageBox.information(self, "Admin", "Already running as Administrator.")
            return
        if confirm(self, "Relaunch as Admin", "Relaunch PyOptimizer with Administrator privileges?"):
            relaunch_as_admin()

    # Ensure consistent updates
    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_dashboard()


def apply_dark_theme(app):
    if qdarkstyle is not None:
        try:
            app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt6'))
        except Exception:
            # Fallback attempt
            try:
                app.setStyleSheet(qdarkstyle.load_stylesheet())
            except Exception:
                pass


def main():
    if os.name != "nt":
        print("This application is intended for Windows 10/11.")
    app = QApplication(sys.argv)
    apply_dark_theme(app)
    app.setWindowIcon(QIcon(resource_path("opt.ico")))
    win = PyOptimizer()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
