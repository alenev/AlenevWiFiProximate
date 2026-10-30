import ctypes
import ctypes.wintypes as wt
import os
import queue
import sys
import threading
import tkinter as tk
import traceback
import uuid
from tkinter import ttk, messagebox, simpledialog

RSSI_AT_1M = -30.0
PATH_LOSS_N = 3.0
REFRESH_MS = 2000

wlan = ctypes.WinDLL("wlanapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

LRESULT = ctypes.c_longlong
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
WM_APP_TRAY = 0x8000 + 0x100
WM_APP_CMD = 0x8000 + 0x101
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0203
NIM_ADD = 0
NIM_DELETE = 2
NIF_MESSAGE = 1
NIF_ICON = 2
NIF_TIP = 4

DOT11_BSS_TYPE_INFRA = 1
BSS_TYPE_ANY = 1
CONN_MODE_PROFILE = 0
CONN_MODE_UNSECURE = 3


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD),
                ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]


def guid_from_struct(g):
    return uuid.UUID(bytes_le=ctypes.string_at(ctypes.addressof(g), 16))


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", wt.ULONG), ("ucSSID", ctypes.c_ubyte * 32)]

    def text(self):
        return bytes(self.ucSSID[:self.uSSIDLength]).decode("utf-8", "replace")


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateLength", wt.ULONG), ("dot11RateSet", ctypes.c_ubyte * 126)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID), ("uPhyId", wt.ULONG),
                ("dot11Bssid", ctypes.c_ubyte * 6), ("dot11BssType", ctypes.c_int),
                ("dot11BssPhyType", ctypes.c_int), ("lRssi", wt.LONG),
                ("uLinkQuality", wt.ULONG), ("bInRegDomain", ctypes.c_ubyte),
                ("usBeaconPeriod", ctypes.c_ushort),
                ("ullTimestamp", ctypes.c_ulonglong),
                ("ullHostTimestamp", ctypes.c_ulonglong),
                ("usCapabilityInformation", ctypes.c_ushort),
                ("ulChCenterFrequency", wt.ULONG),
                ("rateSet", WLAN_RATE_SET),
                ("ulIeOffset", wt.ULONG), ("ulIeSize", wt.ULONG)]


MIN_STRIDE = ctypes.sizeof(WLAN_BSS_ENTRY)
MAX_STRIDE = 1024


def entry_plausible(addr):
    e = WLAN_BSS_ENTRY.from_address(addr)
    n = int(e.dot11Ssid.uSSIDLength)
    if n < 0 or n > 32:
        return False, None
    rssi = int(e.lRssi)
    if not (-110 <= rssi <= -1):
        return False, None
    return True, e


def read_entry(addr):
    ok, e = entry_plausible(addr)
    if not ok:
        return None
    return {
        "ssid": e.dot11Ssid.text(),
        "rssi": int(e.lRssi),
        "bssid": mac_text(bytes(e.dot11Bssid)),
        "freq_khz": int(e.ulChCenterFrequency),
    }


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wt.ULONG), ("dwIndex", wt.ULONG),
                ("wlanBssEntry", WLAN_BSS_ENTRY * 1)]


class WLAN_PROFILE_INFO(ctypes.Structure):
    _fields_ = [("strProfileName", wt.WCHAR * 256), ("dwFlags", wt.DWORD)]


class WLAN_PROFILE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wt.ULONG), ("dwIndex", wt.ULONG),
                ("ProfileInfo", WLAN_PROFILE_INFO * 1)]


class WLAN_CONNECTION_PARAMETERS(ctypes.Structure):
    _fields_ = [("wlanConnectionMode", ctypes.c_int), ("strProfile", wt.LPCWSTR),
                ("pDot11Ssid", ctypes.POINTER(DOT11_SSID)),
                ("pDesiredBssidList", ctypes.c_void_p),
                ("dot11BssType", ctypes.c_int), ("dwFlags", wt.DWORD)]


wlan.WlanOpenHandle.argtypes = [wt.DWORD, ctypes.c_void_p, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.HANDLE)]
wlan.WlanCloseHandle.argtypes = [wt.HANDLE, ctypes.c_void_p]
wlan.WlanEnumInterfaces.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
wlan.WlanGetNetworkBssList.argtypes = [wt.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(DOT11_SSID), ctypes.c_int, wt.BOOL, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
wlan.WlanFreeMemory.argtypes = [ctypes.c_void_p]
wlan.WlanConnect.argtypes = [wt.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(WLAN_CONNECTION_PARAMETERS), ctypes.c_void_p]
wlan.WlanDisconnect.argtypes = [wt.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p]
wlan.WlanSetProfile.argtypes = [wt.HANDLE, ctypes.POINTER(GUID), wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.BOOL, ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
wlan.WlanGetProfileList.argtypes = [wt.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wt.UINT), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wt.HINSTANCE), ("hIcon", wt.HANDLE),
                ("hCursor", wt.HANDLE), ("hbrBackground", wt.HANDLE),
                ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR)]


class MSG(ctypes.Structure):
    _fields_ = [("hwnd", wt.HWND), ("message", wt.UINT), ("wParam", wt.WPARAM),
                ("lParam", wt.LPARAM), ("time", wt.DWORD),
                ("ptx", wt.LONG), ("pty", wt.LONG)]


class NOTIFYICONDATAW(ctypes.Structure):
    _anonymous_ = []
    _fields_ = [("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT),
                ("uFlags", wt.UINT), ("uCallbackMessage", wt.UINT),
                ("hIcon", wt.HANDLE), ("szTip", wt.WCHAR * 128),
                ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD),
                ("szInfo", wt.WCHAR * 256), ("uVersion", wt.UINT),
                ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
                ("guidItem", GUID), ("hBalloonIcon", wt.HANDLE)]


user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   wt.HWND, wt.HANDLE, wt.HINSTANCE, wt.LPVOID]
user32.CreateWindowExW.restype = wt.HWND
user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wt.HWND, wt.UINT, wt.UINT]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.DestroyWindow.argtypes = [wt.HWND]
user32.LoadIconW.argtypes = [wt.HINSTANCE, wt.LPCWSTR]
user32.LoadImageW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, wt.UINT, ctypes.c_int, ctypes.c_int, wt.UINT]
user32.LoadImageW.restype = wt.HANDLE
user32.RegisterWindowMessageW.argtypes = [wt.LPCWSTR]
user32.RegisterWindowMessageW.restype = wt.UINT


class POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


user32.CreatePopupMenu.restype = wt.HANDLE
user32.AppendMenuW.argtypes = [wt.HANDLE, wt.UINT, ctypes.c_void_p, wt.LPCWSTR]
user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.TrackPopupMenuEx.argtypes = [wt.HANDLE, wt.UINT, ctypes.c_int, ctypes.c_int, wt.HWND, ctypes.c_void_p]
user32.TrackPopupMenuEx.restype = wt.BOOL
user32.DestroyMenu.argtypes = [wt.HANDLE]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAY_ICO = os.path.join(BASE_DIR, "AlenevWiFiProximate_tray.ico")
WINDOW_ICO = os.path.join(BASE_DIR, "AlenevWiFiProximate_window.ico")
shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]


class TrayIcon:
    def __init__(self, tip):
        self.tip = tip
        self.events = queue.Queue()
        self.hwnd = None
        self.nid = None
        self.shown = False
        self.msg_taskbar = 0
        self.ready = threading.Event()
        self.cls_name = "AlenevWiFiProximateTrayWnd"
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.wait(5)

    def _run(self):
        wc = WNDCLASSW()
        wc.lpfnWndProc = WNDPROC(self._wndproc)
        wc.hInstance = kernel32.GetModuleHandleW(None)
        wc.lpszClassName = self.cls_name
        user32.RegisterClassW(ctypes.byref(wc))
        self.hwnd = user32.CreateWindowExW(0, self.cls_name, "", 0, 0, 0, 0, 0,
                                           None, None, wc.hInstance, None)
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 0x4e57
        nid.uCallbackMessage = WM_APP_TRAY
        nid.szTip = self.tip
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        cx = user32.GetSystemMetrics(49)
        cy = user32.GetSystemMetrics(50)
        h = user32.LoadImageW(None, TRAY_ICO, 1, cx, cy, 0x10)
        if not h:
            h = user32.LoadIconW(None, wt.LPCWSTR(32512))
        nid.hIcon = h
        self.nid = nid
        self.msg_taskbar = user32.RegisterWindowMessageW("TaskbarCreated")
        self.ready.set()
        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.DispatchMessageW(ctypes.byref(msg))

    def _add_icon(self):
        if self.nid:
            rc = shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self.nid))
            if rc:
                self.shown = True

    def _wndproc(self, hwnd, msg, wp, lp):
        if msg == WM_APP_TRAY:
            if lp == WM_LBUTTONUP:
                self.events.put("L")
            elif lp == WM_RBUTTONUP:
                self._track_menu(hwnd)
            return 0
        if msg == self.msg_taskbar:
            if self.shown:
                self._add_icon()
            return 0
        if msg == WM_APP_CMD:
            if wp == 1:
                self._add_icon()
            elif wp == 2:
                self.shown = False
                self._strip_icon()
            return 0
        if msg == 0x0010:
            user32.DestroyWindow(hwnd)
            return 0
        if msg == 0x0002:
            self._strip_icon()
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wp, lp)

    MENU_ITEMS = [(1, 0, "Показати/ховати вікно"),
                  (0, 0x00000800, None),
                  (3, 0, "Вийти з AlenevWiFiProximate")]

    def _track_menu(self, hwnd):
        m = user32.CreatePopupMenu()
        for cmd, flags, label in self.MENU_ITEMS:
            user32.AppendMenuW(m, flags, cmd, label)
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(hwnd)
        cmd = user32.TrackPopupMenuEx(m, 0x0102, pt.x, pt.y, hwnd, None)
        user32.PostMessageW(hwnd, 0, 0, 0)
        user32.DestroyMenu(m)
        if cmd == 1:
            self.events.put("menu_toggle")
        elif cmd == 3:
            self.events.put("menu_quit")

    def _strip_icon(self):
        if self.nid:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.nid))

    def show_icon(self):
        if self.hwnd:
            user32.PostMessageW(self.hwnd, WM_APP_CMD, 1, 0)

    def remove_icon(self):
        if self.hwnd:
            user32.PostMessageW(self.hwnd, WM_APP_CMD, 2, 0)

    def stop(self):
        self._strip_icon()
        self.nid = None
        if self.hwnd:
            user32.PostMessageW(self.hwnd, 0x0010, 0, 0)
            self.thread.join(2)


def xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def as_guid(g):
    if isinstance(g, uuid.UUID):
        s = GUID()
        ctypes.memmove(ctypes.byref(s), g.bytes_le, 16)
        return s
    return g


def distance_from_rssi(rssi):
    d = 10 ** ((RSSI_AT_1M - rssi) / (10.0 * PATH_LOSS_N))
    return max(d, 0.01)


def mac_text(b):
    return ":".join(f"{x:02X}" for x in b)


class Scanner:
    def __init__(self):
        self.h = wt.HANDLE()
        ver = wt.DWORD()
        rc = wlan.WlanOpenHandle(2, None, ctypes.byref(ver), ctypes.byref(self.h))
        if rc != 0:
            raise OSError(f"WlanOpenHandle error {rc}")
        ifl = ctypes.c_void_p()
        rc = wlan.WlanEnumInterfaces(self.h, None, ctypes.byref(ifl))
        if rc != 0:
            raise OSError(f"WlanEnumInterfaces error {rc}")
        hdr = ctypes.cast(ifl.value, ctypes.POINTER(wt.DWORD * 2)).contents
        count = hdr[0]
        base = ifl.value + 8
        self.interfaces = []
        size = ctypes.sizeof(GUID)
        for i in range(int(count)):
            src = GUID.from_address(base + i * size)
            g = GUID()
            ctypes.memmove(ctypes.byref(g), ctypes.byref(src), size)
            self.interfaces.append(g)
        wlan.WlanFreeMemory(ifl)

    def close(self):
        if self.h:
            wlan.WlanCloseHandle(self.h, None)
            self.h = None

    def bss_scan(self, iface):
        p = ctypes.c_void_p()
        rc = wlan.WlanGetNetworkBssList(self.h, ctypes.byref(iface), None, BSS_TYPE_ANY, False, None, ctypes.byref(p))
        if rc != 0:
            return []
        lst = ctypes.cast(p.value, ctypes.POINTER(WLAN_BSS_LIST)).contents
        n = int(lst.dwNumberOfItems)
        base = ctypes.addressof(lst.wlanBssEntry[0])
        out = []
        try:
            stride = None
            off = 0
            guard = 0
            while off < (n + 1) * MIN_STRIDE and guard < 5000:
                guard += 1
                rec = read_entry(base + off)
                if rec is None:
                    break
                out.append(rec)
                if stride is None:
                    for cand in range(MIN_STRIDE, MAX_STRIDE + 1, 4):
                        ok1, _ = entry_plausible(base + off + cand)
                        ok2, _ = entry_plausible(base + off + 2 * cand)
                        if ok1 and ok2:
                            stride = cand
                            break
                    if stride is None:
                        break
                off += stride
        finally:
            wlan.WlanFreeMemory(p)
        return out

    def profiles(self, iface):
        p = ctypes.c_void_p()
        rc = wlan.WlanGetProfileList(self.h, ctypes.byref(iface), None, ctypes.byref(p))
        if rc != 0:
            return set()
        lst = ctypes.cast(p.value, ctypes.POINTER(WLAN_PROFILE_INFO_LIST)).contents
        n = int(lst.dwNumberOfItems)
        base = ctypes.addressof(lst.ProfileInfo[0])
        esz = ctypes.sizeof(WLAN_PROFILE_INFO)
        names = set()
        for i in range(n):
            names.add(ctypes.wstring_at(base + i * esz))
        wlan.WlanFreeMemory(p)
        return names

    def disconnect(self, guid):
        return wlan.WlanDisconnect(self.h, ctypes.byref(as_guid(guid)), None)

    def connect_profile(self, guid, name):
        self.disconnect(guid)
        p = WLAN_CONNECTION_PARAMETERS(CONN_MODE_PROFILE, name, None, None, DOT11_BSS_TYPE_INFRA, 0)
        rc = wlan.WlanConnect(self.h, ctypes.byref(as_guid(guid)), ctypes.byref(p), None)
        return rc

    def connect_open(self, guid, ssid):
        self.disconnect(guid)
        s = DOT11_SSID()
        raw = ssid.encode("utf-8")[:32]
        s.uSSIDLength = len(raw)
        ctypes.memmove(s.ucSSID, raw, len(raw))
        p = WLAN_CONNECTION_PARAMETERS(CONN_MODE_UNSECURE, None, ctypes.pointer(s), None, DOT11_BSS_TYPE_INFRA, 0)
        return wlan.WlanConnect(self.h, ctypes.byref(as_guid(guid)), ctypes.byref(p), None)

    def add_profile(self, guid, ssid, key):
        self.disconnect(guid)
        xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
<name>{xml_escape(ssid)}</name>
<SSIDConfig><SSID><name>{xml_escape(ssid)}</name></SSID></SSIDConfig>
<connectionType>ESS</connectionType>
<MSM><security>
<authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>{xml_escape(key)}</keyMaterial></sharedKey>
</security></MSM></WLANProfile>'''
        reason = wt.DWORD()
        rc = wlan.WlanSetProfile(self.h, ctypes.byref(as_guid(guid)), 0, xml, None, True, None, ctypes.byref(reason))
        if rc != 0:
            return rc, reason.value
        return self.connect_profile(guid, ssid)


def merged_networks(scanner):
    radios = {}
    for iface in scanner.interfaces:
        recs = scanner.bss_scan(iface)
        profiles = scanner.profiles(iface)
        for r in recs:
            r["guid"] = guid_from_struct(iface)
            key = (r["guid"], r["ssid"], r["bssid"])
            if key not in radios or r["rssi"] > radios[key]["rssi"]:
                radios[key] = r
    nets = {}
    for key in sorted(radios):
        if key[1] == "":
            continue
        r = radios[key]
        ssid = r["ssid"]
        if ssid not in nets:
            nets[ssid] = {"ssid": ssid, "best": r, "bssids": {key[2]}, "guid": r["guid"],
                          "profile": ssid in profiles}
            continue
        n = nets[ssid]
        n["bssids"].add(key[2])
        if r["rssi"] > n["best"]["rssi"]:
            n["best"] = r
            n["guid"] = r["guid"]
        n["profile"] = n["profile"] or ssid in profiles
    for n in nets.values():
        n["count"] = len(n["bssids"])
        n["dist"] = distance_from_rssi(n["best"]["rssi"])
    return sorted(nets.values(), key=lambda n: n["best"]["rssi"], reverse=True)


class App(tk.Tk):
    def report_callback_exception(self, exc, val, tb):
        if hasattr(sys, "excepthook") and sys.excepthook:
            sys.excepthook(exc, val, tb)

    def __init__(self):
        super().__init__()
        self.title("AlenevWiFiProximate — найближчі Wi-Fi точки")
        window_png = os.path.join(BASE_DIR, "icon_window_big.png")
        if os.path.isfile(window_png):
            try:
                self.iconphoto(True, tk.PhotoImage(file=window_png))
            except tk.TclError:
                pass
        self.after(120, self.set_native_icons)
        self.geometry("760x520")
        self.scanner = None
        self.rows = []
        cols = ("dist", "rssi", "ssid", "mac", "n", "prof")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        heads = [("dist", "Відстань", 90), ("rssi", "RSSI dBm", 80),
                 ("ssid", "SSID", 240), ("mac", "MAC (найсильніший)", 150),
                 ("n", "BSSIDs", 60), ("prof", "Профіль", 60)]
        for k, t, w in heads:
            self.tree.heading(k, text=t)
            self.tree.column(k, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        self.tree.bind("<Double-1>", lambda e: self.connect())
        self.tree.bind("<<TreeviewSelect>>", lambda e: None)
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(bar, text="Оновити", command=self.refresh_now).pack(side="left")
        ttk.Button(bar, text="Підключити", command=self.connect).pack(side="left", padx=6)
        self.status = ttk.Label(bar, text="")
        self.status.pack(side="right")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.tray = TrayIcon("AlenevWiFiProximate")
        self.tray.show_icon()
        self.after(100, self.boot)
        self.after(150, self.poll_tray)

    def poll_tray(self):
        try:
            while True:
                ev = self.tray.events.get_nowait()
                if ev == "L":
                    if self.state() == "withdrawn":
                        self.restore()
                    else:
                        self.to_tray()
                elif ev == "menu_show":
                    self.restore()
                elif ev == "menu_toggle":
                    if self.state() == "withdrawn":
                        self.restore()
                elif ev == "menu_quit":
                    self.quit_app()
        except queue.Empty:
            pass
        self.after(150, self.poll_tray)

    def to_tray(self):
        self.withdraw()

    def restore(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_app(self):
        if self.scanner:
            self.scanner.close()
        self.tray.stop()
        self.destroy()

    def on_close(self):
        self.to_tray()

    def set_native_icons(self):
        try:
            self.update_idletasks()
            hwnd = user32.GetAncestor(self.winfo_id(), 2)
            if not hwnd:
                self.after(500, self.set_native_icons)
                return
            smx = user32.GetSystemMetrics(49)
            h_small = user32.LoadImageW(None, WINDOW_ICO, 1, smx, user32.GetSystemMetrics(50), 0x10)
            h_big = user32.LoadImageW(None, WINDOW_ICO, 1, 48, 48, 0x10)
            if h_small:
                user32.SendMessageW(hwnd, 0x0080, 0, h_small)
            if h_big:
                user32.SendMessageW(hwnd, 0x0080, 1, h_big)
            if not h_small or not h_big:
                self.after(500, self.set_native_icons)
        except Exception:
            sys.excepthook(*sys.exc_info())
            self.after(1000, self.set_native_icons)

    def boot(self):
        try:
            self.scanner = Scanner()
        except OSError as e:
            messagebox.showerror("Помилка", str(e))
            self.after(3000, self.boot)
            return
        self.refresh_now()
        self.after(REFRESH_MS, self.tick)

    def tick(self):
        self.refresh_now()
        self.after(REFRESH_MS, self.tick)

    def refresh_now(self):
        if not self.scanner:
            return
        try:
            nets = merged_networks(self.scanner)
        except OSError as e:
            self.status.config(text=str(e))
            return
        self.rows = []
        self.tree.delete(*self.tree.get_children())
        for n in nets:
            d = n["dist"]
            rssi = n["best"]["rssi"]
            vals = (f"{d:.1f} м", str(rssi), n["ssid"], n["best"]["bssid"],
                    str(n["count"]), "\u2705" if n["profile"] else "")
            self.tree.insert("", "end", values=vals)
            self.rows.append(n)

    def selected(self):
        sel = self.tree.selection()
        if not sel:
            return None
        idx = self.tree.index(sel[0])
        return self.rows[idx] if idx < len(self.rows) else None

    def connect(self):
        n = self.selected()
        if not n:
            self.status.config(text="Оберіть мережу")
            return
        ssid = n["ssid"]
        guid = n["guid"]
        if n["profile"]:
            rc = self.scanner.connect_profile(guid, ssid)
            self.report(rc)
            return
        open_net = messagebox.askyesno("Профіль", f"Для '{ssid}' немає збереженого профілю.\nМережа відкрита (без пароля)?")
        if open_net:
            rc = self.scanner.connect_open(guid, ssid)
            self.report(rc, created_profile=True)
            return
        key = simpledialog.askstring("Пароль", f"Пароль WPA2 для '{ssid}':", show="\u2022", parent=self)
        if not key:
            return
        rc, reason = self.scanner.add_profile(guid, ssid, key)
        if rc == 0 and n["count"] > 0:
            self.on_profile_added(ssid)
        self.report(rc, reason=reason)

    def on_profile_added(self, ssid):
        profiles = set()
        for iface in self.scanner.interfaces:
            profiles |= self.scanner.profiles(iface)
        for row in self.rows:
            if row["ssid"] == ssid:
                row["profile"] = ssid in profiles

    def report(self, rc, reason=None, created_profile=False):
        if rc == 0:
            self.status.config(text="Запит на підключення надіслано")
        else:
            msg = f"Помилка {rc}"
            if rc == 5:
                msg = "Помилка 5: доступ заборонений (запустіть від адміністратора)"
            if reason and reason:
                msg += f" (причина {reason})"
            self.status.config(text=msg)
            messagebox.showerror("Підключення", msg)


def fatal_hook(tp, val, tb):
    text = "".join(traceback.format_exception(tp, val, tb))
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "error.log"), "a",
                  encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass
    user32.MessageBoxW(None, text, "Wi-Fi Nearest \u2013 помилка", 0x10)


if __name__ == "__main__":
    try:
        shell32.SetCurrentProcessExplicitAppUserModelID("Alenev.AlenevWiFiProximate")
    except Exception:
        pass
    sys.excepthook = fatal_hook
    app = App()
    try:
        app.mainloop()
    except BaseException:
        tp, val, tb = sys.exc_info()
        fatal_hook(tp, val, tb)
        app.quit_app()
        raise
