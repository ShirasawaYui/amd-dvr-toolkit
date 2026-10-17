"""只读取证脚本（诊断用，非修复必需）。

对指定 PID 的 AMDRSServ.exe 做只读检查：模块清单、代码与磁盘比对、
窗口枚举能力。需要管理员权限；依赖 pefile。
用法：python inspect_dvr_readonly.py --pid <PID> --output out.json
注意：其中的 RVA 偏移针对 Adrenalin 26.20.15.02 的 AMDRSServ.exe，
其他版本结果可能不符。
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import datetime
import json
from pathlib import Path
import struct
import traceback

import pefile


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    result = {"time": datetime.datetime.now().isoformat(timespec="seconds"), "pid": args.pid}
    handle = None
    k = C.WinDLL("kernel32", use_last_error=True)
    u = C.WinDLL("user32", use_last_error=True)
    a = C.WinDLL("advapi32", use_last_error=True)
    ps = C.WinDLL("psapi", use_last_error=True)
    k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    k.OpenProcess.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    k.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, W.LPVOID, C.c_size_t, C.POINTER(C.c_size_t)]
    k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    k.GetCurrentProcess.restype = W.HANDLE
    a.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    a.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)]
    ps.EnumProcessModulesEx.argtypes = [W.HANDLE, C.POINTER(W.HMODULE), W.DWORD, C.POINTER(W.DWORD), W.DWORD]
    ps.GetModuleFileNameExW.argtypes = [W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD]
    ps.GetModuleInformation.argtypes = [W.HANDLE, W.HMODULE, W.LPVOID, W.DWORD]
    u.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
    u.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    callback_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    u.EnumWindows.argtypes = [callback_type, W.LPARAM]

    class ModuleInfo(C.Structure):
        _fields_ = [("base", C.c_void_p), ("size", W.DWORD), ("entry", C.c_void_p)]

    def read(address, length):
        buffer = C.create_string_buffer(length)
        actual = C.c_size_t()
        if not k.ReadProcessMemory(handle, address, buffer, length, C.byref(actual)):
            raise C.WinError(C.get_last_error())
        if actual.value != length:
            raise RuntimeError("Incomplete read at " + hex(address))
        return buffer.raw

    try:
        token = W.HANDLE()
        if not a.OpenProcessToken(k.GetCurrentProcess(), 8, C.byref(token)):
            raise C.WinError(C.get_last_error())
        try:
            for cls, label in [(20, "reader_elevated"), (26, "reader_uiaccess")]:
                value, size = W.DWORD(), W.DWORD()
                if not a.GetTokenInformation(token, cls, C.byref(value), 4, C.byref(size)):
                    raise C.WinError(C.get_last_error())
                result[label] = value.value
        finally:
            k.CloseHandle(token)
        if not result["reader_elevated"]:
            raise RuntimeError("Administrator confirmation was not granted")

        handle = k.OpenProcess(0x410, False, args.pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        path_buffer, path_size = C.create_unicode_buffer(32768), W.DWORD(32768)
        if not k.QueryFullProcessImageNameW(handle, 0, path_buffer, C.byref(path_size)):
            raise C.WinError(C.get_last_error())
        expected = Path("C:/Program Files/AMD/CNext/CNext/AMDRSServ.exe")
        if Path(path_buffer.value) != expected:
            raise RuntimeError("Unexpected process image: " + path_buffer.value)
        result["image"] = path_buffer.value

        modules = (W.HMODULE * 2048)()
        needed = W.DWORD()
        if not ps.EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
            raise C.WinError(C.get_last_error())
        if needed.value > C.sizeof(modules):
            raise RuntimeError("Module enumeration exceeds fixed read limit")
        rows = []
        for mod in modules[:needed.value // C.sizeof(W.HMODULE)]:
            name = C.create_unicode_buffer(32768)
            if not ps.GetModuleFileNameExW(handle, mod, name, len(name)):
                raise C.WinError(C.get_last_error())
            info = ModuleInfo()
            if not ps.GetModuleInformation(handle, mod, C.byref(info), C.sizeof(info)):
                raise C.WinError(C.get_last_error())
            rows.append({"path": name.value, "base": info.base, "size": info.size})
        result["modules"] = rows
        engine = next(row for row in rows if Path(row["path"]) == expected)
        base = engine["base"]
        pe = pefile.PE(str(expected))
        result["class_name"] = read(base + 0x1DBBD0, 40).decode("utf-16le").split("\0", 1)[0]
        result["code_checks"] = []
        for rva, length in [(0x37450, 0x85), (0x37770, 0x4C), (0x43A50, 0x50)]:
            live, disk = read(base + rva, length), pe.get_data(rva, length)
            item = {"rva": hex(rva), "length": length, "matches_disk": live == disk}
            if live != disk:
                item["runtime_bytes"] = live.hex()
                item["disk_bytes"] = disk.hex()
            result["code_checks"].append(item)
        result["interfaces"] = []
        for name, iat_rva in [("GetClassNameW", 0x1AAAB0), ("EnumWindows", 0x1AAAB8), ("SendMessageTimeoutW", 0x1AAAC8)]:
            address = int.from_bytes(read(base + iat_rva, 8), "little")
            owner = next((row for row in rows if row["base"] <= address < row["base"] + row["size"]), None)
            item = {"name": name, "address": hex(address), "module": owner["path"] if owner else None, "runtime_entry": read(address, 48).hex()}
            if owner:
                offset = address - owner["base"]
                disk_pe = pefile.PE(owner["path"])
                disk_entry = disk_pe.get_data(offset, 48)
                item.update({"rva": hex(offset), "matches_disk": bytes.fromhex(item["runtime_entry"]) == disk_entry, "disk_entry": disk_entry.hex()})
            result["interfaces"].append(item)
        windows = []

        @callback_type
        def visit(hwnd, unused):
            class_buffer = C.create_unicode_buffer(520)
            count = u.GetClassNameW(hwnd, class_buffer, 520)
            if count and class_buffer.value in ["CNEventWindowClass", "DVREventWindowClass"]:
                pid = W.DWORD()
                tid = u.GetWindowThreadProcessId(hwnd, C.byref(pid))
                windows.append({"hwnd": hex(hwnd), "pid": pid.value, "tid": tid, "class": class_buffer.value})
            return True

        result["admin_enum_result"] = bool(u.EnumWindows(visit, 0))
        result["admin_enum_windows"] = windows
        result["ok"] = True
    except Exception as exc:
        result["ok"] = False
        result["error"] = str(exc)
        result["detail"] = traceback.format_exc()
    finally:
        if handle:
            k.CloseHandle(handle)
        output = Path(args.output)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
