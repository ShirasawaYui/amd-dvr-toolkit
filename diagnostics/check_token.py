# 轻量只读：读取指定 PID 的令牌属性（Elevation / UIAccess / Integrity Level）
# 用法：python check_token.py <pid>
import ctypes as C
from ctypes import wintypes as W
import sys

pid = int(sys.argv[1])
k = C.WinDLL("kernel32", use_last_error=True)
a = C.WinDLL("advapi32", use_last_error=True)

k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
k.OpenProcess.restype = W.HANDLE
a.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
a.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]

h = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
if not h:
    print("OpenProcess failed:", C.get_last_error())
    sys.exit(1)
token = W.HANDLE()
if not a.OpenProcessToken(h, 0x0008, C.byref(token)):  # TOKEN_QUERY
    print("OpenProcessToken failed:", C.get_last_error())
    sys.exit(1)

for cls, name in [(20, "Elevation(是否提升)"), (26, "UIAccess")]:
    val, size = W.DWORD(), W.DWORD()
    if a.GetTokenInformation(token, cls, C.byref(val), 4, C.byref(size)):
        print(f"{name} = {val.value}")
    else:
        print(f"{name} = <读取失败 {C.get_last_error()}>")


class SID_AND_ATTRIBUTES(C.Structure):
    _fields_ = [("Sid", C.c_void_p), ("Attributes", W.DWORD)]


class TOKEN_MANDATORY_LABEL(C.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


size = W.DWORD()
if a.GetTokenInformation(token, 25, None, 0, C.byref(size)):
    pass
buf = C.create_string_buffer(size.value)
if a.GetTokenInformation(token, 25, buf, size.value, C.byref(size)):
    tml = C.cast(buf, C.POINTER(TOKEN_MANDATORY_LABEL)).contents
    a.GetSidSubAuthorityCount.argtypes = [C.c_void_p]
    a.GetSidSubAuthorityCount.restype = C.POINTER(C.c_ubyte)
    a.GetSidSubAuthority.argtypes = [C.c_void_p, W.DWORD]
    a.GetSidSubAuthority.restype = C.POINTER(W.DWORD)
    cnt = a.GetSidSubAuthorityCount(tml.Label.Sid).contents.value
    rid = a.GetSidSubAuthority(tml.Label.Sid, cnt - 1).contents.value
    labels = {0x0000: "Untrusted", 0x1000: "Low", 0x2000: "Medium", 0x2100: "MediumPlus", 0x3000: "High", 0x4000: "System"}
    print(f"IntegrityLevel = 0x{rid:x} ({labels.get(rid, '?')})")
else:
    print("IntegrityLevel = <读取失败", C.get_last_error(), ">")
