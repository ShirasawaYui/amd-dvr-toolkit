#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AMDRSServ.exe 修复器：2 字节长度补丁 + 清单 uiAccess 修复（统一入口）。

背景：
  - 类名读取越界：偏移 0x3686B 处把 0x208(520字符) 改为 0x100(256字符)，
    修复 998 越界导致的“静默失败”。
  - uiAccess 门槛：声明 uiAccess="true" 的 exe 一旦签名失效，Windows 拒绝
    启动（弹窗“从服务器返回了一个参照”）。因此 2 字节补丁必须配合清单修复。

处理状态（自动识别；所有改写均为等长替换、文件大小不变）：
  - original_untouched ：原始文件 → --apply 一并完成两步
  - needs_manifest_fix ：已打 2 字节补丁、清单未改 → --apply 只改清单
  - already_fixed      ：两步均已完成 → 不动作
  - unexpected         ：与已知版本不符（如 AMD 已更新程序）→ 拒绝动作

两步改写：
  1) 偏移 0x3686B：08 02 -> 00 01
  2) 清单：uiAccess="true"></requestedExecutionLevel>\\r\\n
         -> uiAccess="false"></requestedExecutionLevel>\\n（+1/-1 字节保持长度）

用法: python patch_manifest.py --check|--apply [--exe PATH] --out X.json
依赖: Python 3.8+；pefile 为可选依赖（安装后多一层清单资源区 XML 校验）。
"""
import argparse
import hashlib
import json
from pathlib import Path

try:
    import pefile
except ImportError:  # pefile 为可选依赖：缺失时跳过清单资源区结构校验
    pefile = None
import xml.dom.minidom as MD

DEFAULT_EXE = r"C:\Program Files\AMD\CNext\CNext\AMDRSServ.exe"

SHA_ORIGINAL = "0f28b30898024e49709f5d90ce64d6616ff2fb71f8822f394eafce05d5e450c9"
SHA_PATCHED = "1ae3fcc541677b70ad210370453f7ece4a4b4895e1b173327ab2df8ad88194ba"
SHA_FIXED = "72099cb617109805d5fb79cc345ee3908bf1ec27c6b728df84ecf0b8f7a5f840"

LENGTH_OFFSET = 0x3686B
LENGTH_OLD = b"\x08\x02"
LENGTH_NEW = b"\x00\x01"
MAN_OLD = b'uiAccess="true"></requestedExecutionLevel>\r\n'
MAN_NEW = b'uiAccess="false"></requestedExecutionLevel>\n'
assert len(LENGTH_OLD) == len(LENGTH_NEW), "length replacement must keep size"
assert len(MAN_OLD) == len(MAN_NEW), "manifest replacement must keep size"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def manifest_region(data: bytes):
    """返回 RT_MANIFEST 资源区在文件中的 (offset, size)；找不到返回 None。"""
    pe = pefile.PE(data=data)
    for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if e.struct.Id == 24:  # RT_MANIFEST
            for r in e.directory.entries:
                for d in r.directory.entries:
                    return pe.get_offset_from_rva(d.data.struct.OffsetToData), d.data.struct.Size
    return None


def inspect(data: bytes):
    h = sha256(data)
    n_old, n_new = data.count(MAN_OLD), data.count(MAN_NEW)
    at = data[LENGTH_OFFSET:LENGTH_OFFSET + 2]
    if h == SHA_FIXED and at == LENGTH_NEW and n_old == 0 and n_new == 1:
        return "already_fixed", "两步修改均已完成，无需动作"
    if h == SHA_ORIGINAL and at == LENGTH_OLD and n_old == 1 and n_new == 0:
        return "original_untouched", "原始文件：将一并应用 2 字节补丁与清单修复"
    if h == SHA_PATCHED and at == LENGTH_NEW and n_old == 1 and n_new == 0:
        return "needs_manifest_fix", "已打 2 字节补丁，待修复清单（uiAccess true->false）"
    return "unexpected", ("状态与已知版本不符（sha=%s..., 长度位=%s, uiAccess旧=%d/新=%d）"
                          % (h[:12], at.hex(" "), n_old, n_new))


def build_final(data: bytes, state: str):
    """在内存中构建最终文件并全面校验（长度、标记、XML、终态 sha），返回 (bytes, steps)。"""
    cur, steps = data, []
    if state == "original_untouched":
        cur = cur[:LENGTH_OFFSET] + LENGTH_NEW + cur[LENGTH_OFFSET + 2:]
        if sha256(cur) != SHA_PATCHED:
            raise RuntimeError("length-step intermediate verify failed")
        steps.append("length 0x3686B: 08 02 -> 00 01")
    i = cur.find(MAN_OLD)
    if i < 0:
        raise RuntimeError("manifest marker not found")
    cur = cur[:i] + MAN_NEW + cur[i + len(MAN_OLD):]
    steps.append("manifest: uiAccess true -> false")
    if len(cur) != len(data):
        raise RuntimeError("file size changed")
    if pefile is not None:
        reg = manifest_region(cur)
        if not reg:
            raise RuntimeError("manifest region lost")
        MD.parseString(cur[reg[0]:reg[0] + reg[1]])
    if sha256(cur) != SHA_FIXED:
        raise RuntimeError("final sha mismatch (expected fixed build)")
    return cur, steps


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--apply", action="store_true")
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    exe = Path(a.exe)
    res = {"mode": "apply" if a.apply else "check", "exe": str(exe), "steps": []}
    try:
        data = exe.read_bytes()
        state, msg = inspect(data)
        res.update(result=state, message=msg, sha_before=sha256(data))

        if a.apply and state in ("original_untouched", "needs_manifest_fix"):
            final, steps = build_final(data, state)
            res["steps"] = steps
            res["sha_after"] = sha256(final)
            writes = []
            if state == "original_untouched":
                writes.append((LENGTH_OFFSET, LENGTH_NEW))
            writes.append((final.find(MAN_NEW), MAN_NEW))
            with open(exe, "r+b") as f:
                for off, buf in writes:
                    f.seek(off)
                    f.write(buf)
                f.flush()
            back = exe.read_bytes()
            if sha256(back) != res["sha_after"]:
                raise RuntimeError("readback mismatch after write")
            res["result"] = "applied"
            res["message"] = "修复完成：" + "; ".join(steps)
        elif a.apply:
            res["sha_after"] = res["sha_before"]
    except PermissionError as e:
        res.update(result="error_permission",
                   message="写入被拒绝（需要管理员权限或文件被占用）: %s" % e)
    except Exception as e:
        res.update(result="error", message="%s: %s" % (type(e).__name__, e))

    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
