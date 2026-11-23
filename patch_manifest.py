#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AMDRSServ.exe 修复器（清单驱动版）：2 字节长度补丁 + 清单 uiAccess 修复。

与旧版差异（P1 D04）：不再内嵌 BUILDS 硬编码表，统一从 build_manifest.json
查询（dvr_core.load_manifest，fail-closed）。清单缺失/字段缺失/状态冲突/
规则版本不支持时，--check 报 manifest_error 且 --apply 拒绝一切写入，
禁止回退旧硬编码表。

背景（详见修复报告 §15）：
  - 类名读取越界：偏移 0x3686B 处把 0x208(520字符) 改为 0x100(256字符)
  - uiAccess 门槛：签名失效后 uiAccess=true 会被 Windows 拒启，须同步改 false

处理状态（自动识别；所有改写均为等长替换、文件大小不变）：
  - original_untouched ：原始文件 → --apply 一并完成两步
  - needs_manifest_fix ：已打 2 字节补丁、清单未改 → --apply 只改清单
  - already_fixed      ：两步均已完成 → 不动作
  - unexpected / manifest_error ：拒绝动作

用法: python patch_manifest.py --check|--apply [--exe PATH] [--manifest PATH] --out X.json
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import pefile
import xml.dom.minidom as MD

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dvr_core as core  # noqa: E402

DEFAULT_EXE = r"C:\Program Files\AMD\CNext\CNext\AMDRSServ.exe"
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "build_manifest.json"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def manifest_region(data: bytes):
    """返回 RT_MANIFEST 资源区在文件中的 (offset, size)；找不到返回 None。"""
    pe = pefile.PE(data=data)
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None
    for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if e.struct.Id == 24:  # RT_MANIFEST
            for r in e.directory.entries:
                for d in r.directory.entries:
                    return pe.get_offset_from_rva(d.data.struct.OffsetToData), d.data.struct.Size
    return None


def build_final(data: bytes, state: str, build, rules):
    """在内存中构建最终文件并全面校验，返回 (bytes, steps)。"""
    off, old_b, new_b, man_old, man_new = core._patch_pieces(rules)
    cur, steps = data, []
    if state == "original_untouched":
        cur = cur[:off] + new_b + cur[off + len(old_b):]
        if sha256(cur) != build["hashes"]["patched"]:
            raise RuntimeError("length-step intermediate verify failed")
        steps.append("length %s: %s -> %s" % (hex(off), old_b.hex(" "), new_b.hex(" ")))
    i = cur.find(man_old)
    if i < 0:
        raise RuntimeError("manifest marker not found")
    cur = cur[:i] + man_new + cur[i + len(man_old):]
    steps.append("manifest: uiAccess true -> false")
    if len(cur) != len(data):
        raise RuntimeError("file size changed")
    reg = manifest_region(cur)
    if not reg:
        raise RuntimeError("manifest region lost")
    MD.parseString(cur[reg[0]:reg[0] + reg[1]])
    if sha256(cur) != build["hashes"]["fixed"]:
        raise RuntimeError("final sha mismatch (expected fixed build)")
    return cur, steps


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--apply", action="store_true")
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    exe = Path(a.exe)
    res = {"mode": "apply" if a.apply else "check", "exe": str(exe), "steps": []}

    # 清单 fail-closed：任何清单问题拒绝动作，禁止回退硬编码表
    try:
        manifest = core.load_manifest(a.manifest)
    except core.ManifestError as e:
        res.update(result="manifest_error", message=str(e),
                   sha_before=None, build=None, sha_orig=None)
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(res, ensure_ascii=False))
        return

    rules = manifest["rules"]
    try:
        data = exe.read_bytes()
        c = core.classify(data, manifest)
        build = next((b for b in manifest["builds"] if b["name"] == c["build"]), None)
        state = {"orig": "original_untouched",
                 "patched": "needs_manifest_fix",
                 "fixed": "already_fixed"}.get(c["state"], "unexpected")
        res.update(result=state, message=c["message"], sha_before=c["sha256"],
                   build=c["build"],
                   sha_orig=(build["hashes"]["orig"] if build else None))

        if a.apply and state in ("original_untouched", "needs_manifest_fix"):
            final, steps = build_final(data, state, build, rules)
            res["steps"] = steps
            res["sha_after"] = sha256(final)
            writes = []
            if state == "original_untouched":
                writes.append((off := core._patch_pieces(rules)[0], core._patch_pieces(rules)[2]))
            man_new = core._patch_pieces(rules)[4]
            writes.append((final.find(man_new), man_new))
            with open(exe, "r+b") as f:
                for offw, buf in writes:
                    f.seek(offw)
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
