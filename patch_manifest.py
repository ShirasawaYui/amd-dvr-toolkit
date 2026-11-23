#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AMDRSServ.exe 修复器（2.0.0 通用路径）：2 字节长度补丁 + 清单 uiAccess 修复。

与 1.1.0 的差异：
  - 不再按构建哈希识别，改由 dvr_core.locate_patch_point 现场滑动窗口定位补丁点
  - 写前门禁由「结果 == 清单登记的完整哈希」改为「self-diff 恰为两处补丁点」
  - 成功后原子写 backup/auto_registry.json 审计台账（不影响注入能力）
  - 清单不可用时 --check 报 manifest_error 且 --apply 拒绝一切写入（fail-closed）

补丁内容（跨代恒定）：
  - 类名读取越界：mov r8d, 0x208 -> 0x100（08 02 -> 00 01）
  - uiAccess 门槛：签名失效后 uiAccess=true 会被 Windows 拒启，须同步改 false

处理状态（现场形态识别，不依赖哈希白名单）：
  - original_untouched ：原版 → --apply 一并完成两步
  - needs_manifest_fix ：已打 2 字节补丁、清单未改 → --apply 只改清单
  - already_fixed      ：两步均已完成 → 不动作（零写入）
  - unexpected / manifest_error ：拒绝动作并写 locate_diagnostic.json

用法: python patch_manifest.py --check|--apply [--exe PATH] [--manifest PATH] --out X.json
"""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pefile
import xml.dom.minidom as MD

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dvr_core as core  # noqa: E402

DEFAULT_EXE = r"C:\Program Files\AMD\CNext\CNext\AMDRSServ.exe"
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "build_manifest.json"
HERE = Path(__file__).resolve().parent
BACKUP_DIR = HERE / "backup"
REGISTRY = BACKUP_DIR / "auto_registry.json"
DIAGNOSTIC = HERE / "locate_diagnostic.json"


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


def build_final(data: bytes, state: str, rules: dict, off: int):
    """在内存中构建最终文件并全面校验，返回 (bytes, steps, sites)。

    2.0.0：不再比对任何清单哈希，改用 self-diff —— 输入到结果的所有差异
    必须落在「长度补丁点」与「uiAccess 标记」这两个已知区间内，且文件等长。
    """
    off, old_b, new_b, man_old, man_new = core._patch_pieces(rules, off=off)
    cur, steps = data, []
    if state == "original_untouched":
        if cur[off:off + len(old_b)] != old_b:
            raise RuntimeError("length marker not found at %s" % hex(off))
        cur = cur[:off] + new_b + cur[off + len(old_b):]
        d1 = core.diff_blocks(data, cur)
        if not all(off <= s and e <= off + len(old_b) for s, e in d1):
            raise RuntimeError("length-step self-diff out of scope: %s" % d1)
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

    sites = sorted([(off, off + len(old_b)), (i, i + len(man_old))])
    d2 = core.diff_blocks(data, cur)
    for s, e in d2:
        if not any(rs <= s and e <= re_ for rs, re_ in sites):
            raise RuntimeError("final self-diff out of scope [%s..%s)" % (hex(s), hex(e)))
    if len(d2) != 2:
        raise RuntimeError("final self-diff expected 2 blocks, got %d: %s" % (len(d2), d2))
    return cur, steps, sites


def write_diagnostic(res, diagnostic_path=None):
    """定位失败时把完整诊断写成文件，供操作者带回对话。失败不影响主流程。"""
    try:
        d = dict(res.get("diagnostic") or {})
        d["exe"] = res.get("exe")
        d["result"] = res.get("result")
        d["message"] = res.get("message")
        Path(diagnostic_path or DIAGNOSTIC).write_text(
            json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def find_backup_for(orig_sha):
    """在 backup 里找与输入原版哈希吻合的 .bak（供台账填 backup_file）。"""
    try:
        for p in sorted(BACKUP_DIR.glob("*.bak"), key=lambda x: x.stat().st_mtime, reverse=True):
            if sha256(p.read_bytes()) == orig_sha:
                return p.name
    except Exception:
        pass
    return None


def auto_register(res, manifest, input_sha, final_sha, located, state,
                  registry_path=None):
    """原子写审计台账（默认 backup/auto_registry.json）。

    --registry 可覆盖路径，供回归在隔离目录里测原子写，不污染真实台账。
    台账损坏不影响注入能力：加载失败时把坏文件改名留档，从空列表重建。
    """
    reg_path = Path(registry_path) if registry_path else REGISTRY
    entries = []
    if reg_path.is_file():
        try:
            obj = json.loads(reg_path.read_text(encoding="utf-8"))
            entries = obj if isinstance(obj, list) else (obj.get("entries") or [])
        except Exception:
            try:
                reg_path.rename(reg_path.with_name(
                    reg_path.name + ".bad.%s" % time.strftime("%Y%m%d-%H%M%S")))
            except Exception:
                pass
            entries = []
    entry = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "rule_version": manifest.get("rule_version"),
        "version": res.get("build"),
        "size": res.get("size"),
        "approval": manifest["rules"]["auto_register"]["approval"],
        "exe": res.get("exe"),
        "input_state": state,
        "hashes": {
            "input": input_sha,
            "orig": input_sha if state == "original_untouched" else None,
            "fixed": final_sha,
        },
        "located": {
            "offset": hex(located["off"]) if located.get("off") is not None else None,
            "chosen_N": located.get("chosen_N"),
            "anchor_kind": located.get("anchor_kind"),
        },
        "backup_file": find_backup_for(input_sha),
    }
    entries.append(entry)
    tmp = reg_path.with_name(reg_path.name + ".tmp.%d" % os.getpid())
    tmp.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, reg_path)
    # 复读校验：写坏就留证并报错（不影响已完成的注入）
    back = json.loads(reg_path.read_text(encoding="utf-8"))
    if not isinstance(back, list) or len(back) != len(entries):
        raise RuntimeError("auto_registry readback mismatch")
    return entry


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--apply", action="store_true")
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--out", required=True)
    ap.add_argument("--registry", help="覆盖审计台账路径（回归隔离用）")
    ap.add_argument("--diagnostic", help="覆盖定位诊断报告路径（回归隔离用）")
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
        c = core.classify(data, manifest, str(exe))
        loc = c["located"]
        state = {"orig": "original_untouched",
                 "patched": "needs_manifest_fix",
                 "fixed": "already_fixed"}.get(c["state"], "unexpected")
        res.update(
            result=state, message=c["message"], sha_before=c["sha256"],
            build=c["build"], sha_orig=c["sha256"],   # 现场哈希，不再是清单登记值
            size=len(data),
            located=({"ok": loc["ok"], "off": loc["off"],
                      "chosen_N": loc["chosen_N"], "anchor_kind": loc["anchor_kind"]}
                     if isinstance(loc, dict) else None),
            diagnostic=c.get("diagnostic"),
        )
        if state == "unexpected":
            write_diagnostic(res, a.diagnostic)

        if a.apply and state in ("original_untouched", "needs_manifest_fix"):
            if not loc["ok"]:
                raise RuntimeError("locator unavailable, refuse to write")
            off = loc["off"]
            final, steps, sites = build_final(data, state, rules, off)
            res["steps"] = steps
            res["sites"] = [[hex(s), hex(e)] for s, e in sites]
            res["sha_after"] = sha256(final)

            _, _, new_b, _, man_new = core._patch_pieces(rules, off=off)
            writes = []
            if state == "original_untouched":
                writes.append((off, new_b))
            writes.append((final.find(man_new), man_new))
            with open(exe, "r+b") as f:
                for offw, buf in writes:
                    f.seek(offw)
                    f.write(buf)
                f.flush()
            back_bytes = exe.read_bytes()
            if sha256(back_bytes) != res["sha_after"]:
                raise RuntimeError("readback mismatch after write")

            res["result"] = "applied"
            res["message"] = "修复完成：" + "; ".join(steps)
            try:
                res["auto_registered"] = auto_register(
                    res, manifest, c["sha256"], res["sha_after"], loc, state,
                    a.registry)
            except Exception as e:
                # 台账失败不回滚已完成的注入，但必须在结果里显式留痕
                res["auto_register_error"] = str(e)
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
