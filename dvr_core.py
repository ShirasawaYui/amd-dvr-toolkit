#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dvr_core — AMD DVR 引擎补丁维护核心库（2.0.0 通用路径）。

职责：
  - 统一清单（build_manifest.json）加载与校验（fail-closed，无硬编码回退）
  - 滑动窗口定位补丁点（不依赖构建哈希与绝对偏移）
  - 四态形态识别（orig / patched / fixed / unexpected）与等长派生
  - 现场结构门禁 + self-diff 预演（L1 / L3）
  - 安装实例与「上一次有效记录」的覆盖检测

2.0.0 变化：不再有任何「按构建哈希白名单」逻辑。补丁点由
locate_patch_point() 现场从文件内容定位，结构不变量只保留跨代恒定的
形态字段。旧 1.1.0 含 builds 的清单由 validate_manifest 硬拒绝；
legacy 识别只存在于 dvr_tool.py 的回归模块，不进入运行时。

约束：全部为只读 / 纯内存操作。不写安装目录、不停进程、不做任何落盘副作用
（调用方自行决定是否保存报告）。
"""
import hashlib
import json
import re
import time
import xml.dom.minidom as MD
from pathlib import Path

import pefile

SUPPORTED_RULE_VERSIONS = {"2.0.0"}

STATE_ORIG, STATE_PATCHED, STATE_FIXED = "orig", "patched", "fixed"
STATE_RESULT = {
    STATE_ORIG: "original_untouched",
    STATE_PATCHED: "needs_manifest_fix",
    STATE_FIXED: "already_fixed",
}


class ManifestError(Exception):
    """清单不可用（缺失/解析失败/字段缺失/规则版本不支持）。写操作必须拒绝。"""


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(re.sub(r"\s+", "", s))


def _hex_to_int(s):
    if s == "EOF" or s is None:
        return None
    return int(s, 16)


# ---------------------------------------------------------------- 清单

def load_manifest(path):
    """加载并校验 2.0.0 清单；任何问题抛 ManifestError（fail-closed）。"""
    p = Path(path)
    if not p.is_file():
        raise ManifestError("manifest_missing: %s" % p)
    try:
        m = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise ManifestError("manifest_parse_error: %s" % e)
    errs = validate_manifest(m)
    if errs:
        raise ManifestError("manifest_invalid: " + "; ".join(errs))
    return m


def load_manifest_legacy(path):
    """仅回归用：加载旧 1.1.0 冻结清单，跳过 2.0.0 校验。

    生产路径绝不调用本函数；它存在的唯一目的是让 43/16 支旧回归能继续
    用 manifest_regress.json 造夹具。
    """
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_manifest(m):
    """2.0.0：校验静态规则清单（无 builds、无绝对偏移、无构建哈希）。

    只校验「规则本身是否自洽」，不校验任何具体文件。任何问题由 load_manifest
    转成 ManifestError（fail-closed）。旧 1.1.0 含 builds 的清单硬拒绝。
    """
    errs = []
    for k in ("schema_version", "rule_version", "rules"):
        if k not in m:
            errs.append("field_missing:%s" % k)
    rv = m.get("rule_version")
    if rv is not None and rv not in SUPPORTED_RULE_VERSIONS:
        errs.append("unsupported_rule_version:%s（2.0.0 起需整包迁移：移除 builds、改用滑动窗口定位）" % rv)
    if m.get("builds"):
        errs.append("legacy_builds_present:2.0.0 清单不得含 builds")

    rules = m.get("rules") or {}
    for k in ("patches", "structure_invariants", "locator", "source_verification",
              "rehearsal_gates", "levels", "write_policy", "auto_register"):
        if k not in rules:
            errs.append("field_missing:rules.%s" % k)

    # 补丁定义：锚 / 立即数 / 保长标记
    patches = rules.get("patches")
    if not isinstance(patches, list) or not patches:
        errs.append("patches_empty")
    else:
        by_id = {p.get("id"): p for p in patches if isinstance(p, dict)}
        lp = by_id.get("classname-length") or {}
        for k in ("anchor_hex", "anchor_fixed_hex", "old_hex", "new_hex",
                  "imm_offset_in_anchor"):
            if k not in lp:
                errs.append("field_missing:patches.classname-length.%s" % k)
        for k in ("anchor_hex", "anchor_fixed_hex", "old_hex", "new_hex"):
            v = lp.get(k)
            if v is not None and not (isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F ]+", v)):
                errs.append("bad_hex:patches.classname-length.%s" % k)
        if all(isinstance(lp.get(k), str) for k in ("anchor_hex", "old_hex", "new_hex")):
            a = _hex_to_bytes(lp["anchor_hex"])
            if _hex_to_bytes(lp["old_hex"]) == _hex_to_bytes(lp["new_hex"]):
                errs.append("patch_bytes_conflict")
            if _hex_to_bytes(lp["old_hex"]) not in a:
                errs.append("anchor_imm_mismatch:old_hex 不在 anchor_hex 内")
            af = lp.get("anchor_fixed_hex")
            if isinstance(af, str) and len(_hex_to_bytes(af)) != len(a):
                errs.append("anchor_length_conflict:原版锚与修复锚长度不同")
        mp = by_id.get("manifest-uiAccess") or {}
        for k in ("old", "new"):
            if k not in mp:
                errs.append("field_missing:patches.manifest-uiAccess.%s" % k)
        if isinstance(mp.get("old"), str) and isinstance(mp.get("new"), str):
            if len(mp["old"]) != len(mp["new"]):
                errs.append("patch_length_conflict:manifest-uiAccess")

    # 定位器：PRE 长度、窗口范围
    loc = rules.get("locator") or {}
    plen = loc.get("prefix_length")
    pre = loc.get("stable_anchor_prefix_hex")
    if not isinstance(plen, int) or plen <= 0:
        errs.append("bad_locator:prefix_length")
    elif not (isinstance(pre, str) and re.fullmatch(r"[0-9a-fA-F ]+", pre)):
        errs.append("bad_locator:stable_anchor_prefix_hex")
    elif len(_hex_to_bytes(pre)) != plen:
        errs.append("bad_locator:prefix_length_mismatch")
    ws = loc.get("window_sizes")
    if not (isinstance(ws, list) and ws and
            all(isinstance(x, int) and 0 <= x <= (plen if isinstance(plen, int) else 0)
                for x in ws)):
        errs.append("bad_locator:window_sizes")

    # 结构不变量（只允许跨代恒定的形态字段）
    si = rules.get("structure_invariants") or {}
    for k in ("machine_hex", "section_names_order", "manifest_markers",
              "manifest_resource", "iat_imports", "version_string_regex"):
        if k not in si:
            errs.append("field_missing:rules.structure_invariants.%s" % k)
    if si.get("section_names_order") is not None and not isinstance(si["section_names_order"], list):
        errs.append("bad_structure_invariants:section_names_order")
    return errs


# ---------------------------------------------------------------- 定位器

def _diagnostic(data, rules, windows, chosen, anchor_kind, refuse_reason, exe=None):
    """拼装定位诊断报告。定位失败时由调用方落成 locate_diagnostic.json。"""
    patches = {p["id"]: p for p in rules["patches"]}
    lp = patches["classname-length"]
    mp = patches["manifest-uiAccess"]
    man_old, man_new = mp["old"].encode("utf-8"), mp["new"].encode("utf-8")
    ui_at = data.find(man_old)
    if ui_at < 0:
        ui_at = data.find(man_new)
    facts = {}
    try:
        facts = pe_facts(data)
    except Exception as e:
        facts = {"pe_error": str(e)}
    sf = parse_source_fields((facts.get("version_strings") or {}).get("FileVersion", ""))
    d = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exe": exe,
        "size": len(data),
        "sha256": sha256(data),
        "rule_version": rules.get("_rule_version"),
        "anchor_hex": lp["anchor_hex"],
        "anchor_fixed_hex": lp["anchor_fixed_hex"],
        "stable_anchor_prefix_hex": rules["locator"]["stable_anchor_prefix_hex"],
        "windows": windows,
        "chosen_N": chosen["N"] if chosen else None,
        "anchor_kind": anchor_kind,
        "patch_offset": hex(chosen["off"]) if chosen else None,
        "ui_access_at": hex(ui_at) if ui_at >= 0 else None,
        "manifest_region": facts.get("manifest_region"),
        "sections": facts.get("sections"),
        "cert": facts.get("cert"),
        "version_string": (facts.get("version_strings") or {}).get("FileVersion"),
        "source_hash": (sf or {}).get("source_hash"),
        "hashes": {"input": sha256(data), "orig": None, "patched": None, "fixed": None},
        "refuse_reason": refuse_reason,
        "windows_all_failed": chosen is None,
    }
    return d


def locate_patch_point(data: bytes, rules: dict, exe=None):
    """滑动窗口定位补丁点；不依赖任何构建哈希或绝对偏移。

    pattern = PRE[plen - N:] + anchor      ← 取**紧邻锚**的前 N 字节（不是前缀）
    off     = hit + N + imm_offset_in_anchor

    取所有 count==1 中最小的 N；不同 N 推出不同 off 视为歧义。
    先扫原版锚，全部窗口失配再扫已修复锚（让 fixed/patched 态也能定位）。
    返回 {ok, off, anchor_kind, chosen_N, windows, diagnostic}。
    """
    locator = rules["locator"]
    patches = {p["id"]: p for p in rules["patches"]}
    lp = patches["classname-length"]
    pre = _hex_to_bytes(locator["stable_anchor_prefix_hex"])
    plen = int(locator["prefix_length"])
    sizes = locator["window_sizes"]
    imm = int(lp["imm_offset_in_anchor"])
    old_b = _hex_to_bytes(lp["old_hex"])
    new_b = _hex_to_bytes(lp["new_hex"])

    all_windows = []

    def scan(anchor_hex, kind):
        anchor = _hex_to_bytes(anchor_hex)
        wins, uniq = [], []
        for N in sizes:
            if N > plen:
                continue
            pat = pre[plen - N:] + anchor
            n = data.count(pat)
            q = data.find(pat) if n else -1
            off = (q + N + imm) if (n and q >= 0) else None
            w = {
                "N": N,
                "anchor_kind": kind,
                "pattern_hex": pat.hex(" "),
                "count": n,
                "find": hex(q) if q >= 0 else None,
                "candidate_off": hex(off) if off is not None else None,
                "off": off,
            }
            wins.append(w)
            if n == 1 and off is not None:
                uniq.append(w)
        all_windows.extend(wins)
        return uniq

    chosen, anchor_kind = None, None
    for anchor_hex, kind in ((lp["anchor_hex"], "orig"),
                             (lp["anchor_fixed_hex"], "fixed")):
        uniq = scan(anchor_hex, kind)
        if not uniq:
            continue
        offs = {w["off"] for w in uniq}
        if len(offs) != 1:
            reason = ("locate_ambiguous: 不同窗口推出不同补丁点 %s"
                      % sorted(hex(o) for o in offs))
            return {"ok": False, "off": None, "anchor_kind": kind,
                    "chosen_N": None, "windows": all_windows,
                    "diagnostic": _diagnostic(data, rules, all_windows, None,
                                              kind, reason, exe)}
        chosen, anchor_kind = min(uniq, key=lambda w: w["N"]), kind
        break

    if chosen is None:
        reason = ("locate_failed: 全部 %d 个窗口均非唯一命中（原版锚与修复锚都试过）；"
                  "该版本可能已无需补丁，或指令序列已变化" % len(all_windows))
        return {"ok": False, "off": None, "anchor_kind": None,
                "chosen_N": None, "windows": all_windows,
                "diagnostic": _diagnostic(data, rules, all_windows, None,
                                          None, reason, exe)}

    off = chosen["off"]
    at = data[off:off + len(old_b)]
    if at not in (old_b, new_b):
        reason = ("locate_verify_failed: 补丁点 %s 处字节 %s 不是 %s / %s"
                  % (hex(off), at.hex(" "), old_b.hex(" "), new_b.hex(" ")))
        return {"ok": False, "off": None, "anchor_kind": anchor_kind,
                "chosen_N": chosen["N"], "windows": all_windows,
                "diagnostic": _diagnostic(data, rules, all_windows, None,
                                          anchor_kind, reason, exe)}

    return {"ok": True, "off": off, "anchor_kind": anchor_kind,
            "chosen_N": chosen["N"], "windows": all_windows,
            "diagnostic": _diagnostic(data, rules, all_windows, chosen,
                                      anchor_kind, None, exe)}


def _patch_pieces(rules, patch_points=None, off=None):
    """补丁五元组 (off, old_b, new_b, man_old, man_new)。

    2.0.0：off 由定位器现场给出。patch_points 仅为回归夹具的兼容 overlay，
    可携带旧格式的 offset 字符串。
    """
    by_id = {p["id"]: dict(p) for p in rules["patches"]}
    lp = by_id["classname-length"]
    mp = by_id["manifest-uiAccess"]
    if patch_points:
        if isinstance(patch_points.get("classname-length"), dict):
            lp.update(patch_points["classname-length"])
        if isinstance(patch_points.get("manifest-uiAccess"), dict):
            mp.update(patch_points["manifest-uiAccess"])
    old_b = _hex_to_bytes(lp["old_hex"])
    new_b = _hex_to_bytes(lp["new_hex"])
    if old_b == new_b:
        raise ManifestError("patch_bytes_conflict: old_hex == new_hex")
    if off is None:
        o = lp.get("offset")
        if o is None:
            raise ManifestError("patch_offset_missing: 2.0.0 必须由定位器提供偏移")
        off = _hex_to_int(o)
    return (int(off), old_b, new_b,
            mp["old"].encode("utf-8"), mp["new"].encode("utf-8"))


def runtime_patch_points(off):
    """把定位器结果包装成 _patch_pieces 可吃的 overlay（供 build_final 等复用）。"""
    return {"classname-length": {"offset": hex(off)}}


# ---------------------------------------------------------------- 形态识别与派生

def classify(data: bytes, manifest, exe=None):
    """四态形态识别（不依赖任何哈希白名单）。

    fixed   : 长度位=new_b, uiAccess old=0 / new=1
    orig    : 长度位=old_b, uiAccess old=1 / new=0
    patched : 长度位=new_b, uiAccess old=1 / new=0（中间态）
    unexpected : 定位失败或形态不认识
    """
    rules = manifest["rules"]
    try:
        rules = dict(rules)
        rules["_rule_version"] = manifest.get("rule_version")
    except Exception:
        pass
    h = sha256(data)
    loc = locate_patch_point(data, rules, exe)
    if not loc["ok"]:
        return {"state": "unexpected", "result": "unexpected", "build": None,
                "sha256": h, "message": loc["diagnostic"]["refuse_reason"],
                "located": loc, "diagnostic": loc["diagnostic"]}

    off, old_b, new_b, man_old, man_new = _patch_pieces(rules, off=loc["off"])
    at = data[off:off + len(old_b)]
    n_old, n_new = data.count(man_old), data.count(man_new)
    if at == new_b and n_old == 0 and n_new == 1:
        state = STATE_FIXED
    elif at == old_b and n_old == 1 and n_new == 0:
        state = STATE_ORIG
    elif at == new_b and n_old == 1 and n_new == 0:
        state = STATE_PATCHED
    else:
        state = "unexpected"

    msg = {
        STATE_FIXED: "两步修改均已完成，无需动作（现场定位）",
        STATE_ORIG: "原始文件（现场定位，未登记构建）",
        STATE_PATCHED: "已打 2 字节补丁，待修复清单（现场定位）",
        "unexpected": "形态与已知状态不符（长度位=%s，uiAccess 旧=%d/新=%d，偏移=%s）"
                      % (at.hex(" "), n_old, n_new, hex(off)),
    }[state]
    build = None
    try:
        vf = pe_facts(data).get("version_strings", {}).get("FileVersion", "")
        build = (parse_source_fields(vf) or {}).get("package_version")
    except Exception:
        pass
    return {"state": state, "result": STATE_RESULT.get(state, "unexpected"),
            "build": build, "sha256": h, "message": msg,
            "located": loc, "diagnostic": loc["diagnostic"]}


def derive(data: bytes, state: str, rules, patch_points=None, off=None):
    """纯内存等长派生（patched / fixed），返回 (bytes, steps)。不做任何落盘。

    off 由定位器给出；patch_points 兼容旧回归夹具。
    """
    off, old_b, new_b, man_old, man_new = _patch_pieces(rules, patch_points, off)
    cur, steps = data, []
    if state == STATE_PATCHED:
        if cur[off:off + len(old_b)] != old_b:
            raise RuntimeError("length marker not found at %s" % hex(off))
        cur = cur[:off] + new_b + cur[off + len(old_b):]
        steps.append("length %s: %s -> %s" % (hex(off), old_b.hex(" "), new_b.hex(" ")))
        return cur, steps
    if state == STATE_FIXED:
        if cur[off:off + len(old_b)] == old_b:
            cur = cur[:off] + new_b + cur[off + len(old_b):]
            steps.append("length %s: %s -> %s" % (hex(off), old_b.hex(" "), new_b.hex(" ")))
        i = cur.find(man_old)
        if i < 0:
            raise RuntimeError("manifest marker not found")
        cur = cur[:i] + man_new + cur[i + len(man_old):]
        steps.append("manifest: uiAccess true -> false")
        if len(cur) != len(data):
            raise RuntimeError("file size changed")
        return cur, steps
    raise ValueError(state)


# ---------------------------------------------------------------- PE 事实与差异

def pe_facts(data: bytes):
    pe = pefile.PE(data=data)
    secs = [[s.Name.rstrip(b"\x00").decode(errors="replace"),
             hex(s.PointerToRawData), hex(s.Misc_VirtualSize), hex(s.VirtualAddress)]
            for s in pe.sections]
    cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    man = None
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if e.struct.Id == 24:
                for r in e.directory.entries:
                    for d in r.directory.entries:
                        man = [hex(pe.get_offset_from_rva(d.data.struct.OffsetToData)),
                               d.data.struct.Size]
    iat = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    iat[imp.name.decode(errors="replace")] = hex(imp.address - pe.OPTIONAL_HEADER.ImageBase)
    ver = {}
    if hasattr(pe, "FileInfo"):
        for fi in pe.FileInfo:
            for entry in fi:
                if hasattr(entry, "StringTable"):
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            ks = k.decode() if isinstance(k, bytes) else k
                            if ks in ("FileVersion", "ProductVersion"):
                                ver[ks] = v.decode() if isinstance(v, bytes) else v
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "sections": secs,
        "cert": {"offset": hex(cert.VirtualAddress), "size": hex(cert.Size)},
        "manifest_region": man,
        "iat": iat,
        "version_strings": ver,
    }


def diff_blocks(a: bytes, b: bytes):
    n = min(len(a), len(b))
    out, i = [], 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    if len(a) != len(b):
        out.append((n, max(len(a), len(b))))
    return out


def parse_source_fields(ver_string: str):
    """从 FileVersion/ProductVersion 串解析 (package_version, source_hash, raw)。"""
    if not ver_string:
        return None
    m = re.search(r"AMD-Radeon-Driver/drivers:([0-9a-f]{40})", ver_string)
    src = m.group(1) if m else None
    head = ver_string.split(";")
    pkg = head[0] if head else None
    return {"package_version": pkg, "source_hash": src, "raw": ver_string}


def source_ok(facts, manifest, backup_info_path=None, signature_valid=None):
    """来源核验（2.0.0）：版本串格式强制，签名为加分项，台账不再参与。

    新版本必然不在 backup_info.txt 里，旧的子串包含判定已删除。
    backup_info_path 参数保留仅为兼容旧调用签名。
    """
    inv = manifest["rules"]["structure_invariants"]
    vf = (facts.get("version_strings") or {}).get("FileVersion", "") or ""
    sf = parse_source_fields(vf)
    ok = bool(sf and sf["source_hash"] and re.search(inv["version_string_regex"], vf))
    evid = ["版本串格式命中 source_hash=%s" % sf["source_hash"]] if ok else ["版本串格式不符"]
    if signature_valid is True:
        evid.append("Authenticode 签名有效（加分项，不作前置条件）")
    elif signature_valid is False:
        evid.append("签名无效（不影响判定）")
    return ok, "; ".join(evid)


def structural_check(data: bytes, manifest, reference=None, profile=None, loc=None):
    """现场结构门禁（2.0.0）。只校验跨代恒定的形态不变量，不校验绝对地址。

    loc: 已算好的 locate_patch_point 结果，避免重复扫描。
    reference / profile: 仅为旧回归兼容保留，2.0.0 运行时不使用。
    """
    rules = manifest["rules"]
    inv = (profile or {}).get("structure_invariants") or rules["structure_invariants"]
    reasons = []
    try:
        facts = pe_facts(data)
    except Exception as e:
        return False, ["PE 解析失败: %s" % e], {}

    if facts["machine"] != inv["machine_hex"]:
        reasons.append("架构不符: %s != %s" % (facts["machine"], inv["machine_hex"]))
    names = [s[0] for s in facts["sections"]]
    if names != inv["section_names_order"]:
        reasons.append("节区名称/顺序不符: %s" % names)
    for name in inv["iat_imports"]:
        if name not in facts["iat"]:
            reasons.append("IAT 缺少导入 %s" % name)

    mr = inv.get("manifest_resource") or {}
    reg = facts["manifest_region"]
    if not reg:
        reasons.append("RT_MANIFEST 缺失")
    else:
        want = _hex_to_int(mr.get("size")) if isinstance(mr.get("size"), str) else mr.get("size")
        if want is not None and reg[1] != want:
            reasons.append("RT_MANIFEST size 不符: %d != %d" % (reg[1], want))
        if inv.get("manifest_xml_parseable"):
            try:
                MD.parseString(data[int(reg[0], 16):int(reg[0], 16) + reg[1]])
            except Exception as e:
                reasons.append("RT_MANIFEST XML 不可解析: %s" % e)

    vf = (facts.get("version_strings") or {}).get("FileVersion", "") or ""
    if not re.search(inv["version_string_regex"], vf):
        reasons.append("版本串格式不符（来源核验失败）")

    if loc is None:
        loc = locate_patch_point(data, rules)
    if not loc["ok"]:
        reasons.append("定位失败: %s" % loc["diagnostic"]["refuse_reason"])
    else:
        off, old_b, new_b, _, _ = _patch_pieces(rules, off=loc["off"])
        at = data[off:off + len(old_b)]
        if at not in (old_b, new_b):
            reasons.append("补丁点 %s 字节 %s 不是 %s / %s"
                           % (hex(off), at.hex(" "), old_b.hex(" "), new_b.hex(" ")))
    return (len(reasons) == 0), reasons, facts


# ---------------------------------------------------------------- L1 / L3 分级

def grade(data: bytes, manifest, reference=None, backup_info_path=None,
          signature_valid=None, profile=None):
    """2.0.0 分级：L1（门禁全过，放行）/ L3（拒写，零写入）。

    candidate 字段在 orig 态下会带上内存派生的 patched/fixed 哈希，
    供调用方审计；它不再是「待审批候选」，不构成任何授权语义。
    """
    cls = classify(data, manifest)
    rules = manifest["rules"]
    try:
        facts = pe_facts(data)
    except Exception as e:
        return {"level": "L3", "reasons": ["PE 解析失败: %s" % e],
                "classification": cls, "candidate": None}
    if cls["state"] == "unexpected":
        return {"level": "L3", "reasons": [cls["message"]],
                "classification": cls, "candidate": None, "facts": facts,
                "diagnostic": cls.get("diagnostic")}

    s_ok, s_evid = source_ok(facts, manifest, backup_info_path, signature_valid)
    if not s_ok:
        return {"level": "L3", "reasons": ["来源格式不符（%s）" % s_evid],
                "classification": cls, "candidate": None, "facts": facts}
    st_ok, st_reasons, _ = structural_check(data, manifest, reference, profile,
                                            cls.get("located"))
    if not st_ok:
        return {"level": "L3", "reasons": ["预演门禁未过: " + "；".join(st_reasons)],
                "classification": cls, "candidate": None, "facts": facts}

    off = cls["located"]["off"]
    cand = {"input_sha256": cls["sha256"], "steps": []}
    if cls["state"] == STATE_ORIG:
        try:
            p_bytes, p_steps = derive(data, STATE_PATCHED, rules, off=off)
            f_bytes, f_steps = derive(data, STATE_FIXED, rules, off=off)
            _, old_b, new_b, man_old, man_new = _patch_pieces(rules, off=off)
            man_at = data.find(man_old)
            sites = sorted([(off, off + len(old_b)),
                            (man_at, man_at + len(man_new))])
            blocks = diff_blocks(data, f_bytes)
            if len(f_bytes) != len(data):
                raise RuntimeError("候选文件大小变化")
            for s, e in blocks:
                if not any(rs <= s and e <= re_ for rs, re_ in sites):
                    raise RuntimeError("候选差异越界 [%s..%s)" % (hex(s), hex(e)))
            cand.update(
                candidate_patched_sha256=sha256(p_bytes),
                candidate_fixed_sha256=sha256(f_bytes),
                candidate_size=len(f_bytes),
                steps=p_steps + f_steps,
                located={"offset": hex(off), "chosen_N": cls["located"]["chosen_N"],
                         "anchor_kind": cls["located"]["anchor_kind"]},
                diff_scope="orig→fixed 差异恰为两处补丁点 %s"
                           % [(hex(s), hex(e)) for s, e in sites],
            )
            d = cls.get("diagnostic") or {}
            if isinstance(d, dict):
                d["hashes"]["orig"] = sha256(data)
                d["hashes"]["patched"] = sha256(p_bytes)
                d["hashes"]["fixed"] = sha256(f_bytes)
        except Exception as e:
            return {"level": "L3", "reasons": ["候选派生失败: %s" % e],
                    "classification": cls, "candidate": None, "facts": facts}

    note = {
        STATE_ORIG: "现场门禁全过：自动备份并注入",
        STATE_FIXED: "完整修复：不重复写，零写入",
        STATE_PATCHED: "中间态：补齐清单修复",
    }[cls["state"]]
    return {"level": "L1", "reasons": [note, "来源可核验（%s）" % s_evid],
            "classification": cls, "candidate": cand, "facts": facts}


# ---------------------------------------------------------------- 覆盖检测（记录比较）

def compare_record(prev: dict, cur: dict):
    """与上一次有效记录比较 → 引擎未变 / 重装覆盖 / 一致 / 新构建。"""
    if not prev:
        return {"label": "无上次记录", "detail": "首次登记，只记录事实"}
    if prev.get("engine_sha256") == cur.get("engine_sha256"):
        if prev.get("driver_package_version") != cur.get("driver_package_version"):
            return {"label": "引擎未变",
                    "detail": "驱动包 %s -> %s，引擎文件未变（sha 相同），不触发重打"
                              % (prev.get("driver_package_version"), cur.get("driver_package_version"))}
        return {"label": "一致", "detail": "驱动与引擎文件均与上次记录一致"}
    if (prev.get("driver_package_version") == cur.get("driver_package_version")
            and prev.get("engine_state") == STATE_FIXED and cur.get("engine_state") == STATE_ORIG):
        return {"label": "重装覆盖",
                "detail": "同版从修复态变原版（同版本重装/覆盖），按 U02 处置"}
    if prev.get("driver_package_version") != cur.get("driver_package_version"):
        return {"label": "新构建",
                "detail": "驱动包 %s -> %s，引擎文件已更换（陌生哈希）→ 按新构建处理"
                          % (prev.get("driver_package_version"), cur.get("driver_package_version"))}
    return {"label": "新构建",
            "detail": "版本号相同但出现陌生哈希 → 按新构建处理，不凭版本号放行"}
