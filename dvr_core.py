#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dvr_core — AMD DVR 引擎补丁维护核心库（P1 只读版）。

职责：
  - 统一清单（build_manifest.json）加载与校验（fail-closed，无硬编码回退）
  - 三态识别（orig / patched / fixed）与等长派生
  - 结构不变量校验 + 允许差异区间的离线预演
  - L1 / L2 / L3 候选分级
  - 安装实例与「上一次有效记录」的覆盖检测（引擎未变 / 重装覆盖 / 新构建）

约束：全部为只读 / 纯内存操作。不写安装目录、不停进程、不做任何落盘副作用
（调用方自行决定是否保存报告）。
"""
import hashlib
import json
import re
import xml.dom.minidom as MD
from pathlib import Path

import pefile

SUPPORTED_RULE_VERSIONS = {"1.0.0", "1.1.0"}

STATE_ORIG, STATE_PATCHED, STATE_FIXED = "orig", "patched", "fixed"
STATE_RESULT = {
    STATE_ORIG: "original_untouched",
    STATE_PATCHED: "needs_manifest_fix",
    STATE_FIXED: "already_fixed",
}


class ManifestError(Exception):
    """清单不可用（缺失/解析失败/字段缺失/状态冲突/规则版本不支持）。写操作必须拒绝。"""


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
    """加载并校验清单；任何问题抛 ManifestError（fail-closed）。"""
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


def validate_manifest(m):
    errs = []
    for k in ("schema_version", "rule_version", "rules", "builds"):
        if k not in m:
            errs.append("field_missing:%s" % k)
    rv = m.get("rule_version")
    if rv is not None and rv not in SUPPORTED_RULE_VERSIONS:
        errs.append("unsupported_rule_version:%s" % rv)
    rules = m.get("rules") or {}
    for k in ("patches", "structure_invariants", "allowed_diff_regions",
              "levels", "write_policy", "source_verification", "rehearsal_gates"):
        if k not in rules:
            errs.append("field_missing:rules.%s" % k)
    builds = m.get("builds")
    if not isinstance(builds, list) or not builds:
        errs.append("builds_empty")
        return errs
    seen = {}
    for i, b in enumerate(builds):
        tag = "builds[%d]" % i
        for k in ("name", "rule_version", "size", "hashes", "source", "approval"):
            if k not in b:
                errs.append("field_missing:%s.%s" % (tag, k))
        if b.get("rule_version") and b.get("rule_version") not in SUPPORTED_RULE_VERSIONS:
            errs.append("unsupported_rule_version:%s(%s)" % (b.get("name"), b.get("rule_version")))
        # 可选：按构建补丁点覆盖（1.1.0）——字段缺失/类型错即拒
        pp = b.get("patch_points")
        if pp is not None:
            if not isinstance(pp, dict):
                errs.append("bad_patch_points:%s" % tag)
            else:
                lp = pp.get("classname-length")
                if not (isinstance(lp, dict) and isinstance(lp.get("offset"), str)
                        and re.fullmatch(r"0x[0-9a-fA-F]+", lp["offset"])
                        and re.fullmatch(r"[0-9a-fA-F ]+", lp.get("old_hex", ""))
                        and re.fullmatch(r"[0-9a-fA-F ]+", lp.get("new_hex", ""))):
                    errs.append("bad_patch_points:%s.classname-length" % tag)
        si = b.get("structure_invariants")
        if si is not None:
            if not (isinstance(si, dict) and "sections" in si and "patch_point" in si):
                errs.append("bad_structure_invariants:%s" % tag)
        hs = b.get("hashes") or {}
        for st in (STATE_ORIG, STATE_PATCHED, STATE_FIXED):
            v = hs.get(st)
            if not (isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)):
                errs.append("bad_hash:%s.%s" % (tag, st))
                continue
            # 状态冲突：同一内容不得登记为不同状态
            if v in seen:
                errs.append("state_conflict:%s.%s == %s.%s" % (tag, st, seen[v][0], seen[v][1]))
            else:
                seen[v] = (b.get("name"), st)
        if b.get("approval") not in ("approved", "candidate", "holdout", "rejected"):
            errs.append("bad_approval:%s" % tag)
    return errs


# ---------------------------------------------------------------- 三态识别与派生

def _patch_pieces(rules, patch_points=None):
    """补丁五元组 (off, old_b, new_b, man_old, man_new)。

    patch_points 为按构建/profile 的覆盖（1.1.0）：可覆盖 classname-length 的
    offset/old_hex/new_hex 与 manifest-uiAccess 的 at（仅信息）；字符串补丁
    （manifest-uiAccess）全局同构，覆盖不改其 old/new 语义。
    """
    by_id = {p["id"]: dict(p) for p in rules["patches"]}
    lp = by_id["classname-length"]
    mp = by_id["manifest-uiAccess"]
    if patch_points:
        if isinstance(patch_points.get("classname-length"), dict):
            lp.update(patch_points["classname-length"])
        if isinstance(patch_points.get("manifest-uiAccess"), dict):
            mp.update(patch_points["manifest-uiAccess"])
    if _hex_to_bytes(lp["old_hex"]) == _hex_to_bytes(lp["new_hex"]):
        raise ManifestError("patch_bytes_conflict: old_hex == new_hex")
    return (
        _hex_to_int(lp["offset"]),
        _hex_to_bytes(lp["old_hex"]),
        _hex_to_bytes(lp["new_hex"]),
        mp["old"].encode("utf-8"),
        mp["new"].encode("utf-8"),
    )


def classify(data: bytes, manifest):
    """三态识别。返回 {state, result, build, sha256, message}；build 可为 None（unexpected）。

    1.1.0：逐构建取补丁点（build.patch_points 覆盖优先，否则规则默认），
    保证补丁点漂移的新构建登记后仍能正确验证形态。
    """
    rules = manifest["rules"]
    h = sha256(data)
    for b in manifest["builds"]:
        off, old_b, new_b, man_old, man_new = _patch_pieces(rules, b.get("patch_points"))
        at = data[off:off + len(old_b)]
        n_old, n_new = data.count(man_old), data.count(man_new)
        hs = b["hashes"]
        if h == hs[STATE_FIXED] and at == new_b and n_old == 0 and n_new == 1:
            return {"state": STATE_FIXED, "result": STATE_RESULT[STATE_FIXED],
                    "build": b["name"], "sha256": h,
                    "message": "两步修改均已完成，无需动作（%s）" % b["name"]}
        if h == hs[STATE_ORIG] and at == old_b and n_old == 1 and n_new == 0:
            return {"state": STATE_ORIG, "result": STATE_RESULT[STATE_ORIG],
                    "build": b["name"], "sha256": h,
                    "message": "原始文件（%s）" % b["name"]}
        if h == hs[STATE_PATCHED] and at == new_b and n_old == 1 and n_new == 0:
            return {"state": STATE_PATCHED, "result": STATE_RESULT[STATE_PATCHED],
                    "build": b["name"], "sha256": h,
                    "message": "已打 2 字节补丁（%s），待修复清单" % b["name"]}
    off, old_b, new_b, man_old, man_new = _patch_pieces(rules)
    at = data[off:off + len(old_b)]
    n_old, n_new = data.count(man_old), data.count(man_new)
    return {"state": "unexpected", "result": "unexpected", "build": None, "sha256": h,
            "message": "状态与已知版本不符（sha=%s..., 长度位=%s, uiAccess旧=%d/新=%d）"
                       % (h[:12], at.hex(" "), n_old, n_new)}


def derive(data: bytes, state: str, rules, patch_points=None):
    """纯内存等长派生（patched / fixed），返回 (bytes, steps)。不做任何落盘。

    patch_points：按构建/profile 的补丁点覆盖（见 _patch_pieces）。
    """
    off, old_b, new_b, man_old, man_new = _patch_pieces(rules, patch_points)
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


# ---------------------------------------------------------------- PE 事实与结构校验

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


def structural_check(data: bytes, manifest, reference: bytes = None, profile=None):
    """预演门禁（rehearsal_gates）逐条校验。返回 (ok, reasons[], facts)。

    profile（1.1.0）：未登记新样本的按构建指纹/补丁点 overlay，键同
    build record 的 structure_invariants / patch_points / allowed_diff_regions。
    未提供 profile 时用规则默认（四代布局）。
    """
    rules = manifest["rules"]
    inv = (profile or {}).get("structure_invariants") or rules["structure_invariants"]
    patch_points = (profile or {}).get("patch_points")
    allowed_regions = (profile or {}).get("allowed_diff_regions")
    if allowed_regions is None:
        allowed_regions = rules["allowed_diff_regions"]
    reasons = []
    facts = pe_facts(data)
    off, old_b, new_b, man_old, man_new = _patch_pieces(rules, patch_points)

    if facts["machine"] != inv["machine_hex"]:
        reasons.append("架构不符: %s != %s" % (facts["machine"], inv["machine_hex"]))
    if facts["sections"] != [list(map(str, s)) for s in inv["sections"]]:
        reasons.append("节区表与不变量不符（结构实变）")
    if data[off:off + len(old_b)] != old_b:
        reasons.append("补丁点 %s 字节不是 %s（定位失效/形态非原版）" % (hex(off), old_b.hex(" ")))
    # 定位唯一性（context_pre_hex）：带上下文指纹时，全文件只允许唯一命中
    lp = (patch_points or {}).get("classname-length") or {}
    ctx = lp.get("context_pre_hex")
    if ctx:
        pat = _hex_to_bytes(ctx) + old_b
        n = data.count(pat)
        if n != 1:
            reasons.append("补丁点定位不唯一: context+old 全文件命中 %d 次（要求 1）" % n)
        elif data.find(pat) != off - len(_hex_to_bytes(ctx)):
            reasons.append("补丁点上下文不符: 声明偏移 %s 与唯一命中位置不一致" % hex(off))
    n_old, n_new = data.count(man_old), data.count(man_new)
    if n_old != inv["manifest_markers"]["old_count"] or n_new != inv["manifest_markers"]["new_count"]:
        reasons.append("清单标记计数不符: MAN_OLD=%d MAN_NEW=%d" % (n_old, n_new))
    if inv.get("manifest_xml_parseable"):
        reg = facts["manifest_region"]
        if not reg:
            reasons.append("RT_MANIFEST 缺失")
        else:
            try:
                MD.parseString(data[int(reg[0], 16):int(reg[0], 16) + reg[1]])
            except Exception as e:
                reasons.append("RT_MANIFEST XML 不可解析: %s" % e)
    for name in inv["iat_imports"]:
        if name not in facts["iat"]:
            reasons.append("IAT 缺少导入 %s" % name)
    if reference is not None:
        blocks = diff_blocks(reference, data)
        allowed = [(_hex_to_int(r["start"]),
                   10 ** 18 if _hex_to_int(r["end"]) is None else _hex_to_int(r["end"]))
                  for r in allowed_regions]
        for s, e in blocks:
            if not any(rs <= s and e <= re_ for rs, re_ in allowed):
                reasons.append("差异越界 [%s..%s)（超出允许差异区）" % (hex(s), hex(e)))
                break
    return (len(reasons) == 0), reasons, facts


def parse_source_fields(ver_string: str):
    """从 FileVersion/ProductVersion 串解析 (package_version, build, source_hash)。"""
    if not ver_string:
        return None
    m = re.search(r"AMD-Radeon-Driver/drivers:([0-9a-f]{40})", ver_string)
    src = m.group(1) if m else None
    head = ver_string.split(";")
    pkg = head[0] if head else None
    return {"package_version": pkg, "source_hash": src, "raw": ver_string}


def source_ok(facts, manifest, backup_info_path=None, signature_valid=None):
    """来源可核验判定。返回 (ok, evidence_str)。"""
    fields = parse_source_fields(facts.get("version_strings", {}).get("FileVersion", ""))
    evid = []
    ok = False
    if fields and fields["source_hash"]:
        evid.append("version_string source_hash=%s" % fields["source_hash"])
        if backup_info_path:
            txt = Path(backup_info_path).read_text(encoding="utf-8", errors="replace")
            if fields["source_hash"] in txt:
                ok = True
                evid.append("backup_info 命中")
    if signature_valid is True:
        ok = True
        evid.append("Authenticode 签名有效（外部核验）")
    elif signature_valid is False:
        evid.append("签名无效")
    return ok, "; ".join(evid) or "无来源证据"


# ---------------------------------------------------------------- L1/L2/L3 分级

def grade(data: bytes, manifest, reference: bytes = None,
          backup_info_path=None, signature_valid=None, profile=None):
    """候选分级。返回 dict：level、reasons、classification、candidate（仅 L2）。

    profile（1.1.0）：未登记新样本的 overlay（patch_points / structure_invariants
    / allowed_diff_regions）。带 profile 时允许无参照模板（族内首构建），
    以指纹+定位唯一性代替跨构建差异区核对。
    """
    cls = classify(data, manifest)
    # L1：完整哈希命中已批准构建
    if cls["state"] != "unexpected":
        for b in manifest["builds"]:
            if b["name"] == cls["build"]:
                if b.get("approval") == "approved":
                    note = {
                        STATE_ORIG: "原版：先试录（U04），不先写",
                        STATE_FIXED: "完整修复：不重复写，核对试录",
                        STATE_PATCHED: "中间态：不得充当官方原件；走恢复/完整修复须授权",
                    }[cls["state"]]
                    return {"level": "L1", "reasons": [note], "classification": cls, "candidate": None}
                if b.get("approval") == "candidate":
                    # 已登记候选（U05 审批后新增的候选构建记录）：
                    # 可凭审批绑定进入试补；B 臂验收后才转正式（approved）
                    return {"level": "L2",
                            "reasons": ["候选构建记录（approval=candidate）：%s；"
                                        "试补须凭 U05 审批绑定，B 臂 6/6 验收后转正式"
                                        % cls["state"]],
                            "classification": cls,
                            "candidate": {"input_sha256": cls["sha256"],
                                          "candidate_patched_sha256": b["hashes"][STATE_PATCHED],
                                          "candidate_fixed_sha256": b["hashes"][STATE_FIXED],
                                          "from": "build_record"}}
                return {"level": "L3",
                        "reasons": ["命中构建但未获批准（approval=%s）" % b.get("approval")],
                        "classification": cls, "candidate": None}

    # 未命中 → L2 / L3
    s_ok, s_evid = source_ok(pe_facts(data), manifest, backup_info_path, signature_valid)
    if reference is None and profile is None:
        return {"level": "L3", "reasons": ["无参照模板，差异区预演未完成（L2 门禁不齐）"],
                "classification": cls, "candidate": None}
    st_ok, st_reasons, facts = structural_check(data, manifest, reference, profile)
    if not s_ok:
        return {"level": "L3", "reasons": ["来源不可核验（%s）" % s_evid],
                "classification": cls, "candidate": None, "facts": facts}
    if not st_ok:
        return {"level": "L3", "reasons": ["预演门禁未过: " + "；".join(st_reasons)],
                "classification": cls, "candidate": None, "facts": facts}
    # L2：生成候选（内存派生，登记输入/候选完整哈希）
    patch_points = (profile or {}).get("patch_points")
    cand = {"input_sha256": cls["sha256"], "steps": []}
    try:
        p_bytes, p_steps = derive(data, STATE_PATCHED, manifest["rules"], patch_points)
        f_bytes, f_steps = derive(data, STATE_FIXED, manifest["rules"], patch_points)
        # 候选超范围门禁：orig→fixed 的全部差异必须恰为两处补丁点（等长、大小不变）
        off, old_b, new_b, man_old, man_new = _patch_pieces(manifest["rules"], patch_points)
        sites = sorted([(off, off + len(old_b)), (f_bytes.find(man_new), f_bytes.find(man_new) + len(man_new))])
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
            diff_scope="orig→fixed 差异恰为两处补丁点 %s" % [(hex(s), hex(e)) for s, e in sites],
        )
    except Exception as e:
        return {"level": "L3", "reasons": ["候选派生失败: %s" % e],
                "classification": cls, "candidate": None, "facts": facts}
    return {"level": "L2",
            "reasons": ["来源可核验（%s）" % s_evid, "预演门禁全部通过；候选已生成（未批准，禁止写入安装目标）"],
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
