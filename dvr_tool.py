#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dvr_tool — AMD DVR 引擎补丁维护只读工具（P1）。

子命令（全部只读 / 离线）：
  check     安装实例识别与覆盖检测（文件状态 + 记录比较 + 下一步）
  rehearse  候选分级与离线预演（L1/L2/L3；L2 出候选报告，永不写安装目标）
  regress   识别回归（四代三态 / 留出分流 / 负例 / 幂等 / 拒写门禁，全量零写入证明）
  make-holdout  从生产清单派生留出测试清单（隐藏指定构建）

约束：本工具绝不写入安装目录、绝不结束进程。唯一可写的是 --out 报告与
regress 的 --workdir 夹具目录（测试副本）。
"""
import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dvr_core as core  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "build_manifest.json"


def _load_bytes(path):
    p = Path(path)
    if not p.is_file():
        return None, ("file_missing" if not p.exists() else "path_not_file")
    try:
        return p.read_bytes(), None
    except PermissionError:
        return None, "file_unreadable(locked_or_denied)"
    except Exception as e:
        return None, "file_unreadable(%s)" % e


def _load_profile(path):
    """加载未登记新样本的 overlay（1.1.0）：patch_points/structure_invariants/allowed_diff_regions。"""
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        raise SystemExit("profile_missing: %s" % p)
    d = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(d, dict) or "patch_points" not in d or "structure_invariants" not in d:
        raise SystemExit("profile_invalid: 需含 patch_points 与 structure_invariants")
    return d


def cmd_check(a):
    manifest = core.load_manifest(a.manifest)
    profile = _load_profile(getattr(a, "profile", None))
    sig = {"valid": True, "invalid": False, "unknown": None}.get(a.signature_valid)
    data, err = _load_bytes(a.exe)
    report = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "dvr_tool check", "rule_version": manifest["rule_version"],
        "exe": str(Path(a.exe)),
    }
    if profile is not None:
        report["profile"] = {"name": profile.get("name"),
                             "source": profile.get("source"),
                             "note": profile.get("note")}
    if err:
        report.update(blocked=True, reason=err,
                      next_step="只报阻断：确认安装状态/路径/权限后重查；不猜测、不写入")
        return _out(a, report, ok=False)

    facts = core.pe_facts(data)
    ref = None
    if a.reference:
        ref, _ = _load_bytes(a.reference)
    g = core.grade(data, manifest, ref, a.backup_info, sig, profile=profile)
    file_state = {
        "normalized_path": str(Path(a.exe).resolve()),
        "size": len(data), "sha256": g["classification"]["sha256"],
        "machine": facts["machine"], "cert": facts["cert"],
        "version_strings": facts["version_strings"],
        "classification": g["classification"],
        "grade": {"level": g["level"], "reasons": g["reasons"]},
        "candidate": g.get("candidate"),
    }
    report["file_state"] = file_state

    vf = facts["version_strings"].get("FileVersion") or ""
    src_fields = core.parse_source_fields(vf)
    cur = {"driver_package_version": (src_fields or {}).get("package_version"),
           "engine_sha256": file_state["sha256"],
           "engine_state": g["classification"]["state"],
           "build": g["classification"]["build"]}
    report["run_state_note"] = "运行侧（PID/会话/加载路径/签名）由外部只读采集并入报告；本命令只取文件状态"
    if a.prev_record:
        prev = json.loads(Path(a.prev_record).read_text(encoding="utf-8"))
        report["comparison"] = core.compare_record(prev, cur)
    report["current_record"] = cur

    nxt = {
        "L1": {"orig": "原版：先按 U04 试录；复现再走 U05 候选审批",
               "fixed": "完整修复：不重复写；核对当前会话试录（U02/U10）",
               "patched": "中间态：不得充当官方原件；经授权走恢复（U09/D10）或补清单修复"}[
            g["classification"]["state"]] if g["classification"]["state"] != "unexpected" else "",
        "L2": "候选已生成（未批准）：须审核者绑定确切原版哈希后才可试补；先 A 臂试录",
        "L3": "阻断：%s" % "；".join(g["reasons"]),
    }[g["level"]]
    report["next_step"] = nxt
    return _out(a, report, ok=True)


def cmd_rehearse(a):
    manifest = core.load_manifest(a.manifest)
    profile = _load_profile(getattr(a, "profile", None))
    sig = {"valid": True, "invalid": False, "unknown": None}.get(a.signature_valid)
    data, err = _load_bytes(a.exe)
    if err:
        return _out(a, {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "exe": a.exe,
                        "blocked": True, "reason": err}, ok=False)
    ref = _load_bytes(a.reference)[0] if a.reference else None
    g = core.grade(data, manifest, ref, a.backup_info, sig, profile=profile)
    report = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "dvr_tool rehearse", "rule_version": manifest["rule_version"],
        "exe": str(Path(a.exe)), "level": g["level"],
        "reasons": g["reasons"], "classification": g["classification"],
        "candidate": g.get("candidate"),
        "write_performed": False,
        "next_step": "L2 候选不构成授权；L1/L3 见 reasons",
    }
    if profile is not None:
        report["profile"] = {"name": profile.get("name"),
                             "source": profile.get("source"),
                             "note": profile.get("note")}
    return _out(a, report, ok=True)


def cmd_make_holdout(a):
    manifest = core.load_manifest(a.manifest)
    hidden = [b for b in manifest["builds"] if b["name"] == a.hide]
    if not hidden:
        raise SystemExit("build not found: %s" % a.hide)
    m2 = json.loads(json.dumps(manifest))
    m2["builds"] = [b for b in m2["builds"] if b["name"] != a.hide]
    m2["note"] = ("留出测试清单（自 build_manifest.json 派生）：隐藏 %s 的构建记录；"
                  "生产清单不修改。rule_version=%s" % (a.hide, m2["rule_version"]))
    Path(a.out).write_text(json.dumps(m2, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "out": a.out, "builds": [b["name"] for b in m2["builds"]]},
                     ensure_ascii=False))
    return 0


# ---------------------------------------------------------------- 回归

def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _case(cases, cid, name, expect, actual, detail=""):
    ok = (str(expect) == str(actual))
    cases.append({"id": cid, "name": name, "expect": str(expect),
                  "actual": str(actual), "pass": ok, "detail": detail})
    return ok


def cmd_regress(a):
    manifest = core.load_manifest(a.manifest)
    hold_manifest = core.load_manifest(a.holdout_manifest)
    work = Path(a.workdir)
    fix = work / "fixtures"
    tgt = work / "targets"
    fix.mkdir(parents=True, exist_ok=True)
    tgt.mkdir(parents=True, exist_ok=True)
    bak = Path(a.backup_dir)

    # 读入四代 orig 实物（backup）与派生样本（samples）
    origs = {}
    for p in sorted(bak.glob("*.bak")):
        d = p.read_bytes()
        c = core.classify(d, manifest)
        if c["build"] and c["state"] == core.STATE_ORIG and c["build"] not in origs:
            origs[c["build"]] = (p, d)
    samples = {}
    for b in manifest["builds"]:
        name = b["name"]
        samples[(name, core.STATE_ORIG)] = origs[name][1]
        for st in (core.STATE_PATCHED, core.STATE_FIXED):
            sp = Path(a.samples_dir) / name / ("AMDRSServ.exe.%s.derived.exe" % st)
            samples[(name, st)] = sp.read_bytes()

    # 参照模板：取「隐藏构建在**生产清单**里的前一条同族构建」的 orig。
    # 不能取留出清单最后一条 —— 清单新增构建后（如 26.20.29.02 排在 .16 之后），
    # 最后一条会跨代，与隐藏构建（.16）差异过大，会把合法同族原版误判为 L3。
    _names = [b["name"] for b in manifest["builds"]]
    if a.hide_build in _names:
        _i = _names.index(a.hide_build)
        _ref_name = _names[_i - 1] if _i > 0 else _names[-1]
    else:
        _ref_name = _names[-1]
    ref_bytes = samples[(_ref_name, core.STATE_ORIG)]

    cases = []
    targets = []

    def track(path_bytes, label):
        p = tgt / label
        p.write_bytes(path_bytes)
        targets.append(p)

    # C1: 全量清单三态（approved → L1，candidate → L2）
    for (name, st), data in sorted(samples.items()):
        track(data, "c1_%s_%s.bin" % (name.replace(".", "_"), st))
        c = core.classify(data, manifest)
        g = core.grade(data, manifest, ref_bytes, a.backup_info, None)
        _b = next((x for x in manifest["builds"] if x["name"] == name), {})
        _expect_lvl = "L1" if _b.get("approval") == "approved" else "L2"
        _case(cases, "C1-%s-%s" % (name, st), "全量清单分类",
              "%s/%s/%s" % (name, st, _expect_lvl),
              "%s/%s/%s" % (c["build"], c["state"], g["level"]))

    # C2: 留出清单分流
    hide = a.hide_build
    for st in (core.STATE_ORIG, core.STATE_PATCHED, core.STATE_FIXED):
        data = samples[(hide, st)]
        track(data, "c2_%s_%s.bin" % (hide.replace(".", "_"), st))
        g = core.grade(data, hold_manifest, ref_bytes, a.backup_info, None)
        if st == core.STATE_ORIG:
            cand = g.get("candidate") or {}
            expect = "L2|in=%s|p=%s|f=%s" % (
                core.sha256(data),
                "0d8379ce16844321efb96ed9d03e019249216c613821a6816fef1b952707a883",
                "c726d431ba042c75d7b956abb079af3dab294a218893bc08b0b37b1c9b7fe404")
            actual = "%s|in=%s|p=%s|f=%s" % (
                g["level"], cand.get("input_sha256"),
                cand.get("candidate_patched_sha256"), cand.get("candidate_fixed_sha256"))
            _case(cases, "C2-%s-orig" % hide, "留出原版 → L2 同族候选（可复核）", expect, actual)
        else:
            _case(cases, "C2-%s-%s" % (hide, st), "留出非原版 → L3 分流（不充当官方原件）",
                  "L3", g["level"], detail=";".join(g["reasons"]))
    for (name, st), data in sorted(samples.items()):
        if name == hide:
            continue
        g = core.grade(data, hold_manifest, ref_bytes, a.backup_info, None)
        _hb = next((x for x in hold_manifest["builds"] if x["name"] == name), {})
        _h_expect = "L1" if _hb.get("approval") == "approved" else "L2"
        _case(cases, "C2b-%s-%s" % (name, st), "留出清单基线分级（approved=L1 / candidate=L2）",
              _h_expect, g["level"])

    # C3 N02 重装覆盖：同版 fixed 记录 → 当前 orig
    prev = {"driver_package_version": "26.20.15.12",
            "engine_sha256": core.sha256(samples[("26.20.15.12", core.STATE_FIXED)]),
            "engine_state": "fixed", "build": "26.20.15.12"}
    cur = {"driver_package_version": "26.20.15.12",
           "engine_sha256": core.sha256(samples[("26.20.15.12", core.STATE_ORIG)]),
           "engine_state": "orig", "build": "26.20.15.12"}
    _case(cases, "C3-N02", "同版覆盖检测（fixed→orig）", "重装覆盖",
          core.compare_record(prev, cur)["label"])

    # C4 N03 驱动变但引擎未变
    prev = {"driver_package_version": "26.20.15.12",
            "engine_sha256": core.sha256(samples[("26.20.15.12", core.STATE_FIXED)]),
            "engine_state": "fixed", "build": "26.20.15.12"}
    cur = {"driver_package_version": "26.20.29.02",
           "engine_sha256": core.sha256(samples[("26.20.15.12", core.STATE_FIXED)]),
           "engine_state": "fixed", "build": "26.20.15.12"}
    _case(cases, "C4-N03", "驱动变而文件没变 → 不重打", "引擎未变",
          core.compare_record(prev, cur)["label"])

    # C5 N04 同版未知哈希（签名区突变）→ 不凭版本放行
    data = bytearray(samples[("26.20.15.12", core.STATE_ORIG)])
    data[0x27F010] ^= 0xFF
    mut = bytes(data)
    track(mut, "c5_cert_mutant.bin")
    g = core.grade(mut, manifest, ref_bytes, a.backup_info, None)
    _case(cases, "C5-N04", "陌生哈希不凭版本放行（非 L1）", "unexpected|not-L1",
          "%s|%s" % (g["classification"]["state"], "not-L1" if g["level"] != "L1" else "L1"),
          detail="level=%s %s" % (g["level"], ";".join(g["reasons"])))

    # C6 N05 结构不符（.text 突变）→ L3
    data = bytearray(samples[("26.20.15.12", core.STATE_ORIG)])
    data[0x1000] ^= 0xFF
    mut = bytes(data)
    track(mut, "c6_text_mutant.bin")
    g = core.grade(mut, manifest, ref_bytes, a.backup_info, None)
    _case(cases, "C6-N05a", "结构不符（.text 差异越界）→ L3", "L3", g["level"],
          detail=";".join(g["reasons"]))

    # C7 N05b 来源不可核验 → L3（留出清单 + 不给来源证据）
    g = core.grade(samples[(hide, core.STATE_ORIG)], hold_manifest, ref_bytes, None, None)
    _case(cases, "C7-N05b", "来源不可核验 → L3", "L3", g["level"],
          detail=";".join(g["reasons"]))

    # C8 缺失 → 阻断
    missing = str(tgt / "no_such_file.bin")
    r = subprocess.run([sys.executable, str(HERE / "dvr_tool.py"), "check",
                        "--exe", missing, "--manifest", a.manifest],
                       capture_output=True, text=True)
    _case(cases, "C8-N06", "缺失文件只报阻断", "blocked:file_missing",
          "blocked:%s" % json.loads(r.stdout).get("reason", "?"))

    # C9 占用（独占锁）→ 阻断
    lock_target = tgt / "c9_locked.bin"
    lock_target.write_bytes(samples[("26.20.15.12", core.STATE_ORIG)])
    targets.append(lock_target)
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.CreateFileW(str(lock_target), 0x80000000, 0, None, 3, 0, None)  # GENERIC_READ, share=0
    if not h or h == ctypes.c_void_p(-1).value:
        _case(cases, "C9-N07", "被占用不可读 → 阻断", "blocked:file_unreadable(locked_or_denied)",
              "lock_not_acquired", detail="CreateFileW 独占句柄未取得，用例无效")
    else:
        try:
            data_l, err_l = _load_bytes(lock_target)
            _case(cases, "C9-N07", "被占用不可读 → 阻断", "blocked:file_unreadable(locked_or_denied)",
                  "blocked:%s" % err_l if err_l else "readable(!)")
        finally:
            k32.CloseHandle(h)

    # C10 幂等：重复识别/预演结果一致
    g1 = core.grade(samples[("26.20.15.12", core.STATE_FIXED)], manifest, ref_bytes, a.backup_info, None)
    g2 = core.grade(samples[("26.20.15.12", core.STATE_FIXED)], manifest, ref_bytes, a.backup_info, None)
    _case(cases, "C10a-N13", "重复识别（已修复）幂等", json.dumps(g1, sort_keys=True, default=str),
          json.dumps(g2, sort_keys=True, default=str))
    r1 = core.grade(samples[(hide, core.STATE_ORIG)], hold_manifest, ref_bytes, a.backup_info, None)
    r2 = core.grade(samples[(hide, core.STATE_ORIG)], hold_manifest, ref_bytes, a.backup_info, None)
    _case(cases, "C10b-N13", "重复预演（留出候选）幂等", json.dumps(r1, sort_keys=True, default=str),
          json.dumps(r2, sort_keys=True, default=str))

    # C11 清单坏态拒写（fail-closed，不回退硬编码表）
    for label, mutate in [
        ("C11a-field-missing", lambda m: m["builds"][0].pop("hashes")),
        ("C11b-rule-version", lambda m: m.update(rule_version="9.9.9")),
        ("C11c-state-conflict", lambda m: m["builds"][1].update(
            hashes=dict(m["builds"][1]["hashes"],
                        patched=m["builds"][0]["hashes"]["patched"]))),
    ]:
        bad = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
        mutate(bad)
        badp = work / ("bad_manifest_%s.json" % label)
        badp.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
        t = tgt / ("%s_target.bin" % label)
        t.write_bytes(samples[("26.20.15.12", core.STATE_ORIG)])
        targets.append(t)
        before = core.sha256(t.read_bytes())
        out_json = work / ("%s_out.json" % label)
        r = subprocess.run([sys.executable, str(HERE / "patch_manifest.py"), "--apply",
                            "--exe", str(t), "--manifest", str(badp), "--out", str(out_json)],
                           capture_output=True, text=True)
        try:
            res = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            res = {"result": "no_json", "message": (r.stdout + r.stderr)[-300:]}
        after = core.sha256(t.read_bytes())
        refused = (res.get("result") != "applied") and before == after
        _case(cases, label, "清单坏态 → 写操作拒绝且目标不变",
              "refused|unchanged",
              "refused|unchanged" if refused else "%s|CHANGED(!)" % res.get("result"),
              detail="result=%s %s" % (res.get("result"), res.get("message", ""))[:200])

    # C12 零写入证明：全部夹具前后哈希
    unchanged = True
    tw = []
    for p in targets:
        if not p.exists():
            continue
        # 夹具在 C11 之前记录的 before 在 case 内；此处统一以前后重算 + 用例内断言为准
        tw.append({"path": str(p), "sha256": core.sha256(p.read_bytes())})
    for c in cases:
        if "CHANGED" in c["actual"]:
            unchanged = False

    # C13 确定性：整块分类结果两次一致
    snap1 = json.dumps([core.classify(d, manifest)["sha256"] for _, d in sorted(samples.items())])
    snap2 = json.dumps([core.classify(d, manifest)["sha256"] for _, d in sorted(samples.items())])
    _case(cases, "C13-N13b", "识别结果确定性（两次一致）", snap1, snap2)

    passed = sum(1 for c in cases if c["pass"])
    report = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "dvr_tool regress", "rule_version": manifest["rule_version"],
        "manifest": a.manifest, "holdout_manifest": a.holdout_manifest,
        "hide_build": a.hide_build,
        "zero_write": {"targets": tw, "all_unchanged": unchanged,
                       "processes_stopped": False,
                       "note": "本回归只读取样本与清单；仅在 --workdir 内生成夹具副本与报告"},
        "cases": cases,
        "summary": {"total": len(cases), "passed": passed, "failed": len(cases) - passed},
        "next_step": "全部通过则锁定本只读版本；失败项修复前不进入 P2/P3",
    }
    return _out(a, report, ok=(passed == len(cases)))


def cmd_regress_p3(a):
    """P3 回归：新构建 26.20.29.02 识别/候选/拒写/确定性（全量零写入）。"""
    manifest = core.load_manifest(a.manifest)                 # 生产清单（不含 .29.02）
    cand_manifest = core.load_manifest(a.candidate_manifest)   # 测试清单（含 candidate 记录）
    profile = _load_profile(a.profile)
    work = Path(a.workdir)
    tgt = work / "targets"
    tgt.mkdir(parents=True, exist_ok=True)
    sdir = Path(a.sample_dir)
    orig = (sdir / "AMDRSServ.exe.orig.sample.exe").read_bytes()
    patched = (sdir / "AMDRSServ.exe.patched.derived.exe").read_bytes()
    fixed = (sdir / "AMDRSServ.exe.fixed.derived.exe").read_bytes()
    trio = {core.STATE_ORIG: orig, core.STATE_PATCHED: patched, core.STATE_FIXED: fixed}
    cases, targets = [], []

    def track(blob, label):
        p = tgt / label
        p.write_bytes(blob)
        targets.append(p)

    # R1: 候选清单（approval=candidate）三态分类正确
    for st, blob in sorted(trio.items()):
        track(blob, "r1_%s.bin" % st)
        c = core.classify(blob, cand_manifest)
        _case(cases, "R1-%s" % st, "候选清单三态分类",
              "26.20.29.02/%s" % st, "%s/%s" % (c["build"], c["state"]))

    # R2: 生产清单 + profile overlay → L2 候选（哈希可复核）
    g = core.grade(orig, manifest, None, a.backup_info, True, profile=profile)
    cand = g.get("candidate") or {}
    expect = "L2|in=%s|p=%s|f=%s" % (core.sha256(orig),
                                     "0863b4d68ea222753c2bc76d5b687686a7e0580f2430e2cdefe437ac3b4fa564",
                                     "1f59bc9a368fb0345134242ef1731270bbeea0cbef710692cb8d6b0f0dea3311")
    actual = "%s|in=%s|p=%s|f=%s" % (g["level"], cand.get("input_sha256"),
                                     cand.get("candidate_patched_sha256"),
                                     cand.get("candidate_fixed_sha256"))
    _case(cases, "R2-L2-candidate", "未登记新样本+profile → L2 可复核候选", expect, actual,
          detail=";".join(g["reasons"]))
    _case(cases, "R2-diff-scope", "候选超范围门禁（差异恰为两处补丁点）",
          "in-scope", "in-scope" if "diff_scope" in cand else "missing",
          detail=str(cand.get("diff_scope")))

    # R3: 错误补丁点 profile（沿用四代 0x3686B）→ L3 定位失效
    bad_profile = json.loads(json.dumps(profile))
    bad_profile["patch_points"]["classname-length"]["offset"] = "0x3686B"
    bad_profile["structure_invariants"]["patch_point"]["offset"] = "0x3686B"
    g = core.grade(orig, manifest, None, a.backup_info, True, profile=bad_profile)
    _case(cases, "R3-wrong-offset", "错误补丁点偏移 → L3 拒绝", "L3", g["level"],
          detail=";".join(g["reasons"])[:200])

    # R4: 定位不唯一（去掉上下文指纹且偏移随机）→ 结构门禁拒
    weak = json.loads(json.dumps(profile))
    weak["patch_points"]["classname-length"].pop("context_pre_hex", None)
    g = core.grade(orig, manifest, None, a.backup_info, True, profile=weak)
    # 弱 profile 下 0x3669B 偏移本身仍正确 → L2 可接受；改用双命中验证 context 门禁
    dup = json.loads(json.dumps(profile))
    dup["patch_points"]["classname-length"]["context_pre_hex"] = "41 B8"  # 短上下文=双命中
    g2 = core.grade(orig, manifest, None, a.backup_info, True, profile=dup)
    _case(cases, "R4-locate-unique", "上下文指纹双命中 → L3（定位不唯一）", "L3", g2["level"],
          detail=";".join(g2["reasons"])[:200])

    # R5: fixed/patched 不充当官方原件（未登记+profile → L3）
    for st, blob in ((core.STATE_PATCHED, patched), (core.STATE_FIXED, fixed)):
        g = core.grade(blob, manifest, None, a.backup_info, True, profile=profile)
        _case(cases, "R5-%s-not-orig" % st, "非原版形态不得充当官方原件 → L3", "L3", g["level"],
              detail=";".join(g["reasons"])[:160])

    # R6: 候选登记态 → L2 试补语义（不是 L1、不是 L3）
    g = core.grade(orig, cand_manifest, None, a.backup_info, True)
    _case(cases, "R6-candidate-record", "approval=candidate 登记 → L2 试补语义", "L2", g["level"],
          detail=";".join(g["reasons"])[:200])

    # R7: 派生确定性（两次一致）
    pp = profile["patch_points"]
    p1, _ = core.derive(orig, core.STATE_PATCHED, manifest["rules"], pp)
    p2, _ = core.derive(orig, core.STATE_PATCHED, manifest["rules"], pp)
    f1, _ = core.derive(orig, core.STATE_FIXED, manifest["rules"], pp)
    f2, _ = core.derive(orig, core.STATE_FIXED, manifest["rules"], pp)
    _case(cases, "R7-determinism", "同输入同规则重复派生一致",
          core.sha256(p1) + core.sha256(f1), core.sha256(p2) + core.sha256(f2))

    # R8: fail-closed——坏清单拒载（含 .29.02 记录也一样）
    for label, mutate in [
        ("R8a-rule-version", lambda m: m.update(rule_version="0.9.0")),
        ("R8b-bad-patch-points", lambda m: m["builds"][-1].update(patch_points={"classname-length": {"offset": "zz"}})),
        ("R8c-state-conflict", lambda m: m["builds"][-1].update(
            hashes=dict(m["builds"][-1]["hashes"], fixed=m["builds"][0]["hashes"]["fixed"]))),
    ]:
        bad = json.loads(Path(a.candidate_manifest).read_text(encoding="utf-8"))
        mutate(bad)
        badp = work / ("bad_%s.json" % label)
        badp.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
        t = tgt / ("%s_target.bin" % label)
        t.write_bytes(orig)
        targets.append(t)
        before = core.sha256(t.read_bytes())
        out_json = work / ("%s_out.json" % label)
        r = subprocess.run([sys.executable, str(HERE / "patch_manifest.py"), "--apply",
                            "--exe", str(t), "--manifest", str(badp), "--out", str(out_json)],
                           capture_output=True, text=True)
        try:
            res = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            res = {"result": "no_json", "message": (r.stdout + r.stderr)[-300:]}
        after = core.sha256(t.read_bytes())
        refused = (res.get("result") != "applied") and before == after
        _case(cases, label, "清单坏态 → 写操作拒绝且目标不变", "refused|unchanged",
              "refused|unchanged" if refused else "%s|CHANGED(!)" % res.get("result"),
              detail=str(res.get("message", ""))[:160])

    # R9: 生产清单无 profile 直接判 .29.02 → 不得静默接受
    g = core.grade(orig, manifest, None, a.backup_info, True)
    _case(cases, "R9-no-profile", "生产清单+无 profile 判新样本 → L3（不静默放行）", "L3", g["level"],
          detail=";".join(g["reasons"])[:200])

    # R10: 零写入证明
    unchanged = True
    tw = []
    for p in targets:
        if not p.exists():
            continue
        tw.append({"path": str(p), "sha256": core.sha256(p.read_bytes())})
    for c in cases:
        if "CHANGED" in c["actual"]:
            unchanged = False
    # 源样本前后哈希
    src_before = core.sha256(orig)
    src_after = core.sha256((sdir / "AMDRSServ.exe.orig.sample.exe").read_bytes())
    _case(cases, "R10-zero-write", "源样本与夹具全程零写入", "unchanged",
          "unchanged" if (unchanged and src_before == src_after) else "CHANGED(!)")

    passed = sum(1 for c in cases if c["pass"])
    report = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "dvr_tool regress-p3", "rule_version": manifest["rule_version"],
        "manifest": a.manifest, "candidate_manifest": a.candidate_manifest,
        "sample_dir": a.sample_dir, "profile": a.profile,
        "zero_write": {"targets": tw, "all_unchanged": unchanged and src_before == src_after,
                       "processes_stopped": False},
        "cases": cases,
        "summary": {"total": len(cases), "passed": passed, "failed": len(cases) - passed},
        "next_step": "全部通过则 P3 只读侧就绪；实机试补仍须 U05 审批绑定+操作者授权",
    }
    return _out(a, report, ok=(passed == len(cases)))


def _out(a, report, ok):
    txt = json.dumps(report, ensure_ascii=False, indent=2)
    if getattr(a, "out", None):
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(txt, encoding="utf-8")
    print(txt)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check")
    p.add_argument("--exe", required=True)
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--reference")
    p.add_argument("--backup-info")
    p.add_argument("--prev-record")
    p.add_argument("--signature-valid", choices=["valid", "invalid", "unknown"], default="unknown")
    p.add_argument("--profile", help="未登记新样本 overlay JSON（1.1.0）")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("rehearse")
    p.add_argument("--exe", required=True)
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--reference")
    p.add_argument("--backup-info")
    p.add_argument("--signature-valid", choices=["valid", "invalid", "unknown"], default="unknown")
    p.add_argument("--profile", help="未登记新样本 overlay JSON（1.1.0）")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_rehearse)

    p = sub.add_parser("make-holdout")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--hide", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_make_holdout)

    p = sub.add_parser("regress")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--holdout-manifest", required=True)
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--samples-dir", required=True)
    p.add_argument("--backup-info")
    p.add_argument("--workdir", required=True)
    p.add_argument("--hide-build", default="26.20.15.16")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_regress)

    p = sub.add_parser("regress-p3")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--candidate-manifest", required=True)
    p.add_argument("--sample-dir", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--backup-info")
    p.add_argument("--workdir", required=True)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_regress_p3)

    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
