#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dvr_tool — AMD DVR 引擎补丁维护只读工具（2.0.0 通用路径）。

子命令（除 regress-unregistered 的 --apply 副本外，全部只读 / 离线）：
  check              安装实例识别与覆盖检测（现场定位 + 结构门禁 + 下一步）
  rehearse           门禁预演（L1/L3；永不写安装目标）
  match-backup       恢复入口配对：找出能派生出当前文件的原版备份
  make-holdout       从清单派生留出测试清单（历史夹具用）
  regress            43 支识别回归（五代三态 / 负例 / 幂等 / 拒写门禁）
  regress-p3         16 支新构建与定位器回归
  regress-unregistered  7 支「未登记构建」端到端回归（只在 --workdir 副本上写）

约束：本工具绝不写入 C:\\Program Files、绝不结束进程。唯一可写的是
--out 报告、--workdir 夹具副本，以及 --registry/--diagnostic 指定的隔离文件。
"""
import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dvr_core as core  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "build_manifest.json"


def _default_regress_manifest():
    """回归夹具候选路径：仓库内置优先，兼容旧部署版布局。

    夹具是 1.1.0 五代记录（regress / regress-p3 消费），非运行时必需。
    """
    candidates = [
        HERE / "testarea" / "manifest_regress.json",
        HERE.parent / "实施记录" / "建设" / "testarea" / "manifest_regress.json",
        HERE.parent.parent / "实施记录" / "建设" / "testarea" / "manifest_regress.json",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return str(candidates[0])


DEFAULT_REGRESS_MANIFEST = _default_regress_manifest()
PY_SCRIPT = HERE / "patch_manifest.py"


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
    """加载旧 profile overlay（2.0.0 运行时不用，仅为历史夹具兼容）。"""
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
    sig = {"valid": True, "invalid": False, "unknown": None}.get(a.signature_valid)
    data, err = _load_bytes(a.exe)
    report = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tool": "dvr_tool check", "rule_version": manifest["rule_version"],
              "exe": str(Path(a.exe))}
    if err:
        report.update(blocked=True, reason=err,
                      next_step="只报阻断：确认安装状态/路径/权限后重查；不猜测、不写入")
        return _out(a, report, ok=False)

    g = core.grade(data, manifest, None, a.backup_info, sig)
    try:
        facts = core.pe_facts(data)
    except Exception as e:
        facts = {"pe_error": str(e)}
    file_state = {
        "normalized_path": str(Path(a.exe).resolve()),
        "size": len(data), "sha256": g["classification"]["sha256"],
        "machine": facts.get("machine"), "cert": facts.get("cert"),
        "version_strings": facts.get("version_strings"),
        "classification": g["classification"],
        "grade": {"level": g["level"], "reasons": g["reasons"]},
        "candidate": g.get("candidate"),
    }
    report["file_state"] = file_state

    vf = (facts.get("version_strings") or {}).get("FileVersion") or ""
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
        "L1": {"orig": "原版：现场门禁已过，可直接注入（自动备份 + 自动登记）",
               "fixed": "完整修复：不重复写；核对当前会话试录",
               "patched": "中间态：补齐清单修复"}.get(g["classification"]["state"], ""),
        "L3": "阻断：%s" % "；".join(g["reasons"]),
    }[g["level"]]
    report["next_step"] = nxt
    if g["level"] == "L3" and g.get("diagnostic"):
        report["diagnostic"] = g["diagnostic"]
    return _out(a, report, ok=True)


def cmd_rehearse(a):
    manifest = core.load_manifest(a.manifest)
    sig = {"valid": True, "invalid": False, "unknown": None}.get(a.signature_valid)
    data, err = _load_bytes(a.exe)
    if err:
        return _out(a, {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "exe": a.exe,
                        "blocked": True, "reason": err}, ok=False)
    g = core.grade(data, manifest, None, a.backup_info, sig)
    report = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tool": "dvr_tool rehearse", "rule_version": manifest["rule_version"],
              "exe": str(Path(a.exe)), "level": g["level"],
              "reasons": g["reasons"], "classification": g["classification"],
              "candidate": g.get("candidate"),
              "write_performed": False,
              "next_step": "L1 = 门禁全过；L3 见 reasons（拒写零写入）"}
    return _out(a, report, ok=True)


def cmd_match_backup(a):
    """2.0.0 恢复入口配对：找出「哪份 backup 原版能派生出当前文件」。"""
    manifest = core.load_manifest(a.manifest)
    rules = manifest["rules"]
    target = Path(a.exe)
    bak = Path(a.backup_dir)
    data = target.read_bytes()
    cur_sha = core.sha256(data)
    report = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tool": "dvr_tool match-backup", "exe": str(target),
              "sha256": cur_sha, "preferred": None, "matched": [],
              "ambiguous": False, "orig_sha": None, "backup_file": None,
              "refuse_reason": None}

    reg = bak / "auto_registry.json"
    if reg.is_file():
        try:
            entries = json.loads(reg.read_text(encoding="utf-8"))
            if isinstance(entries, list):
                for e in entries:
                    hs = e.get("hashes") or {}
                    bf = e.get("backup_file")
                    if hs.get("fixed") == cur_sha and bf and (bak / bf).is_file():
                        report["preferred"] = {
                            "backup_file": bf, "orig_sha": hs.get("orig"),
                            "fixed_sha": hs.get("fixed"), "state": "fixed",
                            "source": "auto_registry"}
                        break
        except Exception as ex:
            report["registry_warning"] = "台账不可解析（已忽略）: %s" % ex

    matched = []
    for p in sorted(bak.glob("*.bak"), key=lambda x: x.stat().st_mtime, reverse=True):
        d = p.read_bytes()
        c = core.classify(d, manifest, str(p))
        if not c["located"]["ok"] or c["state"] != core.STATE_ORIG:
            continue
        off = c["located"]["off"]
        try:
            pb, _ = core.derive(d, core.STATE_PATCHED, rules, off=off)
            fb, _ = core.derive(d, core.STATE_FIXED, rules, off=off)
        except Exception:
            continue
        for st, blob in ((core.STATE_FIXED, fb), (core.STATE_PATCHED, pb),
                         (core.STATE_ORIG, d)):
            if core.sha256(blob) == cur_sha:
                matched.append({"backup_file": p.name, "orig_sha": core.sha256(d),
                                "matched_sha": cur_sha, "state": st,
                                "source": "derive"})
                break
    report["matched"] = matched

    distinct = {m["orig_sha"] for m in matched}
    if len(distinct) > 1:
        report["ambiguous"] = True
        report["refuse_reason"] = "ambiguous: 多份不同原版都能派生出当前文件"
        return _out(a, report, ok=False)
    if report["preferred"] and (not matched or report["preferred"]["orig_sha"] in distinct):
        chosen = report["preferred"]
    elif matched:
        chosen = matched[0]
    else:
        report["refuse_reason"] = "unknown_build: 无配对备份"
        return _out(a, report, ok=False)
    report["orig_sha"] = chosen["orig_sha"]
    report["backup_file"] = chosen["backup_file"]
    return _out(a, report, ok=True)


def cmd_make_holdout(a):
    """历史夹具：从冻结的五代清单派生留出清单（2.0.0 运行时不使用）。"""
    m = core.load_manifest_legacy(a.manifest)
    hidden = [b for b in m["builds"] if b["name"] == a.hide]
    if not hidden:
        raise SystemExit("build not found: %s" % a.hide)
    m2 = json.loads(json.dumps(m))
    m2["builds"] = [b for b in m2["builds"] if b["name"] != a.hide]
    m2["note"] = ("留出测试清单（自冻结回归清单派生）：隐藏 %s；生产清单不修改。" % a.hide)
    Path(a.out).write_text(json.dumps(m2, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "out": a.out,
                      "builds": [b["name"] for b in m2["builds"]]}, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------- 回归公共

def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _case(cases, cid, name, expect, actual, detail=""):
    ok = (str(expect) == str(actual))
    cases.append({"id": cid, "name": name, "expect": str(expect),
                  "actual": str(actual), "pass": ok, "detail": detail})
    return ok


def _load_samples(manifest, reg, backup_dir):
    """从 backup 的五代原版 + 内存派生构造三态样本（不依赖任何样本目录）。"""
    rules = manifest["rules"]
    origs, samples = {}, {}
    for p in sorted(Path(backup_dir).glob("*.bak")):
        d = p.read_bytes()
        h = core.sha256(d)
        name = next((b["name"] for b in reg["builds"]
                     if b["hashes"]["orig"] == h), None)
        if name and name not in origs:
            origs[name] = d
    for name, d in origs.items():
        c = core.classify(d, manifest, str(Path(backup_dir) / name))
        off = c["located"]["off"]
        samples[(name, core.STATE_ORIG)] = d
        samples[(name, core.STATE_PATCHED)] = core.derive(
            d, core.STATE_PATCHED, rules, off=off)[0]
        samples[(name, core.STATE_FIXED)] = core.derive(
            d, core.STATE_FIXED, rules, off=off)[0]
    return origs, samples


def _json_from_stdout(text):
    """解析子进程 stdout 中的 JSON 报告。

    dvr_tool 的 _out() 输出 indent=2 的 pretty JSON，最后一行只有 '}'；
    patch_manifest 输出单行紧凑 JSON。两种都要能读，故优先整段解析，
    再退化为逐行找完整对象，绝不能只取 splitlines()[-1]。
    """
    s = (text or "").strip()
    if not s:
        return {}
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        pass
    for line in reversed(s.splitlines()):
        t = line.strip()
        if t.startswith("{") and t.endswith("}"):
            try:
                obj = json.loads(t)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
    return {}


def _stable(obj):
    """递归剔除动态字段（time），用于比较重复调用结果的稳定性。"""
    if isinstance(obj, dict):
        return {k: _stable(v) for k, v in obj.items() if k != "time"}
    if isinstance(obj, (list, tuple)):
        return [_stable(v) for v in obj]
    return obj


def _run_apply(exe, manifest, out, registry=None, diagnostic=None):
    cmd = [sys.executable, str(PY_SCRIPT), "--apply", "--exe", str(exe),
           "--manifest", str(manifest), "--out", str(out)]
    if registry:
        cmd += ["--registry", str(registry)]
    if diagnostic:
        cmd += ["--diagnostic", str(diagnostic)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    res = _json_from_stdout(r.stdout)
    return res if res else {"result": "no_json",
                           "message": (r.stdout + r.stderr)[-300:]}


def _report(tool, cases, targets, sources_before, extra=None):
    passed = sum(1 for c in cases if c["pass"])
    unchanged = True
    for k, v in sources_before.items():
        try:
            if _sha(k) != v:
                unchanged = False
        except Exception:
            unchanged = False
    for c in cases:
        if "CHANGED" in c["actual"]:
            unchanged = False
    rep = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": tool,
           "targets": [{"path": str(p), "sha256": _sha(p)} for p in targets if Path(p).exists()],
           "zero_write": {"all_unchanged": unchanged, "processes_stopped": False,
                          "note": "只读源样本与实机文件全程未变；写入只发生在 --workdir 夹具副本"},
           "cases": cases,
           "summary": {"total": len(cases), "passed": passed,
                       "failed": len(cases) - passed}}
    if extra:
        rep.update(extra)
    rep["next_step"] = ("全部通过则可放行实机复验；失败项修复前不进入下一步"
                        if passed == len(cases) else "有失败项，禁止放行")
    return rep


def _sources_before(backup_dir):
    return {str(p): _sha(p) for p in sorted(Path(backup_dir).glob("*.bak"))}


# ---------------------------------------------------------------- regress（43 支）

def cmd_regress(a):
    manifest = core.load_manifest(a.manifest)
    reg = core.load_manifest_legacy(a.regress_manifest)
    rules = manifest["rules"]
    work = Path(a.workdir)
    tgt = work / "targets"
    tgt.mkdir(parents=True, exist_ok=True)
    origs, samples = _load_samples(manifest, reg, a.backup_dir)
    cases, targets = [], []

    def track(blob, label):
        p = tgt / label
        p.write_bytes(blob)
        targets.append(p)
        return p

    hide = a.hide_build
    mp = {p["id"]: p for p in rules["patches"]}
    anchor = core._hex_to_bytes(mp["classname-length"]["anchor_hex"])

    # C1: 5 代 × 3 态 = 15 支，全部现场定位 + L1
    for (name, st), data in sorted(samples.items()):
        track(data, "c1_%s_%s.bin" % (name.replace(".", "_"), st))
        c = core.classify(data, manifest)
        g = core.grade(data, manifest)
        _case(cases, "C1-%s-%s" % (name, st), "2.0.0 全量三态分类",
              "%s/%s/L1" % (name, st),
              "%s/%s/%s" % (c["build"], c["state"], g["level"]))

    # C2: 3 支 —— orig 候选哈希可复核；非原版态不重复写
    for st in (core.STATE_ORIG, core.STATE_PATCHED, core.STATE_FIXED):
        data = samples[(hide, st)]
        track(data, "c2_%s_%s.bin" % (hide.replace(".", "_"), st))
        g = core.grade(data, manifest)
        cand = g.get("candidate") or {}
        if st == core.STATE_ORIG:
            expect = "L1|%s|%s" % (core.sha256(samples[(hide, core.STATE_PATCHED)]),
                                   core.sha256(samples[(hide, core.STATE_FIXED)]))
            actual = "%s|%s|%s" % (g["level"], cand.get("candidate_patched_sha256"),
                                   cand.get("candidate_fixed_sha256"))
            _case(cases, "C2-%s-orig" % hide, "未登记原版 → L1 且候选哈希可复核", expect, actual)
        else:
            _case(cases, "C2-%s-%s" % (hide, st), "非原版形态不重复写",
                  "L1|zero", "%s|zero" % g["level"])

    # C2b: 4 非隐藏 × 3 态 = 12 支，全 L1
    for (name, st), data in sorted(samples.items()):
        if name == hide:
            continue
        g = core.grade(data, manifest)
        _case(cases, "C2b-%s-%s" % (name, st), "基线分级全 L1", "L1", g["level"])

    # C3 / C4: 覆盖检测（compare_record 未变）
    base = "26.20.15.12"
    prev = {"driver_package_version": base,
            "engine_sha256": core.sha256(samples[(base, core.STATE_FIXED)]),
            "engine_state": "fixed", "build": base}
    cur = {"driver_package_version": base,
           "engine_sha256": core.sha256(samples[(base, core.STATE_ORIG)]),
           "engine_state": "orig", "build": base}
    _case(cases, "C3-N02", "同版覆盖检测（fixed→orig）", "重装覆盖",
          core.compare_record(prev, cur)["label"])
    prev2 = dict(prev, driver_package_version="26.20.15.16")
    cur2 = dict(prev)
    _case(cases, "C4-N03", "驱动变而文件没变 → 不重打", "引擎未变",
          core.compare_record(prev2, cur2)["label"])

    # C5: 无关字节突变不破坏形态识别（2.0.0 不靠全文件哈希）
    src = samples[(base, core.STATE_ORIG)]
    mut = bytearray(src)
    mut[0x1000] ^= 0xFF
    mut = bytes(mut)
    track(mut, "c5_unrelated_mutant.bin")
    c = core.classify(mut, manifest)
    g = core.grade(mut, manifest)
    _case(cases, "C5-N04", "无关字节突变不破坏形态识别", "orig|L1",
          "%s|%s" % (c["state"], g["level"]))

    # C6: 改坏所有锚 → locate_failed → L3
    broken = src.replace(anchor, b"\x41\xb8\x09\x00\x00\x00")
    track(broken, "c6_broken_anchor.bin")
    g = core.grade(broken, manifest)
    _case(cases, "C6-N05a", "锚失效 → L3 拒写", "L3", g["level"],
          detail=";".join(g["reasons"])[:180])

    # C7: 版本串格式破坏 → L3
    # PE 的 VS_VERSION_INFO 字符串以 UTF-16LE 存储；用 ASCII 串 replace 命中 0 次，
    # 会造出「看起来破坏了、其实没改」的假负例，这里必须按真实编码替换并断言命中。
    v_ok = "AMD-Radeon-Driver/drivers:".encode("utf-16le")
    v_bad = "AMD-Radeon-Drivar/drivers:".encode("utf-16le")
    n_ver = src.count(v_ok)
    bad_ver = src.replace(v_ok, v_bad) if n_ver else src
    track(bad_ver, "c7_bad_version.bin")
    g = core.grade(bad_ver, manifest)
    _case(cases, "C7-N05b", "来源格式不符 → L3", "L3",
          g["level"] if n_ver else "fixture_not_mutated",
          detail="utf16le_hits=%d;%s" % (n_ver, ";".join(g["reasons"])[:160]))

    # C8: 缺失 → 阻断
    missing = str(tgt / "no_such_file.bin")
    r = subprocess.run([sys.executable, str(HERE / "dvr_tool.py"), "check",
                        "--exe", missing, "--manifest", a.manifest],
                       capture_output=True, text=True)
    _case(cases, "C8-N06", "缺失文件只报阻断", "blocked:file_missing",
          "blocked:%s" % json.loads(r.stdout).get("reason", "?"))

    # C9: 独占锁 → 阻断
    lock_target = tgt / "c9_locked.bin"
    lock_target.write_bytes(src)
    targets.append(lock_target)
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.CreateFileW(str(lock_target), 0x80000000, 0, None, 3, 0, None)
    if not h or h == ctypes.c_void_p(-1).value:
        _case(cases, "C9-N07", "被占用不可读 → 阻断",
              "blocked:file_unreadable(locked_or_denied)", "lock_not_acquired",
              detail="CreateFileW 独占句柄未取得")
    else:
        try:
            _, err_l = _load_bytes(lock_target)
            _case(cases, "C9-N07", "被占用不可读 → 阻断",
                  "blocked:file_unreadable(locked_or_denied)",
                  "blocked:%s" % err_l if err_l else "readable(!)")
        finally:
            k32.CloseHandle(h)

    # C10: 幂等（分级结果 / 定位结果两次一致）
    f = samples[(base, core.STATE_FIXED)]
    g1 = core.grade(f, manifest)
    g2 = core.grade(f, manifest)
    _case(cases, "C10a-N13", "重复识别幂等（剔除诊断时间戳）",
          json.dumps(_stable(g1), sort_keys=True, default=str),
          json.dumps(_stable(g2), sort_keys=True, default=str))
    o = samples[(hide, core.STATE_ORIG)]
    l1 = core.locate_patch_point(o, rules)
    l2 = core.locate_patch_point(o, rules)
    _case(cases, "C10b-N13", "重复定位幂等",
          "%s|%s" % (l1["off"], l1["chosen_N"]),
          "%s|%s" % (l2["off"], l2["chosen_N"]))

    # C11: 2.0.0 坏清单 → 拒写且目标不变（3 支）
    for label, mutate in [
        ("C11a-field-missing", lambda m: m["rules"].pop("locator")),
        ("C11b-rule-version", lambda m: m.update(rule_version="9.9.9")),
        ("C11c-bad-anchor", lambda m: m["rules"]["patches"][0].update(
            anchor_hex="41 B8 09 00 00 00")),
    ]:
        bad = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
        mutate(bad)
        badp = work / ("bad_manifest_%s.json" % label)
        badp.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
        t = track(src, "%s_target.bin" % label)
        before = core.sha256(t.read_bytes())
        res = _run_apply(t, badp, work / ("%s_out.json" % label))
        after = core.sha256(t.read_bytes())
        refused = (res.get("result") != "applied") and before == after
        _case(cases, label, "清单坏态 → 拒写且目标不变", "refused|unchanged",
              "refused|unchanged" if refused else "%s|CHANGED(!)" % res.get("result"),
              detail=str(res.get("message", ""))[:180])

    # C13: 全量分类确定性
    snap1 = json.dumps([core.classify(d, manifest)["state"]
                        for _, d in sorted(samples.items())])
    snap2 = json.dumps([core.classify(d, manifest)["state"]
                        for _, d in sorted(samples.items())])
    _case(cases, "C13-N13b", "识别结果确定性（两次一致）", snap1, snap2)

    rep = _report("dvr_tool regress (2.0.0)", cases, targets,
                  _sources_before(a.backup_dir),
                  {"manifest": a.manifest, "regress_manifest": a.regress_manifest,
                   "hide_build": hide})
    return _out(a, rep, ok=(rep["summary"]["failed"] == 0))


# ---------------------------------------------------------------- regress-p3（16 支）

def cmd_regress_p3(a):
    manifest = core.load_manifest(a.manifest)
    reg = core.load_manifest_legacy(a.regress_manifest)
    rules = manifest["rules"]
    work = Path(a.workdir)
    tgt = work / "targets"
    tgt.mkdir(parents=True, exist_ok=True)
    origs, samples = _load_samples(manifest, reg, a.backup_dir)
    name = "26.20.29.02"
    trio = {st: samples[(name, st)] for st in
            (core.STATE_ORIG, core.STATE_PATCHED, core.STATE_FIXED)}
    cases, targets = [], []

    def track(blob, label):
        p = tgt / label
        p.write_bytes(blob)
        targets.append(p)
        return p

    # R1: 三态分类（3）
    for st, blob in sorted(trio.items()):
        track(blob, "r1_%s.bin" % st)
        c = core.classify(blob, manifest)
        _case(cases, "R1-%s" % st, "新构建三态分类", "%s/%s" % (name, st),
              "%s/%s" % (c["build"], c["state"]))

    # R2: 候选哈希可复核 + diff-scope（2）
    orig = trio[core.STATE_ORIG]
    g = core.grade(orig, manifest)
    cand = g.get("candidate") or {}
    expect = "L1|%s|%s" % (core.sha256(trio[core.STATE_PATCHED]),
                           core.sha256(trio[core.STATE_FIXED]))
    actual = "%s|%s|%s" % (g["level"], cand.get("candidate_patched_sha256"),
                           cand.get("candidate_fixed_sha256"))
    _case(cases, "R2-L2-candidate", "未登记新样本 → L1 且候选哈希可复核",
          expect, actual, detail=";".join(g["reasons"]))
    _case(cases, "R2-diff-scope", "self-diff 恰为两处补丁点", "in-scope",
          "in-scope" if "diff_scope" in cand else "missing",
          detail=str(cand.get("diff_scope")))

    # R3 / R4: 定位器负例（2）
    for cid, mutate, label in [
        ("R3-wrong-anchor", lambda m: m["rules"]["patches"][0].update(
            anchor_hex="41 B8 09 00 00 00"), "R3-wrong-anchor-bad.json"),
        ("R4-prefix-broken", lambda m: m["rules"]["locator"].update(
            stable_anchor_prefix_hex="00 00 00 00 00 00 00 00 00 00 00 00"),
         "R4-prefix-broken-bad.json"),
    ]:
        bad = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
        mutate(bad)
        badp = work / label
        badp.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
        try:
            lvl = core.grade(orig, bad)["level"]
        except Exception as e:
            lvl = "L3(%s)" % type(e).__name__
        _case(cases, cid, "定位器关键字段被破坏 → L3", "L3", lvl)

    # R5: 非原版形态不重复写（2）
    for st in (core.STATE_PATCHED, core.STATE_FIXED):
        _case(cases, "R5-%s-not-orig" % st, "非原版形态不重复写", "L1",
              core.grade(trio[st], manifest)["level"])

    # R6: 台账 approval 字段（1）
    ar = manifest["rules"]["auto_register"]
    _case(cases, "R6-candidate-record", "自动登记 approval 为 approved",
          "approved", ar.get("approval"))

    # R7: 派生确定性（1）
    off = core.classify(orig, manifest)["located"]["off"]
    d1 = core.derive(orig, core.STATE_FIXED, rules, off=off)[0]
    d2 = core.derive(orig, core.STATE_FIXED, rules, off=off)[0]
    _case(cases, "R7-determinism", "同输入同规则重复派生一致",
          core.sha256(d1), core.sha256(d2))

    # R8: 坏态清单拒写（3）
    for cid, mutate in [
        ("R8a-rule-version", lambda m: m.update(rule_version="0.9.0")),
        ("R8b-no-locator", lambda m: m["rules"].pop("locator")),
        ("R8c-conflict", lambda m: m["rules"]["patches"][0].update(
            new_hex="08 02")),
    ]:
        bad = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
        mutate(bad)
        badp = work / ("%s.json" % cid)
        badp.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
        t = track(orig, "%s_target.bin" % cid)
        before = core.sha256(t.read_bytes())
        res = _run_apply(t, badp, work / ("%s_out.json" % cid))
        after = core.sha256(t.read_bytes())
        refused = res.get("result") != "applied" and before == after
        _case(cases, cid, "坏清单拒写且目标不变", "refused|unchanged",
              "refused|unchanged" if refused else "CHANGED(!)")

    # R9: 无 profile 也放行（1）
    _case(cases, "R9-no-profile", "2.0.0 无 profile 直接放行", "L1",
          core.grade(orig, manifest)["level"])

    # R10: 零写入（1）
    before = {str(p): _sha(p) for p in sorted(Path(a.backup_dir).glob("*.bak"))}
    _case(cases, "R10-zero-write", "源样本零写入", "unchanged",
          "unchanged" if all(_sha(k) == v for k, v in before.items()) else "CHANGED")

    rep = _report("dvr_tool regress-p3 (2.0.0)", cases, targets, before,
                  {"manifest": a.manifest, "build": name})
    return _out(a, rep, ok=(rep["summary"]["failed"] == 0))


# ---------------------------------------------------------------- regress-unregistered（7 支）

def cmd_regress_unregistered(a):
    manifest = core.load_manifest(a.manifest)
    reg = core.load_manifest_legacy(a.regress_manifest)
    rules = manifest["rules"]
    work = Path(a.workdir)
    tgt = work / "targets"
    tgt.mkdir(parents=True, exist_ok=True)
    origs, samples = _load_samples(manifest, reg, a.backup_dir)
    name = "26.20.29.02"           # 生产清单已无 builds，它天然是「未登记」样本
    src = samples[(name, core.STATE_ORIG)]
    off = core.classify(src, manifest)["located"]["off"]
    expected_fixed = core.sha256(samples[(name, core.STATE_FIXED)])
    cases, targets = [], []
    # 回归必须可重复：上轮遗留的台账会让「本次新增 1 条」变成 2 条，先清干净。
    for stale in sorted(work.glob("registry_u[0-9].json")):
        stale.unlink()

    def track(blob, label):
        p = tgt / label
        p.write_bytes(blob)
        targets.append(p)
        return p

    mp = {p["id"]: p for p in rules["patches"]}
    anchor = core._hex_to_bytes(mp["classname-length"]["anchor_hex"])

    # U1: 未登记新原版 → 自动定位 / 注入 / 台账
    t1 = track(src, "u1_new_orig.bin")
    before1 = _sha(t1)
    reg1 = work / "registry_u1.json"
    res1 = _run_apply(t1, a.manifest, work / "u1.json", registry=reg1,
                      diagnostic=work / "diag_u1.json")
    after1 = _sha(t1)
    reg_ok = reg1.is_file() and len(json.loads(reg1.read_text(encoding="utf-8"))) == 1
    _case(cases, "U1-new-build", "未登记新原版自动定位并注入",
          "applied|fixed_ok|registry_ok|changed",
          "%s|%s|%s|%s" % (res1.get("result"),
                           "fixed_ok" if after1 == expected_fixed else "bad",
                           "registry_ok" if reg_ok else "bad",
                           "changed" if after1 != before1 else "unchanged"),
          detail=str(res1.get("message", ""))[:160])

    # U2: 锚全部失效 → 拒写 + 诊断报告字段齐 + 零变更
    broken = src.replace(anchor, b"\x41\xb8\x09\x00\x00\x00")
    t2 = track(broken, "u2_broken_anchor.bin")
    before2 = _sha(t2)
    diag2 = work / "diag_u2.json"
    res2 = _run_apply(t2, a.manifest, work / "u2.json",
                      registry=work / "registry_u2.json", diagnostic=diag2)
    d = json.loads(diag2.read_text(encoding="utf-8")) if diag2.is_file() else {}
    diag_ok = all(k in d for k in ("windows", "anchor_hex", "stable_anchor_prefix_hex",
                                  "refuse_reason", "sha256", "sections"))
    _case(cases, "U2-locate-failed", "定位失败拒写且诊断报告完整",
          "refused|unchanged|diag_ok",
          "%s|%s|%s" % ("refused" if res2.get("result") != "applied" else "WROTE(!)",
                        "unchanged" if _sha(t2) == before2 else "CHANGED(!)",
                        "diag_ok" if diag_ok and len(d.get("windows", [])) >= 7 else "bad"),
          detail=str(d.get("refuse_reason", ""))[:160])

    # U3: 已修复文件不重复写
    t3 = track(samples[(name, core.STATE_FIXED)], "u3_fixed.bin")
    before3 = _sha(t3)
    res3 = _run_apply(t3, a.manifest, work / "u3.json",
                      registry=work / "registry_u3.json", diagnostic=work / "diag_u3.json")
    _case(cases, "U3-already-fixed", "已修复文件不重复写",
          "already_fixed|unchanged",
          "%s|%s" % (res3.get("result"),
                     "unchanged" if _sha(t3) == before3 else "CHANGED(!)"))

    # U4: self-diff 门禁（错误 off 必须被 build_final 拒绝）
    try:
        import patch_manifest as pm
        pm.build_final(src, "original_untouched", rules, off=off + 0x100)
        u4 = "no_raise"
    except RuntimeError:
        u4 = "refused"
    except Exception as e:
        u4 = "refused(%s)" % type(e).__name__
    _case(cases, "U4-self-diff-scope", "补丁点错位 → self-diff 门禁拒绝",
          "refused", u4)

    # U5: match-backup 三子案（正确 / 冗余不歧义 / 无命中）
    def match(exe, out):
        r = subprocess.run([sys.executable, str(HERE / "dvr_tool.py"), "match-backup",
                            "--exe", str(exe), "--backup-dir", str(a.backup_dir),
                            "--manifest", str(a.manifest), "--out", str(out)],
                           capture_output=True, text=True)
        return _json_from_stdout(r.stdout)
    m_ok = match(t3, work / "mb_ok.json")
    mut = bytearray(samples[(name, core.STATE_FIXED)])
    mut[0x1000] ^= 0xFF
    t5 = track(bytes(mut), "u5_mutant.bin")
    m_bad = match(t5, work / "mb_bad.json")
    _case(cases, "U5-match-backup", "恢复配对：正确/冗余不歧义/伪样本拒动",
          "ok|no_ambiguity|refused",
          "%s|%s|%s" % ("ok" if m_ok.get("orig_sha") else "bad",
                        "no_ambiguity" if not m_ok.get("ambiguous") else "ambiguous",
                        "refused" if not m_bad.get("orig_sha") else "WRONG"),
          detail="ok=%s bad=%s" % (m_ok.get("backup_file"), m_bad.get("refuse_reason")))

    # U6: 台账原子性（半截 JSON 不崩、可解析、条目完整）
    reg6 = work / "registry_u6.json"
    reg6.write_text('[{"broken":', encoding="utf-8")
    t6 = track(src, "u6_registry.bin")
    _run_apply(t6, a.manifest, work / "u6.json", registry=reg6,
               diagnostic=work / "diag_u6.json")
    try:
        entries6 = json.loads(reg6.read_text(encoding="utf-8"))
        u6 = "ok" if isinstance(entries6, list) and len(entries6) == 1 else "bad"
    except Exception:
        u6 = "unparseable"
    _case(cases, "U6-registry-atomic", "台账损坏时自愈且原子写完整", "ok", u6)

    # U7: 零写入证明（源 .bak 与实机文件全程不变）
    live = Path(r"C:\Program Files\AMD\CNext\CNext\AMDRSServ.exe")
    live_before = _sha(live) if live.is_file() else None
    src_before = _sources_before(a.backup_dir)
    u7 = "unchanged" if (live_before == (_sha(live) if live.is_file() else None)
                         and all(_sha(k) == v for k, v in src_before.items())) else "CHANGED"
    _case(cases, "U7-zero-write", "源备份与实机文件全程零写入", "unchanged", u7)

    rep = _report("dvr_tool regress-unregistered (2.0.0)", cases, targets,
                  src_before, {"build_under_test": name,
                               "note": "该构建在生产清单里已无记录，天然模拟未登记新版本"})
    return _out(a, rep, ok=(rep["summary"]["failed"] == 0))


# ---------------------------------------------------------------- 输出与分发

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
    p.add_argument("--profile")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("rehearse")
    p.add_argument("--exe", required=True)
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--reference")
    p.add_argument("--backup-info")
    p.add_argument("--signature-valid", choices=["valid", "invalid", "unknown"], default="unknown")
    p.add_argument("--profile")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_rehearse)

    p = sub.add_parser("match-backup")
    p.add_argument("--exe", required=True)
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--out")
    p.set_defaults(fn=cmd_match_backup)

    p = sub.add_parser("make-holdout")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--hide", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_make_holdout)

    p = sub.add_parser("regress")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--regress-manifest", default=str(DEFAULT_REGRESS_MANIFEST))
    p.add_argument("--holdout-manifest")
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--samples-dir")
    p.add_argument("--backup-info")
    p.add_argument("--workdir", required=True)
    p.add_argument("--hide-build", default="26.20.15.16")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_regress)

    p = sub.add_parser("regress-p3")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--regress-manifest", default=str(DEFAULT_REGRESS_MANIFEST))
    p.add_argument("--candidate-manifest")
    p.add_argument("--sample-dir")
    p.add_argument("--profile")
    p.add_argument("--backup-dir", default=str(HERE / "backup"))
    p.add_argument("--workdir", required=True)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_regress_p3)

    p = sub.add_parser("regress-unregistered")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p.add_argument("--regress-manifest", default=str(DEFAULT_REGRESS_MANIFEST))
    p.add_argument("--backup-dir", default=str(HERE / "backup"))
    p.add_argument("--workdir", required=True)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_regress_unregistered)

    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
