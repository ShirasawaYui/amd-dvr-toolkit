#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dvr_drill — D11 隔离副本故障演练。

在 --workdir 沙箱内为每个用例建独立子沙箱（targets / backuplib / txns），
覆盖手册第六节矩阵的写入侧负例，并在「准备替换前 / 替换后未记状态 /
待重启或待验证」三个节点模拟中断。用副本模拟安装器介入，绝不接触
生产安装目录。

每案保存：输入哈希、故障注入点、最终哈希、状态轨迹、实际目标写入次数，
并把结束态归入三分类之一：
  原文件未动 / 同版已恢复 / 安全阻断／需人工恢复
"""
import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dvr_core as core                     # noqa: E402
from dvr_backup import BackupError, BackupLibrary, IDENTITY_OFFICIAL  # noqa: E402
from dvr_txn import (TransactionManager, TxnError,                    # noqa: E402
                     S_BACKED_UP, S_PREPARE, S_PENDING, S_COMMITTED,
                     S_ROLLBACK, S_RESTORED, S_MANUAL,
                     B_UNTOUCHED, B_RESTORED, B_BLOCKED,
                     classify_outcome)


class InjectedCrash(Exception):
    """演练用模拟崩溃。"""


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Sandbox:
    def __init__(self, root: Path, manifest, orig12: bytes, cand12: bytes,
                 orig07: bytes, hashes12: dict):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.target = self.root / "targets" / "AMDRSServ.exe"
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_bytes(orig12)
        self.lib = BackupLibrary(self.root / "backuplib")
        self.txns = self.root / "txns"
        self.manifest = manifest
        self.orig12, self.cand12, self.orig07 = orig12, cand12, orig07
        self.hashes12 = hashes12
        self.official_sha = sha(orig12)
        self.pre_sha = self.official_sha
        self.post_sha = sha(cand12)

    def manager(self, fault_hook=None):
        return TransactionManager(self.txns, self.lib,
                                  self.manifest["rule_version"],
                                  fault_hook=fault_hook)

    def register_official(self, version="26.20.15.12"):
        return self.lib.register(
            identity=IDENTITY_OFFICIAL, data=self.orig12,
            normalized_path=str(self.target.resolve()), version=version,
            source="drill:backup_dir.orig.bak", signature="unknown",
            txn_id="baseline")

    def begin(self, **kw):
        args = dict(
            target_path=str(self.target), candidate_bytes=self.cand12,
            expected_pre_sha=self.pre_sha, expected_post_sha=self.post_sha,
            build_version="26.20.15.12", approver="drill-approver",
            authorization_scope="drill", recovery_scope="restore-to-original",
            official_source_bytes=self.orig12)
        args.update(kw)
        return self.manager().begin(**args)

    def writes(self):
        n = 0
        for p in self.txns.glob("TXN-*.json"):
            rec = json.loads(p.read_text(encoding="utf-8"))
            n += rec.get("target_write_count", 0)
        return n

    def trajectory(self):
        traj = []
        for p in sorted(self.txns.glob("TXN-*.json")):
            rec = json.loads(p.read_text(encoding="utf-8"))
            for e in rec.get("events", []):
                traj.append("%s:%s" % (rec["txn_id"], e["state"]))
        return traj

    def final_sha(self):
        return sha(self.target.read_bytes()) if self.target.is_file() else None


def lock_key_for(target: Path):
    return hashlib.sha256(str(target.resolve()).encode("utf-8")).hexdigest()


def make_lock(sbx: Sandbox):
    (sbx.txns / "locks").mkdir(parents=True, exist_ok=True)
    lp = sbx.txns / "locks" / ("%s.lock" % lock_key_for(sbx.target))
    lp.write_text("holder=external")
    return lp


def run_case(cid, name, matrix_row, injection, expected_bucket, expect_writes, fn,
             cases, mk_sbx):
    sbx = mk_sbx(cid)
    input_sha = sbx.final_sha()
    note = ""
    try:
        note = fn(sbx) or ""
    except (TxnError, BackupError) as e:
        note = "refused: %s" % e
    except InjectedCrash as e:
        note = "injected_crash: %s" % e
    except Exception as e:            # 演练器兜底：任何意外都记为失败证据，不中断全场
        note = "UNEXPECTED: %r" % e
    final_sha = sbx.final_sha()
    writes = sbx.writes()
    base = getattr(sbx, "op_input_sha", None) or input_sha
    bucket = classify_outcome(base, final_sha, sbx.official_sha, writes)
    # 终态一致性核对：声称已恢复则终态必须是官方原件（防吞错报成功）
    ok = (bucket == expected_bucket and writes == expect_writes
          and "UNEXPECTED" not in note and "(!)" not in note)
    if bucket == B_RESTORED and final_sha != sbx.official_sha:
        ok = False
        note += " | 声称已恢复但终态不是官方原件(!)"
    cases.append({
        "id": cid, "name": name, "matrix_row": matrix_row,
        "input_sha256": base, "injection_point": injection,
        "final_sha256": final_sha, "state_trajectory": sbx.trajectory(),
        "target_write_count": writes, "bucket": bucket,
        "expected_bucket": expected_bucket, "expected_writes": expect_writes,
        "pass": ok, "note": note,
    })
    return ok


# ---------------------------------------------------------------- 各用例

def case_01_no_backup(sbx):
    # 不登记原件、也不给官方来源 → begin 拒绝
    try:
        sbx.begin(official_source_bytes=None)
        return "begin 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_02_blob_tamper(sbx):
    sbx.register_official()
    rec = sbx.begin()
    # 篡改库中原件 blob
    blob = sbx.lib.blob_path(sbx.official_sha)
    blob.write_bytes(b"tampered-content-not-the-original")
    try:
        sbx.manager().apply(rec["txn_id"], authorized_by="drill-op",
                            candidate_bytes=sbx.cand12)
        return "apply 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_03_lock_held(sbx):
    sbx.register_official()
    rec = sbx.begin()
    make_lock(sbx)          # 占用不释放
    try:
        sbx.manager().apply(rec["txn_id"], authorized_by="drill-op",
                            candidate_bytes=sbx.cand12,
                            stop_holder_hook=lambda t, lp: False)
        return "apply 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_04_space(sbx):
    # 在 blob 落位路径上放同名目录 → 备份写入失败（模拟空间/写入受限）
    (sbx.lib.blobs / sbx.official_sha).mkdir(parents=True)
    try:
        sbx.begin()
        return "begin 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_05_post_verify_mismatch(sbx):
    sbx.register_official()
    rec = sbx.begin()

    def fault(point, **ctx):
        if point == "replace":
            Path(ctx["staged"]).write_bytes(b"corrupted-after-verify")

    mgr = sbx.manager(fault_hook=fault)
    res = mgr.apply(rec["txn_id"], authorized_by="drill-op",
                    candidate_bytes=sbx.cand12)
    return "write_verify_mismatch 自动回滚：%s" % res.get("result")


def case_06_crash_before_prepare(sbx):
    sbx.register_official()
    rec = sbx.begin()

    def fault(point, **ctx):
        if point == "before_prepare":
            raise InjectedCrash("before_prepare")

    try:
        sbx.manager(fault_hook=fault).apply(
            rec["txn_id"], authorized_by="drill-op", candidate_bytes=sbx.cand12)
    except InjectedCrash:
        pass
    # 模拟重启后对账
    res = sbx.manager().reconcile()
    return "reconcile: %s" % res


def case_07_crash_after_replace(sbx):
    sbx.register_official()
    rec = sbx.begin()

    def fault(point, **ctx):
        if point == "after_replace_before_state":
            raise InjectedCrash("after_replace_before_state")

    try:
        sbx.manager(fault_hook=fault).apply(
            rec["txn_id"], authorized_by="drill-op", candidate_bytes=sbx.cand12)
    except InjectedCrash:
        pass
    res = sbx.manager().reconcile()
    return "reconcile: %s" % res


def case_08_crash_at_pending(sbx):
    sbx.register_official()
    rec = sbx.begin()

    def fault(point, **ctx):
        if point == "after_state":
            raise InjectedCrash("after_state(pending_verify)")

    try:
        sbx.manager(fault_hook=fault).apply(
            rec["txn_id"], authorized_by="drill-op", candidate_bytes=sbx.cand12)
    except InjectedCrash:
        pass
    res = sbx.manager().reconcile()      # 停在待验证（合法），不自动写入
    res2 = sbx.manager().rollback(rec["txn_id"], authorized_by="drill-op",
                                  reason="验收失败撤回")
    return "reconcile=%s rollback=%s" % (res, res2.get("result"))


def case_09_repeat_rollback(sbx):
    sbx.register_official()
    rec = sbx.begin()
    sbx.manager().apply(rec["txn_id"], authorized_by="drill-op",
                        candidate_bytes=sbx.cand12)
    sbx.manager().rollback(rec["txn_id"], authorized_by="drill-op",
                           reason="first")
    before = sbx.writes()
    try:
        sbx.manager().rollback(rec["txn_id"], authorized_by="drill-op",
                               reason="repeat")
        return "重复回滚未拒绝(!)"
    except TxnError as e:
        if sbx.writes() != before:
            return "(!) 重复恢复产生了写入"
        return "repeat refused(零写入): %s" % e


def case_10_installer_takeover(sbx):
    sbx.register_official()
    rec = sbx.begin()
    sbx.target.write_bytes(sbx.orig07)   # 安装器把目标换成另一构建
    try:
        sbx.manager().apply(rec["txn_id"], authorized_by="drill-op",
                            candidate_bytes=sbx.cand12)
        return "apply 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_11_cross_version(sbx):
    # 目标是 .07，却按 .12 的确认去写 → 拒绝（禁止跨版覆盖）
    sbx.target.write_bytes(sbx.orig07)
    sbx.op_input_sha = sha(sbx.orig07)   # 操作输入以当前目标为准
    try:
        sbx.begin()
        return "begin 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_12_rollback_backup_corrupt(sbx):
    sbx.register_official()
    rec = sbx.begin()
    sbx.manager().apply(rec["txn_id"], authorized_by="drill-op",
                        candidate_bytes=sbx.cand12)
    sbx.lib.blob_path(sbx.official_sha).write_bytes(b"backup-damaged")
    res = sbx.manager().rollback(rec["txn_id"], authorized_by="drill-op",
                                 reason="验收失败")
    return "rollback=%s" % res.get("result")


def case_13_rollback_lock(sbx):
    sbx.register_official()
    rec = sbx.begin()
    sbx.manager().apply(rec["txn_id"], authorized_by="drill-op",
                        candidate_bytes=sbx.cand12)
    make_lock(sbx)      # 回滚时目标被占用
    res = sbx.manager().rollback(rec["txn_id"], authorized_by="drill-op",
                                 reason="验收失败")
    return "rollback=%s" % res.get("result")


def case_14_explicit_no_auth(sbx):
    # 无旧事务的已知中间态；无新授权 → 拒绝
    patched, _ = core.derive(sbx.orig12, core.STATE_PATCHED, sbx.manifest["rules"])
    sbx.target.write_bytes(patched)
    sbx.op_input_sha = sha(patched)
    try:
        sbx.manager().explicit_recover(
            target_path=str(sbx.target), build_version="26.20.15.12",
            manifest_hashes=sbx.hashes12, authorized_by="",
            new_authorization_confirmed=False)
        return "explicit_recover 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_15_explicit_with_auth(sbx):
    patched, _ = core.derive(sbx.orig12, core.STATE_PATCHED, sbx.manifest["rules"])
    sbx.target.write_bytes(patched)
    res = sbx.manager().explicit_recover(
        target_path=str(sbx.target), build_version="26.20.15.12",
        manifest_hashes=sbx.hashes12, official_source_bytes=sbx.orig12,
        authorized_by="drill-op", new_authorization_confirmed=True)
    return "explicit_recover=%s" % res.get("result")


def case_16_explicit_repeat(sbx):
    # 目标已是官方原件 → 显式恢复无必要，拒绝且零写入
    try:
        sbx.manager().explicit_recover(
            target_path=str(sbx.target), build_version="26.20.15.12",
            manifest_hashes=sbx.hashes12, official_source_bytes=sbx.orig12,
            authorized_by="drill-op", new_authorization_confirmed=True)
        return "repeat explicit 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


def case_17_repeat_apply_fixed(sbx):
    fixed, _ = core.derive(sbx.orig12, core.STATE_FIXED, sbx.manifest["rules"])
    sbx.target.write_bytes(fixed)        # 已修复态
    sbx.op_input_sha = sha(fixed)
    try:
        sbx.begin()                       # 仍按原版确认 → 拒绝
        return "begin 未拒绝(!)"
    except TxnError as e:
        return "refused: %s" % e


# ---------------------------------------------------------------- 主流程

CASES = [
    ("D11-01", "无可用可信同构建原件 → 拒绝建档", "无可用备份", "begin(登记前)", B_UNTOUCHED, 0, case_01_no_backup),
    ("D11-02", "备份落盘后被篡改 → 写入拒绝", "无可用备份/校验失败", "apply(备报复验)", B_UNTOUCHED, 0, case_02_blob_tamper),
    ("D11-03", "占用不释放 → 停止写入", "权限或占用", "apply(持锁)", B_UNTOUCHED, 0, case_03_lock_held),
    ("D11-04", "备份写入失败（空间/写入受限）→ 零写入", "空间不足", "begin(备份落位)", B_UNTOUCHED, 0, case_04_space),
    ("D11-05", "写后复读不符 → 自动回滚不报成功", "写后校验失配", "replace(替换后复读)", B_RESTORED, 2, case_05_post_verify_mismatch),
    ("D11-06", "中断①准备替换前 → 对账结案", "跨重启中断", "before_prepare", B_UNTOUCHED, 0, case_06_crash_before_prepare),
    ("D11-07", "中断②替换后未记状态 → 对账回滚", "跨重启中断", "after_replace_before_state", B_RESTORED, 2, case_07_crash_after_replace),
    ("D11-08", "中断③待验证 → 撤回恢复", "试录失败/验收失败", "after_state(pending)", B_RESTORED, 2, case_08_crash_at_pending),
    ("D11-09", "重复恢复 → 零写入", "重复执行", "repeat-rollback", B_RESTORED, 2, case_09_repeat_rollback),
    ("D11-10", "安装器换走目标 → 拒写且不覆盖", "安装器介入", "apply(目标核对)", B_BLOCKED, 0, case_10_installer_takeover),
    ("D11-11", "跨构建覆盖企图 → 拒绝", "安装器介入/跨版覆盖", "begin(写前核对)", B_UNTOUCHED, 0, case_11_cross_version),
    ("D11-12", "回滚遇备份损坏 → 需人工恢复", "回滚失败", "rollback(备报复验)", B_BLOCKED, 1, case_12_rollback_backup_corrupt),
    ("D11-13", "回滚遇锁 → 需人工恢复", "回滚失败", "rollback(持锁)", B_BLOCKED, 1, case_13_rollback_lock),
    ("D11-14", "显式恢复无新授权 → 拒绝", "重复执行/授权", "explicit_recover(授权)", B_UNTOUCHED, 0, case_14_explicit_no_auth),
    ("D11-15", "显式恢复有新授权 → 恢复原件", "重复执行/授权", "explicit_recover(授权)", B_RESTORED, 1, case_15_explicit_with_auth),
    ("D11-16", "重复显式恢复 → 零写入", "重复执行", "explicit_recover(repeat)", B_UNTOUCHED, 0, case_16_explicit_repeat),
    ("D11-17", "已修复态重复执行 → 零写入", "重复执行", "begin(写前核对)", B_UNTOUCHED, 0, case_17_repeat_apply_fixed),
]


def run(manifest_path, backup_dir, workdir, out_path):
    manifest = core.load_manifest(manifest_path)
    bak = Path(backup_dir)
    origs = {}
    for p in sorted(bak.glob("*.bak")):
        d = p.read_bytes()
        c = core.classify(d, manifest)
        if c["build"] and c["state"] == core.STATE_ORIG and c["build"] not in origs:
            origs[c["build"]] = d
    orig12 = origs["26.20.15.12"]
    orig07 = origs["26.20.15.07"]
    cand12, _ = core.derive(orig12, core.STATE_FIXED, manifest["rules"])
    b12 = next(b for b in manifest["builds"] if b["name"] == "26.20.15.12")
    assert sha(cand12) == b12["hashes"]["fixed"], "派生终态与清单不符"
    hashes12 = dict(b12["hashes"])

    work = Path(workdir)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    cases = []

    def mk_sbx(cid):
        return Sandbox(work / cid, manifest, orig12, cand12, orig07, hashes12)

    for cid, name, row, inj, bucket, writes, fn in CASES:
        run_case(cid, name, row, inj, bucket, writes, fn, cases, mk_sbx)

    passed = sum(1 for c in cases if c["pass"])
    buckets = {}
    for c in cases:
        buckets[c["bucket"]] = buckets.get(c["bucket"], 0) + 1

    # 放行核对
    classified = all(c["bucket"] in (B_UNTOUCHED, B_RESTORED, B_BLOCKED) for c in cases)
    no_swallowed = all(not ("(!)" in c["note"] or "UNEXPECTED" in c["note"]) for c in cases)
    no_cross = not any(c["id"] == "D11-10" and "(!)" in c["note"] for c in cases)
    restores_ok = all(c["final_sha256"] == c["input_sha256"] or c["bucket"] == B_RESTORED
                      or c["id"] in ("D11-10", "D11-12", "D11-13") for c in cases)

    report = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "dvr_drill (D11)", "rule_version": manifest["rule_version"],
        "sandbox": str(work),
        "matrix_coverage": {
            "已知与留出样本": "P1 识别回归 C1/C2 已覆盖（证据见 D07）",
            "同版覆盖、驱动变化、路径或来源冲突": "P1 C3–C7 已覆盖；写入侧见 D11-10/11",
            "无可用备份、空间不足、权限或占用": ["D11-01", "D11-02", "D11-03", "D11-04"],
            "写后校验失配、跨重启中断、试录失败": ["D11-05", "D11-06", "D11-07", "D11-08"],
            "安装器介入、回滚失败、重复执行": ["D11-10", "D11-12", "D11-13", "D11-09",
                                             "D11-14", "D11-15", "D11-16", "D11-17"],
            "至少一个此前未登记的真实新构建": "P3 D12/D13 范围（26.20.29.02 实机现场），不在本演练",
            "日志关闭、开麦干扰、提升态": "U03/U08 验收口径，属 P3 实机验收，不在写入侧演练",
        },
        "cases": cases,
        "summary": {"total": len(cases), "passed": passed,
                    "failed": len(cases) - passed, "buckets": buckets},
        "gate": {
            "every_failure_classified": classified,
            "no_swallowed_errors": no_swallowed,
            "no_cross_version_overwrite": no_cross,
            "restore_end_state_consistent": restores_ok,
        },
        "next_step": "全部通过才允许 P3 限定试点；任一失败先修事务路径",
    }
    ok = (passed == len(cases)) and classified and no_swallowed and no_cross and restores_ok
    txt = json.dumps(report, ensure_ascii=False, indent=2)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(txt, encoding="utf-8")
    print(json.dumps({"summary": report["summary"], "gate": report["gate"],
                      "out": out_path}, ensure_ascii=False))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--backup-dir", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    sys.exit(run(a.manifest, a.backup_dir, a.workdir, a.out))


if __name__ == "__main__":
    main()
