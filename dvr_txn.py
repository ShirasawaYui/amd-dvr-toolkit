#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dvr_txn — 事务化单次替换、中断对账与主动恢复（D09 / D10）。

事务状态（持久化于 <txn_root>/<txn_id>.json，跨重启可对账）：
  主线：已备份 → 准备替换 → 待验证(=待重启/待验收) → 已提交
  恢复：待回滚 → 已恢复 | 需人工恢复

硬规则（手册 D09/D10）：
  - 写入确认绑定：实际目标路径、写前哈希、候选哈希、规则版本、
    备份定位、本次允许的恢复范围；确认后才由操作者（authorized_by）授权写入；
  - 持锁串行；确认无安装器活动、未完成事务已对账、目标无变化；
    占用释放不掉即停止；落盘「准备替换」后才做一次同卷整文件替换；
  - 写后复读不符不得报成功（自动回滚到同构建官方原件）；
  - 通过只进入「待验证」，绝不用两处原地写作兜底；
  - 重入对账：已是同构建官方原件→不重写只补核验；仍属本事务→授权内
    恢复并复读；归属不明→不猜测不覆盖（需人工恢复）；
  - 显式恢复（无旧事务的已知中间态）：清单完整哈希双确认 + 操作者
    新授权才另开恢复事务；重复恢复零写入。
"""
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from dvr_backup import BackupError, BackupLibrary, IDENTITY_OFFICIAL, IDENTITY_PRE_IMAGE, sha256_bytes


class TxnError(Exception):
    """事务不可继续（前置不符/未授权/锁冲突/归属不明）。调用方零写入。"""


# 事务状态常量
S_BACKED_UP = "已备份"
S_PREPARE = "准备替换"
S_PENDING = "待验证"        # = 待重启 / 待验收
S_COMMITTED = "已提交"
S_ROLLBACK = "待回滚"
S_RESTORED = "已恢复"
S_MANUAL = "需人工恢复"

OPEN_STATES = (S_BACKED_UP, S_PREPARE, S_PENDING, S_ROLLBACK)

# 失败三分类（P2 放行口径）
B_UNTOUCHED = "原文件未动"
B_RESTORED = "同版已恢复"
B_BLOCKED = "安全阻断／需人工恢复"


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class TransactionManager:
    """事务管理器。仅在 txn_root / backuplib / 目标文件上写；不做其他副作用。

    fault_hook(point)：仅供隔离演练注入中断（抛异常即模拟崩溃），
    生产调用不传；point 取值见 _fault()。
    """

    def __init__(self, txn_root, library: BackupLibrary, rule_version,
                 fault_hook=None, installer_active=None):
        self.txn_root = Path(txn_root)
        self.txn_root.mkdir(parents=True, exist_ok=True)
        self.locks = self.txn_root / "locks"
        self.locks.mkdir(exist_ok=True)
        self.lib = library
        self.rule_version = rule_version
        self.fault_hook = fault_hook
        self.installer_active = installer_active or (lambda path: False)

    # ------------------------------------------------------------ 基础

    def _fault(self, point, **ctx):
        if self.fault_hook:
            self.fault_hook(point, **ctx)

    def _txn_path(self, txn_id):
        return self.txn_root / ("%s.json" % txn_id)

    def _load(self, txn_id):
        p = self._txn_path(txn_id)
        if not p.is_file():
            raise TxnError("txn_missing: %s" % txn_id)
        return json.loads(p.read_text(encoding="utf-8"))

    def _save(self, rec):
        rec["updated"] = _now()
        tmp = self.txn_root / (".%s.tmp" % rec["txn_id"])
        tmp.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(self._txn_path(rec["txn_id"])))

    def _event(self, rec, state, note=""):
        rec["state"] = state
        rec.setdefault("events", []).append({"time": _now(), "state": state, "note": note})
        self._save(rec)

    def list_txns(self, target=None):
        out = []
        for p in sorted(self.txn_root.glob("TXN-*.json")):
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if target and rec.get("target", {}).get("normalized_path") != str(Path(target).resolve()):
                continue
            out.append(rec)
        return out

    # ------------------------------------------------------------ 锁

    def _lock_key(self, target_path):
        return sha256_bytes(str(Path(target_path).resolve()).encode("utf-8"))

    def _acquire_lock(self, target_path, stop_holder_hook=None):
        """目标级互斥锁。占用释放不掉即抛 TxnError（D09：遇重拉或无法释放即停止）。"""
        key = self._lock_key(target_path)
        lp = self.locks / ("%s.lock" % key)
        try:
            fd = os.open(str(lp), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, (b"holder=%s time=%s" % (uuid.uuid4().hex.encode(), _now().encode())))
            os.close(fd)
            return lp
        except FileExistsError:
            released = False
            if stop_holder_hook:
                released = bool(stop_holder_hook(target_path, lp))
            if not released:
                raise TxnError("lock_held: 目标被占用且无法释放（%s）" % target_path)
            # 演练钩子声称已停住占用方 → 重试一次
            try:
                os.unlink(lp)
            except OSError:
                raise TxnError("lock_held: 锁文件仍在（%s）" % lp)
            return self._acquire_lock(target_path, None)

    @staticmethod
    def _release_lock(lp):
        if not lp:
            return
        try:
            os.unlink(lp)
        except OSError:
            pass

    # ------------------------------------------------------------ 前置核对

    def _open_txn_on(self, target_path):
        t = str(Path(target_path).resolve())
        return [r for r in self.list_txns(t) if r["state"] in OPEN_STATES]

    def _read_sha(self, path):
        p = Path(path)
        if not p.is_file():
            return None
        try:
            return sha256_bytes(p.read_bytes())
        except OSError:
            return None

    # ------------------------------------------------------------ D09 begin：写前双重备份

    def begin(self, *, target_path, candidate_bytes, expected_pre_sha, expected_post_sha,
              build_version, approver, authorization_scope, recovery_scope,
              official_source_bytes=None, source_desc="", signature="unknown",
              txn_id=None):
        """建事务：核对目标/候选 → 登记官方原件与写前镜像 → 状态=已备份。

        找不到可信同版原件且无 official_source_bytes → 拒绝（零目标写入）。
        """
        txn_id = txn_id or "TXN-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), uuid.uuid4().hex[:6])
        tgt = Path(target_path).resolve()
        if not tgt.is_file():
            raise TxnError("target_missing: %s" % tgt)

        # 未完成事务先对账：同目标有未结事务 → 拒绝
        if self._open_txn_on(tgt):
            raise TxnError("txn_open_exists: 同目标存在未完成事务，先对账（reconcile）")

        pre_sha = self._read_sha(tgt)
        if pre_sha != expected_pre_sha:
            raise TxnError("pre_sha_mismatch: 目标写前哈希 %s != 确认值 %s（目标已变化）"
                           % (pre_sha, expected_pre_sha))
        cand_sha = sha256_bytes(candidate_bytes)
        if cand_sha != expected_post_sha:
            raise TxnError("candidate_sha_mismatch: 候选 %s != 确认值 %s" % (cand_sha, expected_post_sha))

        # 1) 同构建可信官方原件：库里有则复用；否则仅在给了官方来源时登记
        official = self.lib.official_of(build_version)
        if official is None:
            if official_source_bytes is None:
                raise TxnError("no_trusted_original: 找不到 %s 的可信官方原件（零写入）"
                               % build_version)
            try:
                official = self.lib.register(
                    identity=IDENTITY_OFFICIAL, data=official_source_bytes,
                    normalized_path=str(tgt), version=build_version,
                    source=source_desc or "official_source",
                    signature=signature, txn_id="baseline")
            except BackupError as e:
                raise TxnError("backup_failed: %s（零写入）" % e)
        else:
            # 复读校验已有原件，篡改即拒绝
            try:
                self.lib.verify_blob(official["sha256"])
            except BackupError as e:
                raise TxnError("original_tampered: %s（零写入）" % e)

        # 2) 本次写前镜像
        try:
            pre_entry = self.lib.register(
                identity=IDENTITY_PRE_IMAGE, data=tgt.read_bytes(),
                normalized_path=str(tgt), version=build_version,
                source="pre_image@begin", signature="pre_image",
                txn_id=txn_id, note="写前镜像")
        except BackupError as e:
            raise TxnError("backup_failed: %s（零写入）" % e)

        rec = {
            "txn_id": txn_id,
            "state": S_BACKED_UP,
            "created": _now(), "updated": _now(),
            "approver": approver,
            "authorization_scope": authorization_scope,
            "recovery_scope": recovery_scope,
            "rule_version": self.rule_version,
            "target": {"normalized_path": str(tgt),
                       "pre_sha256": pre_sha, "size": tgt.stat().st_size,
                       "permissions_attributes": _stat_attrs(tgt)},
            "candidate": {"sha256": cand_sha, "size": len(candidate_bytes),
                          "source": source_desc or "candidate"},
            "official_original": {"sha256": official["sha256"],
                                  "backup_entry": official["entry_id"],
                                  "version": build_version},
            "pre_image": {"sha256": pre_entry["sha256"],
                          "backup_entry": pre_entry["entry_id"]},
            "expected_post_sha256": expected_post_sha,
            "target_write_count": 0,
            "events": [], "acceptance": None, "recovery": None, "final": None,
        }
        self._save(rec)
        self._event(rec, S_BACKED_UP, "写前双重备份完成：原件=%s 镜像=%s"
                    % (official["sha256"][:12], pre_entry["sha256"][:12]))
        return rec

    # ------------------------------------------------------------ D09 apply：持锁单次替换

    def apply(self, txn_id, *, authorized_by, candidate_bytes, stop_holder_hook=None):
        """确认 → 授权 → 持锁 → 「准备替换」→ 同卷一次整文件替换 → 复读。

        candidate_bytes 与确认哈希不符 → 拒绝。复读不符自动回滚（不报成功）。
        通过只进入「待验证」。
        """
        if not authorized_by:
            raise TxnError("not_authorized: 写入必须由操作者授权（authorized_by）")
        rec = self._load(txn_id)
        if rec["state"] != S_BACKED_UP:
            raise TxnError("bad_state: %s（仅 已备份 可写入）" % rec["state"])
        if sha256_bytes(candidate_bytes) != rec["candidate"]["sha256"]:
            raise TxnError("candidate_sha_mismatch: 提供的候选与确认哈希不符（零写入）")
        tgt = Path(rec["target"]["normalized_path"])
        try:
            lp = self._acquire_lock(tgt, stop_holder_hook)
        except TxnError as e:
            self._event(rec, S_BACKED_UP, "持锁失败，停止：%s" % e)
            raise
        try:
            # 对账：无其他未结事务；无安装器活动；目标无变化
            others = [r for r in self._open_txn_on(tgt) if r["txn_id"] != txn_id]
            if others:
                raise TxnError("txn_open_exists: 存在其他未完成事务 %s" % [r["txn_id"] for r in others])
            if self.installer_active(str(tgt)):
                raise TxnError("installer_active: 安装器活动，拒绝写入")
            cur = self._read_sha(tgt)
            if cur != rec["target"]["pre_sha256"]:
                raise TxnError("target_changed: 目标已变化（%s != %s），拒绝覆盖"
                               % (cur, rec["target"]["pre_sha256"]))
            # 备份复验（原件必须完好）
            try:
                self.lib.verify_blob(rec["official_original"]["sha256"])
                self.lib.verify_blob(rec["pre_image"]["sha256"])
            except BackupError as e:
                raise TxnError("backup_verify_failed: %s（零写入）" % e)

            self._fault("before_prepare")
            rec["authorized_by"] = authorized_by
            rec["authorized_time"] = _now()
            self._event(rec, S_PREPARE, "落盘「准备替换」；授权人=%s" % authorized_by)

            # 同卷暂存候选 → 复读校验 → 一次整文件替换
            staged = tgt.with_name(".dvr_txn_%s.tmp" % txn_id)
            try:
                with open(staged, "wb") as f:
                    f.write(candidate_bytes)
                    f.flush()
                    os.fsync(f.fileno())
                if sha256_bytes(staged.read_bytes()) != rec["candidate"]["sha256"]:
                    raise TxnError("staged_verify_failed: 同卷暂存复读不符（零替换）")
                # 保全必要权限/属性
                _copy_attrs(staged, tgt)
                self._fault("replace", staged=staged, target=tgt)
                os.replace(str(staged), str(tgt))
            finally:
                if staged.exists():
                    try:
                        staged.unlink()
                    except OSError:
                        pass

            rec["target_write_count"] += 1
            rec["write_log"] = rec.get("write_log", []) + [
                {"time": _now(), "op": "replace", "to_sha256": rec["candidate"]["sha256"]}]
            self._save(rec)      # 写入事实先落盘（崩溃也不丢账）

            self._fault("after_replace_before_state")

            # 写后复读
            post = self._read_sha(tgt)
            if post != rec["expected_post_sha256"]:
                # 不得报成功 → 转待回滚并自动恢复
                self._event(rec, S_ROLLBACK, "写后复读不符（%s != %s），自动回滚"
                            % (post, rec["expected_post_sha256"]))
                return self._restore(rec, authorized_by="system:post-verify-fail",
                                     reason="write_verify_mismatch",
                                     lock_already_held=True)
            self._event(rec, S_PENDING, "写后复读通过 → 待重启/待验收")
            self._fault("after_state")
            return {"result": "pending_verify", "txn_id": txn_id, "state": rec["state"],
                    "target_write_count": rec["target_write_count"],
                    "next_step": "待重启/待验收；验收通过后 commit，失败按 D10 恢复"}
        finally:
            self._release_lock(lp)

    # ------------------------------------------------------------ 恢复（D10 核心）

    def _restore(self, rec, *, authorized_by, reason, lock_already_held=False):
        """授权内恢复到同构建官方原件（整文件替换）并复读。"""
        tgt = Path(rec["target"]["normalized_path"])
        off_sha = rec["official_original"]["sha256"]
        try:
            data = self.lib.verify_blob(off_sha)
        except BackupError as e:
            self._event(rec, S_MANUAL, "恢复受阻（备份损坏）：%s" % e)
            rec["recovery"] = {"result": "manual", "reason": "backup_corrupt: %s" % e}
            self._save(rec)
            return {"result": "manual_recovery", "bucket": B_BLOCKED, "txn_id": rec["txn_id"],
                    "state": rec["state"], "detail": str(e)}
        if self.installer_active(str(tgt)):
            self._event(rec, S_MANUAL, "恢复受阻（安装器活动）")
            rec["recovery"] = {"result": "manual", "reason": "installer_active"}
            self._save(rec)
            return {"result": "manual_recovery", "bucket": B_BLOCKED, "txn_id": rec["txn_id"]}
        lp = None
        if not lock_already_held:
            try:
                lp = self._acquire_lock(tgt, None)   # 恢复遇锁 → 需人工恢复
            except TxnError as e:
                self._event(rec, S_MANUAL, "恢复遇锁：%s" % e)
                rec["recovery"] = {"result": "manual", "reason": str(e)}
                self._save(rec)
                return {"result": "manual_recovery", "bucket": B_BLOCKED,
                        "txn_id": rec["txn_id"]}
        try:
            staged = tgt.with_name(".dvr_restore_%s.tmp" % rec["txn_id"])
            try:
                with open(staged, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                if sha256_bytes(staged.read_bytes()) != off_sha:
                    raise TxnError("staged_verify_failed")
                _copy_attrs(staged, tgt)
                os.replace(str(staged), str(tgt))
            except TxnError as e:
                self._event(rec, S_MANUAL, "恢复受阻：%s" % e)
                rec["recovery"] = {"result": "manual", "reason": str(e)}
                self._save(rec)
                return {"result": "manual_recovery", "bucket": B_BLOCKED, "txn_id": rec["txn_id"]}
            finally:
                if staged.exists():
                    try:
                        staged.unlink()
                    except OSError:
                        pass
            rec["target_write_count"] += 1
            rec["write_log"] = rec.get("write_log", []) + [
                {"time": _now(), "op": "restore", "to_sha256": off_sha}]
            post = self._read_sha(tgt)
            if post != off_sha:
                self._event(rec, S_MANUAL, "恢复后复读不符（%s）" % post)
                rec["recovery"] = {"result": "manual", "reason": "restore_verify_mismatch"}
                self._save(rec)
                return {"result": "manual_recovery", "bucket": B_BLOCKED, "txn_id": rec["txn_id"]}
            self._event(rec, S_RESTORED,
                        "已恢复同构建官方原件（%s）；原因=%s；授权=%s" % (off_sha[:12], reason, authorized_by))
            rec["recovery"] = {"result": "restored", "reason": reason,
                               "authorized_by": authorized_by, "sha256": off_sha,
                               "time": _now()}
            rec["final"] = {"state": S_RESTORED, "hash": off_sha,
                            "signature": "官方原件签名有效（恢复未改动）",
                            "attributes": _stat_attrs(tgt),
                            "natural_start": "待实机核验（P3）"}
            self._save(rec)
            return {"result": "restored", "bucket": B_RESTORED, "txn_id": rec["txn_id"],
                    "state": rec["state"], "target_write_count": rec["target_write_count"]}
        except TxnError as e:
            self._event(rec, S_MANUAL, "恢复遇锁/受阻：%s" % e)
            rec["recovery"] = {"result": "manual", "reason": str(e)}
            self._save(rec)
            return {"result": "manual_recovery", "bucket": B_BLOCKED, "txn_id": rec["txn_id"]}
        finally:
            self._release_lock(lp)

    def rollback(self, txn_id, *, authorized_by, reason="operator_rollback"):
        """主动恢复（待验证/待回滚 → 已恢复）。必须由操作者授权。"""
        if not authorized_by:
            raise TxnError("not_authorized")
        rec = self._load(txn_id)
        if rec["state"] not in (S_PENDING, S_ROLLBACK, S_PREPARE):
            raise TxnError("bad_state: %s 不可回滚" % rec["state"])
        cur = self._read_sha(rec["target"]["normalized_path"])
        off_sha = rec["official_original"]["sha256"]
        if cur == off_sha:
            # 已是官方原件：不重写，只补恢复核验
            self._event(rec, S_RESTORED, "已是同构建可信官方原件，零写入补齐恢复核验")
            rec["recovery"] = {"result": "verified_noop", "authorized_by": authorized_by}
            rec["final"] = {"state": S_RESTORED, "hash": off_sha,
                            "signature": "官方原件签名有效（未改动）",
                            "attributes": _stat_attrs(Path(rec["target"]["normalized_path"])),
                            "natural_start": "待实机核验（P3）"}
            self._save(rec)
            return {"result": "verified_noop", "bucket": B_RESTORED, "txn_id": txn_id,
                    "state": rec["state"], "target_write_count": rec["target_write_count"]}
        if cur not in (rec["target"]["pre_sha256"], rec["expected_post_sha256"]):
            self._event(rec, S_MANUAL, "归属不明/被接管（当前 %s），不猜测不覆盖" % cur)
            rec["recovery"] = {"result": "manual", "reason": "ownership_unknown"}
            self._save(rec)
            return {"result": "manual_recovery", "bucket": B_BLOCKED, "txn_id": txn_id}
        self._event(rec, S_ROLLBACK, "操作者主动恢复：%s" % reason)
        return self._restore(rec, authorized_by=authorized_by, reason=reason)

    # ------------------------------------------------------------ D10 对账（重入）

    def reconcile(self, *, authorized_by=None, target_path=None, stop_holder_hook=None):
        """跨重启重入对账。不猜测、不覆盖。返回逐事务结果列表。"""
        results = []
        for rec in self.list_txns(target_path):
            if rec["state"] not in OPEN_STATES:
                continue
            tgt = Path(rec["target"]["normalized_path"])
            cur = self._read_sha(tgt)
            off_sha = rec["official_original"]["sha256"]
            pre_sha = rec["target"]["pre_sha256"]
            post_sha = rec["expected_post_sha256"]
            r = {"txn_id": rec["txn_id"], "state": rec["state"], "current_sha256": cur}
            if cur is None:
                self._event(rec, S_MANUAL, "对账：目标缺失/不可读，需人工恢复")
                rec["recovery"] = {"result": "manual", "reason": "target_missing"}
                self._save(rec)
                r.update(result="manual_recovery", bucket=B_BLOCKED)
            elif cur == off_sha:
                # 已是可信官方原件：不重写，只补恢复核验
                self._event(rec, S_RESTORED, "对账：已是同构建可信官方原件，零写入补齐核验")
                rec["recovery"] = {"result": "verified_noop"}
                rec["final"] = {"state": S_RESTORED, "hash": off_sha,
                                "signature": "官方原件签名有效（未改动）",
                                "attributes": _stat_attrs(tgt), "natural_start": "待实机核验（P3）"}
                self._save(rec)
                r.update(result="verified_noop", bucket=B_RESTORED)
            elif cur in (pre_sha, post_sha):
                if rec["state"] == S_PENDING:
                    # 待重启/待验收：合法停留，不自动写入（主动撤回走 rollback）
                    r.update(result="pending_verify", bucket=None,
                             note="待验证合法停留；如需撤回由操作者 rollback")
                else:
                    # 已备份/准备替换/待回滚：仍属本事务 → 授权内恢复
                    if rec["state"] in (S_BACKED_UP, S_PREPARE) and cur == pre_sha:
                        # 尚未替换过 → 原文件未动，直接结案
                        self._event(rec, S_RESTORED,
                                    "对账：本事务未落替换（目标=写前镜像），零写入结案")
                        rec["recovery"] = {"result": "no_write_abort"}
                        rec["final"] = {"state": S_RESTORED, "hash": pre_sha,
                                        "signature": "未改动", "attributes": _stat_attrs(tgt),
                                        "natural_start": "待实机核验（P3）"}
                        self._save(rec)
                        r.update(result="no_write_abort", bucket=B_UNTOUCHED)
                    else:
                        auth = authorized_by or "reconcile:in-txn-scope"
                        res = self._restore(rec, authorized_by=auth,
                                            reason="reconcile_uncommitted")
                        r.update(result=res["result"], bucket=res.get("bucket"))
            else:
                # 安装器接管/他版覆盖/未知目标 → 不覆盖，需人工
                self._event(rec, S_MANUAL,
                            "对账：目标已被换为其他内容（%s），禁止跨版覆盖，需人工恢复" % cur)
                rec["recovery"] = {"result": "manual", "reason": "installer_takeover"}
                self._save(rec)
                r.update(result="manual_recovery", bucket=B_BLOCKED)
            results.append(r)
        return results

    # ------------------------------------------------------------ D10 显式恢复

    def explicit_recover(self, *, target_path, build_version, manifest_hashes,
                         official_source_bytes=None, authorized_by,
                         new_authorization_confirmed=False):
        """无旧事务的已知中间态 → 显式恢复分支。

        仅当清单能以完整哈希确认「当前中间态」及「同构建官方原件」，
        并且操作者给出新授权（new_authorization_confirmed + authorized_by），
        才另开恢复事务；否则拒绝（零写入）。
        """
        tgt = Path(target_path).resolve()
        if not tgt.is_file():
            raise TxnError("target_missing")
        if self._open_txn_on(tgt):
            raise TxnError("txn_open_exists: 有事务在身，走对账而非显式恢复")
        cur = self._read_sha(tgt)
        hs = manifest_hashes  # {"orig":…, "patched":…, "fixed":…}
        if cur not in (hs.get("patched"), hs.get("fixed")):
            raise TxnError("not_known_intermediate: 当前哈希 %s 不是已知中间态/终态（拒绝）" % cur)
        if not hs.get("orig"):
            raise TxnError("no_original_hash: 清单无同构建官方原件哈希（拒绝）")
        if not (new_authorization_confirmed and authorized_by):
            raise TxnError("not_authorized: 显式恢复需要操作者新授权（拒绝，零写入）")

        # 原件：库中登记或现场登记
        official = self.lib.official_of(build_version)
        if official is None:
            if official_source_bytes is None:
                raise TxnError("no_trusted_original: 无可信同构建官方原件（拒绝）")
            if sha256_bytes(official_source_bytes) != hs["orig"]:
                raise TxnError("original_hash_mismatch: 来源与清单原件哈希不符（拒绝）")
            official = self.lib.register(
                identity=IDENTITY_OFFICIAL, data=official_source_bytes,
                normalized_path=str(tgt), version=build_version,
                source="explicit_recover_source", signature="unknown", txn_id="baseline")
        elif official["sha256"] != hs["orig"]:
            raise TxnError("original_hash_mismatch: 库中原件与清单不符（拒绝）")

        txn_id = "TXN-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), uuid.uuid4().hex[:6])
        rec = {
            "txn_id": txn_id, "state": S_BACKED_UP, "created": _now(), "updated": _now(),
            "approver": authorized_by, "authorization_scope": "explicit_recovery(new)",
            "recovery_scope": "restore-to-original %s" % build_version,
            "rule_version": self.rule_version, "type": "explicit_recovery",
            "target": {"normalized_path": str(tgt), "pre_sha256": cur,
                       "size": tgt.stat().st_size,
                       "permissions_attributes": _stat_attrs(tgt)},
            "candidate": {"sha256": hs["orig"], "size": len(official_source_bytes or b""),
                          "source": "official_original"},
            "official_original": {"sha256": hs["orig"], "backup_entry": official["entry_id"],
                                  "version": build_version},
            "pre_image": {"sha256": cur, "backup_entry": None},
            "expected_post_sha256": hs["orig"],
            "target_write_count": 0, "events": [], "acceptance": None,
            "recovery": None, "final": None,
        }
        self._save(rec)
        self._event(rec, S_BACKED_UP, "显式恢复事务建立（新授权=%s）" % authorized_by)
        # 直接走恢复：目标=中间态 → 换成官方原件
        return self._restore(rec, authorized_by=authorized_by, reason="explicit_recovery")


# ------------------------------------------------------------ 属性工具

def _stat_attrs(p: Path):
    try:
        st = p.stat()
        return {"mode": oct(st.st_mode), "readonly": bool(st.st_file_attributes & 0x1)}
    except OSError:
        return {}


def _copy_attrs(dst: Path, src: Path):
    """把 src 的必要属性（时间/只读位）带到 dst；mode 同步。ACL 完整保留属 P3 实机核验项。"""
    try:
        shutil.copystat(str(src), str(dst))
        st = src.stat()
        if st.st_file_attributes & 0x1:   # FILE_ATTRIBUTE_READONLY → dst 也置只读
            os.chmod(str(dst), st.st_mode & ~0o200)
        else:
            os.chmod(str(dst), st.st_mode | 0o200)
    except OSError:
        pass


def classify_outcome(input_sha, final_sha, official_sha, write_count):
    """失败/结束态三分类（P2 放行口径）。

    - 本事务零写入且目标内容未变        → 原文件未动
    - 有写入且终态为同构建官方完整哈希   → 同版已恢复
    - 其他（他版接管/未知终态/受阻）     → 安全阻断／需人工恢复
    """
    if write_count == 0 and final_sha == input_sha:
        return B_UNTOUCHED
    if write_count >= 1 and final_sha == official_sha:
        return B_RESTORED
    return B_BLOCKED
