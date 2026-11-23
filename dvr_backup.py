#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dvr_backup — 写前双重备份库（D08）。

受控本地备份库（必须位于安装目录之外）：
  <root>/blobs/<sha256>   内容寻址存放，一个哈希一份文件
  <root>/registry.json    登记账（身份分离：official_original / pre_image）

规则（手册 D08）：
  - 两种身份分别登记：「同构建可信官方原件」official_original 与
    「本次写前镜像」pre_image；同哈希允许只存一份文件，但保留两种身份；
  - 先写临时备份 → 复读校验 SHA-256 → 落位 blobs/<sha> → 之后才登记；
  - 不可覆盖已有备份：同一身份键（identity, normalized_path, txn_id）
    已存在且哈希不同 → 拒绝；
  - 读取时复读校验，blob 与登记哈希不符（篡改）→ BackupError；
  - 任何失败零目标写入（本库只写自己的 root）。
"""
import hashlib
import json
import os
import time
import uuid
from pathlib import Path


class BackupError(Exception):
    """备份不可用（缺失/权限/空间/校验失败/篡改/覆盖冲突）。写操作必须拒绝。"""


IDENTITY_OFFICIAL = "official_original"
IDENTITY_PRE_IMAGE = "pre_image"

SCHEMA_VERSION = 1


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class BackupLibrary:
    def __init__(self, root):
        self.root = Path(root)
        self.blobs = self.root / "blobs"
        self.registry_path = self.root / "registry.json"
        self.blobs.mkdir(parents=True, exist_ok=True)
        if not self.registry_path.is_file():
            self._write_registry({"schema_version": SCHEMA_VERSION, "entries": []})

    # ------------------------------------------------------------ registry IO

    def _read_registry(self):
        try:
            reg = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except Exception as e:
            raise BackupError("registry_unreadable: %s" % e)
        if reg.get("schema_version") != SCHEMA_VERSION:
            raise BackupError("registry_schema_mismatch")
        return reg

    def _write_registry(self, reg):
        tmp = self.root / (".registry.tmp-%s" % uuid.uuid4().hex)
        tmp.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(self.registry_path))

    # ------------------------------------------------------------ blob IO

    def blob_path(self, sha: str) -> Path:
        return self.blobs / sha

    def verify_blob(self, sha: str):
        """复读校验 blob；缺失或篡改抛 BackupError。"""
        p = self.blob_path(sha)
        if not p.is_file():
            raise BackupError("blob_missing: %s" % sha)
        data = p.read_bytes()
        if sha256_bytes(data) != sha:
            raise BackupError("blob_tampered: %s（复读哈希不符）" % sha)
        return data

    def read(self, sha: str) -> bytes:
        return self.verify_blob(sha)

    def tamper_report(self):
        """全库复读校验。返回 {ok, checked, tampered[], missing[]}。"""
        reg = self._read_registry()
        checked, tampered, missing = 0, [], []
        for e in reg["entries"]:
            sha = e["sha256"]
            p = self.blob_path(sha)
            if not p.is_file():
                missing.append(sha)
                continue
            checked += 1
            if sha256_bytes(p.read_bytes()) != sha:
                tampered.append(sha)
        return {"ok": not tampered and not missing,
                "checked": checked, "tampered": sorted(set(tampered)),
                "missing": sorted(set(missing))}

    # ------------------------------------------------------------ register

    def register(self, *, identity, data, normalized_path, version,
                 source, signature, txn_id, file_identity=None,
                 permissions_attributes=None, note=""):
        """写临时 → 复读校验 → 落位 → 登记。绝不覆盖已有备份。

        data        : bytes（内容）
        identity    : official_original / pre_image
        txn_id      : 事务号（基线原件用 'baseline'）
        """
        if identity not in (IDENTITY_OFFICIAL, IDENTITY_PRE_IMAGE):
            raise BackupError("bad_identity: %s" % identity)
        if not isinstance(data, (bytes, bytearray)):
            raise BackupError("bad_data")
        data = bytes(data)
        sha = sha256_bytes(data)
        size = len(data)

        # 身份键冲突检查（不可覆盖已有备份）
        reg = self._read_registry()
        key = (identity, str(normalized_path), str(txn_id))
        for e in reg["entries"]:
            if (e["identity"], e["normalized_path"], str(e["txn_id"])) == key:
                if e["sha256"] == sha:
                    return e          # 幂等复用
                raise BackupError(
                    "backup_conflict: 身份键已存在且哈希不同，拒绝覆盖（%s %s %s）"
                    % key)

        # 先写临时文件并复读校验
        tmp = self.blobs / (".tmp-%s" % uuid.uuid4().hex)
        try:
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            back = tmp.read_bytes()
        except OSError as e:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise BackupError("backup_write_failed(权限不足/空间不够): %s" % e)
        if sha256_bytes(back) != sha:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise BackupError("backup_verify_failed: 复读哈希不符")

        # 落位（同哈希只留一份）
        final = self.blob_path(sha)
        try:
            if final.is_file():
                if sha256_bytes(final.read_bytes()) != sha:
                    raise BackupError("blob_tampered: %s（已有文件复读不符）" % sha)
                tmp.unlink()
            else:
                os.replace(str(tmp), str(final))
        except BackupError:
            raise
        except OSError as e:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise BackupError("backup_write_failed(权限不足/空间不够): %s" % e)

        entry = {
            "entry_id": uuid.uuid4().hex[:12],
            "identity": identity,
            "sha256": sha,
            "size": size,
            "normalized_path": str(normalized_path),
            "file_identity": file_identity or {},
            "version": version,
            "source": source,
            "signature": signature,
            "permissions_attributes": permissions_attributes or {},
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "txn_id": str(txn_id),
            "note": note,
        }
        reg = self._read_registry()   # 重读，避免覆盖并发登记
        key = (identity, entry["normalized_path"], entry["txn_id"])
        for e in reg["entries"]:
            if (e["identity"], e["normalized_path"], str(e["txn_id"])) == key:
                if e["sha256"] == sha:
                    return e
                raise BackupError("backup_conflict: 登记竞争，拒绝覆盖")
        reg["entries"].append(entry)
        self._write_registry(reg)
        return entry

    # ------------------------------------------------------------ query

    def find(self, identity=None, txn_id=None, version=None, sha=None):
        reg = self._read_registry()
        out = []
        for e in reg["entries"]:
            if identity and e["identity"] != identity:
                continue
            if txn_id is not None and str(e["txn_id"]) != str(txn_id):
                continue
            if version and e["version"] != version:
                continue
            if sha and e["sha256"] != sha:
                continue
            out.append(e)
        return out

    def official_of(self, version):
        """取某构建的可信官方原件登记（多个取最早）。无则 None。"""
        es = [e for e in self.find(identity=IDENTITY_OFFICIAL, version=version)]
        return es[0] if es else None
