"""内容质量异常服务：异常归档与质量检查。

两条不可变历史线，均只追加：
- 异常（QualityAnomaly）：质检员把一次问题归档为“内容质量异常”，
  分 warning（警告）与 blocking（阻断）两级；归档后不可修改、不可删除。
- 检查结果（QualityCheckRun）：每次执行检查都写入一条新结果。
  Python 重跑、修复后复查都会产生新记录，永不 UPDATE、永不覆盖。

修复不会回写原异常：复查通过只产生一条 outcome=ok 的新结果；
原异常仍在历史里。某异常“当前是否仍存在”由最近一次检查结果的关联
派生（最近一次检查未再发现即视为已修复），而不是改动异常记录本身。
同一问题在未修复期间的多次检查复用同一条异常并各自关联；问题修复后
再次出现（回归）则归档为一条新异常，历史完整可追。
"""
from __future__ import annotations

import json

from ..domain.enums import CheckOutcome, QualityLevel, Role
from ..domain.errors import NotFoundError, ValidationError
from ..domain.fingerprint import canonical_json, digest_json
from ..domain.models import QualityAnomaly, QualityCheckRun, User
from .base import Service, require_roles

# 可作为质量检查对象的实体类型及其存在性校验
_SUBJECT_TYPES = ("material", "version", "package")


class QualityService(Service):
    # ------------------------------------------------------------ 异常归档
    def archive_anomaly(
        self,
        actor: User,
        *,
        subject_type: str,
        subject_id: str,
        check_code: str,
        level: str,
        detail: str = "",
        evidence: dict | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """质检员把一次问题归档为内容质量异常（warning/blocking）。"""
        require_roles(actor, Role.REVIEWER, Role.QUALITY_AUTHORITY)
        level = self._validate_level(level)
        check_code = self._validate_code(check_code)
        self._require_subject(subject_type, subject_id)

        def work() -> dict:
            anomaly = self._build_anomaly(
                subject_type=subject_type,
                subject_id=subject_id,
                check_code=check_code,
                level=level,
                detail=detail,
                evidence=evidence or {},
                archivist_id=actor.user_id,
            )
            self.repo.insert_anomaly(anomaly)
            self.audit(
                actor.user_id,
                "quality.anomaly_archived",
                package_id=(
                    subject_id if subject_type == "package" else None
                ),
                detail={
                    "anomaly_id": anomaly.anomaly_id,
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "check_code": check_code,
                    "level": level,
                },
            )
            return self._anomaly_dict(anomaly, resolved=False)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------ 执行检查
    def record_check(
        self,
        actor: User,
        *,
        subject_type: str,
        subject_id: str,
        findings: list[dict] | None = None,
        note: str = "",
        subject_digest: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """对对象执行一次质量检查并写入【新】结果记录。

        findings 为本次发现的问题列表，每项：
        {"check_code", "level", "detail"?, "evidence"?}。
        空列表/None 表示本次检查通过（outcome=ok）——典型的修复后复查。
        无论是否带 Idempotency-Key，不带键的 Python 重跑总是产生新记录。
        """
        require_roles(actor, Role.REVIEWER, Role.QUALITY_AUTHORITY)
        self._require_subject(subject_type, subject_id)
        normalized = [self._normalize_finding(f) for f in (findings or [])]

        def work() -> dict:
            digest = subject_digest or self._derive_digest(
                subject_type, subject_id
            )
            open_anomalies = self._open_anomalies(subject_type, subject_id)

            linked: list[QualityAnomaly] = []
            for finding in normalized:
                existing = open_anomalies.get(finding["check_code"])
                if existing is None:
                    # 新问题（或修复后的回归）：归档一条新异常
                    existing = self._build_anomaly(
                        subject_type=subject_type,
                        subject_id=subject_id,
                        check_code=finding["check_code"],
                        level=finding["level"],
                        detail=finding["detail"],
                        evidence=finding["evidence"],
                        archivist_id=actor.user_id,
                    )
                    self.repo.insert_anomaly(existing)
                linked.append(existing)

            warning_count = sum(
                1 for a in linked if a.level == QualityLevel.WARNING.value
            )
            blocking_count = sum(
                1 for a in linked if a.level == QualityLevel.BLOCKING.value
            )
            if blocking_count:
                outcome = CheckOutcome.BLOCKING.value
            elif warning_count:
                outcome = CheckOutcome.WARNING.value
            else:
                outcome = CheckOutcome.OK.value

            run = self._build_run(
                subject_type=subject_type,
                subject_id=subject_id,
                subject_digest=digest,
                outcome=outcome,
                warning_count=warning_count,
                blocking_count=blocking_count,
                checked_by=actor.user_id,
                note=note,
                anomaly_ids=tuple(a.anomaly_id for a in linked),
            )
            self.repo.insert_check_run(run)
            self.audit(
                actor.user_id,
                "quality.check_recorded",
                package_id=(
                    subject_id if subject_type == "package" else None
                ),
                detail={
                    "run_id": run.run_id,
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "outcome": outcome,
                    "warning_count": warning_count,
                    "blocking_count": blocking_count,
                },
            )
            return self._run_dict(run, linked)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------ 查询
    def get_anomaly(self, actor: User, anomaly_id: str) -> dict:
        anomaly = self.repo.get_anomaly(anomaly_id)
        if anomaly is None:
            raise NotFoundError("异常不存在", details={"anomaly_id": anomaly_id})
        return self._anomaly_dict(anomaly, self._is_resolved(anomaly))

    def list_anomalies(
        self,
        actor: User,
        *,
        subject_type: str | None = None,
        subject_id: str | None = None,
        level: str | None = None,
    ) -> dict:
        if level is not None:
            level = self._validate_level(level)
        anomalies = self.repo.list_anomalies(
            subject_type=subject_type, subject_id=subject_id, level=level
        )
        return {
            "anomalies": [
                self._anomaly_dict(a, self._is_resolved(a)) for a in anomalies
            ]
        }

    def list_check_runs(
        self,
        actor: User,
        *,
        subject_type: str | None = None,
        subject_id: str | None = None,
    ) -> dict:
        runs = self.repo.list_check_runs(
            subject_type=subject_type, subject_id=subject_id
        )
        return {"check_runs": [self._run_dict(r) for r in runs]}

    def subject_history(self, actor: User, subject_type: str, subject_id: str) -> dict:
        """完整历史：全部归档异常 + 全部检查结果，按时间排列，不丢任何一条。"""
        anomalies = self.repo.list_anomalies(
            subject_type=subject_type, subject_id=subject_id
        )
        runs = self.repo.list_check_runs(
            subject_type=subject_type, subject_id=subject_id
        )
        return {
            "subject_type": subject_type,
            "subject_id": subject_id,
            "anomalies": [
                self._anomaly_dict(a, self._is_resolved(a)) for a in anomalies
            ],
            "check_runs": [self._run_dict(r) for r in runs],
        }

    # ------------------------------------------------------------ 内部
    def _open_anomalies(
        self, subject_type: str, subject_id: str
    ) -> dict[str, QualityAnomaly]:
        """最近一次检查仍发现（因而未修复）的异常，按 check_code 索引。

        尚无检查记录时，历史归档全部视为未解决，便于首次检查复用；
        最近一次检查未再关联的异常视为已修复，再次出现按回归另归档。
        """
        runs = self.repo.list_check_runs(subject_type, subject_id)
        if not runs:
            return {
                a.check_code: a
                for a in self.repo.list_anomalies(subject_type, subject_id)
            }
        latest = runs[-1]
        return {
            a.check_code: a
            for aid in latest.anomaly_ids
            if (a := self.repo.get_anomaly(aid)) is not None
        }

    def _is_resolved(self, anomaly: QualityAnomaly) -> bool:
        runs = self.repo.list_check_runs(
            anomaly.subject_type, anomaly.subject_id
        )
        if not runs:
            return False
        return anomaly.anomaly_id not in runs[-1].anomaly_ids

    def _build_anomaly(
        self,
        *,
        subject_type: str,
        subject_id: str,
        check_code: str,
        level: str,
        detail: str,
        evidence: dict,
        archivist_id: str,
    ) -> QualityAnomaly:
        anomaly_id = self.ids.new_id("anm")
        archived_at = self.clock.now_iso()
        evidence = evidence or {}
        evidence_json = canonical_json(evidence).decode("utf-8")
        payload = {
            "anomaly_id": anomaly_id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "check_code": check_code,
            "level": level,
            "detail": detail or "",
            "evidence": evidence or {},
            "archivist_id": archivist_id,
            "archived_at": archived_at,
        }
        return QualityAnomaly(
            anomaly_id=anomaly_id,
            subject_type=subject_type,
            subject_id=subject_id,
            check_code=check_code,
            level=level,
            detail=detail or "",
            evidence_json=evidence_json,
            archivist_id=archivist_id,
            archived_at=archived_at,
            fingerprint=digest_json(payload),
        )

    def _build_run(
        self,
        *,
        subject_type: str,
        subject_id: str,
        subject_digest: str,
        outcome: str,
        warning_count: int,
        blocking_count: int,
        checked_by: str,
        note: str,
        anomaly_ids: tuple[str, ...],
    ) -> QualityCheckRun:
        run_id = self.ids.new_id("run")
        checked_at = self.clock.now_iso()
        payload = {
            "run_id": run_id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "subject_digest": subject_digest,
            "outcome": outcome,
            "warning_count": warning_count,
            "blocking_count": blocking_count,
            "checked_by": checked_by,
            "checked_at": checked_at,
            "note": note or "",
            "anomaly_ids": sorted(anomaly_ids),
        }
        return QualityCheckRun(
            run_id=run_id,
            subject_type=subject_type,
            subject_id=subject_id,
            subject_digest=subject_digest,
            outcome=outcome,
            warning_count=warning_count,
            blocking_count=blocking_count,
            checked_by=checked_by,
            checked_at=checked_at,
            note=note or "",
            anomaly_ids=tuple(sorted(anomaly_ids)),
            fingerprint=digest_json(payload),
        )

    def _require_subject(self, subject_type: str, subject_id: str) -> None:
        if subject_type not in _SUBJECT_TYPES:
            raise ValidationError(
                "未知检查对象类型",
                details={"subject_type": subject_type, "allowed": list(_SUBJECT_TYPES)},
            )
        if subject_type == "material" and self.repo.get_material(subject_id) is None:
            raise NotFoundError("材料不存在", details={"material_id": subject_id})
        if subject_type == "version" and self.repo.get_version(subject_id) is None:
            raise NotFoundError("版本不存在", details={"version_id": subject_id})
        if subject_type == "package" and self.repo.get_package(subject_id) is None:
            raise NotFoundError("评审包不存在", details={"package_id": subject_id})

    def _derive_digest(self, subject_type: str, subject_id: str) -> str:
        """被检对象当时的内容指纹：重跑内容未变则指纹相同，但结果仍是新记录。"""
        if subject_type == "version":
            version = self.repo.get_version(subject_id)
            return "sha256:" + version.sha256  # type: ignore[union-attr]
        if subject_type == "material":
            material = self.repo.get_material(subject_id)
            assert material is not None
            versions = self.repo.list_versions(subject_id)
            return digest_json(
                {
                    "material_id": material.material_id,
                    "title": material.title,
                    "kind": material.kind,
                    "sensitivity": material.sensitivity,
                    "withdrawn": material.withdrawn,
                    "current_version_id": material.current_version_id,
                    "versions": [
                        {
                            "version_no": v.version_no,
                            "sha256": v.sha256,
                            "withdrawn": v.withdrawn,
                        }
                        for v in versions
                    ],
                }
            )
        package = self.repo.get_package(subject_id)
        assert package is not None
        if package.manifest_fingerprint:
            return package.manifest_fingerprint
        return digest_json(
            {
                "package_id": package.package_id,
                "entries": sorted(
                    (
                        {
                            "material_id": e.material_id,
                            "version_id": e.version_id,
                            "sha256": e.sha256,
                        }
                        for e in package.entries
                    ),
                    key=lambda e: e["version_id"],
                ),
            }
        )

    @staticmethod
    def _normalize_finding(raw: dict) -> dict:
        if not isinstance(raw, dict):
            raise ValidationError("findings 每项必须是对象")
        return {
            "check_code": QualityService._validate_code(raw.get("check_code", "")),
            "level": QualityService._validate_level(raw.get("level", "")),
            "detail": raw.get("detail", "") or "",
            "evidence": raw.get("evidence") or {},
        }

    @staticmethod
    def _validate_level(level: str) -> str:
        valid = {l.value for l in QualityLevel}
        if level not in valid:
            raise ValidationError(
                "异常等级必须是 warning 或 blocking",
                details={"level": level, "allowed": sorted(valid)},
            )
        return level

    @staticmethod
    def _validate_code(code: str) -> str:
        code = (code or "").strip()
        if not code:
            raise ValidationError("check_code 不能为空")
        return code

    @staticmethod
    def _anomaly_dict(anomaly: QualityAnomaly, resolved: bool) -> dict:
        return {
            "anomaly_id": anomaly.anomaly_id,
            "subject_type": anomaly.subject_type,
            "subject_id": anomaly.subject_id,
            "check_code": anomaly.check_code,
            "level": anomaly.level,
            "detail": anomaly.detail,
            "evidence": json.loads(anomaly.evidence_json),
            "archivist_id": anomaly.archivist_id,
            "archived_at": anomaly.archived_at,
            "resolved": resolved,
            "fingerprint": anomaly.fingerprint,
        }

    @staticmethod
    def _run_dict(run: QualityCheckRun, linked: list[QualityAnomaly] | None = None) -> dict:
        return {
            "run_id": run.run_id,
            "subject_type": run.subject_type,
            "subject_id": run.subject_id,
            "subject_digest": run.subject_digest,
            "outcome": run.outcome,
            "warning_count": run.warning_count,
            "blocking_count": run.blocking_count,
            "checked_by": run.checked_by,
            "checked_at": run.checked_at,
            "note": run.note,
            "anomaly_ids": list(run.anomaly_ids),
            "fingerprint": run.fingerprint,
        }
