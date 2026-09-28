"""离线完整性核验。

不依赖时钟/写事务：打开数据库只读连接，重算所有内容字节摘要与每个
已封存包的清单指纹、已签发包的评审记录指纹，任何不一致或“已封存清单
引用了已撤回版本”都会被报告。CLI 命令与（未来的）在线接口共用本模块。
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from ..domain.fingerprint import (
    digest_bytes,
    digest_json,
    manifest_fingerprint,
    review_record_fingerprint,
)


@dataclass
class VerificationReport:
    ok: bool = True
    blob_count: int = 0
    package_count: int = 0
    sealed_count: int = 0
    decided_count: int = 0
    anomaly_count: int = 0
    check_run_count: int = 0
    withdrawn_in_sealed: list[dict] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)

    def fail(self, kind: str, **detail) -> None:
        self.ok = False
        item = {"kind": kind}
        item.update(detail)
        self.failures.append(item)

    def warn(self, kind: str, **detail) -> None:
        item = {"kind": kind}
        item.update(detail)
        self.warnings.append(item)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "blob_count": self.blob_count,
            "package_count": self.package_count,
            "sealed_count": self.sealed_count,
            "decided_count": self.decided_count,
            "anomaly_count": self.anomaly_count,
            "check_run_count": self.check_run_count,
            "withdrawn_in_sealed": self.withdrawn_in_sealed,
            "failures": self.failures,
            "warnings": self.warnings,
        }


def verify_database(path: str) -> VerificationReport:
    """对数据库文件做完整离线核验。只读打开，绝不写入。"""
    report = VerificationReport()
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        _verify_blobs(conn, report)
        _verify_packages(conn, report)
        _verify_quality(conn, report)
    finally:
        conn.close()
    return report


def _verify_blobs(conn: sqlite3.Connection, report: VerificationReport) -> None:
    rows = conn.execute(
        "SELECT sha256, data, size, media_type FROM blobs"
    ).fetchall()
    report.blob_count = len(rows)
    for row in rows:
        raw = row["data"]
        if not isinstance(raw, bytes):
            report.fail(
                "blob_type_mismatch",
                stored=row["sha256"],
                actual_type=type(raw).__name__,
            )
            continue
        data = raw
        actual = digest_bytes(data)
        if actual != row["sha256"]:
            report.fail(
                "blob_digest_mismatch",
                stored=row["sha256"],
                actual=actual,
            )
        if len(data) != row["size"]:
            report.fail(
                "blob_size_mismatch",
                sha256=row["sha256"],
                stored_size=row["size"],
                actual_size=len(data),
            )


def _verify_packages(conn: sqlite3.Connection, report: VerificationReport) -> None:
    packages = conn.execute("SELECT * FROM packages").fetchall()
    report.package_count = len(packages)

    # version_id -> withdrawn，供封存清单引用检查
    withdrawn_versions = {
        r["version_id"]: bool(r["withdrawn"])
        for r in conn.execute("SELECT version_id, withdrawn FROM versions")
    }

    for pkg in packages:
        entries = conn.execute(
            "SELECT * FROM entries WHERE package_id = ?"
            " ORDER BY material_id, version_id",
            (pkg["package_id"],),
        ).fetchall()

        # 条目声明的 sha256 必须与版本表一致，且字节可重算
        for entry in entries:
            version = conn.execute(
                "SELECT sha256, withdrawn FROM versions WHERE version_id = ?",
                (entry["version_id"],),
            ).fetchone()
            if version is None:
                report.fail(
                    "entry_version_missing",
                    package_id=pkg["package_id"],
                    version_id=entry["version_id"],
                )
                continue
            if version["sha256"] != entry["sha256"]:
                report.fail(
                    "entry_digest_drift",
                    package_id=pkg["package_id"],
                    version_id=entry["version_id"],
                    entry_sha256=entry["sha256"],
                    version_sha256=version["sha256"],
                )
            blob = conn.execute(
                "SELECT data FROM blobs WHERE sha256 = ?", (entry["sha256"],)
            ).fetchone()
            if blob is None:
                report.fail(
                    "blob_missing",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )
            elif not isinstance(blob["data"], bytes):
                report.fail(
                    "blob_type_mismatch",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )
            elif digest_bytes(blob["data"]) != entry["sha256"]:
                report.fail(
                    "blob_tampered",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )

        if pkg["status"] in ("sealed", "under_review", "decided"):
            report.sealed_count += 1
            expected = manifest_fingerprint(
                pkg["package_id"],
                pkg["institution_id"],
                [
                    {
                        "material_id": e["material_id"],
                        "version_id": e["version_id"],
                        "sha256": e["sha256"],
                        "kind": e["kind"],
                        "sensitivity": e["sensitivity"],
                    }
                    for e in entries
                ],
                pkg["sealed_at"],
            )
            stored = pkg["manifest_fingerprint"]
            if stored != expected:
                report.fail(
                    "manifest_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    stored=stored,
                    expected=expected,
                )

            # 撤回不破坏历史指纹，但必须显式标注：该包引用的材料事后被撤回
            for e in entries:
                if withdrawn_versions.get(e["version_id"]):
                    report.withdrawn_in_sealed.append(
                        {
                            "package_id": pkg["package_id"],
                            "version_id": e["version_id"],
                            "material_id": e["material_id"],
                        }
                    )
                    report.warn(
                        "sealed_entry_withdrawn",
                        package_id=pkg["package_id"],
                        version_id=e["version_id"],
                    )

        if pkg["status"] == "decided":
            report.decided_count += 1
            requests = [
                {
                    "request_id": r["request_id"],
                    "reviewer_id": r["reviewer_id"],
                    "status": r["status"],
                    "verdict": r["verdict"],
                    "comment": r["comment"],
                    "assigned_at": r["assigned_at"],
                    "completed_at": r["completed_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM requests WHERE package_id = ? ORDER BY request_id",
                    (pkg["package_id"],),
                )
            ]
            objections = [
                {
                    "objection_id": r["objection_id"],
                    "request_id": r["request_id"],
                    "reviewer_id": r["reviewer_id"],
                    "category": r["category"],
                    "detail": r["detail"],
                    "created_at": r["created_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM objections WHERE package_id = ? ORDER BY objection_id",
                    (pkg["package_id"],),
                )
            ]
            expected_review = review_record_fingerprint(
                pkg["package_id"],
                pkg["manifest_fingerprint"],
                requests,
                objections,
            )
            if pkg["review_fingerprint"] != expected_review:
                report.fail(
                    "review_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    stored=pkg["review_fingerprint"],
                    expected=expected_review,
                )


def _verify_quality(conn: sqlite3.Connection, report: VerificationReport) -> None:
    """重算质量异常与检查结果的归档指纹，校验关联完整性与历史唯一性。"""
    anomalies = conn.execute("SELECT * FROM quality_anomalies").fetchall()
    runs = conn.execute("SELECT * FROM quality_check_runs").fetchall()
    report.anomaly_count = len(anomalies)
    report.check_run_count = len(runs)

    import json as _json

    seen_anomaly_fps: dict[str, str] = {}
    anomaly_ids: set[str] = set()
    for row in anomalies:
        anomaly_ids.add(row["anomaly_id"])
        try:
            evidence = _json.loads(row["evidence_json"])
        except (ValueError, TypeError):
            report.fail(
                "anomaly_evidence_invalid_json", anomaly_id=row["anomaly_id"]
            )
            continue
        expected = digest_json(
            {
                "anomaly_id": row["anomaly_id"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "check_code": row["check_code"],
                "level": row["level"],
                "detail": row["detail"],
                "evidence": evidence,
                "archivist_id": row["archivist_id"],
                "archived_at": row["archived_at"],
            }
        )
        if row["fingerprint"] != expected:
            report.fail(
                "anomaly_fingerprint_mismatch",
                anomaly_id=row["anomaly_id"],
                stored=row["fingerprint"],
                expected=expected,
            )
        prior = seen_anomaly_fps.get(row["fingerprint"])
        if prior is not None:
            report.fail(
                "anomaly_history_duplicated",
                anomaly_id=row["anomaly_id"],
                duplicates=prior,
            )
        else:
            seen_anomaly_fps[row["fingerprint"]] = row["anomaly_id"]

    seen_run_fps: dict[str, str] = {}
    run_ids: set[str] = set()
    for row in runs:
        run_ids.add(row["run_id"])
        linked = [
            r["anomaly_id"]
            for r in conn.execute(
                "SELECT anomaly_id FROM quality_check_run_anomalies"
                " WHERE run_id = ? ORDER BY anomaly_id",
                (row["run_id"],),
            )
        ]
        for aid in linked:
            if aid not in anomaly_ids:
                report.fail(
                    "check_link_anomaly_missing",
                    run_id=row["run_id"],
                    anomaly_id=aid,
                )
        expected = digest_json(
            {
                "run_id": row["run_id"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "subject_digest": row["subject_digest"],
                "outcome": row["outcome"],
                "warning_count": row["warning_count"],
                "blocking_count": row["blocking_count"],
                "checked_by": row["checked_by"],
                "checked_at": row["checked_at"],
                "note": row["note"],
                "anomaly_ids": sorted(linked),
            }
        )
        if row["fingerprint"] != expected:
            report.fail(
                "check_run_fingerprint_mismatch",
                run_id=row["run_id"],
                stored=row["fingerprint"],
                expected=expected,
            )
        # 等级计数必须与关联异常一致，outcome 必须由计数派生
        warnings = sum(1 for aid in linked if _anomaly_level(conn, aid) == "warning")
        blockings = sum(1 for aid in linked if _anomaly_level(conn, aid) == "blocking")
        if warnings != row["warning_count"] or blockings != row["blocking_count"]:
            report.fail(
                "check_run_count_mismatch",
                run_id=row["run_id"],
                stored_warning=row["warning_count"],
                actual_warning=warnings,
                stored_blocking=row["blocking_count"],
                actual_blocking=blockings,
            )
        expected_outcome = (
            "blocking" if blockings else ("warning" if warnings else "ok")
        )
        if row["outcome"] != expected_outcome:
            report.fail(
                "check_run_outcome_mismatch",
                run_id=row["run_id"],
                stored=row["outcome"],
                expected=expected_outcome,
            )
        prior = seen_run_fps.get(row["fingerprint"])
        if prior is not None:
            report.fail(
                "check_run_history_duplicated", run_id=row["run_id"], duplicates=prior
            )
        else:
            seen_run_fps[row["fingerprint"]] = row["run_id"]

    # 关联表不得悬挂到不存在的检查运行
    for row in conn.execute(
        "SELECT DISTINCT run_id FROM quality_check_run_anomalies"
    ):
        if row["run_id"] not in run_ids:
            report.fail("check_link_run_missing", run_id=row["run_id"])


def _anomaly_level(conn: sqlite3.Connection, anomaly_id: str) -> str | None:
    row = conn.execute(
        "SELECT level FROM quality_anomalies WHERE anomaly_id = ?", (anomaly_id,)
    ).fetchone()
    return None if row is None else row["level"]
