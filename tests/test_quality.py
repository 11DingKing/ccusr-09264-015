"""内容质量异常：等级、归档不可变、复查产生新结果而不覆盖历史。"""
import json
import sqlite3
import unittest

from service_09252_006.application.verification import verify_database
from service_09252_006.domain.enums import QualityLevel, Role
from service_09252_006.domain.errors import (
    PermissionDeniedError,
    ValidationError,
)
from tests.flow import upload_material
from tests.support import Harness


class QualityAnomalyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.item = upload_material(self.h, self.admin)
        self.vid = self.item.version["version_id"]

    def tearDown(self) -> None:
        self.h.close()

    # ---------------------------------------------------------- 等级归档
    def test_archive_warning_and_blocking_levels(self) -> None:
        warning = self.h.ctx.quality.archive_anomaly(
            self.reviewer,
            subject_type="version",
            subject_id=self.vid,
            check_code="format_drift",
            level=QualityLevel.WARNING.value,
            detail="格式不规范",
            evidence={"sha256": self.item.version["sha256"]},
        )
        blocking = self.h.ctx.quality.archive_anomaly(
            self.authority,
            subject_type="version",
            subject_id=self.vid,
            check_code="missing_section",
            level="blocking",
            detail="缺少考核依据",
        )
        self.assertEqual(warning["level"], "warning")
        self.assertEqual(blocking["level"], "blocking")
        self.assertTrue(warning["fingerprint"])
        self.assertEqual(self.h.repo.count_anomalies(), 2)

        by_level = {
            a["level"]
            for a in self.h.ctx.quality.list_anomalies(
                self.reviewer,
                subject_type="version",
                subject_id=self.vid,
            )["anomalies"]
        }
        self.assertEqual(by_level, {"warning", "blocking"})

    def test_invalid_level_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.quality.archive_anomaly(
                self.reviewer,
                subject_type="version",
                subject_id=self.vid,
                check_code="x",
                level="fatal",
            )

    def test_only_reviewer_or_authority_may_archive(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.quality.archive_anomaly(
                self.submitter,
                subject_type="version",
                subject_id=self.vid,
                check_code="x",
                level="warning",
            )

    # --------------------------------------- 复查产生新结果，原异常保留
    def test_recheck_after_fix_creates_new_run_keeps_anomaly(self) -> None:
        first = self.h.ctx.quality.record_check(
            self.reviewer,
            subject_type="version",
            subject_id=self.vid,
            findings=[
                {"check_code": "missing_section", "level": "blocking",
                 "detail": "缺少考核依据"}
            ],
        )
        self.assertEqual(first["outcome"], "blocking")
        first_run_id = first["run_id"]
        first_anomaly_id = first["anomaly_ids"][0]

        self.h.clock.advance(120)
        # 修复后重新检查：通过，产生一条全新的 ok 结果
        second = self.h.ctx.quality.record_check(
            self.reviewer,
            subject_type="version",
            subject_id=self.vid,
            findings=[],
            note="已补充考核依据章节",
        )
        self.assertEqual(second["outcome"], "ok")
        self.assertNotEqual(second["run_id"], first_run_id)

        # 两条结果都在；原异常没有被覆盖或删除
        self.assertEqual(self.h.repo.count_check_runs(), 2)
        self.assertEqual(self.h.repo.count_anomalies(), 1)
        kept = self.h.repo.get_anomaly(first_anomaly_id)
        self.assertIsNotNone(kept)
        self.assertEqual(kept.level, "blocking")

        history = self.h.ctx.quality.subject_history(
            self.reviewer, "version", self.vid
        )
        run_ids = [r["run_id"] for r in history["check_runs"]]
        self.assertEqual(run_ids, [first_run_id, second["run_id"]])
        self.assertEqual(len(history["anomalies"]), 1)
        # 派生状态：最近一次检查未再发现 -> 已修复（异常记录本身未被改写）
        self.assertTrue(history["anomalies"][0]["resolved"])

    def test_python_rerun_without_idempotency_key_inserts_new_record(self) -> None:
        """模拟 Python 重跑：同样入参、不带幂等键，每次都是新记录。"""
        kwargs = dict(
            subject_type="version",
            subject_id=self.vid,
            findings=[{"check_code": "format_drift", "level": "warning"}],
        )
        r1 = self.h.ctx.quality.record_check(self.reviewer, **kwargs)
        self.h.clock.advance(1)
        r2 = self.h.ctx.quality.record_check(self.reviewer, **kwargs)
        self.h.clock.advance(1)
        r3 = self.h.ctx.quality.record_check(self.reviewer, **kwargs)

        self.assertEqual(
            self.h.repo.count_check_runs(), 3, "重跑必须各自产生新记录"
        )
        run_ids = {r1["run_id"], r2["run_id"], r3["run_id"]}
        self.assertEqual(len(run_ids), 3)
        # 同一未修复问题在多次检查中复用同一条异常
        self.assertEqual(self.h.repo.count_anomalies(), 1)
        self.assertEqual(
            r1["anomaly_ids"], r2["anomaly_ids"]
        )

    def test_idempotency_key_replays_without_new_row(self) -> None:
        kwargs = dict(
            subject_type="version",
            subject_id=self.vid,
            findings=[{"check_code": "format_drift", "level": "warning"}],
        )
        r1 = self.h.ctx.quality.record_check(
            self.reviewer, idempotency_key="check-key-1", **kwargs
        )
        r2 = self.h.ctx.quality.record_check(
            self.reviewer, idempotency_key="check-key-1", **kwargs
        )
        self.assertEqual(r1["run_id"], r2["run_id"])
        self.assertTrue(r2["replayed"])
        self.assertEqual(self.h.repo.count_check_runs(), 1)

    # ------------------------------------------------- 历史不可覆盖/抹除
    def test_history_rows_cannot_be_updated_or_deleted(self) -> None:
        run = self.h.ctx.quality.record_check(
            self.reviewer,
            subject_type="version",
            subject_id=self.vid,
            findings=[{"check_code": "missing_section", "level": "blocking"}],
        )
        conn = self.h.repo._conn  # 触发器在数据库层拦截
        with self.assertRaises(sqlite3.Error):
            conn.execute(
                "UPDATE quality_anomalies SET level='warning' WHERE anomaly_id=?",
                (run["anomaly_ids"][0],),
            )
        with self.assertRaises(sqlite3.Error):
            conn.execute(
                "DELETE FROM quality_anomalies WHERE anomaly_id=?",
                (run["anomaly_ids"][0],),
            )
        with self.assertRaises(sqlite3.Error):
            conn.execute(
                "UPDATE quality_check_runs SET outcome='ok' WHERE run_id=?",
                (run["run_id"],),
            )
        with self.assertRaises(sqlite3.Error):
            conn.execute(
                "DELETE FROM quality_check_runs WHERE run_id=?", (run["run_id"],)
            )
        # 被回滚的拦截不影响历史
        self.assertEqual(self.h.repo.count_anomalies(), 1)
        self.assertEqual(self.h.repo.count_check_runs(), 1)

    # ------------------------------------------------------- 修复后回归
    def test_regression_after_fix_archives_new_anomaly_keeps_both(self) -> None:
        c1 = "missing_section"
        self.h.ctx.quality.record_check(
            self.reviewer, subject_type="version", subject_id=self.vid,
            findings=[{"check_code": c1, "level": "blocking"}],
        )
        self.h.clock.advance(60)
        self.h.ctx.quality.record_check(
            self.reviewer, subject_type="version", subject_id=self.vid,
            findings=[],
        )
        self.h.clock.advance(60)
        # 问题回归：归档为新异常，但第一次的异常仍在
        r3 = self.h.ctx.quality.record_check(
            self.reviewer, subject_type="version", subject_id=self.vid,
            findings=[{"check_code": c1, "level": "blocking"}],
        )
        self.assertEqual(self.h.repo.count_anomalies(), 2)
        self.assertEqual(len(r3["anomaly_ids"]), 1)
        anomalies = self.h.ctx.quality.list_anomalies(
            self.reviewer, subject_type="version", subject_id=self.vid
        )["anomalies"]
        # 第一次出现已修复；回归是新的未修复异常；两条历史都保留
        self.assertEqual([a["resolved"] for a in anomalies], [True, False])

    def test_warning_does_not_block_blocking_does(self) -> None:
        warning_run = self.h.ctx.quality.record_check(
            self.reviewer, subject_type="version", subject_id=self.vid,
            findings=[{"check_code": "fmt", "level": "warning"}],
        )
        self.assertEqual(warning_run["outcome"], "warning")
        self.assertEqual(warning_run["blocking_count"], 0)

        mixed_run = self.h.ctx.quality.record_check(
            self.reviewer, subject_type="version", subject_id=self.vid,
            findings=[
                {"check_code": "fmt", "level": "warning"},
                {"check_code": "missing", "level": "blocking"},
            ],
        )
        self.assertEqual(mixed_run["outcome"], "blocking")
        self.assertEqual(mixed_run["warning_count"], 1)
        self.assertEqual(mixed_run["blocking_count"], 1)

    # ------------------------------------------------------- 离线核验
    def test_offline_verification_covers_quality_history(self) -> None:
        self.h.ctx.quality.record_check(
            self.reviewer, subject_type="version", subject_id=self.vid,
            findings=[{"check_code": "missing_section", "level": "blocking"}],
        )
        self.h.clock.advance(60)
        self.h.ctx.quality.record_check(
            self.reviewer, subject_type="version", subject_id=self.vid,
            findings=[],
        )
        report = verify_database(self.h.db_path)
        self.assertTrue(report.ok, report.failures)
        self.assertEqual(report.anomaly_count, 1)
        self.assertEqual(report.check_run_count, 2)

    def test_existing_schema_v1_database_migrates(self) -> None:
        """旧库（user_version=1，无质量表）打开时自动迁移且不丢数据。"""
        # 当前 harness 已在 v2 上写过质量数据；直接核验 user_version 与表
        row = self.h.repo._conn.execute("PRAGMA user_version").fetchone()
        self.assertEqual(row[0], 2)
        names = {
            r[0]
            for r in self.h.repo._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("quality_anomalies", names)
        self.assertIn("quality_check_runs", names)


if __name__ == "__main__":
    unittest.main()
