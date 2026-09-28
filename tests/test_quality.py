"""内容质量异常：两级、重新检查只追加不覆盖、阻断签发、指纹与持久化。"""
from __future__ import annotations

import sqlite3
import unittest

from service_09252_006.application.container import ApplicationContext
from service_09252_006.application.verification import verify_database
from service_09252_006.domain.enums import Decision, QualityCheckResult, Role
from service_09252_006.domain.errors import ConflictError, PermissionDeniedError
from tests.flow import complete_review, seal_new_package
from tests.support import Harness


def raw_tables(path: str) -> tuple[int, int]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        inspections = conn.execute(
            "SELECT COUNT(*) FROM quality_inspections"
        ).fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM quality_findings").fetchone()[0]
        return inspections, findings
    finally:
        conn.close()


class QualityInspectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.inspector = self.h.user("insp-a", Role.QUALITY_INSPECTOR)
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        sealed = seal_new_package(self.h, self.admin)
        self.pid = sealed.package_id
        self.version_id = sealed.items[0].version["version_id"]
        complete_review(self.h, self.authority, self.reviewer, self.pid)

    def tearDown(self) -> None:
        self.h.close()

    # --------------------------------------------------------- 等级与结论
    def test_no_findings_is_pass(self) -> None:
        result = self.h.ctx.quality.record_inspection(
            self.inspector, package_id=self.pid, findings=[]
        )
        self.assertEqual(result["result"], QualityCheckResult.PASS.value)
        self.assertEqual(result["findings"], [])
        self.assertIsNotNone(result["fingerprint"])

    def test_warning_level_does_not_escalate(self) -> None:
        result = self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[
                {"severity": "warning", "category": "格式", "detail": "页眉不统一"}
            ],
        )
        self.assertEqual(result["result"], QualityCheckResult.WARNING.value)

    def test_blocking_level_and_mixed_findings(self) -> None:
        result = self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[
                {"severity": "warning", "category": "格式", "detail": "页眉不统一"},
                {
                    "severity": "blocking",
                    "category": "材料缺失",
                    "detail": "缺少考核评分标准",
                    "version_id": self.version_id,
                },
            ],
        )
        self.assertEqual(result["result"], QualityCheckResult.BLOCKED.value)
        severities = {f["severity"] for f in result["findings"]}
        self.assertEqual(severities, {"warning", "blocking"})

    def test_invalid_severity_rejected(self) -> None:
        from service_09252_006.domain.errors import ValidationError

        with self.assertRaises(ValidationError):
            self.h.ctx.quality.record_inspection(
                self.inspector,
                package_id=self.pid,
                findings=[{"severity": "fatal", "category": "x", "detail": "y"}],
            )

    def test_finding_target_must_be_in_sealed_manifest(self) -> None:
        from service_09252_006.domain.errors import ValidationError

        with self.assertRaises(ValidationError):
            self.h.ctx.quality.record_inspection(
                self.inspector,
                package_id=self.pid,
                findings=[
                    {
                        "severity": "blocking",
                        "category": "版本错误",
                        "detail": "引用了不在清单里的版本",
                        "version_id": "ver_does_not_exist",
                    }
                ],
            )

    # --------------------------------------------------------- 权限
    def test_only_inspector_or_authority_may_record(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.quality.record_inspection(
                self.submitter, package_id=self.pid, findings=[]
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.quality.record_inspection(
                self.reviewer, package_id=self.pid, findings=[]
            )
        # 质量权威可以归档
        ok = self.h.ctx.quality.record_inspection(
            self.authority, package_id=self.pid, findings=[]
        )
        self.assertEqual(ok["result"], "pass")

    # --------------------------------------------------------- 历史只追加
    def test_rerun_produces_new_records_and_keeps_history(self) -> None:
        first = self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[
                {
                    "severity": "blocking",
                    "category": "材料缺失",
                    "detail": "缺少考核评分标准",
                }
            ],
        )
        # 修复后重新检查（Python 再次调用）：必须产生新记录
        second = self.h.ctx.quality.record_inspection(
            self.inspector, package_id=self.pid, findings=[]
        )
        self.assertNotEqual(first["inspection_id"], second["inspection_id"])
        self.assertEqual(first["result"], "blocked")
        self.assertEqual(second["result"], "pass")

        listing = self.h.ctx.quality.list_inspections(self.inspector, self.pid)
        self.assertEqual(listing["count"], 2)
        self.assertEqual(listing["latest_result"], "pass")
        ids = [i["inspection_id"] for i in listing["inspections"]]
        self.assertEqual(ids, [first["inspection_id"], second["inspection_id"]])

        # 原异常仍原样挂在第一次检查下，未被第二次检查覆盖/清理
        old = self.h.ctx.quality.get_inspection(
            self.inspector, first["inspection_id"]
        )
        self.assertEqual(old["result"], "blocked")
        self.assertEqual(len(old["findings"]), 1)
        self.assertEqual(old["findings"][0]["detail"], "缺少考核评分标准")

        # 数据库里确实是两条检查 + 一条异常，没有任何 UPDATE 覆盖
        n_inspections, n_findings = raw_tables(self.h.db_path)
        self.assertEqual((n_inspections, n_findings), (2, 1))

    def test_rerun_with_identical_content_still_appends(self) -> None:
        payload = [{"severity": "warning", "category": "格式", "detail": "同样的问题"}]
        a = self.h.ctx.quality.record_inspection(
            self.inspector, package_id=self.pid, findings=payload
        )
        b = self.h.ctx.quality.record_inspection(
            self.inspector, package_id=self.pid, findings=payload
        )
        self.assertNotEqual(a["inspection_id"], b["inspection_id"])
        n_inspections, n_findings = raw_tables(self.h.db_path)
        self.assertEqual((n_inspections, n_findings), (2, 2))

    def test_idempotency_key_replays_without_new_rows(self) -> None:
        a = self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[{"severity": "warning", "category": "a", "detail": "b"}],
            idempotency_key="qc-1",
        )
        b = self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[{"severity": "blocking", "category": "x", "detail": "y"}],
            idempotency_key="qc-1",
        )
        self.assertTrue(b["replayed"])
        self.assertEqual(a["inspection_id"], b["inspection_id"])
        self.assertEqual(b["result"], "warning")  # 回放首次结果
        n_inspections, n_findings = raw_tables(self.h.db_path)
        self.assertEqual((n_inspections, n_findings), (1, 1))

    def test_history_survives_context_reopen(self) -> None:
        first = self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[{"severity": "blocking", "category": "缺项", "detail": "缺大纲"}],
        )
        self.h.ctx.close()
        # 新进程式的重开：历史仍在，重新检查继续追加
        ctx2 = ApplicationContext(self.h.db_path, clock=self.h.clock, ids=self.h.ids)
        try:
            history = ctx2.repo.list_inspections(self.pid)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0].inspection_id, first["inspection_id"])
            self.assertEqual(history[0].findings[0].severity, "blocking")
        finally:
            ctx2.close()

    # --------------------------------------------------------- 阻断签发
    def test_blocking_inspection_blocks_decision(self) -> None:
        self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[
                {"severity": "blocking", "category": "材料缺失", "detail": "缺少评分标准"}
            ],
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.reviews.issue_decision(
                self.authority,
                package_id=self.pid,
                decision=Decision.APPROVED.value,
            )

        # 修复后重新检查通过：历史 blocked 保留，但签发放行
        self.h.ctx.quality.record_inspection(
            self.inspector, package_id=self.pid, findings=[]
        )
        decision = self.h.ctx.reviews.issue_decision(
            self.authority, package_id=self.pid, decision=Decision.APPROVED.value
        )
        self.assertEqual(decision["decision"], "approved")

        # 旧的阻断记录仍可查
        old = self.h.ctx.quality.list_inspections(self.inspector, self.pid)
        self.assertEqual(
            [i["result"] for i in old["inspections"]], ["blocked", "pass"]
        )

    def test_warning_inspection_does_not_block_decision(self) -> None:
        self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[{"severity": "warning", "category": "格式", "detail": "页眉问题"}],
        )
        decision = self.h.ctx.reviews.issue_decision(
            self.authority, package_id=self.pid, decision=Decision.APPROVED.value
        )
        self.assertEqual(decision["decision"], "approved")

    # --------------------------------------------------------- 离线核验
    def test_clean_inspections_verify(self) -> None:
        self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[
                {"severity": "warning", "category": "格式", "detail": "页眉不统一"},
                {
                    "severity": "blocking",
                    "category": "材料缺失",
                    "detail": "缺少评分标准",
                    "version_id": self.version_id,
                },
            ],
        )
        self.h.ctx.close()
        report = verify_database(self.h.db_path)
        self.assertTrue(report.ok, report.failures)
        self.assertEqual(report.inspection_count, 1)

    def test_tampered_finding_severity_detected(self) -> None:
        self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[
                {"severity": "blocking", "category": "材料缺失", "detail": "缺少评分标准"}
            ],
        )
        self.h.ctx.close()
        conn = sqlite3.connect(self.h.db_path)
        # 事后把阻断改成警告并同时洗白结论——指纹与 result 一致性都应报警
        conn.execute(
            "UPDATE quality_findings SET severity = 'warning'"
        )
        conn.execute("UPDATE quality_inspections SET result = 'warning'")
        conn.commit()
        conn.close()

        report = verify_database(self.h.db_path)
        self.assertFalse(report.ok)
        kinds = {f["kind"] for f in report.failures}
        self.assertIn("inspection_fingerprint_mismatch", kinds)

    def test_deleted_finding_detected(self) -> None:
        self.h.ctx.quality.record_inspection(
            self.inspector,
            package_id=self.pid,
            findings=[
                {"severity": "warning", "category": "a", "detail": "x"},
                {"severity": "warning", "category": "b", "detail": "y"},
            ],
        )
        self.h.ctx.close()
        conn = sqlite3.connect(self.h.db_path)
        conn.execute("DELETE FROM quality_findings WHERE category = 'b'")
        conn.commit()
        conn.close()

        report = verify_database(self.h.db_path)
        self.assertFalse(report.ok)
        self.assertTrue(
            any(f["kind"] == "inspection_fingerprint_mismatch" for f in report.failures)
        )


if __name__ == "__main__":
    unittest.main()
