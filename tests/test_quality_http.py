"""内容质量异常的 HTTP 端到端：归档、重检新结果、历史查询与鉴权。"""
import base64
import unittest

from service_09252_006.api.http_api import HttpApiServer
from tests.support import Harness
from tests.test_http_api import ApiClient


class QualityHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot-secret")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _user(self, user_id, roles, institution_id=None, token=None):
        status, body = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        self.assertEqual(status, 201, body)
        status, body = self.boot.request(
            "POST", "/v1/admin/tokens",
            {"user_id": user_id, "token": token},
        )
        self.assertEqual(status, 201, body)
        return ApiClient(self.base, token=token)

    def _upload_version(self, admin):
        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "大纲"},
        )
        self.assertEqual(status, 201, mat)
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(b"syllabus-v1").decode("ascii")},
        )
        self.assertEqual(status, 201, ver)
        return ver["version_id"]

    def test_archive_and_recheck_history_over_http(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        submitter = self._user("sub-a", ["institution_submitter"], "inst-a", "t-sub")
        reviewer = self._user("rev-1", ["reviewer"], "inst-ext", "t-rev")
        vid = self._upload_version(admin)

        # 提交人无权归档质量异常
        status, body = submitter.request(
            "POST", "/v1/quality/anomalies",
            {"subject_type": "version", "subject_id": vid,
             "check_code": "x", "level": "warning"},
        )
        self.assertEqual(status, 403)

        # 质检员归档一条阻断异常
        status, anm = reviewer.request(
            "POST", "/v1/quality/anomalies",
            {"subject_type": "version", "subject_id": vid,
             "check_code": "missing_section", "level": "blocking",
             "detail": "缺少考核依据",
             "evidence": {"version_id": vid}},
        )
        self.assertEqual(status, 201, anm)
        self.assertEqual(anm["level"], "blocking")
        self.assertFalse(anm["resolved"])
        anomaly_id = anm["anomaly_id"]

        # 非法等级
        status, body = reviewer.request(
            "POST", "/v1/quality/anomalies",
            {"subject_type": "version", "subject_id": vid,
             "check_code": "x", "level": "fatal"},
        )
        self.assertEqual(status, 422)

        # 修复后重新检查：新结果，通过
        status, ok_run = reviewer.request(
            "POST", "/v1/quality/checks",
            {"subject_type": "version", "subject_id": vid,
             "findings": [], "note": "已修复"},
        )
        self.assertEqual(status, 201, ok_run)
        self.assertEqual(ok_run["outcome"], "ok")

        # 原异常仍可取，且派生为已修复
        status, fetched = reviewer.request(
            "GET", f"/v1/quality/anomalies/{anomaly_id}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(fetched["anomaly_id"], anomaly_id)
        self.assertTrue(fetched["resolved"])

        # 历史：一条异常 + 一条检查结果（归档不产生 check run）
        status, history = reviewer.request(
            "GET",
            "/v1/quality/history?subject_type=version"
            f"&subject_id={vid}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(history["anomalies"]), 1)
        self.assertEqual(len(history["check_runs"]), 1)
        self.assertEqual(history["check_runs"][0]["run_id"], ok_run["run_id"])

    def test_rerun_inserts_new_check_record(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        reviewer = self._user("rev-1", ["reviewer"], "inst-ext", "t-rev")
        vid = self._upload_version(admin)

        payload = {
            "subject_type": "version", "subject_id": vid,
            "findings": [{"check_code": "fmt", "level": "warning"}],
        }
        s1, r1 = reviewer.request("POST", "/v1/quality/checks", payload)
        s2, r2 = reviewer.request("POST", "/v1/quality/checks", payload)
        self.assertEqual((s1, s2), (201, 201))
        self.assertNotEqual(r1["run_id"], r2["run_id"], "重跑必须产生新记录")

        status, listing = reviewer.request(
            "GET",
            "/v1/quality/checks?subject_type=version"
            f"&subject_id={vid}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["check_runs"]), 2)
        self.assertEqual(
            {r["anomaly_ids"][0] for r in listing["check_runs"]},
            set(r1["anomaly_ids"]),
        )


if __name__ == "__main__":
    unittest.main()
