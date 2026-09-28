"""内容质量检查服务：质检员归档异常，结果按等级只追加写入。

核心规则：
- 异常分两级：warning（警告，不阻断）与 blocking（阻断，必须修复后
  重新检查）；一次检查的结论 result 取本次发现的最高等级
  （blocking > warning > pass）；
- 每次检查都【新建】一条 inspection 及其 findings，即使内容与上次
  完全相同也产生新记录；系统不提供任何更新/删除路径，修复后重新
  检查不会覆盖或清理历史异常——“当时查出了什么”永远可证；
- 检查结果带规范化指纹，离线核验重算，事后改写等级/内容会被发现；
- 业务效果：包的最近一次检查为 blocked 时不能签发（见评审服务），
  warning 不阻断；修复后重新检查得到 pass 即可放行，旧 blocked 留痕。
"""
from __future__ import annotations

from ..domain.enums import QualityCheckResult, QualitySeverity, Role
from ..domain.errors import (
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.fingerprint import inspection_fingerprint
from ..domain.models import QualityFinding, QualityInspection, User
from .base import Service, require_roles

_SEVERITIES = {s.value for s in QualitySeverity}


class QualityService(Service):
    # ------------------------------------------------------------- 归档检查
    def record_inspection(
        self,
        actor: User,
        *,
        package_id: str,
        findings: list[dict] | None = None,
        note: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.QUALITY_INSPECTOR, Role.QUALITY_AUTHORITY)
        normalized = self._normalize_findings(findings or [])

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在", details={"package_id": package_id})
            if (
                not actor.has_role(Role.QUALITY_AUTHORITY)
                and package.institution_id != actor.institution_id
            ):
                raise PermissionDeniedError("只能检查本机构评审包")

            entries_by_version = {e.version_id: e for e in package.entries}
            checked_at = self.clock.now_iso()
            inspection_id = self.ids.new_id("qin")

            finding_objects: list[QualityFinding] = []
            for index, item in enumerate(normalized, start=1):
                self._validate_finding_target(package_id, item, entries_by_version)
                finding_objects.append(
                    QualityFinding(
                        finding_id=self.ids.new_id("qf"),
                        inspection_id=inspection_id,
                        package_id=package_id,
                        institution_id=package.institution_id,
                        severity=item["severity"],
                        category=item["category"],
                        detail=item["detail"],
                        material_id=item.get("material_id"),
                        version_id=item.get("version_id"),
                        created_by=actor.user_id,
                        created_at=checked_at,
                    )
                )

            result = self._result_for(finding_objects)
            fingerprint = inspection_fingerprint(
                inspection_id,
                package_id,
                result,
                actor.user_id,
                checked_at,
                [
                    {
                        "finding_id": f.finding_id,
                        "severity": f.severity,
                        "category": f.category,
                        "detail": f.detail,
                        "material_id": f.material_id,
                        "version_id": f.version_id,
                    }
                    for f in finding_objects
                ],
            )
            inspection = QualityInspection(
                inspection_id=inspection_id,
                package_id=package_id,
                institution_id=package.institution_id,
                result=result,
                checked_by=actor.user_id,
                checked_at=checked_at,
                note=note.strip() if note and note.strip() else None,
                findings=tuple(finding_objects),
                fingerprint=fingerprint,
            )
            # 纯 INSERT：重复主键会被数据库拒绝，不存在覆盖路径
            self.repo.insert_inspection(inspection)
            self.audit(
                actor.user_id, "quality.inspected",
                package_id=package_id, institution_id=package.institution_id,
                detail={
                    "inspection_id": inspection_id,
                    "result": result,
                    "findings": len(finding_objects),
                    "blocking": sum(
                        1 for f in finding_objects
                        if f.severity == QualitySeverity.BLOCKING.value
                    ),
                },
            )
            return self._inspection_dict(inspection)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------- 查询
    def get_inspection(self, actor: User, inspection_id: str) -> dict:
        inspection = self.repo.get_inspection(inspection_id)
        if inspection is None:
            raise NotFoundError("质量检查记录不存在")
        self._require_can_view(actor, inspection.package_id)
        return self._inspection_dict(inspection)

    def list_inspections(self, actor: User, package_id: str) -> dict:
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        self._require_can_view(actor, package_id)
        inspections = self.repo.list_inspections(package_id)
        return {
            "package_id": package_id,
            "count": len(inspections),
            "latest_result": inspections[-1].result if inspections else None,
            "inspections": [self._inspection_dict(i) for i in inspections],
        }

    # ------------------------------------------------------------- 内部
    def _require_can_view(self, actor: User, package_id: str) -> None:
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        if (
            actor.institution_id == package.institution_id
            or actor.has_role(Role.QUALITY_AUTHORITY)
            or actor.has_role(Role.QUALITY_INSPECTOR)
            or actor.has_role(Role.AUDITOR)
        ):
            return
        if actor.has_role(Role.REVIEWER) and any(
            r.reviewer_id == actor.user_id
            for r in self.repo.list_requests_by_package(package_id)
        ):
            return
        raise PermissionDeniedError("不能查看该评审包的质量检查记录")

    @staticmethod
    def _normalize_findings(raw: list[dict]) -> list[dict]:
        if not isinstance(raw, list):
            raise ValidationError("findings 必须是数组")
        normalized: list[dict] = []
        for item in raw:
            if not isinstance(item, dict):
                raise ValidationError("每条异常必须是对象")
            severity = item.get("severity")
            category = str(item.get("category") or "").strip()
            detail = str(item.get("detail") or "").strip()
            if severity not in _SEVERITIES:
                raise ValidationError(
                    "异常等级必须是 warning 或 blocking",
                    details={"severity": severity},
                )
            if not category or not detail:
                raise ValidationError("异常类别与内容不能为空")
            normalized.append(
                {
                    "severity": severity,
                    "category": category,
                    "detail": detail,
                    "material_id": item.get("material_id"),
                    "version_id": item.get("version_id"),
                }
            )
        return normalized

    def _validate_finding_target(
        self,
        package_id: str,
        item: dict,
        entries_by_version: dict,
    ) -> None:
        version_id = item.get("version_id")
        material_id = item.get("material_id")
        if version_id is None and material_id is None:
            return  # 针对整包的异常
        if version_id is not None:
            entry = entries_by_version.get(version_id)
            if entry is None:
                raise ValidationError(
                    "异常定位的版本不在该评审包封存清单中",
                    details={"package_id": package_id, "version_id": version_id},
                )
            if material_id is not None and entry.material_id != material_id:
                raise ValidationError(
                    "异常的 material_id 与版本不匹配",
                    details={"version_id": version_id, "material_id": material_id},
                )
            item["material_id"] = entry.material_id
        elif material_id is not None:
            material = self.repo.get_material(material_id)
            if material is None:
                raise ValidationError(
                    "异常定位的材料不存在", details={"material_id": material_id}
                )

    @staticmethod
    def _result_for(findings: list[QualityFinding]) -> str:
        severities = {f.severity for f in findings}
        if QualitySeverity.BLOCKING.value in severities:
            return QualityCheckResult.BLOCKED.value
        if QualitySeverity.WARNING.value in severities:
            return QualityCheckResult.WARNING.value
        return QualityCheckResult.PASS.value

    @staticmethod
    def _inspection_dict(i: QualityInspection) -> dict:
        return {
            "inspection_id": i.inspection_id,
            "package_id": i.package_id,
            "institution_id": i.institution_id,
            "result": i.result,
            "checked_by": i.checked_by,
            "checked_at": i.checked_at,
            "note": i.note,
            "fingerprint": i.fingerprint,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity,
                    "category": f.category,
                    "detail": f.detail,
                    "material_id": f.material_id,
                    "version_id": f.version_id,
                    "created_by": f.created_by,
                    "created_at": f.created_at,
                }
                for f in i.findings
            ],
        }


def latest_inspection_blocks(repo, package_id: str) -> QualityInspection | None:
    """评审签发前调用：返回阻断中的最近一次检查，否则 None。

    只看【最近一次】检查结论——修复后的 pass 检查即解除阻断，
    历史 blocked 记录保留但不再阻止流程。
    """
    inspections = repo.list_inspections(package_id)
    if not inspections:
        return None
    latest = inspections[-1]
    return latest if latest.result == QualityCheckResult.BLOCKED.value else None
