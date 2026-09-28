"""领域枚举：角色、材料类型、敏感度、状态机取值。"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    INSTITUTION_ADMIN = "institution_admin"
    INSTITUTION_SUBMITTER = "institution_submitter"
    REVIEWER = "reviewer"
    QUALITY_AUTHORITY = "quality_authority"
    QUALITY_INSPECTOR = "quality_inspector"  # 质检员：归档内容质量异常
    AUDITOR = "auditor"


class MaterialKind(str, Enum):
    SYLLABUS = "syllabus"               # 课程大纲
    FACULTY = "faculty"                 # 师资材料
    ASSESSMENT = "assessment"           # 考核材料
    ENTERPRISE_FEEDBACK = "enterprise_feedback"  # 企业反馈


class Sensitivity(str, Enum):
    NORMAL = "normal"
    SENSITIVE = "sensitive"  # 敏感企业反馈等，按机构与角色最小披露


class PackageStatus(str, Enum):
    DRAFT = "draft"                # 组包中，可追加材料
    SEALED = "sealed"              # 已封存，清单指纹固定
    UNDER_REVIEW = "under_review"  # 已分配评审
    DECIDED = "decided"            # 结论已签发，不可再改
    # 后补材料永远进入新的复审包，旧包不复活


class RequestStatus(str, Enum):
    PENDING = "pending"      # 已分配，等待评审人响应
    ACCEPTED = "accepted"
    DECLINED = "declined"
    COMPLETED = "completed"  # 评审人已提交结论
    CANCELLED = "cancelled"  # 被重新分配


class Verdict(str, Enum):
    APPROVE = "approve"
    OBJECT = "object"  # 有异议


class Decision(str, Enum):
    APPROVED = "approved"
    NEEDS_REVISION = "needs_revision"
    REJECTED = "rejected"


class QualitySeverity(str, Enum):
    """内容质量异常等级：警告不阻断流程，阻断要求修复后重新检查。"""

    WARNING = "warning"    # 警告：记录但不阻断
    BLOCKING = "blocking"  # 阻断：必须修复并重新检查


class QualityCheckResult(str, Enum):
    """单次质量检查结论。"""

    PASS = "pass"        # 未发现异常
    WARNING = "warning"  # 存在警告级异常，不阻断
    BLOCKED = "blocked"  # 存在阻断级异常
