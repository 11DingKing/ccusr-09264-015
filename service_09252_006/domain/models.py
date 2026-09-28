"""领域实体（贫血数据载体，业务规则在领域服务/应用服务中）。

时间一律以带时区的 UTC ISO-8601 字符串存储；截止时间同时保存原始
IANA 时区用于展示，比较时统一换化为 UTC 时刻，从而正确处理跨时区截止。
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Optional

from .enums import (
    Decision,
    MaterialKind,
    PackageStatus,
    RequestStatus,
    Role,
    Sensitivity,
    Verdict,
)


@dataclass
class User:
    user_id: str
    institution_id: Optional[str]  # 机构用户非空；权威机构/审计可为空
    roles: tuple[str, ...]
    display_name: str = ""

    def has_role(self, role: Role | str) -> bool:
        wanted = role.value if isinstance(role, Role) else role
        return wanted in self.roles


@dataclass
class Material:
    """逻辑材料（课程大纲、师资、考核、企业反馈中的某一份）。"""

    material_id: str
    institution_id: str
    kind: str                      # MaterialKind
    sensitivity: str               # Sensitivity
    title: str
    current_version_id: Optional[str]
    withdrawn: bool
    created_at: str


@dataclass
class MaterialVersion:
    """材料的一次不可变版本。字节内容按 sha256 内容寻址、去重存储。"""

    version_id: str
    material_id: str
    institution_id: str
    sha256: str
    size: int
    media_type: str
    version_no: int
    supersedes_version_id: Optional[str]
    created_by: str
    created_at: str
    withdrawn: bool                # 该版本是否已撤回


@dataclass
class PackageEntry:
    """评审包对材料【具体版本】的固定引用。"""

    entry_id: str
    package_id: str
    material_id: str
    version_id: str
    sha256: str
    kind: str
    sensitivity: str
    added_at: str


@dataclass
class ReviewPackage:
    package_id: str
    institution_id: str
    title: str
    status: str                    # PackageStatus
    created_by: str
    created_at: str
    sealed_at: Optional[str]
    manifest_fingerprint: Optional[str]
    decided_at: Optional[str]
    decision: Optional[str]        # Decision
    decision_note: Optional[str]
    review_fingerprint: Optional[str]
    supersedes_package_id: Optional[str]  # 后补材料触发的复审包指向前序包
    entries: list[PackageEntry] = field(default_factory=list)

    def is_mutable(self) -> bool:
        return self.status == PackageStatus.DRAFT.value


@dataclass
class ReviewRequest:
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    status: str                    # RequestStatus
    assigned_by: str
    assigned_at: str
    responded_at: Optional[str]
    completed_at: Optional[str]
    verdict: Optional[str]         # Verdict
    comment: Optional[str]
    deadline_at_utc: Optional[str]  # 截止时刻（UTC）
    deadline_timezone: Optional[str]  # 原始 IANA 时区，仅展示用


@dataclass
class Objection:
    objection_id: str
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    category: str
    detail: str
    created_at: str


@dataclass
class Blob:
    sha256: str
    data: bytes
    media_type: str
    created_at: str


@dataclass
class AuditEntry:
    audit_id: str
    package_id: Optional[str]
    institution_id: Optional[str]
    actor_id: str
    action: str
    at: str
    detail: dict = field(default_factory=dict)


@dataclass
class QualityAnomaly:
    """一次内容质量异常归档。

    异常是归档事件：一经记录即不可变，修复不会更新或删除它。修复后
    重新检查会产生新的 QualityCheckRun，原异常永远保留在历史中。
    """

    anomaly_id: str
    subject_type: str              # material / version / package
    subject_id: str
    check_code: str                # 稳定的检查项代码，如 blank_title
    level: str                     # QualityLevel: warning / blocking
    detail: str
    evidence_json: str             # 归档时快照（sha256、版本号等）
    archivist_id: str              # 归档质检员
    archived_at: str
    fingerprint: str = ""          # 归档内容指纹（含 id，全局唯一）
    # 注：异常行一经写入永不更新；“是否已修复”由后续检查运行的关联
    # 记录派生（最近一次检查未再发现即视为已修复），不回写本记录。


@dataclass
class QualityCheckRun:
    """一次质量检查的不可变结果。

    每次执行（含 Python 重跑）都插入新记录；结果永不 UPDATE/覆盖。
    与归档异常的关联是“当次检查仍发现该异常”，而不是异常的生命周期。
    """

    run_id: str
    subject_type: str
    subject_id: str
    subject_digest: str            # 被检对象当时的内容指纹
    outcome: str                   # CheckOutcome: ok / warning / blocking
    warning_count: int
    blocking_count: int
    checked_by: str
    checked_at: str
    note: str = ""
    anomaly_ids: tuple[str, ...] = ()  # 本次发现/关联的既有异常
    fingerprint: str = ""


def asdict(obj) -> dict:
    return dataclasses.asdict(obj)
