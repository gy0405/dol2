"""3단계 — 관련도 점수 + 신호 태깅.

'인증·인가 관점에서 왜 흥미로운가'를 신호로 붙이고 점수를 매긴다.
점수는 우선순위용일 뿐, 취약 판정이 아니다(판정은 gate/vectors가 함).
"""
from __future__ import annotations

import re

from ..models import HttpRecord
from .normalize import auth_cookie_fingerprint

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

_ADMIN_PATH = re.compile(r"/(admin|manage|internal|console|dashboard|sys|root)\b", re.IGNORECASE)
_ROLE_PARAM = re.compile(r"\b(role|is[_-]?admin|privilege|grant|scope)\b", re.IGNORECASE)
_AUTH_FLOW = re.compile(
    r"/(login|logout|signin|signout|auth|oauth|token|refresh|password|reset|mfa|otp|verify)\b",
    re.IGNORECASE,
)
_OBJECT_REF = re.compile(r"\b(id|uid|user|account|order|doc|file|record|no)=", re.IGNORECASE)

# 신호 → 가중치
_WEIGHTS = {
    "auth-material": 1.0,     # 인증 재료가 실려 있음
    "object-ref": 1.5,        # IDOR 표면
    "role-indicator": 1.5,    # 권한/역할 지표
    "state-change": 1.0,      # 상태 변경 동작
    "auth-flow": 1.2,         # 인증 흐름 엔드포인트
    "authz-divergent": 2.0,   # 같은 엔드포인트가 신원별로 다른 상태코드 (교차분석)
}


def _signals_for(rec: HttpRecord) -> list[str]:
    req = rec.request
    sig: list[str] = []

    if req.headers.get("authorization") or auth_cookie_fingerprint(req.headers.get("cookie", "")):
        sig.append("auth-material")

    # 객체 참조: 경로에 {id}가 생겼거나 쿼리/본문에 id류 파라미터
    if "{id}" in rec.endpoint_template or _OBJECT_REF.search(req.query + "&" + req.body):
        sig.append("object-ref")

    if _ADMIN_PATH.search(req.path) or _ROLE_PARAM.search(req.query + "&" + req.body):
        sig.append("role-indicator")

    if req.method in _STATE_CHANGING:
        sig.append("state-change")

    if _AUTH_FLOW.search(req.path):
        sig.append("auth-flow")

    return sig


def score(records: list[HttpRecord]) -> list[HttpRecord]:
    """개별 요청 점수. (교차분석 신호 authz-divergent는 cross_score에서 추가.)"""
    for rec in records:
        rec.signals = _signals_for(rec)
        rec.relevance = sum(_WEIGHTS.get(s, 0.0) for s in rec.signals)
    return cross_score(records)


def cross_score(records: list[HttpRecord]) -> list[HttpRecord]:
    """교차 분석 — 같은 엔드포인트 템플릿을 여러 신원이 접근했는데 상태코드가
    갈리면(예: 한 신원은 200, 다른 신원은 403) authz 경계가 걸려 있다는 신호다.
    이 묶음은 IDOR/권한우회 분석의 1순위 후보가 된다.
    """
    by_template: dict[str, list[HttpRecord]] = {}
    for rec in records:
        by_template.setdefault(rec.endpoint_template, []).append(rec)

    for group in by_template.values():
        identities = {r.identity.label for r in group if r.identity}
        statuses = {r.response.status for r in group if r.response and r.response.present}
        if len(identities) > 1 and len(statuses) > 1:
            for rec in group:
                if "authz-divergent" not in rec.signals:
                    rec.signals.append("authz-divergent")
                    rec.relevance += _WEIGHTS["authz-divergent"]
    return records


def group_by_template(records: list[HttpRecord]) -> dict[str, list[HttpRecord]]:
    out: dict[str, list[HttpRecord]] = {}
    for rec in records:
        out.setdefault(rec.endpoint_template, []).append(rec)
    return out
