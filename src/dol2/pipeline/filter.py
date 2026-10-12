"""1단계 — 노이즈 제거 + 스코프.

볼 가치 없는 트래픽을 떨군다. 여기서 틀리면(= 흥미로운 요청을 노이즈로 버리면)
뒤 단계가 아무리 좋아도 못 잡으니, '애매하면 남긴다'를 기본값으로 한다.
"""
from __future__ import annotations

import re

from ..config import ScopeConfig
from ..models import HttpRecord

# 정적 자원 확장자(이것만으로 버리진 않고, 상태변경/인증재료 없을 때만 버림)
_STATIC_EXT = re.compile(
    r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|avif)(?:\?|$)",
    re.IGNORECASE,
)

# 애널리틱스/텔레메트리 성격 호스트·경로(대표 예시만. 실전에선 보강)
_TELEMETRY = re.compile(
    r"(google-analytics|googletagmanager|doubleclick|/telemetry|/beacon|/collect\b)",
    re.IGNORECASE,
)


def _in_scope(host: str, scope: ScopeConfig) -> bool:
    if any(re.search(p, host) for p in scope.host_deny):
        return False
    if scope.host_allow:  # allow가 지정되면 화이트리스트로 동작
        return any(re.search(p, host) for p in scope.host_allow)
    return True  # allow 비어 있으면 전부 허용(실습용). 실전은 반드시 채울 것.


def is_noise(rec: HttpRecord) -> bool:
    """버려도 되는 노이즈인가."""
    req = rec.request

    # OPTIONS 프리플라이트
    if req.method == "OPTIONS":
        return True

    # 인증 재료가 실려 있으면 정적 자원이라도 일단 남긴다(세션 고정/탈취 맥락일 수 있음)
    has_auth_material = bool(
        req.headers.get("authorization") or req.headers.get("cookie")
    )

    if _STATIC_EXT.search(req.target) and not has_auth_material:
        return True

    if _TELEMETRY.search(req.host + req.target):
        return True

    return False


def coarse_filter(
    records: list[HttpRecord], scope: ScopeConfig | None = None
) -> list[HttpRecord]:
    """스코프 안 + 노이즈 아님만 통과."""
    scope = scope or ScopeConfig()
    out: list[HttpRecord] = []
    for rec in records:
        if not _in_scope(rec.request.host, scope):
            continue
        if is_noise(rec):
            continue
        out.append(rec)
    return out
