"""2단계 — 엔드포인트 정규화 + 신원 라벨링.

돌돌이의 핵심 데이터 모델. 인증·인가 취약점은 '같은 엔드포인트를 서로 다른
신원으로 비교'해야 보이므로, 두 축을 안정적인 키로 만든다.

* 엔드포인트 템플릿: /api/users/1023 -> GET /api/users/{id}
* 신원 라벨: 쿠키/Authorization/JWT sub 등에서 *추정*
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from ..models import HttpRecord, Identity, ParsedRequest

# 경로 세그먼트 중 '변수'로 볼 패턴 → {id} 치환
_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEXLONG = re.compile(r"^[0-9a-fA-F]{16,}$")
_B64ISH = re.compile(r"^[A-Za-z0-9_\-]{20,}={0,2}$")


def _is_variable_segment(seg: str) -> bool:
    return bool(
        _NUMERIC.match(seg)
        or _UUID.match(seg)
        or _HEXLONG.match(seg)
        or _B64ISH.match(seg)
    )


def endpoint_template(req: ParsedRequest) -> str:
    """메서드 + 변수 치환된 경로."""
    segs = req.path.split("/")
    norm = [("{id}" if _is_variable_segment(s) else s) for s in segs]
    return f"{req.method} {'/'.join(norm)}"


# --------------------------------------------------------------------------- #
# 신원 라벨링 — 어디까지나 '추정'. confidence와 source를 같이 노출한다.
# --------------------------------------------------------------------------- #
def _decode_jwt_sub(token: str) -> dict[str, str] | None:
    """JWT payload를 *검증 없이* 디코드해 참고용 클레임만 읽는다."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return {k: str(v) for k, v in payload.items() if k in ("sub", "user", "uid", "role", "scope")}


def infer_identity(req: ParsedRequest) -> Identity:
    auth = req.headers.get("authorization", "")
    cookie = req.headers.get("cookie", "")

    # 1) Bearer JWT가 있으면 sub 기준(가장 신뢰도 높음)
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        claims = _decode_jwt_sub(token)
        if claims and "sub" in claims:
            return Identity(
                label=f"jwt-sub:{claims['sub']}",
                source="jwt",
                confidence=0.8,
                claims=claims,
            )
        # JWT 아니거나 sub 없음 → 토큰 해시로 그룹
        return Identity(
            label=f"bearer:{_short_hash(token)}", source="authorization", confidence=0.6
        )

    if auth:
        return Identity(
            label=f"auth:{_short_hash(auth)}", source="authorization", confidence=0.6
        )

    # 2) 세션 쿠키로 그룹(쿠키 전체 해시 — 세션 식별자가 바뀌면 다른 주체로 추정)
    if cookie:
        return Identity(
            label=f"cookie:{_short_hash(cookie)}", source="cookie", confidence=0.4
        )

    # 3) 아무 신원 재료 없음
    return Identity(label="anon", source="none", confidence=0.3)


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:10]


def normalize(records: list[HttpRecord]) -> list[HttpRecord]:
    for rec in records:
        rec.endpoint_template = endpoint_template(rec.request)
        rec.identity = infer_identity(rec.request)
    return records
