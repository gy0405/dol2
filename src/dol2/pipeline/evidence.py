"""4단계 — 증거 레코드 생성.

원본 패킷 전체를 LLM/리포트에 던지지 않는다. 사람이 Burp에서 바로 되짚을 수
있는 '압축 증거'만 만든다. (원본은 Burp 히스토리에 그대로 있으므로 index로 가리킴)
"""
from __future__ import annotations

from ..models import Evidence, HttpRecord


def to_evidence(rec: HttpRecord, history_index: int | None = None) -> Evidence:
    return Evidence(
        method=rec.request.method,
        endpoint_template=rec.endpoint_template,
        actual_target=rec.request.target,
        identity_label=rec.identity.label if rec.identity else "unknown",
        status=rec.response.status if (rec.response and rec.response.present) else None,
        note=";".join(rec.signals),
        history_index=history_index,
    )
