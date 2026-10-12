"""Impact gate — 돌돌이의 판정 철학을 강제하는 관문.

탐지기들이 낸 Finding을 모은 뒤, 계약을 '다시 한 번' 검증한다:
  precondition 과 enabling_condition 이 둘 다 비어있지 않아야 통과.
단독 hygiene 지적(보강 조건 없음)은 여기서 전부 떨어진다.

탐지기가 스스로 계약을 지키는 게 1차 방어선이고, 이 게이트는 2차 방어선이다.
(새 탐지기를 추가할 때 실수로 단독 지적을 흘리는 걸 막는다.)
"""
from __future__ import annotations

from .models import Finding, HttpRecord
from .vectors import DEFAULT_DETECTORS
from .vectors.base import VectorDetector

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def passes_gate(f: Finding) -> bool:
    """단독 hygiene인가? precondition만 있고 enabling_condition이 없으면 탈락."""
    return bool(f.precondition.strip()) and bool(f.enabling_condition.strip())


def run_detectors(
    records: list[HttpRecord],
    detectors: list[VectorDetector] | None = None,
) -> list[Finding]:
    detectors = detectors if detectors is not None else DEFAULT_DETECTORS
    collected: list[Finding] = []
    for det in detectors:
        for f in det.detect(records):
            if passes_gate(f):
                collected.append(f)
            # else: 단독 지적 → 조용히 폐기(출력도 안 함)
    collected.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
    return collected
