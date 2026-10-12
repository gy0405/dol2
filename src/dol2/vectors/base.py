"""벡터 탐지기 인터페이스."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Finding, HttpRecord


@runtime_checkable
class VectorDetector(Protocol):
    """하나의 취약점 벡터를 탐지하는 단위.

    계약:
      * 입력은 정규화·점수화까지 끝난 레코드 전체(교차분석 가능하도록).
      * 출력 Finding은 반드시 precondition + enabling_condition 둘 다 채운다.
        둘 중 하나라도 비면(= 단독 hygiene 지적) 반환하지 않는다.
    """

    name: str

    def detect(self, records: list[HttpRecord]) -> list[Finding]:
        ...
