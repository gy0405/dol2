"""취약점 벡터 탐지기들.

각 탐지기는 `VectorDetector` 인터페이스를 구현하고, 반드시 impact gate를
통과하는 Finding만 생성한다(= precondition + enabling_condition 둘 다 관찰).
"""
from .base import VectorDetector
from .chains import CookieFlagChain, SecurityHeaderChain
from .idor import HorizontalAuthzDetector
from .xss import ReflectedXssDetector

# 기본 탐지기 레지스트리. 여기 추가하면 서버가 자동으로 돌린다.
DEFAULT_DETECTORS: list[VectorDetector] = [
    HorizontalAuthzDetector(),
    ReflectedXssDetector(),
    CookieFlagChain(),
    SecurityHeaderChain(),
]

__all__ = [
    "VectorDetector",
    "CookieFlagChain",
    "SecurityHeaderChain",
    "HorizontalAuthzDetector",
    "ReflectedXssDetector",
    "DEFAULT_DETECTORS",
]
