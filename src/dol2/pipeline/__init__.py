"""돌돌이 데이터 파이프라인.

    raw 히스토리
        │  filter   (노이즈 제거 + 스코프)
        ▼
    관심 요청
        │  normalize (엔드포인트 템플릿화 + 신원 라벨링)
        ▼
    정규화 레코드
        │  score    (인증·인가 관점 관련도 점수 + 신호 태깅)
        ▼
    점수화 레코드  ──▶ gate / vectors 로 전달
"""
from . import evidence, filter, normalize, score  # noqa: F401
