"""주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드(2026) 매핑.

돌돌이는 웹 트래픽만 보므로, 가이드의 'X. Web Application(웹)' 장(21개 항목)만
대상으로 한다. 각 Finding을 해당 웹 점검 항목 코드로 매핑하고, 가이드 양식의
보고서 문구로 렌더링한다.

주의(정직성):
  - 이 표는 가이드 '웹' 장의 항목 코드·명·중요도·페이지만 담는다(모두 '상').
  - 서버/OS/DBMS/네트워크 등 가이드의 나머지 장은 웹 트래픽으로 관찰 불가 →
    돌돌이 범위 밖. "가이드 전체 자동 점검"이 아니다.
  - 매핑이 없는 벡터(예: Clickjacking)는 '해당 항목 없음'으로 솔직히 표기한다.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True)
class GuideItem:
    code: str
    name: str
    severity: str   # 가이드 '항목 중요도'
    page: int        # 상세가이드 페이지


# 가이드 'X. Web Application(웹)' 21개 항목 (p.678 항목표 + 목차 기준)
WEB_ITEMS: dict[str, GuideItem] = {
    "CI": GuideItem("CI", "코드 인젝션(Code Injection)", "상", 679),
    "SI": GuideItem("SI", "SQL 인젝션(SQL Injection)", "상", 693),
    "DI": GuideItem("DI", "디렉터리 인덱싱", "상", 700),
    "EP": GuideItem("EP", "에러 페이지 적용 미흡", "상", 703),
    "IL": GuideItem("IL", "정보 누출", "상", 708),
    "XS": GuideItem("XS", "크로스사이트 스크립트(XSS)", "상", 711),
    "CF": GuideItem("CF", "크로스사이트 요청 위조(CSRF)", "상", 715),
    "SF": GuideItem("SF", "서버사이드 요청 위조(SSRF)", "상", 719),
    "BF": GuideItem("BF", "약한 비밀번호 정책", "상", 726),
    "IA": GuideItem("IA", "불충분한 인증 절차", "상", 729),
    "IN": GuideItem("IN", "불충분한 권한 검증", "상", 733),
    "PR": GuideItem("PR", "취약한 비밀번호 복구 절차", "상", 739),
    "PV": GuideItem("PV", "프로세스 검증 누락", "상", 739),
    "FU": GuideItem("FU", "악성 파일 업로드", "상", 744),
    "FD": GuideItem("FD", "파일 다운로드", "상", 753),
    "IS": GuideItem("IS", "불충분한 세션 관리", "상", 759),
    "SN": GuideItem("SN", "데이터 평문 전송", "상", 766),
    "CC": GuideItem("CC", "쿠키 변조", "상", 769),
    "AE": GuideItem("AE", "관리자 페이지 노출", "상", 775),
    "AU": GuideItem("AU", "자동화 공격", "상", 777),
    "WM": GuideItem("WM", "불필요한 Method 악용", "상", 779),
}

# 돌돌이 벡터 → 가이드 항목 코드(들). 첫 코드가 주 매핑.
VECTOR_TO_CODES: dict[str, list[str]] = {
    "reflected-xss": ["XS"],
    "header-csp-xss-chain": ["XS"],
    "horizontal-authz": ["IN"],
    "cookie-httponly-xss-chain": ["IS", "XS"],
    "cookie-samesite-csrf-chain": ["CF"],
    "cookie-secure-chain": ["SN", "IS"],
    "header-hsts-chain": ["SN"],
    # 가이드에 전용 항목이 없는 벡터는 매핑하지 않음(아래에서 '해당 없음' 처리)
    # "header-clickjacking-chain": [],
}


def guide_items_for(vector: str) -> list[GuideItem]:
    return [WEB_ITEMS[c] for c in VECTOR_TO_CODES.get(vector, []) if c in WEB_ITEMS]


def render_finding(f: Finding, index: int) -> str:
    """Finding 하나를 가이드 양식 문구로.

    형태: "[코드] 항목명 취약점이 <근거> 때문에 의심되니, <PoC/CVE>로 점검하라".
    """
    items = guide_items_for(f.vector)
    if items:
        head = " / ".join(f"[{g.code}] {g.name} (가이드 p.{g.page})" for g in items)
    else:
        head = f"(가이드 웹 항목에 직접 대응 없음 — 참고: {f.attack_class})"

    pkts = ", ".join(
        f"#{e.history_index}" for e in f.evidence if e.history_index is not None
    ) or "원본 참조"

    lines = [
        f"{index}. {head}  — 의심 (중요도: {f.severity})",
        f"    · 의심 근거: {f.precondition} + {f.enabling_condition}",
        f"    · 공격 유형: {f.attack_class}",
        f"    · 점검(PoC): {f.poc_sketch}",
    ]
    if f.cve_hint:
        lines.append(f"    · 참고: {f.cve_hint}")
    lines.append(f"    · 원본 패킷: {pkts}  (엔드포인트 {f.endpoint_template})")
    lines.append("    · ※ 돌돌이는 자동 점검하지 않음 — 위 PoC로 점검자가 직접 확인")
    return "\n".join(lines)


def render_report(findings: list[Finding]) -> str:
    """전체 findings를 가이드 양식 보고서(결과지) 텍스트로. (PDF 아님, 텍스트)"""
    if not findings:
        return (
            "주요정보통신기반시설 가이드(웹) 기준 — 트래픽에서 체인으로 성립하는 "
            "의심 항목이 발견되지 않음. (설정 부재 단독은 보고하지 않음)"
        )
    header = (
        "주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드(2026) — "
        "Web Application(웹) 기준 의심 점검 항목\n"
        "아래는 '판정'이 아니라 점검자가 확인해야 할 우선순위 후보임.\n"
    )
    body = "\n\n".join(render_finding(f, i + 1) for i, f in enumerate(findings))
    return header + "\n" + body
