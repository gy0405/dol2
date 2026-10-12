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

import re
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
    "SF": GuideItem("SF", "서버사이트 요청 위조(SSRF)", "상", 719),
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


# --------------------------------------------------------------------------- #
# 상세 리포트용 보강 데이터: 조치 권고 / 참고 링크 / 재현 PoC
# (가이드는 '무엇을 점검하라'까지만 준다. 아래는 점검자가 바로 쓰도록
#  '어떻게 재현·확인하고 무엇을 고치는가'를 덧붙인 것 — 모두 참고용.)
# --------------------------------------------------------------------------- #

# 가이드 웹 항목 코드 → 조치 권고(요약).
REMEDIATION_BY_CODE: dict[str, str] = {
    "IN": "서버 측에서 매 요청마다 '요청 주체 == 객체 소유자/권한'을 검증(거부 기본값). "
          "순차·추측 가능한 식별자 대신 소유권 검사와 무작위 식별자를 사용.",
    "CF": "상태변경 요청에 CSRF 토큰(동기화 토큰 또는 double-submit) 검증을 강제하고, "
          "세션 쿠키에 SameSite=Lax/Strict 지정. 쿠키 인증만으로 상태변경 금지.",
    "XS": "컨텍스트별 출력 인코딩 + 입력 검증 + CSP(script-src 제한). 세션 쿠키는 HttpOnly.",
    "IS": "로그인 시 세션 식별자 재발급, 적절한 만료·로그아웃 무효화, 쿠키에 Secure·HttpOnly·SameSite.",
    "SN": "전 구간 HTTPS 강제 + HSTS 적용. 평문(HTTP) 접근은 HTTPS로 리다이렉트하거나 차단.",
    "CC": "민감 쿠키는 서버가 서명/암호화하여 변조를 검증하고, 신뢰 경계 밖의 값은 신뢰하지 않음.",
}

# 가이드에 전용 항목이 없는 벡터의 조치 권고(벡터 키로 보강).
REMEDIATION_BY_VECTOR: dict[str, str] = {
    "header-clickjacking-chain":
        "응답에 X-Frame-Options: DENY(또는 SAMEORIGIN) 또는 "
        "CSP frame-ancestors 'none'/'self' 를 설정해 iframe 삽입을 차단.",
}

# 벡터 → 참고 링크(OWASP 등). CWE 링크는 cve_hint에서 자동 생성.
VECTOR_REFS: dict[str, list[str]] = {
    "horizontal-authz": [
        "OWASP WSTG — Testing for IDOR: "
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
        "05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        "OWASP API Security Top 10 — API1:2023 BOLA: "
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ],
    "cookie-samesite-csrf-chain": [
        "OWASP CSRF Prevention Cheat Sheet: "
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    "header-clickjacking-chain": [
        "OWASP Clickjacking Defense Cheat Sheet: "
        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    ],
    "reflected-xss": [
        "OWASP XSS Prevention Cheat Sheet: "
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    "header-csp-xss-chain": [
        "OWASP XSS Prevention Cheat Sheet: "
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    "cookie-httponly-xss-chain": [
        "OWASP XSS Prevention Cheat Sheet: "
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    "cookie-secure-chain": [
        "OWASP Transport Layer Security Cheat Sheet: "
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
    "header-hsts-chain": [
        "OWASP HTTP Strict Transport Security Cheat Sheet: "
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    ],
}

_CWE_RE = re.compile(r"CWE-(\d+)")


def _cwe_url(cve_hint: str) -> str:
    """cve_hint 문자열에서 CWE 번호를 뽑아 MITRE 정의 URL로."""
    m = _CWE_RE.search(cve_hint or "")
    return (
        "https://cwe.mitre.org/data/definitions/%s.html" % m.group(1) if m else ""
    )


def _remediation_for(f: Finding) -> str:
    for g in guide_items_for(f.vector):
        if g.code in REMEDIATION_BY_CODE:
            return REMEDIATION_BY_CODE[g.code]
    return REMEDIATION_BY_VECTOR.get(f.vector, "")


def _refs_for(f: Finding) -> list[str]:
    refs: list[str] = []
    url = _cwe_url(f.cve_hint)
    if url:
        refs.append("%s — %s" % (f.cve_hint, url))
    refs.extend(VECTOR_REFS.get(f.vector, []))
    return refs


def _poc_block(f: Finding) -> list[str]:
    """벡터별 '구체 재현/검증' 블록. 관찰된 증거로 실제 요청 예시를 만든다.

    주의: 아래 요청은 사람이 '인가된 대상'에만 직접 실행해야 한다. 돌돌이는
    자동으로 보내지 않는다. <...> 는 점검자가 채운다.
    """
    lines: list[str] = []
    ev = f.evidence or []
    # 증거에서 신원/대상 수집
    idents, targets = [], []
    for e in ev:
        if e.identity_label and e.identity_label not in idents:
            idents.append(e.identity_label)
        if e.actual_target and e.actual_target not in targets:
            targets.append(e.actual_target)

    if f.vector == "horizontal-authz":
        a = idents[0] if idents else "<신원A>"
        tgt = targets[0] if targets else f.endpoint_template.split(" ", 1)[-1]
        idx = next((e.history_index for e in ev if e.history_index is not None), "?")
        kind = "Authorization: Bearer <A_TOKEN>" if a.startswith("bearer") \
            else "Cookie: token=<A_TOKEN>"
        lines += [
            "        # 1) 신원 A(%s)의 세션/토큰을 준비" % a,
            "        # 2) A의 자격으로 '다른 소유자' 객체를 요청:",
            "        curl -i 'http://<대상>%s' -H '%s'" % (tgt, kind),
            "        # 기대(취약 시): 200 + 타인 객체 데이터가 그대로 반환 → 수평 권한 우회 성립",
            "        # Burp Repeater: history #%s 요청에서 인증 헤더만 A로 교체해 재전송" % idx,
            "        # dol2 능동검증: send_http1_request 로 위 요청을 재전송",
        ]
    elif f.vector == "cookie-samesite-csrf-chain":
        tgt = targets[0] if targets else f.endpoint_template.split(" ", 1)[-1]
        lines += [
            "        <!-- 피해자가 로그인된 상태로 아래 페이지를 열면 자동 전송 -->",
            "        <form action=\"http://<대상>%s\" method=\"POST\">" % tgt,
            "          <input type=\"hidden\" name=\"<param>\" value=\"<value>\">",
            "        </form>",
            "        <script>document.forms[0].submit()</script>",
            "        # CSRF 토큰 없이 2xx + 상태변경이 발생하면 취약",
        ]
    elif f.vector == "header-clickjacking-chain":
        lines += [
            "        <style>iframe{opacity:.0001;position:absolute;top:0;left:0;",
            "               width:100%;height:100%}</style>",
            "        <iframe src=\"http://<대상>/#/<민감기능>\"></iframe>",
            "        <button style=\"position:absolute;top:<y>;left:<x>\">여기 클릭</button>",
            "        # 투명 오버레이 위 버튼 클릭이 iframe 내부 민감 동작으로 전달되면 취약",
        ]
    elif f.vector in ("reflected-xss", "header-csp-xss-chain", "cookie-httponly-xss-chain"):
        tgt = targets[0] if targets else f.endpoint_template.split(" ", 1)[-1]
        lines += [
            "        # 입력 지점에 반사 테스트 페이로드를 넣고 응답에 '그대로' 박히는지 확인:",
            "        curl -i 'http://<대상>%s' --data-urlencode 'q=<svg/onload=alert(1)>'" % tgt,
            "        # 응답 본문에 인코딩 없이 그대로 나오면 반사형 XSS 성립",
        ]
    else:
        lines.append("        # (수동) %s" % f.poc_sketch)
    return lines


def _impact_for(f: Finding) -> str:
    """관찰 근거로부터 '성립 시 예상 영향'을 한 줄로."""
    return {
        "horizontal-authz": "타 사용자 소유 데이터 열람/조작(수평 권한 우회), 대량 추출 가능성",
        "cookie-samesite-csrf-chain": "피해자 권한으로 의도치 않은 상태변경 실행",
        "header-clickjacking-chain": "피해자의 클릭을 가로채 민감 동작을 유도",
        "reflected-xss": "피해자 브라우저에서 임의 스크립트 실행 → 세션/계정 탈취",
        "cookie-httponly-xss-chain": "XSS로 세션 쿠키 탈취 → 계정 탈취",
        "cookie-secure-chain": "평문 구간에서 세션 쿠키 노출 → 세션 탈취(MITM)",
    }.get(f.vector, f.attack_class)


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
        f"    · 예상 영향: {_impact_for(f)}",
        f"    · 점검 개요: {f.poc_sketch}",
        "    · 재현/검증 (인가된 대상에만 직접 실행 — 돌돌이는 자동 전송하지 않음):",
    ]
    lines.extend(_poc_block(f))

    remediation = _remediation_for(f)
    if remediation:
        lines.append(f"    · 조치 권고: {remediation}")

    refs = _refs_for(f)
    if refs:
        lines.append("    · 참고 링크:")
        lines.extend(f"        - {r}" for r in refs)

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
