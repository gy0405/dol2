"""hygiene → 익스플로잇 체인 탐지기.

핵심 원칙(사용자 확정):
  설정 옵션/헤더의 '부재'는 단독으로는 절대 올리지 않는다.
  트래픽에서 관찰된 보강 조건과 맞물려 PoC/CVE 체인이 성립할 때만,
  "이게 빠져서 → 이런 공격이 가능하다"는 형태로만 인정한다.

따라서 각 탐지기는 두 가지가 '모두 관찰'되어야 Finding을 만든다:
  precondition      = 플래그/헤더 부재
  enabling_condition = 트래픽에서 실제로 본 보강 조건

여기 구현은 대표 체인의 뼈대다. 탐지 로직 자체는 보수적으로(오탐<미탐이 아니라,
단독 hygiene을 절대 안 올리는 방향으로) 더 정교화할 여지가 있다.
"""
from __future__ import annotations

import re

from ..models import Evidence, Finding, HttpRecord

_SET_COOKIE = "set-cookie"


def _session_set_cookies(records: list[HttpRecord]) -> list[tuple[int, HttpRecord, str]]:
    """응답에서 세션성 쿠키를 심는 Set-Cookie들을 모은다. (index, rec, cookie_line)"""
    out = []
    for i, rec in enumerate(records):
        if not (rec.response and rec.response.present):
            continue
        for k, v in rec.response.headers.items():
            if k == _SET_COOKIE:
                out.append((i, rec, v))
    return out


def _has_flag(cookie_line: str, flag: str) -> bool:
    return re.search(rf"(?i)\b{re.escape(flag)}\b", cookie_line) is not None


def _any_plaintext_http(records: list[HttpRecord]) -> HttpRecord | None:
    """평문 HTTP(비 TLS) 요청이 트래픽에 실제로 있었는지.

    Burp 히스토리 문자열만으로는 scheme가 100% 확실치 않다. 휴리스틱:
    Host는 있는데 보안 전송 흔적이 없고 포트가 80/8080 등으로 보이는 경우.
    (실전에서는 Burp 쪽 메타데이터로 교체 권장 — 지금은 보수적 placeholder)
    """
    for rec in records:
        host = rec.request.host
        if re.search(r":80\b|:8080\b", host):
            return rec
    return None


class CookieFlagChain:
    """세션 쿠키 플래그 부재 → 체인.

      * Secure 없음  + 평문 HTTP 관찰      → 세션 쿠키 평문 노출 → 세션 탈취
      * HttpOnly 없음 + XSS 표면 관찰(TODO) → document.cookie 탈취 → 계정 탈취
      * SameSite 없음 + 쿠키인증 상태변경 POST + CSRF 토큰 없음 → CSRF
    """

    name = "cookie-flag-chain"

    def detect(self, records: list[HttpRecord]) -> list[Finding]:
        findings: list[Finding] = []
        set_cookies = _session_set_cookies(records)
        if not set_cookies:
            return findings

        plaintext = _any_plaintext_http(records)

        for idx, rec, cookie_line in set_cookies:
            cookie_name = cookie_line.split("=", 1)[0].strip()
            ev = Evidence(
                method=rec.request.method,
                endpoint_template=rec.endpoint_template,
                actual_target=rec.request.target,
                identity_label=rec.identity.label if rec.identity else "unknown",
                status=rec.response.status if rec.response else None,
                note=f"Set-Cookie: {cookie_name}",
                history_index=idx,
            )

            # --- Secure 체인 ---
            if not _has_flag(cookie_line, "Secure") and plaintext is not None:
                findings.append(
                    Finding(
                        vector="cookie-secure-chain",
                        severity="high",
                        endpoint_template=rec.endpoint_template,
                        precondition=f"세션 쿠키 '{cookie_name}' 에 Secure 플래그 없음",
                        enabling_condition=f"평문 HTTP 트래픽 관찰됨 (host={plaintext.request.host})",
                        attack_class="세션 쿠키 평문 노출 → 세션 탈취(MITM)",
                        poc_sketch=(
                            "동일 네트워크/MITM 위치에서 평문 요청을 가로채 Set-Cookie/Cookie "
                            "값을 획득 → 해당 세션으로 인증된 요청 재현"
                        ),
                        cve_hint="CWE-614 (Sensitive Cookie Without 'Secure')",
                        evidence=[ev],
                    )
                )

            # --- SameSite + CSRF 체인 ---
            if not _has_flag(cookie_line, "SameSite"):
                csrf_target = self._cookie_auth_statechange_without_csrf(records)
                if csrf_target is not None:
                    ti, trec = csrf_target
                    findings.append(
                        Finding(
                            vector="cookie-samesite-csrf-chain",
                            severity="medium",
                            endpoint_template=trec.endpoint_template,
                            precondition=f"세션 쿠키 '{cookie_name}' 에 SameSite 지정 없음",
                            enabling_condition=(
                                f"쿠키 인증만으로 상태를 바꾸는 {trec.request.method} 요청 존재 "
                                f"({trec.endpoint_template}), CSRF 토큰 미관찰"
                            ),
                            attack_class="CSRF (Cross-Site Request Forgery)",
                            poc_sketch=(
                                "공격자 페이지에서 해당 엔드포인트로 자동 제출되는 폼/요청을 심어 "
                                "피해자 브라우저의 쿠키로 상태변경을 유발"
                            ),
                            cve_hint="CWE-352 (CSRF)",
                            evidence=[ev, _rec_evidence(trec, ti)],
                        )
                    )

            # --- HttpOnly 체인: XSS 표면 관찰이 선행 조건.
            #     XSS 탐지는 별도 벡터로 분리 예정이라 여기서는 체인만 열어 둠(TODO). ---

        return findings

    @staticmethod
    def _cookie_auth_statechange_without_csrf(
        records: list[HttpRecord],
    ) -> tuple[int, HttpRecord] | None:
        csrf_re = re.compile(r"(?i)csrf|xsrf|_token")
        for i, rec in enumerate(records):
            req = rec.request
            if req.method not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            if not req.headers.get("cookie"):
                continue
            if req.headers.get("authorization"):
                continue  # 토큰 인증이면 CSRF 전제(쿠키 자동전송)가 약함
            blob = req.target + "\n" + "\n".join(f"{k}:{v}" for k, v in req.headers.items()) + "\n" + req.body
            if csrf_re.search(blob):
                continue  # CSRF 토큰 흔적 있으면 제외
            return i, rec
        return None


class SecurityHeaderChain:
    """보안 헤더 부재 → 체인. (쿠키 플래그와 동일 게이트)

      * X-Frame-Options/CSP frame-ancestors 없음 + 민감 상태변경 동작 → Clickjacking
      * HSTS 없음 + 평문 HTTP 관찰 → SSL stripping
      * CSP 없음 + XSS 표면 관찰(TODO) → XSS 영향 확대
    """

    name = "security-header-chain"

    def detect(self, records: list[HttpRecord]) -> list[Finding]:
        findings: list[Finding] = []
        plaintext = _any_plaintext_http(records)

        for i, rec in enumerate(records):
            resp = rec.response
            if not (resp and resp.present):
                continue
            h = resp.headers

            # --- Clickjacking 체인 ---
            no_framebusting = ("x-frame-options" not in h) and (
                "frame-ancestors" not in h.get("content-security-policy", "").lower()
            )
            if no_framebusting and rec.request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                findings.append(
                    Finding(
                        vector="header-clickjacking-chain",
                        severity="low",
                        endpoint_template=rec.endpoint_template,
                        precondition="X-Frame-Options / CSP frame-ancestors 모두 없음",
                        enabling_condition=f"민감 상태변경 동작 존재 ({rec.endpoint_template})",
                        attack_class="Clickjacking",
                        poc_sketch="대상 페이지를 iframe으로 감싸 투명 오버레이로 클릭 유도",
                        cve_hint="CWE-1021 (Improper Restriction of Rendered UI Layers)",
                        evidence=[_rec_evidence(rec, i)],
                    )
                )

            # --- HSTS + 평문 HTTP 체인 ---
            if "strict-transport-security" not in h and plaintext is not None:
                findings.append(
                    Finding(
                        vector="header-hsts-chain",
                        severity="medium",
                        endpoint_template=rec.endpoint_template,
                        precondition="HSTS(Strict-Transport-Security) 헤더 없음",
                        enabling_condition=f"평문 HTTP 트래픽 관찰됨 (host={plaintext.request.host})",
                        attack_class="SSL stripping → 평문 다운그레이드",
                        poc_sketch="MITM 위치에서 HTTPS를 HTTP로 다운그레이드해 세션/자격증명 평문 노출",
                        cve_hint="CWE-319 (Cleartext Transmission)",
                        evidence=[_rec_evidence(rec, i)],
                    )
                )
        return findings


def _rec_evidence(rec: HttpRecord, idx: int) -> Evidence:
    return Evidence(
        method=rec.request.method,
        endpoint_template=rec.endpoint_template,
        actual_target=rec.request.target,
        identity_label=rec.identity.label if rec.identity else "unknown",
        status=rec.response.status if (rec.response and rec.response.present) else None,
        note=";".join(rec.signals),
        history_index=idx,
    )
