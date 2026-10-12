"""파이프라인 스모크 테스트 — Burp 없이 합성 데이터로 핵심 로직 검증.

여기서 보는 것:
  1) 원본 HTTP 문자열 파싱
  2) 엔드포인트 정규화 (/api/users/1 -> {id})
  3) 신원 라벨링 (JWT sub)
  4) impact gate: 단독 hygiene은 떨어지고, 체인만 올라오는가
  5) 수평 권한(IDOR) 후보 묶기
"""
from __future__ import annotations

from dol2.gate import passes_gate, run_detectors
from dol2.models import Finding, RawHistoryItem, parse_history_item
from dol2.pipeline.filter import coarse_filter
from dol2.pipeline.normalize import endpoint_template, normalize
from dol2.pipeline.score import score
from dol2.vectors.xss import tag_xss_surface


def _run(items):
    """filter → normalize → score → xss 태깅까지 돌린 레코드."""
    recs = [parse_history_item(it) for it in items]
    return tag_xss_surface(score(normalize(coarse_filter(recs))))

# user 1 의 JWT (sub=1), user 2 의 JWT (sub=2) — 서명 무의미, payload만.
JWT_U1 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
JWT_U2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.sig"


def _req(method, target, headers=None, body=""):
    h = "\r\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    return f"{method} {target} HTTP/1.1\r\nHost: shop.test\r\n{h}\r\n\r\n{body}"


def _resp(status, headers=None, body=""):
    h = "\r\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    return f"HTTP/1.1 {status} OK\r\n{h}\r\n\r\n{body}"


def test_parse_and_normalize():
    item = RawHistoryItem(request=_req("GET", "/api/users/1023"), response=_resp(200))
    rec = parse_history_item(item)
    assert rec.request.method == "GET"
    assert rec.request.path == "/api/users/1023"
    assert endpoint_template(rec.request) == "GET /api/users/{id}"


def test_identity_jwt():
    item = RawHistoryItem(
        request=_req("GET", "/api/me", {"Authorization": f"Bearer {JWT_U1}"}),
        response=_resp(200),
    )
    recs = normalize([parse_history_item(item)])
    assert recs[0].identity.label == "jwt-sub:1"
    assert recs[0].identity.source == "jwt"


def test_gate_rejects_lonely_hygiene():
    # precondition만, enabling_condition 없음 → 게이트 탈락
    lonely = Finding(
        vector="x", severity="low", endpoint_template="GET /",
        precondition="Secure 없음", enabling_condition="",
        attack_class="", poc_sketch="",
    )
    assert passes_gate(lonely) is False


def test_cookie_secure_chain_only_with_plaintext():
    # Secure 없는 세션쿠키 + 평문 HTTP(host :80) → 체인 성립
    login = RawHistoryItem(
        request=_req("POST", "/login"),
        response=_resp(200, {"Set-Cookie": "SID=abc; HttpOnly"}),  # Secure 없음
    )
    # 평문 흔적: host에 :80
    plain = RawHistoryItem(
        request="GET /x HTTP/1.1\r\nHost: shop.test:80\r\n\r\n",
        response=_resp(200),
    )
    recs = score(normalize(coarse_filter(
        [parse_history_item(login), parse_history_item(plain)]
    )))
    findings = run_detectors(recs)
    vectors = {f.vector for f in findings}
    assert "cookie-secure-chain" in vectors


def test_cookie_secure_no_chain_without_plaintext():
    # 평문 HTTP가 없으면 Secure 부재만으로는 아무것도 안 올라와야 함
    login = RawHistoryItem(
        request=_req("POST", "/login"),
        response=_resp(200, {"Set-Cookie": "SID=abc; HttpOnly"}),
    )
    recs = score(normalize(coarse_filter([parse_history_item(login)])))
    findings = run_detectors(recs)
    assert all(f.vector != "cookie-secure-chain" for f in findings)


def test_horizontal_authz_candidate():
    # 같은 /api/orders/{id} 를 두 신원이 접근, 상태코드 갈림 + 2xx 성공
    a = RawHistoryItem(
        request=_req("GET", "/api/orders/1", {"Authorization": f"Bearer {JWT_U1}"}),
        response=_resp(200),
    )
    b = RawHistoryItem(
        request=_req("GET", "/api/orders/2", {"Authorization": f"Bearer {JWT_U2}"}),
        response=_resp("403"),
    )
    recs = score(normalize(coarse_filter(
        [parse_history_item(a), parse_history_item(b)]
    )))
    findings = run_detectors(recs)
    assert any(f.vector == "horizontal-authz" for f in findings)


# --------------------------------------------------------------------------- #
# 반사형 XSS 표면 + 깨어난 체인들
# --------------------------------------------------------------------------- #
HTML = {"Content-Type": "text/html; charset=utf-8"}


def test_reflected_xss_surface_flagged():
    # 쿼리값 '"><b>'가 HTML 응답에 인코딩 안 된 채 그대로 반사 → 후보로 올라와야 함
    payload = '"><b>x'
    item = RawHistoryItem(
        request=_req("GET", "/search?q=%22%3E%3Cb%3Ex"),  # URL인코딩된 "><b>x
        response=_resp(200, HTML, body=f"<p>검색어: {payload}</p>"),
    )
    findings = run_detectors(_run([item]))
    assert any(f.vector == "reflected-xss" for f in findings)


def test_reflected_xss_encoded_is_not_flagged():
    # 같은 입력이 인코딩돼 반사되면(&lt;) 표면 아님 → 안 올라와야 함
    item = RawHistoryItem(
        request=_req("GET", "/search?q=%22%3E%3Cb%3Ex"),
        response=_resp(200, HTML, body="<p>검색어: &quot;&gt;&lt;b&gt;x</p>"),
    )
    findings = run_detectors(_run([item]))
    assert all(f.vector != "reflected-xss" for f in findings)


def test_reflected_xss_non_html_is_not_flagged():
    # JSON 응답이면 반사돼도 반사형 XSS 표면으로 안 봄
    item = RawHistoryItem(
        request=_req("GET", "/api/search?q=%22%3E%3Cb%3Ex"),
        response=_resp(200, {"Content-Type": "application/json"}, body='{"q":"\\"><b>x"}'),
    )
    findings = run_detectors(_run([item]))
    assert all(f.vector != "reflected-xss" for f in findings)


def test_httponly_chain_wakes_with_xss_surface():
    # HttpOnly 없는 세션쿠키 + 같은 트래픽에 XSS 표면 → 체인 성립
    login = RawHistoryItem(
        request=_req("POST", "/login"),
        response=_resp(200, {"Set-Cookie": "SID=abc; Secure"}),  # HttpOnly 없음
    )
    xss = RawHistoryItem(
        request=_req("GET", "/search?q=%22%3E%3Cb%3Ex"),
        response=_resp(200, HTML, body='<p>"><b>x</p>'),
    )
    findings = run_detectors(_run([login, xss]))
    assert any(f.vector == "cookie-httponly-xss-chain" for f in findings)


def test_httponly_no_chain_without_xss_surface():
    # XSS 표면이 없으면 HttpOnly 부재만으로는 안 올라와야 함
    login = RawHistoryItem(
        request=_req("POST", "/login"),
        response=_resp(200, {"Set-Cookie": "SID=abc; Secure"}),
    )
    findings = run_detectors(_run([login]))
    assert all(f.vector != "cookie-httponly-xss-chain" for f in findings)


# --------------------------------------------------------------------------- #
# 무해한 쿠키를 인증 재료로 오인하지 않는지 (실측에서 나온 버그)
# --------------------------------------------------------------------------- #
def test_benign_cookie_not_auth_material():
    # language 쿠키만 달린 정적 .js 는 노이즈로 걸러져야 함
    item = RawHistoryItem(
        request=_req("GET", "/main.js", {"Cookie": "language=en"}),
        response=_resp(200, {"Content-Type": "application/javascript"}),
    )
    recs = _run([item])
    assert recs == []  # 필터에서 제거됨


def test_benign_cookie_identity_is_anon():
    item = RawHistoryItem(
        request=_req("GET", "/rest/products/search?q=", {"Cookie": "language=en"}),
        response=_resp(200, {"Content-Type": "application/json"}),
    )
    recs = _run([item])
    assert recs and recs[0].identity.label == "anon"
    assert "auth-material" not in recs[0].signals


def test_session_cookie_still_counts():
    item = RawHistoryItem(
        request=_req("GET", "/account", {"Cookie": "language=en; session=abc123"}),
        response=_resp(200, {"Content-Type": "text/html"}),
    )
    recs = _run([item])
    assert recs and recs[0].identity.source == "cookie"
    assert "auth-material" in recs[0].signals
