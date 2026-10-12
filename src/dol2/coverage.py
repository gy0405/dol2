"""커버리지 피드백 — 지금 트래픽으로 뭘 평가할 수 있었고, 뭘 못 했고,
무엇을 더 돌아다녀야 하는지 알려준다.

돌돌이는 쌓인 트래픽만 보므로 '발견 0'이 '안전'을 뜻하지 않는다. 각 가이드
항목별로 "평가에 필요한 트래픽 조건"이 트래픽에 있는지 점검해, 점검자가 다음에
무엇을 해야 하는지(트래픽 플레이북의 동적 버전)를 제시한다.

상태:
  ok           — 평가에 필요한 트래픽이 충분히 관찰됨(발견 여부와 무관)
  insufficient — 일부만 관찰됨 → 조금 더 돌아다니면 평가 가능
  none         — 관련 트래픽이 아예 없음 → 이 항목은 평가 못 함
"""
from __future__ import annotations

from dataclasses import dataclass

from .guide import WEB_ITEMS
from .models import HttpRecord
from .pipeline.normalize import auth_cookie_fingerprint
from .pipeline.score import group_by_template

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class CoverageItem:
    code: str
    name: str
    status: str   # ok | insufficient | none
    detail: str
    advice: str


def _has_session(rec: HttpRecord) -> bool:
    if rec.request.headers.get("authorization"):
        return True
    if auth_cookie_fingerprint(rec.request.headers.get("cookie", "")):
        return True
    if rec.response and rec.response.present:
        for k, v in rec.response.headers.items():
            if k == "set-cookie" and auth_cookie_fingerprint(v):
                return True
    return False


def _facts(records: list[HttpRecord]) -> dict:
    html = any(
        r.response and r.response.present
        and "html" in r.response.headers.get("content-type", "").lower()
        for r in records
    )
    state_change = any(r.request.method in _STATE_CHANGING for r in records)
    session = any(_has_session(r) for r in records)
    plaintext = any(
        (":80" in r.request.host or ":8080" in r.request.host) for r in records
    )
    input_points = any((r.request.query or r.request.body) for r in records)
    xss_surface = any("xss-surface" in r.signals for r in records)

    groups = group_by_template(records)
    obj_templates = {t: g for t, g in groups.items() if "{id}" in t}
    obj_multi_identity = any(
        len({r.identity.label for r in g if r.identity}) >= 2
        for g in obj_templates.values()
    )
    identities = {
        r.identity.label for r in records if r.identity and r.identity.label != "anon"
    }
    return {
        "html": html,
        "state_change": state_change,
        "session": session,
        "plaintext": plaintext,
        "input_points": input_points,
        "xss_surface": xss_surface,
        "has_obj_ref": bool(obj_templates),
        "obj_multi_identity": obj_multi_identity,
        "identity_count": len(identities),
    }


def build_coverage(records: list[HttpRecord]) -> list[CoverageItem]:
    f = _facts(records)
    items: list[CoverageItem] = []

    def item(code, status, detail, advice):
        g = WEB_ITEMS[code]
        items.append(CoverageItem(g.code, g.name, status, detail, advice))

    # IN — 불충분한 권한 검증 (IDOR / 수평 권한)
    if not f["has_obj_ref"]:
        item("IN", "none",
             "객체 참조(.../{id}) 엔드포인트 트래픽이 없음",
             "id가 URL/파라미터에 드러나는 기능(주문·장바구니·프로필 조회)을 사용하세요.")
    elif not f["obj_multi_identity"]:
        item("IN", "insufficient",
             "객체 참조 엔드포인트를 한 신원만 접근함",
             "두 번째 계정으로 로그인해 같은 기능을 사용하세요(2계정 교차).")
    else:
        item("IN", "ok", "서로 다른 신원이 같은 객체참조 엔드포인트에 접근함", "")

    # XS — 크로스사이트 스크립트 (반사형)
    if not f["html"]:
        item("XS", "none",
             "HTML 응답이 관찰되지 않음(JSON API/SPA일 가능성)",
             "서버가 HTML을 그리는 페이지를 방문하세요. (SPA는 DOM XSS라 범위 밖)")
    elif not f["input_points"]:
        item("XS", "insufficient",
             "HTML은 있으나 입력값이 실린 요청이 없음",
             "검색/폼/URL 파라미터에 특수문자(\"><b>)를 넣어 결과 페이지를 방문하세요.")
    else:
        item("XS", "ok", "HTML 응답 + 입력 지점이 관찰됨(반사 평가 가능)", "")

    # IS — 불충분한 세션 관리 (쿠키 플래그 계열의 선행 조건)
    if not f["session"]:
        item("IS", "none",
             "세션 쿠키/인증 토큰 트래픽이 없음",
             "로그인/로그아웃을 수행하세요. (JWT를 localStorage에 넣는 사이트는 세션 쿠키가 없을 수 있음)")
    else:
        item("IS", "ok", "세션/인증 트래픽이 관찰됨", "")

    # CF — CSRF (세션 쿠키 + 상태변경)
    if not f["session"]:
        item("CF", "none",
             "세션 쿠키 트래픽이 없어 CSRF 전제 불성립",
             "로그인 후 상태 변경 동작을 수행하세요.")
    elif not f["state_change"]:
        item("CF", "insufficient",
             "세션은 있으나 상태 변경(POST/PUT/DELETE) 동작이 없음",
             "글쓰기·설정 변경·구매 등 상태 변경 기능을 수행하세요.")
    else:
        item("CF", "ok", "세션 + 상태변경 동작이 관찰됨", "")

    # SN — 데이터 평문 전송 (평문 HTTP 관찰)
    if not f["plaintext"]:
        item("SN", "none",
             "평문 HTTP 트래픽이 관찰되지 않음",
             "http:// 로도 접속해보세요. (HTTPS 전용 사이트면 이 항목은 자연히 비해당)")
    else:
        item("SN", "ok", "평문 HTTP 트래픽이 관찰됨", "")

    return items


def render_coverage(items: list[CoverageItem]) -> str:
    mark = {"ok": "[평가가능]", "insufficient": "[트래픽부족]", "none": "[트래픽없음]"}
    lines = ["── 커버리지 (지금 트래픽으로 평가 가능한 범위) ──"]
    for it in items:
        line = f"{mark.get(it.status, '[?]')} [{it.code}] {it.name} — {it.detail}"
        lines.append(line)
        if it.advice:
            lines.append(f"    → 더 필요: {it.advice}")
    lines.append("※ '평가가능'도 '안전'을 뜻하지 않음 — 발견이 없을 뿐 사람 점검은 별도.")
    return "\n".join(lines)
