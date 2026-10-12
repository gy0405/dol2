"""반사형(reflected) XSS 표면 탐지기 — 전적으로 수동(관찰) 방식.

중요: 돌돌이는 **공격 페이로드를 쏘지 않는다.** 이미 Burp에 쌓인 트래픽만 보고,
'사용자 입력이 응답에 인코딩 없이 메아리치는 자리'를 찾는다. 확증(실제 실행되는지)은
사람이 PoC로 확인한다.

판단 규칙(오탐을 줄이기 위해 보수적으로):
  1) 요청의 사용자 입력값(쿼리/본문 파라미터)을 뽑는다.
  2) 그 값이 응답 본문에 '그대로(verbatim)' 나타나는가.
  3) 응답이 HTML 맥락인가 (Content-Type: text/html).
  4) 값에 HTML 특수문자(< > " ')가 있고, 그게 인코딩되지 않은 채 반사됐는가.
     → raw 값이 응답의 부분문자열이면 그 자리는 인코딩 안 된 것이다
       (인코딩됐다면 &lt; 형태라 raw 값은 부분문자열로 안 잡힘).

한계(정직하게): 수동이라 '관찰된 입력'에 특수문자가 우연히 들어가 반사된 경우만
잡는다. 특수문자를 일부러 넣어보는 능동 프로빙은 하지 않으므로, 여기서 안 잡혔다고
XSS가 없다는 뜻은 아니다. 그래서 결과는 '후보'이고 PoC는 사람이 확인한다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl

from ..models import Evidence, Finding, HttpRecord

_SPECIAL = ("<", ">", '"', "'")
_MIN_LEN = 3  # 너무 짧은 값(1~2자)은 우연 반사 노이즈가 많아 제외


@dataclass
class Reflection:
    param: str          # 어떤 파라미터에서 온 값인가
    where: str          # "query" | "body"
    value: str          # 반사된 값


def _iter_input_values(rec: HttpRecord):
    """요청에서 사용자 입력값 (param, where, value)들을 뽑는다. URL 디코드 포함."""
    req = rec.request

    # 쿼리 파라미터
    for k, v in parse_qsl(req.query, keep_blank_values=False):
        yield k, "query", v

    # 본문 — form-urlencoded / JSON만 간단 파싱
    ctype = req.headers.get("content-type", "")
    body = req.body or ""
    if "application/x-www-form-urlencoded" in ctype:
        for k, v in parse_qsl(body, keep_blank_values=False):
            yield k, "body", v
    elif "application/json" in ctype and body.strip():
        try:
            obj = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            obj = None
        yield from _json_strings(obj, "body")


def _json_strings(obj, where, key="json"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _json_strings(v, where, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _json_strings(v, where, key)
    elif isinstance(obj, str):
        yield key, where, obj


def detect_reflection(rec: HttpRecord) -> list[Reflection]:
    """한 레코드에서 '인코딩 안 된 특수문자 반사(= XSS 표면)'를 찾는다."""
    resp = rec.response
    if not (resp and resp.present):
        return []
    if "html" not in resp.headers.get("content-type", "").lower():
        return []  # HTML 맥락 아님 → 반사형 XSS 표면으로 보지 않음

    body = resp.body or ""
    found: list[Reflection] = []
    seen: set[str] = set()
    for param, where, value in _iter_input_values(rec):
        if len(value) < _MIN_LEN:
            continue
        if not any(c in value for c in _SPECIAL):
            continue  # 특수문자 없는 값의 반사는 XSS 표면으로 인정 안 함(보수적)
        if value in body and value not in seen:   # raw 값이 그대로 있음 = 미인코딩
            found.append(Reflection(param=param, where=where, value=value))
            seen.add(value)
    return found


def tag_xss_surface(records: list[HttpRecord]) -> list[HttpRecord]:
    """반사가 발견된 레코드에 'xss-surface' 신호를 붙인다.

    이 신호를 chains.py의 HttpOnly/CSP 체인이 보강조건으로 읽는다.
    파이프라인(score 이후)에서 한 번 호출한다.
    """
    for rec in records:
        if detect_reflection(rec):
            if "xss-surface" not in rec.signals:
                rec.signals.append("xss-surface")
    return records


class ReflectedXssDetector:
    """반사형 XSS '후보'를 Finding으로 올린다. (판정 아님 — 사람이 PoC로 확인)"""

    name = "reflected-xss"

    def detect(self, records: list[HttpRecord]) -> list[Finding]:
        findings: list[Finding] = []
        for i, rec in enumerate(records):
            reflections = detect_reflection(rec)
            if not reflections:
                continue
            r = reflections[0]
            params = ", ".join(sorted({f"{x.where}:{x.param}" for x in reflections}))
            findings.append(
                Finding(
                    vector="reflected-xss",
                    severity="high",
                    endpoint_template=rec.endpoint_template,
                    precondition=f"사용자 입력({params})이 응답 본문에 반사됨",
                    enabling_condition=(
                        "HTML 응답에 특수문자(<>\"')가 인코딩되지 않은 채 반사됨 "
                        f"(예: {r.value!r})"
                    ),
                    attack_class="반사형 XSS 후보 (reflected XSS)",
                    poc_sketch=(
                        f"파라미터 '{r.param}'에 <script>alert(1)</script> 류 페이로드를 넣어 "
                        "응답에서 그대로 실행 가능한지 사람이 직접 확인 "
                        "(돌돌이는 자동으로 쏘지 않음)"
                    ),
                    cve_hint="CWE-79 (Improper Neutralization of Input — XSS)",
                    evidence=[
                        Evidence(
                            method=rec.request.method,
                            endpoint_template=rec.endpoint_template,
                            actual_target=rec.request.target,
                            identity_label=rec.identity.label if rec.identity else "unknown",
                            status=rec.response.status if (rec.response and rec.response.present) else None,
                            note=f"reflected={r.value!r} via {r.where}:{r.param}",
                            history_index=i,
                        )
                    ],
                )
            )
        return findings
