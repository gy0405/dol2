"""돌돌이의 데이터 모델.

공식 Burp MCP는 프록시 히스토리 항목을 ``{request: str, response: str, notes: str}``
형태(원본 HTTP 메시지 문자열)로 준다. 돌돌이는 이것을 파싱해
분석하기 좋은 구조로 바꾼다.

흐름:  RawHistoryItem --parse--> HttpRecord --normalize--> (endpoint template + identity)
       --score--> relevance --gate--> Finding
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- #
# 1) Burp MCP가 주는 원본 그대로
# --------------------------------------------------------------------------- #
@dataclass
class RawHistoryItem:
    """``get_proxy_http_history`` 응답 1건의 원본."""

    request: str
    response: str
    notes: str = ""


# --------------------------------------------------------------------------- #
# 2) 파싱된 HTTP 메시지
# --------------------------------------------------------------------------- #
@dataclass
class ParsedRequest:
    method: str
    target: str           # 요청 라인의 경로+쿼리 (예: /api/users/10?x=1)
    version: str
    headers: dict[str, str]
    body: str
    raw: str

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def query(self) -> str:
        return self.target.split("?", 1)[1] if "?" in self.target else ""

    @property
    def host(self) -> str:
        return self.headers.get("host", "")


@dataclass
class ParsedResponse:
    status: int
    reason: str
    version: str
    headers: dict[str, str]
    body: str
    raw: str
    present: bool = True   # Burp가 응답을 캡처 못한 경우 False (<no response>)


@dataclass
class HttpRecord:
    """파싱 완료된 요청/응답 한 쌍 + 분석 중 붙는 메타데이터."""

    request: ParsedRequest
    response: Optional[ParsedResponse]
    notes: str = ""

    # normalize 단계에서 채워짐
    endpoint_template: str = ""        # 예: GET /api/users/{id}
    identity: Optional["Identity"] = None

    # score 단계에서 채워짐
    relevance: float = 0.0
    signals: list[str] = field(default_factory=list)   # 왜 흥미로운지(IDOR-ref, state-change ...)


@dataclass
class Identity:
    """요청을 보낸 주체에 대한 *추정*.

    Burp 히스토리는 "이건 A 사용자"라고 알려주지 않으므로, 쿠키/토큰/JWT sub
    등에서 추정할 뿐이다. 추정이라는 점을 label과 함께 드러낸다.
    """

    label: str                      # 안정적인 그룹 키(예: jwt-sub:123, cookie:ab12…, anon)
    source: str                     # 어디서 뽑았나: "jwt" | "cookie" | "authorization" | "none"
    confidence: float = 0.5
    claims: dict[str, str] = field(default_factory=dict)  # jwt payload 등 참고용


# --------------------------------------------------------------------------- #
# 3) 최종 산출물
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """돌돌이가 올리는 '의심 벡터' 한 건.

    impact gate를 통과한 것만 생성된다. 반드시 다음을 담는다:
      - precondition: 관찰된 전제(예: 세션 쿠키에 Secure 없음)
      - enabling_condition: 관찰된 보강 조건(예: 평문 HTTP 요청 존재)
      - attack_class / cve_hint / poc_sketch: 그래서 뭐가 가능한가
      - evidence: 원본 패킷으로 되짚는 포인터
    """

    vector: str                     # "idor" | "missing-authz" | "cookie-secure-chain" ...
    severity: str                   # "info" | "low" | "medium" | "high"
    endpoint_template: str
    precondition: str
    enabling_condition: str
    attack_class: str
    poc_sketch: str
    cve_hint: str = ""
    evidence: list["Evidence"] = field(default_factory=list)


@dataclass
class Evidence:
    """원본 패킷으로 되짚기 위한 압축 레코드(원본 전체를 들고 다니지 않음)."""

    method: str
    endpoint_template: str
    actual_target: str
    identity_label: str
    status: Optional[int]
    note: str = ""
    # 원본 히스토리에서의 위치(돌돌이 세션 내 인덱스). 사람이 Burp에서 바로 확인.
    history_index: Optional[int] = None


# --------------------------------------------------------------------------- #
# 파서
# --------------------------------------------------------------------------- #
_REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<version>HTTP/[\d.]+)\s*$")
_STATUS_LINE = re.compile(r"^(?P<version>HTTP/[\d.]+)\s+(?P<status>\d{3})\s*(?P<reason>.*)$")

_NO_RESPONSE_MARKERS = {"<no response>", ""}


def _split_head_body(raw: str) -> tuple[list[str], str]:
    """헤더부와 바디를 분리. CRLF/LF 모두 허용."""
    # 첫 빈 줄 기준 분리
    for sep in ("\r\n\r\n", "\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            head = raw[:idx]
            body = raw[idx + len(sep):]
            return head.splitlines(), body
    return raw.splitlines(), ""


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return headers


def parse_request(raw: str) -> ParsedRequest:
    head_lines, body = _split_head_body(raw)
    if not head_lines:
        raise ValueError("빈 요청")
    m = _REQUEST_LINE.match(head_lines[0])
    if not m:
        raise ValueError(f"요청 라인 파싱 실패: {head_lines[0]!r}")
    headers = _parse_headers(head_lines[1:])
    return ParsedRequest(
        method=m["method"],
        target=m["target"],
        version=m["version"],
        headers=headers,
        body=body,
        raw=raw,
    )


def parse_response(raw: str) -> ParsedResponse:
    if raw is None or raw.strip() in _NO_RESPONSE_MARKERS:
        return ParsedResponse(
            status=0, reason="", version="", headers={}, body="", raw=raw or "", present=False
        )
    head_lines, body = _split_head_body(raw)
    if not head_lines:
        return ParsedResponse(
            status=0, reason="", version="", headers={}, body="", raw=raw, present=False
        )
    m = _STATUS_LINE.match(head_lines[0])
    if not m:
        # 상태줄이 안 맞으면 응답은 있으나 비표준 — present=True로 두되 status=0
        return ParsedResponse(
            status=0, reason="", version="", headers=_parse_headers(head_lines[1:]),
            body=body, raw=raw, present=True,
        )
    return ParsedResponse(
        status=int(m["status"]),
        reason=m["reason"].strip(),
        version=m["version"],
        headers=_parse_headers(head_lines[1:]),
        body=body,
        raw=raw,
        present=True,
    )


def parse_history_item(item: RawHistoryItem) -> HttpRecord:
    req = parse_request(item.request)
    resp = parse_response(item.response)
    return HttpRecord(request=req, response=resp, notes=item.notes)
