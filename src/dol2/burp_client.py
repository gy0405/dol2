"""공식 Burp MCP 서버에 MCP 클라이언트로 붙는 계층.

공식 Burp MCP는 kotlin-sdk의 ``Application.mcp { }``로 서버를 띄우는데, 이건
**옛 HTTP+SSE 트랜스포트를 "루트 경로(/)"에** 연다(Streamable HTTP 아님).
따라서 sse_client로 base URL(경로 없음)에 접속한다. SSE 스트림이 보내주는
endpoint 이벤트로 메시지 POST 주소가 자동 결정된다.

돌돌이는 여기서 패킷을 끌어온다. 공식 서버가 노출하는 도구 중 돌돌이가 쓰는 것:

* ``get_proxy_http_history``        (count/offset 페이지네이션) — 주 입력
* ``get_proxy_http_history_regex``  (regex, count/offset)        — 서버단 필터
* ``send_http1_request`` / ``send_http2_request``                — 검증용 재전송(능동)

지금 단계에서는 히스토리를 끌어오는 것까지만 실제로 구현한다.
재전송(active verify)은 vectors 단계에서 붙인다.
"""
from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from .config import BurpConfig
from .models import RawHistoryItem


class BurpMcpClient:
    """공식 Burp MCP(SSE)에 대한 얇은 래퍼."""

    def __init__(self, config: BurpConfig | None = None) -> None:
        self.config = config or BurpConfig()
        self._session: ClientSession | None = None

    @asynccontextmanager
    async def connect(self) -> AsyncIterator["BurpMcpClient"]:
        """SSE 세션(루트 경로)을 열고 initialize까지 마친 상태로 넘긴다."""
        async with sse_client(self.config.endpoint_url, timeout=self.config.connect_timeout) as (
            read,
            write,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self._session = session
                try:
                    yield self
                finally:
                    self._session = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("connect() 컨텍스트 안에서만 호출 가능")
        return self._session

    # ---------------------------------------------------------------- #
    # 공식 서버 결과 파싱 헬퍼
    # ---------------------------------------------------------------- #
    @staticmethod
    def _content_to_items(result: Any) -> list[RawHistoryItem]:
        """CallToolResult의 content 블록(들)을 RawHistoryItem 목록으로.

        공식 서버는 히스토리 항목을 JSON(= HttpRequestResponse 스키마:
        request/response/notes)으로 직렬화해 text content로 돌려준다.
        방어적으로: JSON 파싱 실패 시 text 자체를 request로 담아 둔다.
        """
        items: list[RawHistoryItem] = []
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if text is None:
                continue
            parsed = _safe_json(text)
            if isinstance(parsed, list):
                for obj in parsed:
                    items.append(_obj_to_item(obj))
            elif isinstance(parsed, dict):
                items.append(_obj_to_item(parsed))
            else:
                # 공식 Burp MCP는 N건을 '한 text 블록'에 빈 줄로 구분된 JSON 객체들로
                # 몰아서 돌려준다(유효한 JSON 배열 아님). 통째로 1건으로 삼키지 말고
                # 순차적으로 객체를 뽑아낸다. 하나도 못 뽑으면 원문을 그대로 1건으로.
                objs = _extract_objects(text)
                if objs:
                    items.extend(_obj_to_item(o) for o in objs)
                else:
                    items.append(RawHistoryItem(request=text, response="<no response>"))
        return items

    # ---------------------------------------------------------------- #
    # 도구 호출
    # ---------------------------------------------------------------- #
    async def list_tools(self) -> list[str]:
        result = await self.session.list_tools()
        return [t.name for t in result.tools]

    async def get_proxy_history(
        self, count: int | None = None, offset: int = 0
    ) -> list[RawHistoryItem]:
        count = count or self.config.page_size
        result = await self.session.call_tool(
            "get_proxy_http_history", {"count": count, "offset": offset}
        )
        return self._content_to_items(result)

    async def get_proxy_history_regex(
        self, regex: str, count: int | None = None, offset: int = 0
    ) -> list[RawHistoryItem]:
        count = count or self.config.page_size
        result = await self.session.call_tool(
            "get_proxy_http_history_regex",
            {"regex": regex, "count": count, "offset": offset},
        )
        return self._content_to_items(result)

    async def iter_all_history(self) -> AsyncIterator[RawHistoryItem]:
        """페이지네이션을 돌며 전체 히스토리를 스트리밍."""
        offset = 0
        while True:
            page = await self.get_proxy_history(self.config.page_size, offset)
            if not page:
                break
            for item in page:
                yield item
            if len(page) < self.config.page_size:
                break
            offset += self.config.page_size


def _safe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


# 한 text 블록 안에 '이어붙은' 히스토리 객체들을 관용적으로 뽑아낸다.
# 공식 Burp MCP는 N건을 {"request":"...","response":"...","notes":"..."} 형태로
# \n\n 로 이어붙여 한 블록에 담아 보내는데, 긴 값(특히 response 본문)을 중간에서
# '... (truncated)' 로 잘라 버린다. 그래서 각 객체는 '유효한 JSON이 아니다'
# (문자열이 안 닫히고 raw 제어문자까지 섞임) — json.loads / raw_decode 로는 못 쪼갠다.
# 따라서 JSON 파싱을 포기하고, 객체 경계({"request":")로 나눈 뒤 각 청크에서
# request/response/notes 문자열만 이스케이프를 해석하며 뽑는다. 잘렸으면 거기까지만.
# dol2 분석에 필요한 요청라인·헤더·상태코드는 잘림 지점 앞에 있어 지장 없다.
_ITEM_START = re.compile(r'\{"request":"')
_ESC = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
        '"': '"', "\\": "\\", "/": "/"}


def _read_json_string(text: str, i: int) -> tuple[str, int]:
    """text[i] 는 여는 따옴표. (디코딩된 값, 닫는따옴표_다음_index) 반환.

    닫는 따옴표를 만나기 전에 끝(잘림)에 닿으면 그때까지 모은 값을 돌려준다.
    """
    i += 1
    out: list[str] = []
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            if i + 1 >= n:
                break  # 매달린 백슬래시 = 잘림
            d = text[i + 1]
            if d == "u" and i + 5 < n:
                try:
                    out.append(chr(int(text[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(_ESC.get(d, d))
            i += 2
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    return "".join(out), i  # 끝까지 = 잘림


def _extract_objects(text: str) -> list[dict]:
    starts = [m.start() for m in _ITEM_START.finditer(text)]
    objs: list[dict] = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(text)
        chunk = text[s:e]
        obj = {"request": "", "response": "<no response>", "notes": ""}
        for key in ("request", "response", "notes"):
            kp = chunk.find('"%s":' % key)
            if kp == -1:
                continue
            oq = chunk.find('"', kp + len('"%s":' % key))
            if oq == -1:
                continue
            obj[key], _ = _read_json_string(chunk, oq)
        objs.append(obj)
    return objs


def _obj_to_item(obj: dict) -> RawHistoryItem:
    return RawHistoryItem(
        request=obj.get("request", "") or "",
        response=obj.get("response", "<no response>") or "<no response>",
        notes=obj.get("notes", "") or "",
    )
