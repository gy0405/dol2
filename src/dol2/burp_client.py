"""공식 Burp MCP 서버(SSE)에 MCP 클라이언트로 붙는 계층.

돌돌이는 여기서 패킷을 끌어온다. 공식 서버가 노출하는 도구 중 돌돌이가 쓰는 것:

* ``get_proxy_http_history``        (count/offset 페이지네이션) — 주 입력
* ``get_proxy_http_history_regex``  (regex, count/offset)        — 서버단 필터
* ``send_http1_request`` / ``send_http2_request``                — 검증용 재전송(능동)

지금 단계에서는 히스토리를 끌어오는 것까지만 실제로 구현한다.
재전송(active verify)은 vectors 단계에서 붙인다.
"""
from __future__ import annotations

import json
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
        """SSE 세션을 열고 initialize까지 마친 상태로 넘긴다."""
        async with sse_client(self.config.sse_url, timeout=self.config.connect_timeout) as (
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


def _obj_to_item(obj: dict) -> RawHistoryItem:
    return RawHistoryItem(
        request=obj.get("request", "") or "",
        response=obj.get("response", "<no response>") or "<no response>",
        notes=obj.get("notes", "") or "",
    )
