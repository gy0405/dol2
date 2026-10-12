"""돌돌이 설정.

환경변수로 덮어쓸 수 있게 해 두고, 기본값은 Burp 공식 MCP의 기본값을 따른다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class BurpConfig:
    """공식 Burp MCP 접속 설정.

    공식 Burp MCP(kotlin-sdk 0.15)는 **Streamable HTTP** 트랜스포트를 루트
    경로에 노출한다(옛 SSE 아님). Burp 쪽 ``MCP`` 탭의 Host/Port(기본
    127.0.0.1:9876)와 맞춘다. 엔드포인트가 루트가 아니면 ``http_path``로 맞춘다.
    """

    base_url: str = field(
        default_factory=lambda: os.environ.get("DOL2_BURP_BASE_URL", "http://127.0.0.1:9876")
    )
    # Streamable HTTP 엔드포인트 경로. 공식 서버는 루트("")라 보통 비워 둔다.
    http_path: str = field(
        default_factory=lambda: os.environ.get("DOL2_BURP_HTTP_PATH", "")
    )
    # 한 번에 끌어올 히스토리 페이지 크기(공식 서버가 count/offset 페이지네이션 제공).
    page_size: int = field(
        default_factory=lambda: int(os.environ.get("DOL2_BURP_PAGE_SIZE", "100"))
    )
    connect_timeout: float = 5.0

    @property
    def endpoint_url(self) -> str:
        base = self.base_url.rstrip("/")
        return base + "/" + self.http_path.lstrip("/") if self.http_path else base


@dataclass
class ScopeConfig:
    """분석 범위. 실제 인가된 점검에서는 반드시 좁혀서 쓴다.

    ``host_allow`` 가 비어 있으면 전부 허용(개발/실습용). 실전에서는
    대상 호스트 정규식을 반드시 채운다.
    """

    host_allow: list[str] = field(default_factory=list)  # 정규식 문자열 목록
    host_deny: list[str] = field(default_factory=list)
