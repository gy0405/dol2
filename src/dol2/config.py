"""돌돌이 설정.

환경변수로 덮어쓸 수 있게 해 두고, 기본값은 Burp 공식 MCP의 기본값을 따른다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class BurpConfig:
    """공식 Burp MCP(SSE) 접속 설정.

    Burp 쪽 ``MCP`` 탭의 Host/Port(기본 127.0.0.1:9876)와 맞춰야 한다.
    SSE 엔드포인트 경로는 Burp 버전에 따라 다를 수 있으니(보통 ``/sse``)
    실제 탭에 표시되는 URL로 맞추는 것을 권장한다.
    """

    base_url: str = field(
        default_factory=lambda: os.environ.get("DOL2_BURP_BASE_URL", "http://127.0.0.1:9876")
    )
    sse_path: str = field(
        default_factory=lambda: os.environ.get("DOL2_BURP_SSE_PATH", "/sse")
    )
    # 한 번에 끌어올 히스토리 페이지 크기(공식 서버가 count/offset 페이지네이션 제공).
    page_size: int = field(
        default_factory=lambda: int(os.environ.get("DOL2_BURP_PAGE_SIZE", "100"))
    )
    connect_timeout: float = 5.0

    @property
    def sse_url(self) -> str:
        return self.base_url.rstrip("/") + "/" + self.sse_path.lstrip("/")


@dataclass
class ScopeConfig:
    """분석 범위. 실제 인가된 점검에서는 반드시 좁혀서 쓴다.

    ``host_allow`` 가 비어 있으면 전부 허용(개발/실습용). 실전에서는
    대상 호스트 정규식을 반드시 채운다.
    """

    host_allow: list[str] = field(default_factory=list)  # 정규식 문자열 목록
    host_deny: list[str] = field(default_factory=list)
