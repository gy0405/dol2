"""돌돌이 MCP 서버.

사용자의 AI가 호출하는 쪽. 공식 Burp MCP에서 패킷을 끌어와(파이프라인) 의심
벡터를 돌려준다. 공식 SDK 2.x의 MCPServer(구 FastMCP) + stdio 트랜스포트.

노출 도구:
  * burp_tools          — 공식 Burp MCP가 실제 노출하는 도구 목록(연결 점검용)
  * analyze_history     — 히스토리를 끌어와 파이프라인+게이트를 돌려 Finding 반환
  * peek_history        — 원본 1건 미리보기(디버그/연결 확인용)

주의: 이 도구들은 '우선순위화' 결과를 준다. 취약 '판정'이 아니며, 모든 항목은
원본 패킷(history_index)으로 사람이 되짚어 확인해야 한다.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any

from mcp.server.mcpserver import MCPServer

from .burp_client import BurpMcpClient
from .config import BurpConfig, ScopeConfig
from .coverage import build_coverage, render_coverage
from .gate import run_detectors
from .guide import guide_items_for, render_report
from .models import parse_history_item
from .pipeline.filter import coarse_filter
from .pipeline.normalize import normalize
from .pipeline.score import score
from .vectors.xss import tag_xss_surface

server = MCPServer(name="dol2", version="0.1.0",
                   instructions="Burp 트래픽 기반 취약점 판단 '지원' 도구. 판정이 아니라 우선순위화.")


def _pipeline(raw_items, scope: ScopeConfig):
    """raw 히스토리 → 파싱 → 필터 → 정규화 → 점수."""
    records = []
    for it in raw_items:
        try:
            records.append(parse_history_item(it))
        except ValueError:
            continue  # 파싱 불가 항목은 건너뜀(비표준/바이너리)
    records = coarse_filter(records, scope)
    records = normalize(records)
    records = score(records)
    records = tag_xss_surface(records)   # 반사형 XSS 표면에 'xss-surface' 신호 부착
    return records


@server.tool(description="공식 Burp MCP가 실제 노출하는 도구 목록을 반환(연결 점검).")
async def burp_tools() -> list[str]:
    client = BurpMcpClient()
    async with client.connect():
        return await client.list_tools()


@server.tool(description="프록시 히스토리 원본 N건을 그대로 미리보기(디버그/연결 확인).")
async def peek_history(count: int = 1) -> list[dict[str, Any]]:
    client = BurpMcpClient()
    async with client.connect():
        items = await client.get_proxy_history(count=count, offset=0)
    return [asdict(it) for it in items]


@server.tool(
    description=(
        "프록시 히스토리를 끌어와 선별·정규화·점수·impact gate를 돌려 의심 공격 벡터를 "
        "반환한다. host_allow 정규식으로 범위를 좁힐 것(실전 필수)."
    )
)
async def analyze_history(
    host_allow: list[str] | None = None,
    host_deny: list[str] | None = None,
    max_items: int = 1000,
) -> dict[str, Any]:
    scope = ScopeConfig(host_allow=host_allow or [], host_deny=host_deny or [])
    client = BurpMcpClient()

    raw_items = []
    async with client.connect():
        async for it in client.iter_all_history():
            raw_items.append(it)
            if len(raw_items) >= max_items:
                break

    records = _pipeline(raw_items, scope)
    findings = run_detectors(records)
    coverage = build_coverage(records)

    findings_out = []
    for f in findings:
        d = asdict(f)
        # 주요정보통신기반시설 가이드(웹) 항목 매핑을 붙임
        d["guide_refs"] = [
            {"code": g.code, "name": g.name, "severity": g.severity, "page": g.page}
            for g in guide_items_for(f.vector)
        ]
        findings_out.append(d)

    return {
        "summary": {
            "raw_fetched": len(raw_items),
            "after_filter": len(records),
            "findings": len(findings),
            "note": "판정이 아니라 우선순위화. 각 항목은 history_index로 원본 패킷 확인 필요.",
        },
        # 가이드 양식 결과지 + 커버리지 피드백(텍스트). 사용자가 바로 읽는 보고서 형태.
        "report": render_report(findings) + "\n\n" + render_coverage(coverage),
        "findings": findings_out,
        "coverage": [asdict(c) for c in coverage],
    }


def main() -> None:
    """stdio 트랜스포트로 서버 실행(Claude Desktop 등이 띄우는 기본 방식)."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
