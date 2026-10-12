"""수평적 권한 우회 / IDOR 탐지기.

cross_score가 붙여 준 'authz-divergent' 신호(같은 엔드포인트 템플릿을 서로 다른
신원이 접근했고 상태코드가 갈림)를 전제로 삼는다.

여기서도 impact gate 원칙은 동일하다:
  precondition      = 객체 참조가 있는 엔드포인트 ({id} 포함)
  enabling_condition = 신원별 접근 결과가 갈리거나, 다른 신원의 객체에 200 접근 관찰

지금은 '수동 검토 후보'를 묶어 올리는 수준이다. 확증(다른 신원으로 재전송 →
200이면 IDOR 확정)은 send_http*_request를 쓰는 능동 단계로 뒤에 붙인다.
"""
from __future__ import annotations

from ..models import Evidence, Finding, HttpRecord
from ..pipeline.score import group_by_template


class HorizontalAuthzDetector:
    name = "horizontal-authz"

    def detect(self, records: list[HttpRecord]) -> list[Finding]:
        findings: list[Finding] = []
        groups = group_by_template(records)

        for template, group in groups.items():
            if "{id}" not in template:
                continue  # 객체 참조 전제가 없음 → IDOR 표면 아님

            identities = {r.identity.label for r in group if r.identity}
            if len(identities) < 2:
                continue  # 비교할 신원이 하나뿐이면 수평 권한 판단 불가

            # 보강 조건: 신원별 상태코드가 갈리거나, 성공(2xx)이 섞여 있음
            statuses = {
                r.response.status for r in group if r.response and r.response.present
            }
            divergent = len(statuses) > 1
            has_success = any(
                r.response and r.response.present and 200 <= r.response.status < 300
                for r in group
            )
            if not (divergent and has_success):
                continue

            evidence = [
                Evidence(
                    method=r.request.method,
                    endpoint_template=template,
                    actual_target=r.request.target,
                    identity_label=r.identity.label if r.identity else "unknown",
                    status=r.response.status if (r.response and r.response.present) else None,
                    note=";".join(r.signals),
                    history_index=i,
                )
                for i, r in enumerate(group)
            ]

            findings.append(
                Finding(
                    vector="horizontal-authz",
                    severity="high",
                    endpoint_template=template,
                    precondition=f"객체 참조 엔드포인트({template}) — 서로 다른 객체 id 접근",
                    enabling_condition=(
                        f"서로 다른 신원({len(identities)}종)의 접근 결과가 갈림 "
                        f"(status={sorted(statuses)}), 2xx 성공 포함"
                    ),
                    attack_class="수평적 권한 우회 / IDOR 후보",
                    poc_sketch=(
                        "신원 A의 세션/토큰으로 신원 B 소유 객체 id를 재전송해 2xx+타인 데이터가 "
                        "반환되는지 확인 (send_http1_request로 능동 검증)"
                    ),
                    cve_hint="CWE-639 (Authorization Bypass Through User-Controlled Key)",
                    evidence=evidence,
                )
            )
        return findings
