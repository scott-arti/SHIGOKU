"""vuln type → specialist の routing マッピング。

hypothesis から実行すべき specialist を選択する責務を保持する。
validation・skip reason・cache 書き込みは持たない。
"""

from typing import Dict, List, Set

from src.core.agents.swarm.injection.manager_internal.hunter_registry import (
    hypothesis_specialist_pairs,
)


SPECIALIST_MAP: Dict[str, str] = {
    "sqli": "sqli",
    "xss": "xss",
    "lfi": "lfi",
    "ssti": "ssti",
    "ssrf": "ssrf",
    "api": "sqli",
    "csrf": "xss",
    "idor": "sqli",
    "crlf": "crlf",
    "graphql": "graphql",
}

# SGK-2026-0504: レジストリ駆動の新設ハンター（hypothesis→key）を routing に追加する。
# 既存キーは上書きしない（新規 hypothesis 名のみ許可＝旧9種の routing 不変）。
for _hypothesis, _key in hypothesis_specialist_pairs().items():
    SPECIALIST_MAP.setdefault(_hypothesis, _key)

DEFAULT_SPECIALISTS: List[str] = ["xss", "sqli"]


def select_specialists(
    hypotheses: List[str],
    *,
    available_specialists: Set[str],
) -> List[str]:
    selected: List[str] = []
    for h in hypotheses:
        mapped = SPECIALIST_MAP.get(h)
        if mapped and mapped not in selected:
            selected.append(mapped)

    if not selected:
        selected = list(DEFAULT_SPECIALISTS)

    return [name for name in selected if name in available_specialists]
