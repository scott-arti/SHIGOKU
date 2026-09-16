"""レジストリ駆動の追加ハンター定義（SGK-2026-0504）。

旧来の9ハンター(sqli/xss/lfi/cmd_ssrf/ssrf/ssti/cors/crlf/graphql/redirect)は
`InjectionManagerAgent` に個別の `run_*_hunter` を持ち、dispatch も if/elif で
ハードコードされている。新設ハンター（NoSQL 等）を毎回3箇所（登録・routing・dispatch）へ
手書きで追記すると配線漏れが起きるため、ここでは新ハンターを「データ」として宣言する。

このリストに1エントリ足すだけで:
  1. `InjectionManagerAgent._initialize_specialists` が `self.specialists[key]` へ登録し、
  2. `specialist_router.SPECIALIST_MAP` が hypothesis→key の routing を得て、
  3. `InjectionManagerAgent._run_registered_hunter` が汎用 dispatch で起動する。

各ハンターは `Specialist`(`swarm/base.py`) を継承し `execute_with_retry(task, quick_mode)` を
持つ前提（旧9種と同一契約）。signal→hypothesis の生成規則自体は脆弱性ごとの知識のため
`manager_internal/unknown_hypotheses.py` 側に置く（`hypotheses` はそこで生成される名前と一致させる）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class HunterSpec:
    """自走経路へレジストリ駆動で載せる追加ハンターの宣言。

    key: `self.specialists` のキー兼 dispatch キー（例 "nosql"）。
    module / class_name: lazy import 対象（旧9種と同じく import 失敗は他を止めない）。
    hypotheses: この specialist を選択させる hypothesis 名の集合
        （`unknown_hypotheses.build_unknown_hypotheses` が生成する名前と一致させる）。
    vuln_name / severity: 汎用結果整形 `format_simple_hunter_result` の表示用。
    """

    key: str
    module: str
    class_name: str
    hypotheses: Tuple[str, ...]
    vuln_name: str
    severity: str


# 新設ハンターの宣言（1エントリ=1配線）。まずは pilot として NoSQL を載せる。
NEW_HUNTER_SPECS: Tuple[HunterSpec, ...] = (
    HunterSpec(
        key="nosql",
        module="src.core.agents.swarm.injection.smart_nosql",
        class_name="SmartNoSQLHunter",
        hypotheses=("nosql",),
        vuln_name="NoSQL Injection",
        severity="HIGH",
    ),
)


HUNTER_SPEC_BY_KEY: Dict[str, HunterSpec] = {spec.key: spec for spec in NEW_HUNTER_SPECS}


def hypothesis_specialist_pairs() -> Dict[str, str]:
    """hypothesis 名 → specialist key の routing 追加分を返す（`SPECIALIST_MAP` 拡張用）。"""
    pairs: Dict[str, str] = {}
    for spec in NEW_HUNTER_SPECS:
        for hypothesis in spec.hypotheses:
            pairs[hypothesis] = spec.key
    return pairs
