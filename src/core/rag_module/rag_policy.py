"""
RAG Usage Policy: コンポーネント別 RAG 参照可否と novelty/counter-example budget 管理。

SGK-2026-0262: 継続学習アーキテクチャ参照ドキュメントの設計原則を実装レベルで固定する。
- RAG は gating しない
- RAG は hypothesis advisor に限定
- novelty budget / counter-example budget を明示的に持つ
- graceful degradation: RAG が落ちても本流は止めない

責務固定表（SGK-2026-0262 §2.5）に基づくコンポーネント別 RAG 参照ポリシー:
  Recon:   consume only（RAGHint を受け取るが、生成しない）
  MC:      own（いつ RAG を引くかを制御する）
  Swarm:   consume（RAGHint を戦略ヒントとして利用）
  Recipe:  consume（follow-up hint としてのみ利用、trigger 正本にはしない）
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src.core.rag_module.rag_types import LearningPolicy


# ── RAG 使用状況のトレース ──

class RAGUsageDecision(str, Enum):
    """MC が下す RAG 利用判断"""
    NO_RAG = "no_rag"              # RAG 不要（KG + signal で十分）
    RAG_ASSIST = "rag_assist"       # RAG を補助的に利用
    RAG_RETRY = "rag_retry"         # Agentic RAG で再検索
    RAG_FALLBACK = "rag_fallback"   # 他が失敗した場合のみ RAG


@dataclass
class RAGBudgetState:
    """RAG 利用予算の実行時状態"""
    total_candidates: int = 0          # 全候補数
    rag_matched: int = 0               # RAG がマッチした数
    novelty_used: int = 0              # 既知例に似ない候補の消費数
    counter_example_used: int = 0      # RAG 逆張り探索の消費数

    @property
    def novelty_ratio(self) -> float:
        if self.total_candidates == 0:
            return 0.0
        return self.novelty_used / self.total_candidates

    @property
    def counter_example_ratio(self) -> float:
        if self.total_candidates == 0:
            return 0.0
        return self.counter_example_used / self.total_candidates


# ── ポリシー判断関数 ──

def should_use_rag_for_component(
    component: str,
    context: Optional[dict] = None,
    policy: Optional[LearningPolicy] = None,
) -> RAGUsageDecision:
    """
    指定されたコンポーネントが RAG を参照すべきか判断する。

    Args:
        component: "recon", "mc", "swarm", "recipe" のいずれか
        context: 判断に使う追加コンテキスト
        policy: LearningPolicy（省略時はデフォルト）

    Returns:
        RAGUsageDecision
    """
    if policy is None:
        policy = get_default_policy()

    if not policy.enable_rag:
        return RAGUsageDecision.NO_RAG

    # コンポーネント別の基本ポリシー
    component_policy = {
        "recon": _recon_rag_policy,
        "mc": _mc_rag_policy,
        "swarm": _swarm_rag_policy,
        "recipe": _recipe_rag_policy,
    }

    handler = component_policy.get(component, _mc_rag_policy)
    return handler(context, policy)


def _recon_rag_policy(context: Optional[dict], policy: LearningPolicy) -> RAGUsageDecision:
    """
    Recon は RAG から checklist / blind-spot / caution の hint を受け取ることはできるが、
    脆弱性評価や suppress の正本にはしない。
    原則として NO_RAG または RAG_ASSIST（補助のみ）。
    """
    if context and context.get("needs_checklist"):
        return RAGUsageDecision.RAG_ASSIST
    return RAGUsageDecision.NO_RAG


def _mc_rag_policy(context: Optional[dict], policy: LearningPolicy) -> RAGUsageDecision:
    """
    MC の RAG 参照ポリシー:
    - まず KG と signal を見る
    - KG + signal で十分なら RAG を引かない
    - attack surface が曖昧で仮説が多いとき、または specialist 選定に複数案があるときに RAG_ASSIST
    - 失敗後の再試行では RAG_FALLBACK
    """
    if context is None:
        return RAGUsageDecision.NO_RAG

    # 明示的に RAG が必要とされているケース
    if context.get("require_rag"):
        return RAGUsageDecision.RAG_ASSIST

    # 失敗後のフォールバック
    if context.get("is_fallback") or context.get("error_count", 0) > 0:
        return RAGUsageDecision.RAG_FALLBACK

    # 曖昧な局面（仮説が多い、または specialist 選定に迷う）
    if context.get("ambiguous_surface") or len(context.get("candidates", [])) > 3:
        return RAGUsageDecision.RAG_ASSIST

    # KG + signal だけで十分
    return RAGUsageDecision.NO_RAG


def _swarm_rag_policy(context: Optional[dict], policy: LearningPolicy) -> RAGUsageDecision:
    """
    Swarm は RAG から strategy hint / similar-case / blind-spot を受け取る。
    原則 RAG_ASSIST（補助ヒントとして）。
    """
    return RAGUsageDecision.RAG_ASSIST if policy.enable_rag else RAGUsageDecision.NO_RAG


def _recipe_rag_policy(context: Optional[dict], policy: LearningPolicy) -> RAGUsageDecision:
    """
    Recipe は RAG から primary trigger を受け取らない。
    許可されるのは follow-up hint / caution hint / variant checklist のみ。
    """
    if context and context.get("is_followup"):
        return RAGUsageDecision.RAG_ASSIST
    # Recipe trigger の正本は signal + KG
    return RAGUsageDecision.NO_RAG


# ── Novelty / Counter-Example Budget ──

def should_explore_novelty(budget_state: RAGBudgetState, policy: LearningPolicy) -> bool:
    """
    novelty budget の範囲内で未知候補を探索すべきか判断する。

    RAG に出ないから却下、を禁止し、既知例に似ない候補も一定割合で探索する。
    """
    if policy.novelty_budget <= 0:
        return False
    return budget_state.novelty_ratio < policy.novelty_budget


def should_try_counter_example(budget_state: RAGBudgetState, policy: LearningPolicy) -> bool:
    """
    counter-example budget の範囲内で RAG 推奨と逆の仮説を試すべきか判断する。

    既知の「良さそうな観点」に逆張りする余地を残す。
    """
    if policy.counter_example_budget <= 0:
        return False
    return budget_state.counter_example_ratio < policy.counter_example_budget


def check_rag_usage_budget(
    current_rag_queries: int,
    policy: LearningPolicy,
) -> bool:
    """
    RAG クエリ回数が予算内かチェックする。

    Returns:
        True ならまだ RAG を引ける
    """
    if policy.rag_usage_budget <= 0:
        return False
    return current_rag_queries < policy.rag_usage_budget


# ── デフォルトポリシー ──

_default_policy: Optional[LearningPolicy] = None


def get_default_policy() -> LearningPolicy:
    """デフォルトの LearningPolicy インスタンスを取得"""
    global _default_policy
    if _default_policy is None:
        _default_policy = LearningPolicy()
    return _default_policy


def set_default_policy(policy: LearningPolicy) -> None:
    """デフォルトの LearningPolicy を上書き"""
    global _default_policy
    _default_policy = policy
