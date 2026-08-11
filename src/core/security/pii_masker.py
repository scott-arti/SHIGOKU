"""
PIIMasker: 双方向PII/機密情報マスキング

AI APIへの送信前にPII/機密情報をトークン化してマスクし、
ツール実行時に元の値を復元する双方向マスキング機能。

設計:
    1. マスク時: 検出したPIIを `[PII:TYPE:TOKEN_ID]` 形式に置換
    2. トークンマップ: TOKEN_ID → 元の値 の対応表を保持
    3. 復元時: ツール引数内のトークンを元の値に戻す
"""
from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class PIIPattern:
    """PIIパターン定義"""
    name: str
    pattern: str
    description: str = ""


@dataclass
class MaskResult:
    """マスク処理結果"""
    original: str
    masked: str
    token_map: Dict[str, str] = field(default_factory=dict)
    detections: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def has_pii(self) -> bool:
        return len(self.detections) > 0


class PIIMasker:
    """
    双方向PII/機密情報マスキングクラス
    
    マスク→外部AI送信→復元のフローをサポート。
    
    使用例:
        masker = PIIMasker()
        
        # マスク
        result = masker.mask("My API key is sk-1234567890abcdef")
        print(result.masked)  # "My API key is [PII:OPENAI_API_KEY:abc123]"
        
        # 復元（ツール実行時）
        restored = masker.unmask("[PII:OPENAI_API_KEY:abc123]")
        print(restored)  # "sk-1234567890abcdef"
    """
    
    # トークンパターン（復元用）
    TOKEN_PATTERN = re.compile(r"\[PII:([A-Z_]+):([a-f0-9]{8})\]")
    
    # PIIパターン定義（優先度順）
    PATTERNS: List[PIIPattern] = [
        # === 秘密鍵・証明書 ===
        PIIPattern(
            name="PRIVATE_KEY",
            pattern=r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|EC|DSA|OPENSSH)\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?(?:PRIVATE|EC|DSA|OPENSSH)\s+KEY-----",
            description="SSH/RSA/EC秘密鍵",
        ),
        
        # === APIキー（プロバイダ固有） ===
        PIIPattern(
            name="OPENAI_API_KEY",
            pattern=r"sk-[a-zA-Z0-9]{20,}",
            description="OpenAI APIキー",
        ),
        PIIPattern(
            name="AWS_ACCESS_KEY",
            pattern=r"AKIA[0-9A-Z]{16}",
            description="AWS Access Key ID",
        ),
        PIIPattern(
            name="AWS_SECRET_KEY",
            pattern=r"(?i)(?:aws)?_?secret_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
            description="AWS Secret Access Key",
        ),
        PIIPattern(
            name="GITHUB_TOKEN",
            pattern=r"gh[pousr]_[A-Za-z0-9_]{36,}",
            description="GitHub Personal Access Token",
        ),
        PIIPattern(
            name="SLACK_TOKEN",
            pattern=r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
            description="Slack Token",
        ),
        PIIPattern(
            name="STRIPE_KEY",
            pattern=r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
            description="Stripe APIキー",
        ),
        PIIPattern(
            name="GOOGLE_API_KEY",
            pattern=r"AIza[0-9A-Za-z\-_]{35}",
            description="Google APIキー",
        ),
        PIIPattern(
            name="DISCORD_TOKEN",
            pattern=r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
            description="Discord Bot Token",
        ),
        
        # === JWT ===
        PIIPattern(
            name="JWT",
            pattern=r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            description="JSON Web Token",
        ),
        
        # === Bearer Token ===
        PIIPattern(
            name="BEARER_TOKEN",
            pattern=r"(?i)Bearer\s+[A-Za-z0-9\-_\.~\+\/]+=*",
            description="Bearer認証トークン",
        ),
        
        # === クレジットカード番号 ===
        PIIPattern(
            name="CREDIT_CARD",
            pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            description="クレジットカード番号",
        ),
        
        # === メールアドレス ===
        PIIPattern(
            name="EMAIL",
            pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            description="メールアドレス",
        ),
        
        # === 電話番号（日本） ===
        PIIPattern(
            name="PHONE_JP",
            pattern=r"(?:\+81|0)[0-9]{1,4}[-\s]?[0-9]{1,4}[-\s]?[0-9]{4}",
            description="日本の電話番号",
        ),
        
        # === IPアドレス ===
        PIIPattern(
            name="IPV4",
            pattern=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            description="IPv4アドレス",
        ),
        
        # === UUID ===
        PIIPattern(
            name="UUID",
            pattern=r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            description="UUID",
        ),
        
        # === マイナンバー（12桁） ===
        PIIPattern(
            name="MY_NUMBER",
            pattern=r"\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
            description="マイナンバー（12桁）",
        ),
    ]
    
    # トークンをスキップするためのパターン（二重マスク防止）
    SKIP_TOKEN_PATTERN = re.compile(r"\[PII:[A-Z_]+:[a-f0-9]{8}\]")
    
    # IPアドレスのホワイトリスト
    IP_WHITELIST = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "255.255.255.0"}
    
    def __init__(self, enabled: bool = True, custom_patterns: Optional[List[PIIPattern]] = None):
        """
        初期化
        
        Args:
            enabled: マスキングを有効にするか
            custom_patterns: 追加のカスタムパターン
        """
        self.enabled = enabled
        self._patterns = list(self.PATTERNS)
        
        if custom_patterns:
            self._patterns.extend(custom_patterns)
        
        # 正規表現をコンパイル
        self._compiled = [
            (p, re.compile(p.pattern, re.MULTILINE))
            for p in self._patterns
        ]
        
        # グローバルトークンマップ（セッション中保持）
        self._token_map: Dict[str, str] = {}
        # 逆引きマップ（同じ値に同じトークンを割り当てる）
        self._reverse_map: Dict[str, str] = {}
    
    def _generate_token(self, pii_type: str, original_value: str) -> str:
        """
        トークンを生成し、マップに登録
        
        同じ値には同じトークンを返す（冪等性）
        """
        # 既存のトークンがあれば再利用
        if original_value in self._reverse_map:
            return self._reverse_map[original_value]
        
        # 新規トークン生成
        token_id = uuid.uuid4().hex[:8]
        token = f"[PII:{pii_type}:{token_id}]"
        
        self._token_map[token] = original_value
        self._reverse_map[original_value] = token
        
        return token

    def _register_query_value_token(self, value: str) -> str:
        """SGK-2026-0439: register an unrecognized query value as a generic
        token (deny-by-default masking). Reuses the existing private token
        registration so idempotency and the token format stay unchanged."""
        return self._generate_token("VALUE", value)

    def mask_url_query_values(self, url: str) -> str:
        """SGK-2026-0439: deny-by-default masking of EVERY query param value
        in a URL while preserving param names and locations.

        - Known secret patterns are masked via the existing ``mask()`` (typed
          token). Unrecognized values (``?id=12345``, ``?q=test``) are
          tokenized as a whole via the same token_map mechanism (generic
          ``[PII:VALUE:...]`` token, idempotent through the reverse map).
        - Empty values stay empty; already-tokenized values are left as-is
          (no nested tokens); URLs without a query are returned unchanged.
        - ``masker.unmask(mask_url_query_values(url))`` restores the same
          query values (round-trip).
        - Disabled masker returns the URL unchanged.
        """
        if not self.enabled or not url:
            return url

        from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

        parsed = urlsplit(url)
        if not parsed.query:
            return url

        masked_pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if value == "":
                masked_pairs.append((key, ""))
                continue
            if self.SKIP_TOKEN_PATTERN.fullmatch(value):
                # already a token (idempotent re-masking) — never nest
                masked_pairs.append((key, value))
                continue
            result = self.mask(value)
            if result.masked != value:
                # typed token (or partial replacement) from known patterns
                masked_pairs.append((key, result.masked))
            else:
                # unrecognized format → deny-by-default generic token
                masked_pairs.append((key, self._register_query_value_token(value)))

        def _quote_via(
            string: str | bytes,
            safe: str | bytes,
            encoding: str = "utf-8",
            errors: str = "strict",
        ) -> str:
            # keep [PII:...] tokens verbatim so unmask() can restore them;
            # everything else keeps %-encoding style
            return quote(str(string), safe="[]:")

        new_query = urlencode(masked_pairs, quote_via=_quote_via)
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
        )

    def has_tokens(self, text: str) -> bool:
        """SGK-2026-0439: True when TOKEN_PATTERN matches anywhere in
        ``text`` — used for the fail-closed residual check after unmask."""
        return bool(text) and bool(self.TOKEN_PATTERN.search(text))

    def mask(self, text: str) -> MaskResult:
        """
        テキスト内のPII/機密情報をトークン化してマスクする
        
        Args:
            text: マスク対象のテキスト
            
        Returns:
            MaskResult: マスク結果（token_map含む）
        """
        if not self.enabled or not text:
            return MaskResult(original=text, masked=text)
        
        masked = text
        detections: List[Dict[str, Any]] = []
        local_token_map: Dict[str, str] = {}
        
        for pattern_def, compiled in self._compiled:
            # マッチを検索（置換後の位置ずれを避けるため、逆順で処理）
            matches = list(compiled.finditer(masked))
            
            for match in reversed(matches):
                matched_text = match.group(0)
                
                # 既存のトークン内のマッチはスキップ（二重マスク防止）
                start_pos = match.start()
                
                # マッチ箇所が既存トークン内かチェック
                is_inside_token = False
                for token_match in self.SKIP_TOKEN_PATTERN.finditer(masked):
                    if token_match.start() <= start_pos < token_match.end():
                        is_inside_token = True
                        break
                if is_inside_token:
                    continue
                
                # IPアドレスのホワイトリストチェック
                if pattern_def.name == "IPV4" and matched_text in self.IP_WHITELIST:
                    continue
                
                # トークン生成
                token = self._generate_token(pattern_def.name, matched_text)
                local_token_map[token] = matched_text
                
                # 置換
                masked = masked[:match.start()] + token + masked[match.end():]
                
                detections.append({
                    "type": pattern_def.name,
                    "description": pattern_def.description,
                    "token": token,
                })
        
        if detections:
            logger.info(
                "PIIMasker: Masked %d item(s): %s",
                len(detections),
                [d["type"] for d in detections]
            )
        
        return MaskResult(
            original=text,
            masked=masked,
            token_map=local_token_map,
            detections=detections,
        )
    
    def unmask(self, text: str) -> str:
        """
        トークンを元の値に復元する
        
        Args:
            text: トークンを含むテキスト
            
        Returns:
            復元されたテキスト
        """
        if not text:
            return text
        
        def replace_token(match: re.Match) -> str:
            full_token = match.group(0)
            return self._token_map.get(full_token, full_token)
        
        return self.TOKEN_PATTERN.sub(replace_token, text)
    
    def unmask_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        辞書内のすべての文字列値を再帰的に復元する
        
        Args:
            data: ツール引数などの辞書
            
        Returns:
            復元された辞書
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.unmask(value)
            elif isinstance(value, dict):
                result[key] = self.unmask_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.unmask(v) if isinstance(v, str)
                    else self.unmask_dict(v) if isinstance(v, dict)
                    else v
                    for v in value
                ]
            else:
                result[key] = value
        return result
    
    def mask_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        メッセージリスト内のcontentをマスクする
        
        Args:
            messages: LLMに送信するメッセージリスト
            
        Returns:
            マスク済みメッセージリスト（元のリストは変更しない）
        """
        if not self.enabled:
            return messages
        
        masked_messages = []
        
        for msg in messages:
            new_msg = dict(msg)
            
            if "content" in new_msg and isinstance(new_msg["content"], str):
                result = self.mask(new_msg["content"])
                new_msg["content"] = result.masked
            
            masked_messages.append(new_msg)
        
        return masked_messages
    
    def clear_session(self) -> None:
        """セッション中のトークンマップをクリア"""
        self._token_map.clear()
        self._reverse_map.clear()
        logger.debug("PIIMasker: Session cleared")
    
    def get_token_count(self) -> int:
        """現在保持しているトークン数を取得"""
        return len(self._token_map)


# モジュールレベルのシングルトン
_masker_instance: Optional[PIIMasker] = None


def get_pii_masker(enabled: bool = True) -> PIIMasker:
    """PIIMaskerのシングルトンインスタンスを取得"""
    if globals().get("_masker_instance") is None:
        globals()["_masker_instance"] = PIIMasker(enabled=enabled)
    return globals()["_masker_instance"]


def mask_pii(text: str) -> str:
    """便利関数: テキスト内のPIIをマスクして返す"""
    return get_pii_masker().mask(text).masked


def unmask_pii(text: str) -> str:
    """便利関数: トークンを元の値に復元して返す"""
    return get_pii_masker().unmask(text)
