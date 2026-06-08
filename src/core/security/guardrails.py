"""セキュリティガードレール - 入出力フィルタリング"""
import os
import re
import base64
from typing import Optional, Tuple

class Guardrails:
    """セキュリティガードレールの基底クラス"""
    _enabled = os.getenv("SHIGOKU_GUARDRAILS", "true").lower() == "true"
    
    @classmethod
    def is_enabled(cls) -> bool:
        """ガードレールが有効か確認"""
        return cls._enabled
    
    @classmethod
    def enable(cls):
        """ガードレールを有効化"""
        cls._enabled = True
    
    @classmethod
    def disable(cls):
        """ガードレールを無効化"""
        cls._enabled = False


class InputGuardrail(Guardrails):
    """入力ガードレール - プロンプトインジェクション検知"""
    
    # Unicodeホモグラフマッピング（キリル文字→ラテン文字）
    HOMOGRAPH_MAP = {
        'а': 'a', 'А': 'A', 'е': 'e', 'Е': 'E', 'о': 'o', 'О': 'O',
        'р': 'p', 'Р': 'P', 'с': 'c', 'С': 'C', 'у': 'y', 'У': 'Y',
        'х': 'x', 'Х': 'X', 'і': 'i', 'І': 'I', 'ј': 'j', 'Ј': 'J',
        'ѕ': 's', 'Ѕ': 'S', 'ԁ': 'd', 'Ԁ': 'D', 'ɡ': 'g', 'ԛ': 'q',
        'ѡ': 'w', 'Ѡ': 'W', 'ν': 'v', 'Ν': 'N', 'Κ': 'K', 'Μ': 'M',
        'Τ': 'T', 'Β': 'B', 'Ζ': 'Z', 'Η': 'H',
    }
    
    # プロンプトインジェクションパターン
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|above|all|prior)\s+instructions?",
        r"disregard\s+(previous|above|all|prior)\s+instructions?",
        r"forget\s+(previous|above|all|prior)\s+instructions?",
        r"ignore\s+all\s+(previous|prior)",  # "ignore all previous"も検知
        r"system\s*:\s*you\s+(are|must|should)",
        r"<\s*admin\s*>",
        r"<\s*root\s*>",
        r"\{\{.*\}\}",  # Template injection
        r"\[SYSTEM\]",
        r"\[INST\].*\[/INST\]",  # Llama instruction format
    ]
    
    @classmethod
    def normalize_unicode_homographs(cls, text: str) -> str:
        """
        Unicodeホモグラフを正規化
        
        視覚的に類似した文字（キリル文字等）をASCIIに変換し、
        ホモグラフ攻撃を防ぐ。
        """
        import unicodedata
        # NFKC正規化で互換文字を統一
        normalized = unicodedata.normalize("NFKC", text)
        # 追加: キリル文字→ラテン文字マッピング
        for homograph, ascii_char in cls.HOMOGRAPH_MAP.items():
            normalized = normalized.replace(homograph, ascii_char)
        return normalized
    
    @classmethod
    def detect_homograph_attack(cls, text: str) -> bool:
        """
        ホモグラフ攻撃の可能性を検知
        
        正規化前後でテキストが変化し、かつ正規化後に
        インジェクションパターンが検出された場合はTrue
        """
        normalized = cls.normalize_unicode_homographs(text)
        if normalized != text:
            # 正規化で変化があった = ホモグラフ文字が含まれていた
            for pattern in cls.INJECTION_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    return True
        return False
    
    @classmethod
    def check(cls, user_input: str) -> Tuple[bool, Optional[str]]:
        """
        ユーザー入力をチェック
        
        Returns:
            (is_safe, reason): 安全ならTrue, 検知したらFalseと理由を返す
        """
        if not cls.is_enabled():
            return True, None
        
        # 1. ホモグラフ攻撃検知（正規化前後の比較）
        if cls.detect_homograph_attack(user_input):
            return False, "Unicode homograph attack detected"
        
        # 2. 正規化後のテキストでパターンマッチング
        normalized_input = cls.normalize_unicode_homographs(user_input)
        for pattern in cls.INJECTION_PATTERNS:
            if re.search(pattern, normalized_input, re.IGNORECASE):
                return False, f"Potential prompt injection detected: {pattern}"
        
        return True, None


class OutputGuardrail(Guardrails):
    """出力ガードレール - 危険なコマンド検知"""
    
    # 危険なコマンドパターン
    DANGEROUS_PATTERNS = [
        # Fork bomb
        (r":\(\)\{\s*:\|\:&\s*\};:", "Fork bomb detected"),
        
        # Recursive delete
        (r"rm\s+-[rf]{1,2}\s+/(?!tmp|var/tmp)", "Dangerous recursive delete"),
        (r"rm\s+--recursive\s+--force\s+/", "Dangerous recursive delete"),
        
        # Disk operations
        (r"dd\s+if=.*of=/dev/(?!null)", "Dangerous disk write"),
        (r"mkfs\.", "Filesystem format attempt"),
        
        # Reverse shell
        (r"/dev/tcp/[^/]+/\d+\s*>&", "Reverse shell detected"),
        (r"nc\s+-[el]+\s+\d+", "Netcat listener detected"),
        (r"bash\s+-i\s*>&\s*/dev/tcp", "Reverse shell detected"),
        
        # Privilege escalation attempts
        (r"chmod\s+[67]777", "Dangerous permission change"),
        (r"sudo\s+su\s+-", "Privilege escalation attempt"),
        
        # Data exfiltration
        (r"curl\s+.*\|\s*bash", "Piping to bash detected"),
        (r"wget\s+.*\|\s*bash", "Piping to bash detected"),
        
        # NoSQL Injection patterns (Heuristic detection)
        (r"\$ne\s*:\s*null", "Potential NoSQL Injection ($ne: null) detected"),
        (r"\$gt\s*:\s*['\"]?['\"]?", "Potential NoSQL Injection ($gt) detected"),
        (r"\$where\s*:", "Dangerous NoSQL $where clause detected"),
        (r"\$regex\s*:", "Potential NoSQL Regex injection detected"),
    ]
    
    @classmethod
    def check(cls, command: str) -> Tuple[bool, Optional[str]]:
        """
        コマンドをチェック
        
        Returns:
            (is_safe, reason): 安全ならTrue, 検知したらFalseと理由を返す
        """
        if not cls.is_enabled():
            return True, None
        
        # パターンマッチング
        for pattern, reason in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, reason
        
        # Base64エンコードされたペイロードをチェック
        is_safe, reason = cls._check_encoded_payload(command)
        if not is_safe:
            return False, reason
        
        return True, None
    
    @classmethod
    def _check_encoded_payload(cls, command: str) -> Tuple[bool, Optional[str]]:
        """Base64/Base32エンコードされたペイロードを検知"""
        # Base64パターンを検出（より長いパターンのみ）
        base64_pattern = r"[A-Za-z0-9+/=]{30,}"
        matches = re.findall(base64_pattern, command)
        
        for match in matches:
            # "=" padding を追加してBase64デコード試行
            try:
                # paddingを調整
                padding = (4 - len(match) % 4) % 4
                padded_match = match + "=" * padding
                
                decoded = base64.b64decode(padded_match).decode('utf-8', errors='ignore')
                
                # 少なくとも5文字の有効なテキストがあるかチェック
                if len(decoded) < 5:
                    continue
                
                # デコード結果に危険パターンがあるかチェック
                for pattern, reason in cls.DANGEROUS_PATTERNS:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        return False, f"Encoded payload detected: {reason}"
            except Exception:
                continue
        
        return True, None


def check_input(user_input: str) -> Tuple[bool, Optional[str]]:
    """入力チェックのヘルパー関数"""
    return InputGuardrail.check(user_input)


def check_output(command: str) -> Tuple[bool, Optional[str]]:
    """出力チェックのヘルパー関数"""
    return OutputGuardrail.check(command)
