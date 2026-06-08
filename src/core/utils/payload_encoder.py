"""
Payload Encoder - ペイロードエンコーディングユーティリティ

各種エンコーディング手法を提供。
SSTI, XSS, SSRF, SQLi 等の脆弱性テストで利用可能。
"""

from typing import List
from urllib.parse import quote, quote_plus
import html


class PayloadEncoder:
    """
    ペイロードエンコーディングユーティリティ
    
    WAF回避やコンテキスト適応のための各種エンコード機能を提供。
    """
    
    @staticmethod
    def url_encode(payload: str, safe: str = '') -> str:
        """
        URL エンコード
        
        Args:
            payload: エンコード対象文字列
            safe: エンコードしない文字
        
        Returns:
            URLエンコードされた文字列
        
        Example:
            >>> PayloadEncoder.url_encode("{{7*7}}")
            '%7B%7B7%2A7%7D%7D'
        """
        return quote(payload, safe=safe)
    
    @staticmethod
    def url_encode_plus(payload: str) -> str:
        """
        URL エンコード（スペースを+に変換）
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            URLエンコードされた文字列（スペース→+）
        """
        return quote_plus(payload)
    
    @staticmethod
    def double_url_encode(payload: str, safe: str = '') -> str:
        """
        Double URL エンコード
        
        WAFバイパスに有効。2重エンコードでフィルタを回避。
        
        Args:
            payload: エンコード対象文字列
            safe: エンコードしない文字
        
        Returns:
            2重URLエンコードされた文字列
        
        Example:
            >>> PayloadEncoder.double_url_encode("{{7*7}}")
            '%257B%257B7%252A7%257D%257D'
        """
        first_encode = quote(payload, safe=safe)
        return quote(first_encode, safe=safe)
    
    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """
        HTML Entity エンコード（数値参照）
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            HTML数値文字参照でエンコードされた文字列
        
        Example:
            >>> PayloadEncoder.html_entity_encode("{{7*7}}")
            '&#123;&#123;7&#42;7&#125;&#125;'
        """
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def html_entity_hex_encode(payload: str) -> str:
        """
        HTML Entity エンコード（16進数参照）
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            HTML16進数文字参照でエンコードされた文字列
        
        Example:
            >>> PayloadEncoder.html_entity_hex_encode("<script>")
            '&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;'
        """
        return ''.join(f'&#x{ord(c):x};' for c in payload)
    
    @staticmethod
    def html_escape(payload: str) -> str:
        """
        HTML エスケープ（標準）
        
        Args:
            payload: エスケープ対象文字列
        
        Returns:
            HTMLエスケープされた文字列
        """
        return html.escape(payload)
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        r"""
        Unicode エスケープ
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            Unicodeエスケープされた文字列
        
        Example:
            >>> PayloadEncoder.unicode_encode("{{7*7}}")
            '\\u007b\\u007b7\\u002a7\\u007d\\u007d'
        """
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def unicode_encode_upper(payload: str) -> str:
        r"""
        Unicode エスケープ（大文字）
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            Unicodeエスケープされた文字列（大文字16進数）
        """
        return ''.join(f'\\u{ord(c):04X}' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """
        Base64 エンコード
        
        WAFバイパスによく使われる。デコード処理がある場合に有効。
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            Base64エンコードされた文字列
        
        Example:
            >>> PayloadEncoder.base64_encode("<script>")
            'PHNjcmlwdD4='
        """
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """
        16進数 エンコード
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            16進数エンコードされた文字列（0x形式）
        
        Example:
            >>> PayloadEncoder.hex_encode("abc")
            '0x616263'
        """
        return '0x' + payload.encode().hex()
    
    @staticmethod
    def hex_encode_spaced(payload: str) -> str:
        """
        16進数 エンコード（スペース区切り）
        
        SQLi等でよく使われる。
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            16進数エンコードされた文字列（スペース区切り）
        
        Example:
            >>> PayloadEncoder.hex_encode_spaced("abc")
            '61 62 63'
        """
        return ' '.join(f'{ord(c):02x}' for c in payload)
    
    @staticmethod
    def mixed_case(payload: str) -> str:
        """
        大小文字混合（Case Variation）
        
        WAFのパターンマッチングを回避。
        
        Args:
            payload: エンコード対象文字列
        
        Returns:
            大小文字が交互になった文字列
        
        Example:
            >>> PayloadEncoder.mixed_case("script")
            'sCrIpT'
        """
        return ''.join(
            c.upper() if i % 2 else c.lower() 
            for i, c in enumerate(payload)
        )
    
    @staticmethod
    def insert_comments(payload: str, comment_style: str = "sql") -> str:
        """
        コメント挿入
        
        キーワードをコメントで分割してWAFを回避。
        
        Args:
            payload: エンコード対象文字列
            comment_style: "sql"(/**/) or "html"(<!---->)
        
        Returns:
            コメントが挿入された文字列
        
        Example:
            >>> PayloadEncoder.insert_comments("SELECT", "sql")
            'S/**/E/**/L/**/E/**/C/**/T'
        """
        if comment_style == "sql":
            comment = "/**/"
        elif comment_style == "html":
            comment = "<!---->"
        else:
            comment = ""
        return comment.join(payload)
    
    @staticmethod
    def insert_newlines(payload: str, newline_type: str = "crlf") -> str:
        """
        改行挿入
        
        HTTPヘッダーインジェクション等で使用。
        
        Args:
            payload: エンコード対象文字列
            newline_type: "crlf", "lf", "cr", "encoded"
        
        Returns:
            改行が挿入された文字列
        """
        newlines = {
            "crlf": "\r\n",
            "lf": "\n",
            "cr": "\r",
            "encoded": "%0d%0a",
        }
        nl = newlines.get(newline_type, "\n")
        return nl.join(payload)
    
    @staticmethod
    def null_byte_insert(payload: str, position: str = "prefix") -> str:
        """
        NULLバイト挿入
        
        ファイル拡張子チェック等のバイパスに使用。
        
        Args:
            payload: エンコード対象文字列
            position: "prefix", "suffix", "between"
        
        Returns:
            NULLバイトが挿入された文字列
        
        Example:
            >>> PayloadEncoder.null_byte_insert("shell.php", "suffix")
            'shell.php%00'
        """
        null = "%00"
        if position == "prefix":
            return null + payload
        elif position == "suffix":
            return payload + null
        elif position == "between":
            return null.join(payload)
        return payload
    
    @staticmethod
    def concat_chunks(payload: str, chunk_size: int = 2, 
                      concat_style: str = "sql") -> str:
        """
        文字列を分割して結合式に変換
        
        SQLiでよく使われるCONCAT回避テクニック。
        
        Args:
            payload: 変換対象文字列
            chunk_size: 分割サイズ
            concat_style: "sql"(CONCAT), "js"(+), "python"(+)
        
        Returns:
            結合式に変換された文字列
        
        Example:
            >>> PayloadEncoder.concat_chunks("admin", 2, "sql")
            "CONCAT('ad','mi','n')"
        """
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        
        if concat_style == "sql":
            quoted = [f"'{c}'" for c in chunks]
            return f"CONCAT({','.join(quoted)})"
        elif concat_style in ("js", "python"):
            quoted = [f"'{c}'" for c in chunks]
            return "+".join(quoted)
        return payload
    
    @classmethod
    def encode_all_variants(cls, payload: str) -> List[str]:
        """
        全エンコード亜種を生成
        
        Args:
            payload: 元のペイロード
        
        Returns:
            各種エンコード済みペイロードのリスト
        """
        return [
            payload,  # オリジナル
            cls.url_encode(payload),
            cls.double_url_encode(payload),
            cls.html_entity_encode(payload),
            cls.html_entity_hex_encode(payload),
            cls.unicode_encode(payload),
            cls.base64_encode(payload),
            cls.hex_encode(payload),
            cls.mixed_case(payload),
            cls.insert_comments(payload, "sql"),
            cls.null_byte_insert(payload, "suffix"),
        ]
    
    @classmethod
    def encode_waf_bypass_variants(cls, payload: str) -> List[str]:
        """
        WAFバイパス特化の亜種を生成
        
        より積極的なバイパステクニックを含む。
        
        Args:
            payload: 元のペイロード
        
        Returns:
            WAFバイパス用エンコード済みペイロードのリスト
        """
        variants = [
            payload,
            cls.double_url_encode(payload),
            cls.unicode_encode(payload),
            cls.mixed_case(payload),
            cls.insert_comments(payload, "sql"),
            cls.insert_comments(payload, "html"),
            cls.concat_chunks(payload, 2, "sql"),
            cls.null_byte_insert(payload, "between"),
            # 組み合わせ
            cls.url_encode(cls.mixed_case(payload)),
            cls.double_url_encode(cls.insert_comments(payload, "sql")),
        ]
        return list(dict.fromkeys(variants))  # 重複除去


def create_payload_encoder() -> PayloadEncoder:
    """PayloadEncoder作成ヘルパー"""
    return PayloadEncoder()
