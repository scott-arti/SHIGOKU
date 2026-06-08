#!/usr/bin/env python3
"""
Caido Importer Tool

Caido からエクスポートされた JSON ログを取り込み、PII マスクを適用し、
標準化されたフォーマットで出力する。
"""

import json
import base64
import logging
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# PII Masker のインポート
try:
    from src.core.security.pii_masker import get_pii_masker
except ImportError:
    sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))
    from src.core.security.pii_masker import get_pii_masker

# ロギング設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CaidoImporter")

# 静的ファイル拡張子（除外対象）
STATIC_EXTENSIONS = {
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map'
}


class CaidoImporter:
    def __init__(self):
        self.pii_masker = get_pii_masker()
        self.skipped_count = 0
        self.processed_count = 0

    def _is_static_file(self, url: str) -> bool:
        """URL が静的ファイルかどうかを判定"""
        path = Path(url.split('?')[0])  # クエリパラメータを除去
        return path.suffix.lower() in STATIC_EXTENSIONS

    def _decode_base64(self, data: str) -> str:
        """Base64 文字列を安全にデコード"""
        if not data:
            return ""
        try:
            return base64.b64decode(data).decode('utf-8', errors='replace')
        except Exception as e:
            logger.warning("Base64 デコード失敗: %s", e)
            return "[DECODE_ERROR]"

    def _mask_pii(self, text: str) -> str:
        """PII マスクを適用"""
        if not text:
            return ""
        result = self.pii_masker.mask(text)
        # MaskResult オブジェクトから masked 文字列を取得
        return result.masked if hasattr(result, 'masked') else str(result)

    def import_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Caido JSON エクスポートファイルを読み込み、処理する。
        
        Args:
            file_path: Caido JSON ファイルのパス
            
        Returns:
            処理済みリクエストの辞書リスト
        """
        path = Path(file_path)
        
        # エラーハンドリング: ファイル存在チェック
        if not path.exists():
            raise FileNotFoundError(f"ファイルが存在しません: {file_path}")

        # エラーハンドリング: 空ファイルチェック
        if path.stat().st_size == 0:
            raise ValueError("コンテンツがありません")

        # JSON ロード
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except UnicodeDecodeError as e:
            raise ValueError(f"エンコーディングエラー (非 UTF-8): {e}")
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON パース失敗: {e}")

        # 単一オブジェクトをリストに変換
        if isinstance(data, dict):
            data = [data]

        logger.info("%s から %d エントリを読み込みました", file_path, len(data))

        processed_entries = []
        for entry in data:
            try:
                processed = self._process_entry(entry)
                if processed:
                    processed_entries.append(processed)
            except Exception as e:
                logger.error("エントリ %s の処理中にエラー: %s", entry.get('id', 'unknown'), e)
        
        logger.info("処理完了: %d 件処理、%d 件スキップ", self.processed_count, self.skipped_count)
        return processed_entries

    def _process_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """単一の Caido ログエントリを処理"""
        
        # 基本情報の取得
        req_id = entry.get("id")
        host = entry.get("host")
        port = entry.get("port")
        path = entry.get("path")
        method = entry.get("method")
        is_tls = entry.get("is_tls", False)
        query = entry.get("query", "")
        
        if not host or not path:
            self.skipped_count += 1
            return None

        # URL 構築
        scheme = "https" if is_tls else "http"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            url = f"{scheme}://{host}{path}"
        else:
            url = f"{scheme}://{host}:{port}{path}"
            
        if query:
            url += f"?{query}"

        # 静的ファイル除外
        if self._is_static_file(url):
            self.skipped_count += 1
            logger.debug("静的ファイルをスキップ: %s", url)
            return None

        # Request のデコードとマスク
        raw_req_b64 = entry.get("raw", "")
        raw_req_decoded = self._decode_base64(raw_req_b64)
        masked_req = self._mask_pii(raw_req_decoded)
        
        # Request ヘッダーと Body のパース
        req_headers, req_body = self._parse_http_raw(raw_req_decoded)

        # Response のデコードとマスク
        response_data = entry.get("response", {})
        res_status = response_data.get("status_code", 0)
        raw_res_b64 = response_data.get("raw", "")
        raw_res_decoded = self._decode_base64(raw_res_b64)
        masked_res = self._mask_pii(raw_res_decoded)
        
        res_headers, res_body = self._parse_http_raw(raw_res_decoded)

        # 標準化されたオブジェクトの構築
        self.processed_count += 1
        return {
            "id": req_id,
            "url": self._mask_pii(url),
            "method": method,
            "headers": req_headers,
            "body": self._mask_pii(req_body),
            "response": {
                "status": res_status,
                "body": self._mask_pii(res_body)
            },
            "source": "caido_import"
        }

    def _parse_http_raw(self, raw_http: str) -> tuple:
        """
        生の HTTP 文字列をヘッダーと Body にパース。
        簡易的なパーサー（標準 HTTP フォーマットを想定）。
        """
        if not raw_http:
            return {}, ""
            
        parts = raw_http.split('\r\n\r\n', 1)
        header_part = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        
        headers = {}
        # 最初の行（Request Line / Status Line）をスキップ
        header_lines = header_part.split('\r\n')[1:]
        
        for line in header_lines:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        
        return headers, body


def prompt_for_input() -> str:
    """ユーザーにファイルパスの入力を促す"""
    while True:
        file_path = input("Caido JSON エクスポートファイルのパスを入力してください: ").strip()
        if file_path:
            return file_path
        print("パスが空です。再入力してください。")


def main():
    parser = argparse.ArgumentParser(description="Caido JSON ログをインポートして PII マスクを適用")
    parser.add_argument("-i", "--input", help="Caido JSON エクスポートファイルのパス")
    parser.add_argument("-o", "--output", help="出力 JSON ファイルのパス", default="caido_imported.json")
    
    args = parser.parse_args()
    
    # ファイルパスの取得（CLI 引数または対話的入力）
    file_path = args.input
    if not file_path:
        file_path = prompt_for_input()
    
    importer = CaidoImporter()
    
    # 再入力ループ
    while True:
        try:
            results = importer.import_file(file_path)
            break
        except (FileNotFoundError, ValueError) as e:
            logger.error("エラー: %s", e)
            file_path = prompt_for_input()
    
    # 結果を出力
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"✅ {len(results)} 件のレコードを {args.output} にエクスポートしました")


if __name__ == "__main__":
    main()
