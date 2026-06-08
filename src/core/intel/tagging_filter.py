#!/usr/bin/env python3
"""
Tagging Filter

Caido Importer から出力された JSON を読み込み、URL をタグ付けし、
認証コンテキストと証拠を抽出して、タグごとに分類されたファイルを出力する。

ルール定義は config/tagging_rules.yaml から読み込む（必須）。
"""

import json
import re
import logging
import argparse
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime
from typing import Dict, List, Any, Set, Optional, Pattern, TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.intel.subdomain_context_loader import SubdomainContextLoader

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TaggingFilter")

# 静的ファイル拡張子（Importer のフォールバック）
STATIC_EXTENSIONS = {
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map'
}

# 認証関連ヘッダー
AUTH_HEADERS = {
    'authorization', 'cookie', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token', 'set-cookie'
}

# ルール設定ファイルのパス
RULES_CONFIG_PATH = Path(__file__).parents[3] / "config" / "tagging_rules.yaml"


@dataclass
class TaggingRule:
    """タグ付けルール"""
    name: str
    tag: str
    match_on: str  # path, query, body, response_body, headers, response_headers
    pattern: Pattern
    status: List[int] = field(default_factory=list)  # 空なら全ステータス
    param_extract: Optional[int] = None  # パラメータ名を抽出するグループ番号
    header_name: Optional[Pattern] = None  # headers/response_headers 用
    max_search_length: int = 0  # response_body 用


class TaggingFilter:
    """URL タグ付けフィルター"""
    
    def __init__(self, project_name: str = "unknown", rules_path: Optional[Path] = None):
        self.project_name = project_name
        self.seen_keys: Set[str] = set()  # 重複排除用
        self.rules: List[TaggingRule] = []
        
        # ルール読み込み
        rules_file = rules_path or RULES_CONFIG_PATH
        self._load_rules_from_yaml(rules_file)
        
        # 統計初期化（読み込んだルールからタグを抽出）
        all_tags = set(rule.tag for rule in self.rules)
        all_tags.add("uncategorized")
        self.stats = {tag: 0 for tag in all_tags}
        
        logger.info("Loaded %d tagging rules from %s", len(self.rules), rules_file)
    
    def _load_rules_from_yaml(self, rules_path: Path) -> None:
        """YAML からルールを読み込む（必須）"""
        if not rules_path.exists():
            raise FileNotFoundError(
                f"Tagging rules file not found: {rules_path}\n"
                "This file is required. Please create config/tagging_rules.yaml"
            )
        
        with open(rules_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        if not config or "rules" not in config:
            raise ValueError(f"Invalid tagging rules file: {rules_path}")
        
        for rule_dict in config["rules"]:
            try:
                # パターンをコンパイル
                pattern = re.compile(rule_dict["pattern"], re.IGNORECASE)
                
                # ヘッダー名パターン（オプション）
                header_name = None
                if "header_name" in rule_dict:
                    header_name = re.compile(rule_dict["header_name"], re.IGNORECASE)
                
                rule = TaggingRule(
                    name=rule_dict["name"],
                    tag=rule_dict["tag"],
                    match_on=rule_dict["match_on"],
                    pattern=pattern,
                    status=rule_dict.get("status", []),
                    param_extract=rule_dict.get("param_extract"),
                    header_name=header_name,
                    max_search_length=rule_dict.get("max_search_length", 0),
                )
                self.rules.append(rule)
            except (KeyError, re.error) as e:
                logger.warning("Skipping invalid rule %s: %s", rule_dict.get("name", "?"), e)

    def _normalize_url(self, url: str) -> str:
        """URL を正規化（クエリソート、ポート省略、フラグメント除去）"""
        parsed = urlparse(url)
        
        # クエリパラメータをソート
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params.items()), doseq=True)
        
        # ポート省略（80/443）
        netloc = parsed.netloc
        if parsed.port:
            if (parsed.scheme == 'http' and parsed.port == 80) or (parsed.scheme == 'https' and parsed.port == 443):
                netloc = parsed.hostname
        
        # フラグメント除去、正規化された URL を構築
        normalized = f"{parsed.scheme}://{netloc}{parsed.path}"
        if sorted_query:
            normalized += f"?{sorted_query}"
        
        return normalized

    def _get_unique_key(self, method: str, url: str) -> str:
        """一意キーを生成（Method + 正規化済み URL）"""
        return f"{method}:{self._normalize_url(url)}"

    def _is_static_file(self, url: str) -> bool:
        """静的ファイル判定（フォールバック）"""
        path = Path(urlparse(url).path)
        return path.suffix.lower() in STATIC_EXTENSIONS

    def _extract_auth_context(self, headers: Dict[str, str]) -> Dict[str, str]:
        """認証関連ヘッダーを抽出"""
        context = {}
        for key, value in headers.items():
            if key.lower() in AUTH_HEADERS:
                context[key] = value
        return context

    def _extract_evidence(self, response_body: str, tags: List[str]) -> str:
        """証拠（エラーメッセージ等）を抽出"""
        if "debug_info" in tags and response_body:
            return response_body[:200].replace("\n", " ") + "..."
        return ""

    def _classify_entry(self, entry: Dict[str, Any]) -> List[str]:
        """エントリをタグ付け（ルールベース）"""
        matched_tags = set()
        
        url = entry.get("url", "")
        body = entry.get("body", "")
        response = entry.get("response", {})
        response_body = response.get("body", "") or ""
        status = response.get("status", 0)
        headers = entry.get("headers", {})
        response_headers = response.get("headers", {})
        
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query
        
        for rule in self.rules:
            # ステータスフィルタ
            if rule.status and status not in rule.status:
                continue
            
            # match_on に応じてマッチング対象を選択
            target_text = ""
            if rule.match_on == "path":
                target_text = path
            elif rule.match_on == "query":
                target_text = query
            elif rule.match_on == "body":
                target_text = body
            elif rule.match_on == "response_body":
                # パフォーマンス対策：max_search_length が設定されていればその範囲のみ
                max_len = rule.max_search_length or 10000
                target_text = response_body[:max_len]
            elif rule.match_on == "headers":
                # ヘッダーは個別に走査してマッチング
                if not headers:
                    continue
                for header_name, header_value in headers.items():
                    # header_name パターンがあればそれでフィルタ
                    if rule.header_name and not rule.header_name.search(header_name):
                        continue
                    if rule.pattern.search(str(header_value)):
                        matched_tags.add(rule.tag)
                        break  # 1つマッチすれば十分
                continue  # 次のルールへ
            elif rule.match_on == "response_headers":
                # レスポンスヘッダーも個別に走査
                if not response_headers:
                    continue
                for header_name, header_value in response_headers.items():
                    # header_name パターンがあればそれでフィルタ
                    if rule.header_name and not rule.header_name.search(header_name):
                        continue
                    if rule.pattern.search(str(header_value)):
                        matched_tags.add(rule.tag)
                        break
                continue
            elif rule.match_on == "metadata":
                # メタデータ(entry自体)のキー存在チェックや値チェック
                if rule.pattern.pattern in entry and entry[rule.pattern.pattern]:
                    matched_tags.add(rule.tag)
                continue
            else:
                continue
            
            # パターンマッチ
            if rule.pattern.search(target_text):
                matched_tags.add(rule.tag)
        
        # フォームが存在する場合の追加処理
        if entry.get("metadata", {}).get("forms"):
            matched_tags.add("xss_candidate")
            
            # フォーム内に脆弱性が疑われるフィールド名がある場合、id_param も付与
            form_fields = []
            for form in entry["metadata"]["forms"]:
                form_fields.extend([f.get("name", "").lower() for f in form.get("inputs", [])])
            
            sqli_indicators = ["id", "user", "pass", "search", "query", "text", "msg"]
            if any(any(ind in field for ind in sqli_indicators) for field in form_fields if field):
                matched_tags.add("id_param")

        return list(matched_tags)

    def _classify_entry_rich(self, entry: Dict[str, Any]) -> List['TagMatch']:
        """
        エントリをタグ付けし、TagMatch オブジェクトのリストを返す（リッチ版）
        
        YAML から読み込んだルールを動的に適用する。
        """
        from src.core.models.url_context import TagMatch
        
        matches: List[TagMatch] = []
        
        url = entry.get("url", "")
        body = entry.get("body", "") or ""
        response = entry.get("response", {})
        response_body = response.get("body", "") or ""
        status = response.get("status", 0)
        headers = entry.get("headers", {})
        response_headers = response.get("headers", {})
        
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query

        # 各ルールを適用
        for rule in self.rules:
            # ステータスコード条件チェック
            if rule.status and status not in rule.status:
                continue
            
            # match_on に応じてマッチング
            if rule.match_on == "path":
                match = rule.pattern.search(path)
                if match:
                    matches.append(TagMatch(
                        tag=rule.tag,
                        rule_name=rule.name,
                        matched_on="path",
                        matched_value=match.group(0),
                    ))
            
            elif rule.match_on == "query":
                match = rule.pattern.search(query)
                if match:
                    param_name = None
                    if rule.param_extract and len(match.groups()) >= rule.param_extract:
                        param_name = match.group(rule.param_extract)
                    matches.append(TagMatch(
                        tag=rule.tag,
                        rule_name=rule.name,
                        matched_on="query",
                        matched_value=match.group(0),
                        param_name=param_name,
                    ))
            
            elif rule.match_on == "body":
                match = rule.pattern.search(body)
                if match:
                    param_name = None
                    if rule.param_extract and len(match.groups()) >= rule.param_extract:
                        param_name = match.group(rule.param_extract)
                    matches.append(TagMatch(
                        tag=rule.tag,
                        rule_name=rule.name,
                        matched_on="body",
                        matched_value=match.group(0),
                        param_name=param_name,
                    ))
            
            elif rule.match_on == "response_body":
                # max_search_length が指定されていれば制限
                search_text = response_body
                if rule.max_search_length > 0:
                    search_text = response_body[:rule.max_search_length]
                
                match = rule.pattern.search(search_text)
                if match:
                    matches.append(TagMatch(
                        tag=rule.tag,
                        rule_name=rule.name,
                        matched_on="response_body",
                        matched_value=match.group(0)[:100],  # 長すぎる場合は切り詰め
                    ))
            
            elif rule.match_on == "headers":
                for header_name, header_value in headers.items():
                    # header_name パターンがあればそれでフィルタ
                    if rule.header_name and not rule.header_name.search(header_name):
                        continue
                    
                    match = rule.pattern.search(header_value)
                    if match:
                        matches.append(TagMatch(
                            tag=rule.tag,
                            rule_name=rule.name,
                            matched_on="headers",
                            matched_value=f"{header_name}: {match.group(0)[:50]}",
                        ))
            
            elif rule.match_on == "response_headers":
                for header_name, header_value in response_headers.items():
                    # header_name パターンがあればそれでフィルタ
                    if rule.header_name and not rule.header_name.search(header_name):
                        continue
                    
                    match = rule.pattern.search(header_value)
                    if match:
                        matches.append(TagMatch(
                            tag=rule.tag,
                            rule_name=rule.name,
                            matched_on="response_headers",
                            matched_value=f"{header_name}: {match.group(0)[:50]}",
                        ))
            
            elif rule.match_on == "metadata":
                # Check for key existence and truthiness in the original entry dict
                if rule.pattern.pattern in entry and entry[rule.pattern.pattern]:
                    matches.append(TagMatch(
                        tag=rule.tag,
                        rule_name=rule.name,
                        matched_on="metadata",
                        matched_value=f"found metadata key: {rule.pattern.pattern}",
                    ))
        
        return matches

    def process_to_rich_contexts(
        self,
        entries: List[Dict[str, Any]],
        context_loader: Optional['SubdomainContextLoader'] = None,
    ) -> List['RichUrlContext']:
        """
        エントリリストを RichUrlContext のリストに変換
        
        Args:
            entries: CaidoImporter からのエントリリスト
            context_loader: SubdomainContextLoader (optional)
        
        Returns:
            RichUrlContext のリスト
        """
        from src.core.models.url_context import RichUrlContext
        
        results: List[RichUrlContext] = []
        
        for entry in entries:
            url = entry.get("url", "")
            method = entry.get("method", "")
            
            # 静的ファイル除外
            if self._is_static_file(url):
                continue
            
            # 重複排除
            unique_key = self._get_unique_key(method, url)
            if unique_key in self.seen_keys:
                continue
            self.seen_keys.add(unique_key)
            
            # SubdomainContext を取得
            subdomain_context = None
            if context_loader:
                subdomain_context = context_loader.get_context_for_url(url)
            
            # RichUrlContext を構築
            rich_ctx = RichUrlContext.from_caido_entry(entry, subdomain_context)
            
            # タグ付け（リッチ版）
            rich_ctx.tags = self._classify_entry_rich(entry)
            
            # 認証コンテキストを設定
            rich_ctx.auth_context = self._extract_auth_context(entry.get("headers", {}))
            
            results.append(rich_ctx)
            
            # 統計更新
            for tag_match in rich_ctx.tags:
                if tag_match.tag in self.stats:
                    self.stats[tag_match.tag] += 1
        
        logger.info("Processed %d entries to RichUrlContext", len(results))
        return results

    def process_file(self, input_path: str, output_dir: str) -> Dict[str, int]:
        """
        JSON ファイルを処理し、タグごとにファイルを出力。
        
        Args:
            input_path: caido_importer からの出力 JSON
            output_dir: 出力ディレクトリ
            
        Returns:
            タグごとの件数
        """
        # ファイル読み込み
        with open(input_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)
        
        logger.info("%d エントリを読み込みました", len(entries))
        
        # 出力ディレクトリ作成
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # タグごとの分類結果
        classified: Dict[str, List[Dict[str, Any]]] = {
            "auth": [],
            "admin": [],
            "id_param": [],
            "redirect_param": [],
            "file_param": [],
            "upload": [],
            "debug_info": [],
            "uncategorized": []
        }
        
        for entry in entries:
            url = entry.get("url", "")
            method = entry.get("method", "")
            
            # 静的ファイル除外
            if self._is_static_file(url):
                continue
            
            # 重複排除
            unique_key = self._get_unique_key(method, url)
            if unique_key in self.seen_keys:
                continue
            self.seen_keys.add(unique_key)
            
            # タグ付け
            tags = self._classify_entry(entry)
            
            # コンテキストと証拠を抽出
            auth_context = self._extract_auth_context(entry.get("headers", {}))
            response_obj = entry.get("response", {})
            if not isinstance(response_obj, dict):
                response_obj = {}
            response_body = str(response_obj.get("body", "") or "")
            response_headers = response_obj.get("headers", {})
            if not isinstance(response_headers, dict):
                response_headers = {}
            evidence = self._extract_evidence(response_body, tags)
            
            # 出力用エントリ
            output_entry = {
                "url": url,
                "method": method,
                "auth_context": auth_context,
                "evidence": evidence,
                "original_id": entry.get("id"),
                "forms": entry.get("forms", []),  # フォーム情報を保存（Hunter で使用）
                # unknown 分類で使うため、軽量な証拠を保持
                "source": entry.get("source", ""),
                "response_status": response_obj.get("status", 0),
                "response_headers": response_headers,
                "response_body_snippet": response_body[:1200],
                "has_form_tag": bool(re.search(r"<form\b", response_body, re.IGNORECASE)),
            }
            
            if not tags:
                classified["uncategorized"].append(output_entry)
            else:
                for tag in tags:
                    if tag not in classified:
                        classified[tag] = []
                    classified[tag].append(output_entry)
        
        # ファイル出力
        date_str = datetime.now().strftime("%Y%m%d")
        for tag, entries_list in classified.items():
            if entries_list:
                filename = f"{date_str}_{self.project_name}_tagged_{tag}.jsonl"
                filepath = output_path / filename
                with open(filepath, 'w', encoding='utf-8') as f:
                    for e in entries_list:
                        f.write(json.dumps(e, ensure_ascii=False) + "\n")
                self.stats[tag] = len(entries_list)
                logger.info("[%s] %d 件 -> %s", tag, len(entries_list), filepath)
        
        return self.stats


def main():
    parser = argparse.ArgumentParser(description="Caido ログをタグ付けして分類")
    parser.add_argument("-i", "--input", required=True, help="caido_importer の出力 JSON ファイル")
    parser.add_argument("-o", "--output", default="workspace/projects/unknown/tagged_urls", help="出力ディレクトリ（デフォルト: workspace/projects/unknown/tagged_urls）")
    parser.add_argument("-p", "--project", default="unknown", help="プロジェクト名（ファイル命名に使用）")
    
    args = parser.parse_args()
    
    filter_instance = TaggingFilter(project_name=args.project)
    stats = filter_instance.process_file(args.input, args.output)
    
    print("\n✅ タグ付け完了:")
    for tag, count in stats.items():
        if count > 0:
            print(f"  - {tag}: {count} 件")


if __name__ == "__main__":
    main()
