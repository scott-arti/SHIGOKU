#!/usr/bin/env python3
"""
Phase B: URL分類とタグ付け実行スクリプト

Juice Shopエンドポイントの再分類とuncategorized削減を実行
"""
import json
import sys
from pathlib import Path
from urllib.parse import urljoin

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.core.validation.url_classifier import URLClassifier, classify_url


def load_urls_from_session(session_file: str) -> list:
    """セッションファイルからURL一覧を抽出"""
    try:
        with open(session_file, 'r') as f:
            data = json.load(f)
        
        urls = []
        # tagged_urls から URL を抽出
        tagged = data.get("tagged_urls", {})
        for category, entries in tagged.items():
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict) and "url" in entry:
                        urls.append({
                            "url": entry["url"],
                            "method": entry.get("method", "GET"),
                            "original_category": category,
                        })
        return urls
    except Exception as e:
        print(f"Error loading session: {e}")
        return []


def classify_and_save(urls: list, output_dir: Path, base_url: str = "http://localhost:3000"):
    """URLを分類してタグ付けファイルを保存"""
    classifier = URLClassifier()
    
    # カテゴリ別にURLを集積
    categorized = {}
    uncategorized = []
    
    for entry in urls:
        url = entry.get("url", "")
        method = entry.get("method", "GET")
        
        # 相対URLを絶対URLに変換
        if url.startswith("/"):
            url = urljoin(base_url, url)
        
        result = classifier.classify(url, method)
        
        if result.tags:
            # 分類成功
            entry["tags"] = list(result.tags)
            entry["primary_tag"] = result.primary_tag
            entry["confidence"] = result.confidence
            
            # プライマリタグで分類
            primary = result.primary_tag or "unknown"
            if primary not in categorized:
                categorized[primary] = []
            categorized[primary].append(entry)
        else:
            # 未分類
            uncategorized.append(entry)
    
    # 出力ディレクトリ作成
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 分類済みURLを保存
    for tag, entries in categorized.items():
        output_file = output_dir / f"tagged_{tag}.jsonl"
        with open(output_file, 'w') as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
        print(f"  {tag}: {len(entries)} URLs -> {output_file}")
    
    # 未分類URLを保存
    if uncategorized:
        output_file = output_dir / "tagged_uncategorized.jsonl"
        with open(output_file, 'w') as f:
            for entry in uncategorized:
                f.write(json.dumps(entry) + "\n")
        print(f"  uncategorized: {len(uncategorized)} URLs -> {output_file}")
    
    # 統計
    total = len(urls)
    uncategorized_count = len(uncategorized)
    categorized_count = total - uncategorized_count
    
    print(f"\n統計:")
    print(f"  合計: {total} URLs")
    print(f"  分類済み: {categorized_count} URLs ({categorized_count/total*100:.1f}%)")
    print(f"  未分類: {uncategorized_count} URLs ({uncategorized_count/total*100:.1f}%)")
    
    return {
        "total": total,
        "categorized": categorized_count,
        "uncategorized": uncategorized_count,
        "uncategorized_rate": uncategorized_count / total if total > 0 else 0,
    }


def main():
    print("=" * 60)
    print("Phase B: Juice Shop URL 分類とタグ付け")
    print("=" * 60)
    
    # デモ用: 一般的なJuice Shopエンドポイントを分類
    demo_urls = [
        {"url": "/rest/admin/application-configuration", "method": "GET"},
        {"url": "/rest/admin/application-version", "method": "GET"},
        {"url": "/rest/user/login", "method": "POST"},
        {"url": "/rest/user/register", "method": "POST"},
        {"url": "/rest/products/search", "method": "GET"},
        {"url": "/api/basket", "method": "GET"},
        {"url": "/api/basket", "method": "POST"},
        {"url": "/api/orders", "method": "GET"},
        {"url": "/api/feedback", "method": "POST"},
        {"url": "/#/search", "method": "GET"},
        {"url": "/#/basket", "method": "GET"},
        {"url": "/socket.io/", "method": "GET"},
        {"url": "/api/Challenges", "method": "GET"},
        {"url": "/rest/user/reset-password", "method": "POST"},
        {"url": "/api/products/1/reviews", "method": "GET"},
        {"url": "/ftp/", "method": "GET"},
        {"url": "/unknown/path1", "method": "GET"},
        {"url": "/unknown/path2", "method": "GET"},
        {"url": "/api/coupon", "method": "POST"},
        {"url": "/#/", "method": "GET"},
    ]
    
    output_dir = Path("workspace/projects/juice_shop_demo/tagged_urls")
    stats = classify_and_save(demo_urls, output_dir)
    
    print("\n" + "=" * 60)
    print("Phase B完了")
    print("=" * 60)
    
    # KPI判定
    if stats["uncategorized_rate"] <= 0.10:
        print(f"✅ uncategorized率: {stats['uncategorized_rate']*100:.1f}% (目標: 10%以下) - 達成")
    else:
        print(f"⚠️  uncategorized率: {stats['uncategorized_rate']*100:.1f}% (目標: 10%以下) - 要改善")


if __name__ == "__main__":
    main()
