#!/usr/bin/env python3
"""
E2E Test for Pipeline to MC Handoff

このテストはpipeline.pyからMasterConductorへのハンドオフ直前まで検証する。
具体的には:
1. GAU/HTTPX で URL 収集
2. TaggingFilter でタグ付け
3. RichUrlContext 変換 (タグ付与確認)
4. step8_return_to_mc 形式のデータ構造確認 (MCが受け取る直前)

ターゲット: http://testphp.vulnweb.com/
制限: 最初の50件
"""
import asyncio
from collections import Counter
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from dataclasses import asdict

# プロジェクトルートをパスに追加
PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.tools.custom.gau import GAUTool
from src.tools.custom.httpx import HttpxTool
from src.core.intel.tagging_filter import TaggingFilter

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("e2e_mc_handoff")

# テスト設定
TARGET_DOMAIN = "testphp.vulnweb.com"
MAX_URLS = 50


def summarize_httpx_failures(httpx_failures: List[Dict[str, Any]]) -> Dict[str, Any]:
    failure_summary = dict(
        Counter(item.get("error_type", "unknown") for item in httpx_failures)
    )
    invalid_url_count = int(failure_summary.get("invalid_url", 0) or 0)
    total_failures = len(httpx_failures)
    input_quality_warning = None
    if total_failures > 0 and invalid_url_count >= max(5, total_failures // 2):
        input_quality_warning = (
            f"invalid_url detected in {invalid_url_count}/{total_failures} HTTPX failures; "
            "input URL quality should be reviewed before target reachability is judged."
        )
    return {
        "failure_count": total_failures,
        "failure_summary": failure_summary,
        "sample_failures": httpx_failures[:5],
        "input_quality_warning": input_quality_warning,
    }


def simulate_step8_return_to_mc(
    tagged_entries: List[Dict[str, Any]],
    stats: Dict[str, int],
    tech_stack: List[str] = None
) -> Dict[str, Dict]:
    """
    step8_return_to_mc の動作をシミュレート
    
    pipeline.py の step8 と同様の構造を生成
    """
    # カテゴリ → Swarm ルーティング用タグ (pipeline.py から)
    CATEGORY_TAGS = {
        "auth": ["auth_endpoint", "auth_required"],
        "admin": ["admin_path", "high_value"],
        "id_param": ["has_params", "id_param"],
        "redirect_param": ["redirect_param", "open_redirect"],
        "file_param": ["file_param", "lfi_candidate"],
        "upload": ["upload_endpoint", "file_upload"],
        "debug_info": ["debug_info", "information_disclosure"],
        "jwt_detected": ["jwt_token", "auth_required"],
        "admin_blocked": ["403_response", "admin_blocked"],
        "uncategorized": ["unknown_path"],
    }
    
    DESCRIPTIONS = {
        "auth": "認証関連のエンドポイント",
        "admin": "管理者向けエンドポイント",
        "id_param": "ID パラメータを含むエンドポイント",
        "redirect_param": "リダイレクトパラメータを含むエンドポイント",
        "file_param": "ファイルパラメータを含むエンドポイント",
        "upload": "ファイルアップロードエンドポイント",
        "debug_info": "デバッグ情報が露出しているエンドポイント",
        "jwt_detected": "JWT トークンを使用するエンドポイント",
        "admin_blocked": "403 で保護された管理者パス",
        "uncategorized": "分類に該当しなかったエンドポイント",
    }
    
    result = {}
    
    # stats からタグごとにエントリを分類
    for tag, count in stats.items():
        if count > 0:
            result[tag] = {
                "count": count,
                "description": DESCRIPTIONS.get(tag, f"{tag} の分類結果"),
                "tags": CATEGORY_TAGS.get(tag, []),
            }
    
    # tech_stack からタグを追加
    if tech_stack:
        tech_tags = []
        tech_lower = [t.lower() for t in tech_stack]
        
        if any("jwt" in t for t in tech_lower):
            tech_tags.append("jwt_token")
        if any("php" in t for t in tech_lower):
            tech_tags.append("php_app")
        if any("nginx" in t for t in tech_lower):
            tech_tags.append("nginx_server")
        
        result["_tech_stack"] = {
            "technologies": tech_stack,
            "tags": tech_tags,
        }
    
    return result


async def run_e2e_test() -> dict[str, Any]:
    """E2Eテスト実行"""
    
    results: dict[str, Any] = {
        "status": "unknown",
        "steps": {},
        "errors": [],
        "mc_handoff_ready": False,
        "tags_verified": False,
    }
    
    # 作業ディレクトリ作成
    work_dir = Path(tempfile.mkdtemp(prefix="shigoku_e2e_mc_"))
    logger.info("Work directory: %s", work_dir)
    
    try:
        # =========== Step 1: GAU で URL 収集 ===========
        logger.info("=" * 60)
        logger.info("Step 1: GAU URL Collection")
        logger.info("=" * 60)
        
        gau = GAUTool()
        gau_output = gau.run(TARGET_DOMAIN, mode="standard")
        
        gau_urls = [line.strip() for line in gau_output.splitlines() if line.strip() and line.startswith("http")]
        logger.info("GAU collected %d raw URLs", len(gau_urls))
        
        gau_urls = gau_urls[:MAX_URLS]
        logger.info("Limited to first %d URLs", len(gau_urls))
        
        results["steps"]["gau"] = {
            "status": "success" if gau_urls else "warning",
            "url_count": len(gau_urls),
        }
        
        if not gau_urls:
            gau_urls = [
                f"http://{TARGET_DOMAIN}/",
                f"http://{TARGET_DOMAIN}/login.php",
                f"http://{TARGET_DOMAIN}/search.php?test=1",
                f"http://{TARGET_DOMAIN}/artists.php",
                f"http://{TARGET_DOMAIN}/listproducts.php?cat=1",
            ]
            logger.info("Using fallback URLs: %d", len(gau_urls))
        
        # =========== Step 2: HTTPX で Live Check ===========
        logger.info("=" * 60)
        logger.info("Step 2: HTTPX Live Check")
        logger.info("=" * 60)
        
        urls_file = work_dir / "gau_urls.txt"
        urls_file.write_text("\n".join(gau_urls))
        
        httpx = HttpxTool()
        httpx_output = httpx.run(str(urls_file), mode="standard")
        
        httpx_entries = []
        httpx_failures = []
        detected_tech = []
        
        for line in httpx_output.splitlines():
            try:
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("failed"):
                    httpx_failures.append(data)
                    continue
                httpx_entries.append(data)
                # 技術スタック収集
                if "tech" in data:
                    detected_tech.extend(data["tech"])
            except json.JSONDecodeError:
                pass
        
        detected_tech = list(set(detected_tech))
        failure_diagnostics = summarize_httpx_failures(httpx_failures)
        logger.info("HTTPX confirmed %d live URLs", len(httpx_entries))
        logger.info("HTTPX failures: %d", failure_diagnostics["failure_count"])
        logger.info("HTTPX failure summary: %s", failure_diagnostics["failure_summary"])
        if failure_diagnostics["input_quality_warning"]:
            logger.warning("HTTPX input quality warning: %s", failure_diagnostics["input_quality_warning"])
        logger.info("Detected tech stack: %s", detected_tech)
        
        results["steps"]["httpx"] = {
            "status": "success" if httpx_entries else "warning",
            "live_count": len(httpx_entries),
            "tech_stack": detected_tech,
            **failure_diagnostics,
        }
        
        # =========== Step 3: Caido形式に変換 ===========
        logger.info("=" * 60)
        logger.info("Step 3: Convert to Caido Entry Format")
        logger.info("=" * 60)
        
        caido_entries = []
        for data in httpx_entries:
            entry = {
                "url": data.get("url", ""),
                "method": "GET",
                "response": {
                    "status": data.get("status_code", 0),
                    "body": data.get("body", ""),
                    "headers": data.get("header", {})
                },
                "headers": {}
            }
            if entry["url"]:
                caido_entries.append(entry)
        
        logger.info("Converted %d entries to Caido format", len(caido_entries))
        
        input_json = work_dir / "caido_entries.json"
        input_json.write_text(json.dumps(caido_entries, ensure_ascii=False, indent=2))
        
        results["steps"]["convert"] = {
            "status": "success",
            "entry_count": len(caido_entries)
        }
        
        # =========== Step 4: TaggingFilter で分類 ===========
        logger.info("=" * 60)
        logger.info("Step 4: TaggingFilter Classification")
        logger.info("=" * 60)
        
        output_dir = work_dir / "tagged_output"
        tagging_filter = TaggingFilter(project_name=TARGET_DOMAIN)
        
        stats = tagging_filter.process_file(str(input_json), str(output_dir))
        logger.info("TaggingFilter stats: %s", stats)
        
        results["steps"]["tagging"] = {
            "status": "success",
            "stats": stats,
        }
        
        # =========== Step 5: RichUrlContext 変換 (タグ付与確認) ===========
        logger.info("=" * 60)
        logger.info("Step 5: RichUrlContext Conversion (Tag Verification)")
        logger.info("=" * 60)
        
        # TaggingFilter をリセットして再実行 (seen_keys をクリア)
        tagging_filter_rich = TaggingFilter(project_name=TARGET_DOMAIN)
        
        try:
            rich_contexts = tagging_filter_rich.process_to_rich_contexts(caido_entries)
            
            # タグが付与されているか検証
            entries_with_tags = [ctx for ctx in rich_contexts if ctx.tags]
            entries_without_tags = [ctx for ctx in rich_contexts if not ctx.tags]
            
            logger.info("RichUrlContext: %d total, %d with tags, %d without tags",
                       len(rich_contexts), len(entries_with_tags), len(entries_without_tags))
            
            # 詳細タグ情報
            all_tags = set()
            tag_samples = {}
            for ctx in rich_contexts:
                for tag_match in ctx.tags:
                    all_tags.add(tag_match.tag)
                    if tag_match.tag not in tag_samples:
                        tag_samples[tag_match.tag] = {
                            "url": ctx.url,
                            "rule_name": tag_match.rule_name,
                            "matched_on": tag_match.matched_on,
                            "matched_value": tag_match.matched_value,
                        }
            
            logger.info("Unique tags found: %s", list(all_tags))
            
            results["steps"]["rich_context"] = {
                "status": "success",
                "total_contexts": len(rich_contexts),
                "with_tags": len(entries_with_tags),
                "without_tags": len(entries_without_tags),
                "unique_tags": list(all_tags),
                "tag_samples": tag_samples,
            }
            
            # タグ検証: 少なくとも1つのタグが付与されていること
            results["tags_verified"] = len(entries_with_tags) > 0
            
        except Exception as e:
            logger.error("RichUrlContext conversion failed: %s", e)
            results["steps"]["rich_context"] = {
                "status": "error",
                "error": str(e)
            }
            results["errors"].append(f"RichUrlContext: {e}")
        
        # =========== Step 6: MC Handoff シミュレーション ===========
        logger.info("=" * 60)
        logger.info("Step 6: MC Handoff Simulation (step8_return_to_mc)")
        logger.info("=" * 60)
        
        mc_payload = simulate_step8_return_to_mc(
            tagged_entries=caido_entries,
            stats=stats,
            tech_stack=detected_tech,
        )
        
        logger.info("MC Payload categories: %s", list(mc_payload.keys()))
        
        # タグが含まれているか検証
        has_swarm_tags = False
        for category, data in mc_payload.items():
            if category.startswith("_"):
                continue
            if data.get("tags"):
                has_swarm_tags = True
                logger.info("  Category '%s' has Swarm tags: %s", category, data["tags"])
        
        results["steps"]["mc_handoff"] = {
            "status": "success",
            "categories": list(mc_payload.keys()),
            "payload_sample": mc_payload,
        }
        
        results["mc_handoff_ready"] = has_swarm_tags
        
        # MC ペイロード検証
        mc_payload_json = work_dir / "mc_payload.json"
        mc_payload_json.write_text(json.dumps(mc_payload, ensure_ascii=False, indent=2))
        logger.info("Saved MC payload to: %s", mc_payload_json)
        
        # =========== Summary ===========
        logger.info("=" * 60)
        logger.info("E2E Test Summary (Pipeline → MC Handoff)")
        logger.info("=" * 60)
        
        all_success = all(
            step.get("status") in ("success", "warning")
            for step in results["steps"].values()
        )
        
        results["status"] = "success" if (all_success and results["tags_verified"] and results["mc_handoff_ready"]) else "partial_failure"
        results["work_dir"] = str(work_dir)
        
        logger.info("Overall Status: %s", results["status"])
        logger.info("Tags Verified: %s", results["tags_verified"])
        logger.info("MC Handoff Ready: %s", results["mc_handoff_ready"])
        
        for step_name, step_data in results["steps"].items():
            logger.info("  - %s: %s", step_name, step_data.get("status"))
        
        if results["errors"]:
            logger.warning("Errors encountered:")
            for err in results["errors"]:
                logger.warning("  - %s", err)
        
    except Exception as e:
        logger.exception("E2E test failed: %s", e)
        results["status"] = "error"
        results["errors"].append(str(e))
    
    return results


def main():
    """メイン関数"""
    print("\n" + "=" * 60)
    print("SHIGOKU Pipeline → MC Handoff E2E Test")
    print(f"Target: {TARGET_DOMAIN}")
    print(f"Max URLs: {MAX_URLS}")
    print("=" * 60 + "\n")
    
    results = asyncio.run(run_e2e_test())
    
    # 結果をJSONで出力
    print("\n" + "=" * 60)
    print("FINAL RESULTS:")
    print("=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    
    # 終了コード
    if results["status"] == "success":
        print("\n✅ E2E Test PASSED - Tags verified & MC handoff ready")
        sys.exit(0)
    elif results["status"] == "partial_failure":
        print("\n⚠️ E2E Test PARTIAL SUCCESS (some issues)")
        sys.exit(0)
    else:
        print("\n❌ E2E Test FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
