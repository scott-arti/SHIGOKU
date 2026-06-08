"""
Recon Mode Command
"""
from pathlib import Path
from src.commands import print_header, print_step, print_result

def run_recon_phase(target_url: str, scope_file: str = None, mode: str = "bugbounty"):
    """
    Recon Mode
    
    ターゲットの徹底的な偵察を行う。
    1. Cartographer: サイトマップ作成
    2. Fingerprinter: 技術スタック特定
    3. Neo4j: グラフDBへ保存
    
    モード設定によりツールの実行を制御。
    """
    from src.core.intel.cartographer import Cartographer
    from src.core.intel.fingerprinter import Fingerprinter
    from src.core.infra.knowledge_graph import KnowledgeGraph
    from src.core.security.scope_parser import load_scope_from_yaml
    from src.core.infra.proxy_rotation import RotatingSession
    from src.core.engine.mode_manager import get_mode_manager
    from src.core.tool_registry import get_tool_registry
    
    print_header("🗺️ RECON PHASE START")
    print_step("🎯", f"Target: {target_url}")
    
    # モード設定
    mode_manager = get_mode_manager()
    tool_registry = get_tool_registry()
    
    try:
        mode_config = mode_manager.set_mode(mode)
        print_step("🔧", f"Mode: {mode_config.display_name}")
    except Exception as e:
        print_result(False, f"Mode configuration failed: {e}")
        return
    
    # スコープ設定
    if scope_file and Path(scope_file).exists():
        load_scope_from_yaml(scope_file)
        print_step("🛡️", f"Scope loaded: {scope_file}")
    
    # 1. Cartographer Execution (ツールチェック)
    if not tool_registry.is_enabled("cartographer"):
        print_step("⏭️", "Cartographer disabled by mode, skipping")
        return
    
    print_header("1. MAPPING SITE")
    cartographer = Cartographer(target_url, max_depth=3, max_pages=100)
    sitemap = cartographer.map_site()
    
    print_result(True, f"Found {len(sitemap.nodes)} nodes")
    
    # 2. Tech Stack Identification (ツールチェック)
    if not tool_registry.is_enabled("fingerprinter"):
        print_step("⏭️", "Fingerprinter disabled by mode, skipping tech identification")
    else:
        print_header("2. IDENTIFYING TECH STACK")
        fingerprinter = Fingerprinter()
        session = RotatingSession()
        
        nodes_count = len(sitemap.nodes)
        for i, (url, node) in enumerate(sitemap.nodes.items(), 1):
            try:
                # コンテンツ再取得 (Cartographerはコンテンツを保存しないため)
                # ※ 本番ではキャッシュ活用を検討すべき
                if node.method == "GET":
                    resp = session.get(url, timeout=5)
                    techs = fingerprinter.identify(resp.text, dict(resp.headers))
                    
                    if techs:
                        tech_names = ", ".join([t.name for t in techs])
                        print(f"  [{i}/{nodes_count}] {url} -> {tech_names}")
                        # ノードに技術情報を一時的にアタッチ (KG保存用)
                        node.techs = techs 
                    else:
                        node.techs = []
            except Exception as e:
                print(f"  [{i}/{nodes_count}] {url} -> Error: {e}")
                node.techs = []

    # 3. Knowledge Graph Storing
    print_header("3. STORING TO KNOWLEDGE GRAPH")
    try:
        # Docker環境のデフォルトパスワードを使用
        kg = KnowledgeGraph(password="shigoku2024")
        if kg.driver:
            kg.store_sitemap(sitemap)
            
            # 技術情報の保存
            for url, node in sitemap.nodes.items():
                if hasattr(node, 'techs') and node.techs:
                    kg.store_tech_stack(url, node.techs)
            
            print_result(True, "Data stored in Neo4j")
            kg.close()
        else:
            print_result(False, "Neo4j connection failed (Start docker container?)")
    except Exception as e:
        print_result(False, f"Error storing to KG: {e}")

    print_header("📊 RECON SUMMARY")
    print_step("🗺️", f"Pages Mapped: {len(sitemap.nodes)}")
    print_step("💾", "Graph Database: Updated")
