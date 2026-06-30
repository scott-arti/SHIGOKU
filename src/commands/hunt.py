"""
Hybrid Hunt Mode Command
"""
import asyncio
from pathlib import Path
from typing import Optional
from src.commands import print_header, print_step, print_result, print_finding
from src.core.utils.logging.hunting_logger import HuntingLogger, LogPhase

def run_hybrid_hunt(
    log_path: str,
    scope_file: Optional[str] = None,
    project_name: Optional[str] = None,
    mode: str = "bugbounty",
    sessions_file: Optional[str] = None,
    cross_test_approved: bool = False,
):
    """
    Hybrid Hunt Mode
    
    Caidoログを解析し、検出された候補に対して自動攻撃を実行。
    ハンティングの思考プロセスと証拠を自動記録。
    モード設定に基づいて動作を調整。
    
    Args:
        log_path: Caidoログファイルのパス
        scope_file: スコープ定義ファイル（オプション）
        project_name: プロジェクト名（オプション）
        mode: 動作モード（bugbounty/ctf）
        sessions_file: マルチアカウントセッションファイル（オプション）
        cross_test_approved: クロステスト実行が承認済みか
    """
    from src.intelligence.proxy_log_analyzer import ProxyLogAnalyzer, SmellType
    from src.core.agents.swarm import (
        JWTInspector, OAuthDancer, MFABypasser,
        create_bizlogic_hunter
    )
    from src.core.reports.auto_reporter import AutoReporter
    from src.core.security.scope_parser import load_scope_from_yaml
    from src.core.project.project_manager import ProjectManager
    from src.core.engine.mode_manager import get_mode_manager
    from src.core.tool_registry import get_tool_registry
    from src.core.rag_module.rag import get_rag_switch
    from src.core.session import get_session_manager
    from src.core.deduplication import deduplicate_findings
    from src.core.models.finding import Finding, VulnType, Severity
    from src.tools.builtin.handoff import HandoffContext
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from src.core.notifications.finding_notification_router import FindingNotificationRouter
    import logging

    logger = logging.getLogger(__name__)
    
    # マルチアカウントセッション管理（オプション）
    session_manager = None
    if sessions_file:
        from src.core.security.multi_account_session import create_session_manager
        sessions_path = Path(sessions_file)
        if not sessions_path.exists():
            print_result(False, f"Sessions file not found: {sessions_file}")
            return
        
        session_manager = create_session_manager(sessions_path)
        if not session_manager:
            print_result(False, "Failed to load sessions file")
            return
        
        if not session_manager.is_configured():
            print_result(False, "Both 'attacker' and 'victim' sessions required in sessions.json")
            return
        
        print_step("🔑", f"Loaded sessions: {', '.join(session_manager.get_session_names())}")
    
    print_header("🎯 HYBRID HUNT MODE")
    print_step("📁", f"Log file: {log_path}")

    
    # モード設定
    mode_manager = get_mode_manager()
    try:
        mode_config = mode_manager.set_mode(mode)
        print_step("🔧", f"Mode: {mode_config.display_name}")
        print_step("⚡", f"Attack Aggressiveness: {mode_config.attack_aggressiveness}")
        
        # ツールレジストリを取得（後で個別チェック用）
        tool_registry = get_tool_registry()
        
        # RAGコレクション切り替え
        rag_switch = get_rag_switch()
        rag_switch.switch_mode(mode)
    except Exception as e:
        print_result(False, f"Mode configuration failed: {e}")
        return
    
    # Initialize notification router for this hunt run
    finding_router = FindingNotificationRouter(run_id=f"hunt-{log_path}")
    
    # プロジェクト設定
    if not project_name:
        # ログファイル名からプロジェクト名を推測
        project_name = Path(log_path).stem
    
    pm = ProjectManager(project_name)
    pm.init_project(
        target_url=f"project_{project_name}",
        description=f"Hybrid Hunt from {log_path}"
    )
    
    hunt_logger = HuntingLogger(project_name)
    hunt_logger.log(
        phase=LogPhase.THINKING,
        content="Hybrid Huntモードを開始",
        reasoning=f"Caidoログファイル {log_path} を解析し、脆弱性を探索する",
        evidence_paths=[str(Path(log_path).absolute())],
        agent_name="main",
    )
    
    # スコープ設定
    if scope_file and Path(scope_file).exists():
        load_scope_from_yaml(scope_file)
        print_step("🛡️", f"Scope loaded: {scope_file}")
        hunt_logger.log(
            phase=LogPhase.JUDGMENT,
            content="スコープ定義を適用",
            reasoning="倫理ガードラインに従い、許可された範囲内でのみ攻撃を実行",
            evidence_paths=[str(Path(scope_file).absolute())],
        )
    
    # ログ解析
    print_step("🔍", "Analyzing proxy log...")
    analyzer = ProxyLogAnalyzer()
    plans = analyzer.analyze(log_path)
    
    hunt_logger.log(
        phase=LogPhase.DISCOVERY,
        content=f"{len(plans)}件の攻撃候補を発見",
        reasoning="ProxyLogAnalyzerが検出したSmellパターンに基づく",
        confidence=0.7,
    )
    
    if not plans:
        print_result(False, "No attack candidates found")
        hunt_logger.log(
            phase=LogPhase.OUTPUT,
            content="攻撃候補なし、終了",
        )
        return
    
    print_result(True, f"Found {len(plans)} attack candidates")
    
    # エージェント初期化（モード設定を適用）
    jwt_inspector = JWTInspector(program_name="HybridHunt")
    if hasattr(jwt_inspector, 'set_mode'):
        jwt_inspector.set_mode(mode_config)
    
    oauth_dancer = OAuthDancer(program_name="HybridHunt")
    if hasattr(oauth_dancer, 'set_mode'):
        oauth_dancer.set_mode(mode_config)
    
    mfa_bypasser = MFABypasser(program_name="HybridHunt")
    if hasattr(mfa_bypasser, 'set_mode'):
        mfa_bypasser.set_mode(mode_config)
    
    bizlogic_hunter = create_bizlogic_hunter(program_name="HybridHunt")
    if hasattr(bizlogic_hunter, 'set_mode'):
        bizlogic_hunter.set_mode(mode_config)
    
    # セッションマネージャーをbizlogic_hunterに設定
    if session_manager:
        bizlogic_hunter.set_session_manager(session_manager)
    
    reporter = AutoReporter()
    
    findings = []
    
    # IDOR候補のクロステスト処理
    idor_candidates = [
        p.candidate for p in plans 
        if hasattr(p, 'candidate') and p.candidate.smell_type == SmellType.IDOR_CANDIDATE
    ]
    
    if idor_candidates:
        if session_manager and cross_test_approved:
            # クロステスト実行
            print_header("🔓 IDOR CROSS-TEST (Approved)")
            from src.core.security.idor_cross_tester import create_idor_cross_tester
            
            cross_tester = create_idor_cross_tester(session_manager, "HybridHunt")
            cross_test_findings = cross_tester.run_full_test(idor_candidates)
            
            for finding in cross_test_findings:
                findings.append(finding)
                print_finding(finding)
            
            if cross_test_findings:
                print_result(True, f"Cross-test confirmed {len(cross_test_findings)} IDOR vulnerabilities")
            else:
                print_step("✓", "No IDOR vulnerabilities confirmed via cross-test")
            
            # クロステスト済みIDOR候補は通常のテストからスキップ
            tested_urls = {f.target_url for f in cross_test_findings}
            plans = [p for p in plans if p.target_url not in tested_urls]
        
        elif session_manager and not cross_test_approved:
            # セッションは設定されているが、クロステスト未承認
            print_header("⚠️ IDOR CROSS-TEST AVAILABLE")
            print_step("🔍", f"Found {len(idor_candidates)} IDOR candidates")
            print_step("📝", "To run confirmed cross-test, re-run with --cross-test-approved")
            
            # 通知を送信
            try:
                from src.core.notifications.notifier import get_notifier
                notifier = get_notifier()
                notifier.notify_action_required(
                    action_type="IDOR_CROSS_TEST",
                    message=(
                        f"Detected {len(idor_candidates)} IDOR candidates. "
                        f"Cross-test is available but requires explicit approval."
                    ),
                    details={
                        "candidates": len(idor_candidates),
                        "sessions_file": sessions_file,
                        "command": f"shigoku hunt --log {log_path} --sessions-file {sessions_file} --cross-test-approved",
                    }
                )
            except Exception as e:
                logger.debug(f"Notification failed: {e}")
        
        else:
            # セッションファイルなし
            print_header("💡 IDOR CROSS-TEST RECOMMENDATION")
            print_step("🔍", f"Found {len(idor_candidates)} IDOR candidates")
            print_step("📝", "For accurate IDOR detection, create sessions.json with 'attacker' and 'victim' sessions")
            print_step("📝", "Then re-run: shigoku hunt --log <log> --sessions-file sessions.json --cross-test-approved")


    
    # 関数: 単一プランの実行
    def _execute_single_plan(plan):
        def _convert_handoff_finding(finding_dict):
            if not isinstance(finding_dict, dict):
                return None
            try:
                vuln_type_raw = finding_dict.get("vuln_type") or finding_dict.get("type")
                severity_raw = finding_dict.get("severity", "high")
                vuln_type = VulnType(vuln_type_raw) if vuln_type_raw in {v.value for v in VulnType} else VulnType.BROKEN_ACCESS_CONTROL
                severity = Severity(severity_raw) if severity_raw in {s.value for s in Severity} else Severity.HIGH

                return Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    title=finding_dict.get("title", "Auth Finding"),
                    description=finding_dict.get("description", ""),
                    target_url=finding_dict.get("target_url") or finding_dict.get("url") or "",
                    target_program=finding_dict.get("target_program", "HybridHunt"),
                    evidence=finding_dict.get("evidence", {}),
                    reproduction_steps=finding_dict.get("reproduction_steps", []),
                    impact=finding_dict.get("impact", ""),
                    source_agent=finding_dict.get("source_agent", "auth_ninja"),
                    confidence=float(finding_dict.get("confidence", 0.7) or 0.7),
                    cwe_id=finding_dict.get("cwe_id"),
                    cvss_score=finding_dict.get("cvss_score"),
                    additional_info=finding_dict.get("additional_info", {}),
                )
            except Exception as e:
                logger.debug(f"Failed to convert handoff finding: {e}")
                return None

        result = None
        finding = None
        
        # エージェント選択と実行
        if plan.recommended_agent == "jwt_inspector":
            token = plan.attack_params.get("token", "")
            if token:
                hunt_logger.log(
                    phase=LogPhase.THINKING,
                    content=f"JWT Inspector でalg=none攻撃を試行すべきか判断中",
                    reasoning=f"ターゲット {plan.target_url} でJWTトークンを検出",
                    hypothesis="alg=noneが許可されている可能性がある",
                    confidence=0.6,
                    agent_name="jwt_inspector",
                    target_url=plan.target_url,
                )
                
                context = HandoffContext.from_params(
                    {
                        "target": plan.target_url,
                        "token": token,
                        "test_endpoint": plan.target_url,
                    }
                )
                result = asyncio.run(jwt_inspector.execute(context=context))

                if result and getattr(result, "findings", None):
                    finding = _convert_handoff_finding(result.findings[0])
                
                if finding:
                    hunt_logger.log(
                        phase=LogPhase.DISCOVERY,
                        content=f"JWT脆弱性を発見: {finding.title}",
                        reasoning=result.bypass_method or "alg=none攻撃成功",
                        confidence=finding.confidence,
                        agent_name="jwt_inspector",
                        target_url=plan.target_url,
                    )
        
        elif plan.recommended_agent == "oauth_dancer":
            context = HandoffContext.from_params(
                {
                    "target": plan.target_url,
                    "authorize_url": plan.target_url,
                    "client_id": plan.attack_params.get("client_id", ""),
                }
            )
            result = asyncio.run(oauth_dancer.execute(context=context))
            if result and getattr(result, "findings", None):
                finding = _convert_handoff_finding(result.findings[0])
        
        elif plan.recommended_agent == "mfa_bypasser":
            context = HandoffContext.from_params(
                {
                    "target": plan.target_url,
                    "login_endpoint": plan.target_url,
                }
            )
            result = asyncio.run(mfa_bypasser.execute(context=context))
            if result and getattr(result, "findings", None):
                finding = _convert_handoff_finding(result.findings[0])
        
        elif plan.recommended_agent == "bizlogic_hunter":
            result = asyncio.run(bizlogic_hunter.execute(plan.target_url, plan.candidate))
            if hasattr(result, 'finding'):
                finding = result.finding
        
        return finding

    print_header("⚔️ EXECUTING ATTACKS")
    
    # 並列実行の設定確認
    parallel_enabled = getattr(mode_config, 'parallel_scan_enabled', False)
    max_workers = getattr(mode_config, 'parallel_workers', 3)
    
    if parallel_enabled:
        print_step("⚡", f"Parallel scan enabled (Workers: {max_workers})")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_plan = {executor.submit(_execute_single_plan, plan): plan for plan in plans}
            for i, future in enumerate(as_completed(future_to_plan), 1):
                plan = future_to_plan[future]
                print_step("🎯", f"[{i}/{len(plans)}] Finished: {plan.candidate.smell_type.value}")
                try:
                    finding = future.result()
                    if finding:
                        findings.append(finding)
                except Exception as exc:
                    print(f"Plan generated an exception: {exc}")
    else:
        # 直列実行
        for i, plan in enumerate(plans, 1):
            print_step("🎯", f"[{i}/{len(plans)}] {plan.candidate.smell_type.value}")
            print(f"       URL: {plan.target_url[:60]}...")
            print(f"       Agent: {plan.recommended_agent}")
            
            finding = _execute_single_plan(plan)
            if finding:
                findings.append(finding)
    
    # 検出されたFindingの表示
    if findings:
        for finding in findings:
            print_finding(finding)
    
    # 重複排除
    if getattr(mode_config, 'deduplication_enabled', True):
        if findings and len(findings) > 1:
            print_header("🔍 DEDUPLICATING FINDINGS")
            original_count = len(findings)
            findings = deduplicate_findings(findings)
            if len(findings) < original_count:
                print_step("✨", f"Merged duplicates: {original_count} → {len(findings)}")
    
    # 通知送信（全FindingをRouter経由で統一通知）
    if findings and getattr(mode_config, 'notifications_enabled', True):
        try:
            results = finding_router.process_batch(
                findings,
                source_component="hunt",
                ingress_path="run_hybrid_hunt",
            )
            for dto in results:
                finding_router.route_and_notify(
                    dto,
                    source_component="hunt",
                    ingress_path="run_hybrid_hunt",
                )
            summary = finding_router.get_summary()
            print_step("📢", f"Notifications: {summary.get('total_sent', 0)} sent, "
                      f"{summary.get('dedup_skipped', 0)} skipped (dedup), "
                      f"{summary.get('dto_failed', 0)} failed")
        except Exception as e:
            logger.warning("Notification routing failed: %s", e)
    
    # RAG Feedback: False Positive判定
    fp_candidates = []
    if findings and getattr(mode_config, 'rag_feedback_enabled', True):
        try:
            from src.core.rag_module.rag_feedback import create_rag_feedback_manager
            
            print_header("🧠 RAG FEEDBACK ANALYSIS")
            fb_manager = create_rag_feedback_manager()
            
            # FP候補をフィルタ
            findings_filtered, fp_candidates = fb_manager.filter_likely_fps(
                [f.to_dict() if hasattr(f, 'to_dict') else {
                    'type': f.vuln_type.value if hasattr(f, 'vuln_type') else 'unknown',
                    'url': f.target_url if hasattr(f, 'target_url') else '',
                    'title': f.title if hasattr(f, 'title') else '',
                } for f in findings],
                threshold=0.7
            )
            
            if fp_candidates:
                print_step("⚠️", f"False Positive candidates detected: {len(fp_candidates)}")
                for fp in fp_candidates[:3]:  # 最初の3件のみ表示
                    confidence = fp.get('_fp_confidence', 0)
                    reason = fp.get('_fp_reason', 'Unknown')
                    print(f"     └─ {fp.get('title', 'Unknown')[:50]} (confidence: {confidence:.0%}, reason: {reason})")
                
                # 元のfindingsリストから対応するものを削除
                fp_titles = {fp.get('title') for fp in fp_candidates}
                findings = [f for f in findings if f.title not in fp_titles]
                
                print_step("✅", f"Findings after FP filtering: {len(findings)}")
        except Exception as e:
            print_step("⚠️", f"RAG Feedback skipped: {e}")

    
    # レポート生成
    if findings:
        print_header("📊 GENERATING REPORTS")
        
        for finding in findings:
            report_path = reporter.save_report(finding, output_dir=str(pm.get_reports_dir()))
            hunt_logger.log(
                phase=LogPhase.OUTPUT,
                content=f"レポート生成完了: {finding.title}",
                evidence_paths=[str(report_path)],
                agent_name="auto_reporter",
                target_url=finding.target_url,
            )
    
    print_header("📊 HUNT SUMMARY")
    print_step("🎯", f"Candidates analyzed: {len(plans)}")        
    if findings: 
        print_result(True, f"All reports and exports saved to: {pm.project_dir}")
        
        # タイムライン生成
        try:
            from src.core.visualization import generate_timeline
            timeline_path = generate_timeline(pm.project_dir, findings)
            print_step("📅", f"Timeline generated: {timeline_path.name}")
        except Exception as e:
            logger.debug(f"Timeline generation failed: {e}")
    
    print_step("🔥", f"Vulnerabilities found: {len(findings)}")

    # エージェントの後処理（未クローズセッション警告を抑制）
    for agent in [jwt_inspector, oauth_dancer, mfa_bypasser, bizlogic_hunter]:
        close_fn = getattr(agent, "close", None)
        if callable(close_fn):
            try:
                asyncio.run(close_fn())
            except Exception as e:
                logger.debug("Agent cleanup failed for %s: %s", agent.__class__.__name__, e)
    
    # ハンティングログをフラッシュ
    hunt_logger.flush()
    print_step("📝", f"Hunting log saved: {pm.project_dir}/hunting_log/{hunt_logger.session_id}.md")
