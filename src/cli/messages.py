"""
CLI user-facing message catalog (Japanese).

All user-facing CLI display strings are centralized here via message key lookup.
Internal logger messages, JSON output keys, and external tool raw output
are NOT included -- those remain in English.

Message Key Convention:
    module.category.specific_id

    module   = target source module (argparse, main, cli, logger, graph, dashboard)
    category = functional area (help, error, hint, status, result, banner)
    specific = unique identifier within the category

Examples:
    argparse.log.help       → "--log option help text"
    main.deferred.no_artifact → "No deferred backlog artifact found."
    cli.welcome.header      → Welcome panel header
    logger.tree.default_title → Default tree title "Execution Tree"

Usage:
    from src.cli.messages import msg

    # Simple lookup
    text = msg("argparse.log.help")

    # With format parameters
    text = msg("main.focus.groups_header")  # returns "テストグループ:"

    # Identifiers (command names, paths, task_ids) are interpolated via
    # format kwargs -- they remain in ASCII/English as-is.
    text = msg("main.deferred.status_summary",
               pending=5, in_progress=2, done=10, rejected=0, total=17)
"""

from __future__ import annotations

from typing import Any, Dict

# ============================================================
# Message Catalog (Japanese) -- canonical source of user-facing text
# ============================================================

_MESSAGES_JA: Dict[str, str] = {
    # ----------------------------------------------------------
    # argparse: description and epilog
    # ----------------------------------------------------------
    "argparse.description": (
        "SHIGOKU（至極）- 自律型バグバウンティハンター\n\n"
        "Caidoログ解析、GitHub監視、RAGナレッジベース検索、DNS履歴取得など、\n"
        "バグハンティングに必要な機能を統合したCLIツール。"
    ),
    "argparse.epilog": (
        "使用例:\n"
        "  %(prog)s --log caido.json --scope scope.yml --mode bugbounty\n"
        "  %(prog)s --watch owner/repo --scope scope.yml\n"
        "  %(prog)s --rag-ingest ./docs/\n"
        "  %(prog)s --rag-query \"How to find XSS?\"\n"
        "  %(prog)s --rag-stats\n"
        "  %(prog)s --dns example.com\n"
        "  %(prog)s --recon https://example.com\n"
        "  %(prog)s --demo\n"
        "  %(prog)s --mode bugbounty --target https://example.com\n"
        "  %(prog)s --projects\n"
        "  %(prog)s --mode vulntest --target https://example.com\n"
        "  %(prog)s --mode ctf --target https://example.com\n"
        "  %(prog)s --json\n"
        "\n"
        "環境変数:\n"
        "  SHIGOKU_SKIP_SUBPROCESS  - サブプロセス呼び出しをスキップ（--dry-runより強力）\n"
        "  SHIGOKU_RECON_START_STEP - 偵察開始ステップ (1-8)\n"
        "  SHIGOKU_RECON_END_STEP   - 偵察終了ステップ (1-8)\n"
    ),

    # ----------------------------------------------------------
    # argparse: individual argument help strings
    # ----------------------------------------------------------
    "argparse.log.help": (
        "統合ハント: プロキシログを解析し攻撃を実行する"
    ),
    "argparse.sessions_file.help": (
        "マルチアカウントセッション設定ファイル（クロスセッションIDORテスト用、オプション）"
    ),
    "argparse.cross_test_approved.help": (
        "承認済みIDORクロスセッション確認を有効化（--sessions-fileが必要）"
    ),
    "argparse.scope.help": "スコープ定義ファイル（YAML形式）",
    "argparse.watch.help": "センチネル監視: GitHubリポジトリを監視（owner/repo）",
    "argparse.demo.help": "グランドデモ: 全機能をデモンストレーション",
    "argparse.recon.help": (
        "偵察フェーズ: サイトの探索、技術スタックの特定、Neo4jへの保存"
    ),
    "argparse.mode.help": "ハントモード: bugbounty（デフォルト）, vulntest, ctf",
    "argparse.profile.help": (
        "スキャンプロファイル: bbpt（レポート品質重視）または ctf（速度・攻撃性重視）"
    ),
    "argparse.target.help": "ターゲット: 対象URLを指定（--reconのエイリアス）",
    "argparse.skip_initial_recon.help": (
        "MC前の初回偵察フェーズをスキップ（開発イテレーション高速化用）"
    ),
    "argparse.recon_start_step.help": (
        "recon_masterタスクの偵察パイプライン開始ステップを上書き（1-8）"
    ),
    "argparse.recon_end_step.help": (
        "recon_masterタスクの偵察パイプライン終了ステップを上書き（1-8）"
    ),
    "argparse.fast_iterate.help": (
        "高速イテレーション用ショートカット: --skip-initial-recon "
        "--recon-start-step 6 --recon-end-step 8"
    ),
    "argparse.recipe.help": "レシピ: 実行するレシピファイル（YAML形式）を指定",
    "argparse.cookie.help": (
        "認証済みスキャン用のCookieを渡す（例: 'PHPSESSID=...'）"
    ),
    "argparse.bearer_token.help": (
        "認証済みスキャン用のBearerトークンを渡す（生JWTまたは 'Bearer <token>'）"
    ),
    "argparse.crawl.help": "クロール: gospider/katanaをCaidoプロキシ経由で実行",
    "argparse.crawl_depth.help": "クロール深度: quick(1), standard(3), deep(5)",
    "argparse.analyze.help": (
        "解析: アプリの機能、種別、アーキテクチャ、脆弱性スコアを分析"
    ),
    "argparse.debug.help": (
        "デバッグモード: ハンドオフ/判断トレースを含む詳細ログを有効化"
    ),
    "argparse.rag_ingest.help": "RAG: 指定パスからファイルを取り込む（ディレクトリまたはPDF）",
    "argparse.rag_query.help": "RAG: ナレッジベースに問い合わせる",
    "argparse.rag_stats.help": "RAG: ナレッジベースの統計情報を表示",
    "argparse.pdf_only.help": "RAG取り込み: PDFファイルのみを処理",
    "argparse.reset_db.help": "RAG取り込み: 取り込み前にデータベースをリセット",
    "argparse.num_results.help": "RAG検索: 取得結果数（デフォルト: 5）",
    "argparse.dns.help": "DNS履歴: 過去のDNSレコードを取得",
    "argparse.fuzz.help": (
        "パラメータファジング: 隠しパラメータを発見し反射を確認"
    ),
    "argparse.openapi.help": (
        "OpenAPIテスト: Swagger/OpenAPIエンドポイントを自動テスト"
    ),
    "argparse.takeover.help": (
        "乗っ取り検出: サブドメイン乗っ取りの脆弱性をチェック"
    ),
    "argparse.export.help": "エクスポート: 検出結果をファイルに出力",
    "argparse.format.help": (
        "エクスポート/レポート形式: json（デフォルト）, csv, pdf, markdown, html, haddix"
    ),
    "argparse.tools.help": "ツール一覧: 登録されている全ツールとその状態を表示",
    "argparse.projects.help": "プロジェクト一覧: 利用可能な全プロジェクトを表示",
    "argparse.interactive.help": (
        "対話モード: Master Conductorとの対話セッションを開始"
    ),
    "argparse.resume.help": "セッション再開: 中断された前回のセッションから続行",
    "argparse.hitl_list.help": "セッション内の保留中HITLチケットを一覧表示",
    "argparse.deferred_list.help": (
        "最新のhaddix_deferredアーティファクトから遅延シナリオバックログを一覧表示"
    ),
    "argparse.deferred_checklist.help": (
        "遅延シナリオバックログから実行チェックリスト（Markdown）を生成"
    ),
    "argparse.deferred_status.help": "遅延シナリオのステータスサマリーを表示",
    "argparse.deferred_resolve.help": "遅延シナリオを解決済みとしてマーク（繰り返し可）",
    "argparse.deferred_note.help": "--deferred-resolveと併用する解決メモ",
    "argparse.deferred_resolved_by.help": (
        "--deferred-resolveと併用する解決者ラベル（デフォルト: operator）"
    ),
    "argparse.deferred_file.help": (
        "--deferred-*モード用のhaddix_deferred_*.jsonパスを明示指定"
    ),
    "argparse.deferred_checklist_output.help": (
        "--deferred-checklistのMarkdown出力先（デフォルト: "
        "reports/haddix_deferred_checklist_<timestamp>.md）"
    ),
    "argparse.hitl_run.help": "承認済みHITLチケットをキューに投入して実行",
    "argparse.hitl_approve.help": "HITLチケットを承認（繰り返し可）",
    "argparse.hitl_reject.help": "HITLチケットを却下（繰り返し可）",
    "argparse.intervention_gate_mode.help": (
        "この実行の介入ゲートモードを上書き"
    ),
    "argparse.report.help": "前回のセッションの実行レポートを表示",
    "argparse.report_replay.help": (
        "report_adapter復旧後、保留中のcanonical_report_payloadキューを再処理"
    ),
    "argparse.report_retry_failed.help": (
        "失敗したリプレイキューを保留中に戻して手動リトライ"
    ),
    "argparse.report_replay_list.help": (
        "リプレイキューをオペレーター確認用に一覧表示"
    ),
    "argparse.report_replay_platform.help": (
        "保留中レポートキューをリプレイする対象プラットフォーム"
    ),
    "argparse.report_replay_queue.help": (
        "リプレイキューパスを上書き（デフォルト: "
        "workspace/runtime/report_adapter_replay_queue.jsonl）"
    ),
    "argparse.report_replay_limit.help": (
        "処理する保留中リプレイエントリの最大数"
    ),
    "argparse.report_replay_queue_id.help": (
        "report-retry-failedの対象を特定のリプレイキューIDに絞る"
    ),
    "argparse.report_replay_status.help": (
        "リプレイ一覧をステータスでフィルター"
    ),
    "argparse.json.help": "JSON形式で出力",
    "argparse.dry_run.help": (
        "ドライラン: 実際の攻撃なしでワークフローを実行（safe_mode=True）"
    ),
    "argparse.translate_logs.help": (
        "実験的機能: ローカルLLMを使ってログを日本語に翻訳"
    ),
    "argparse.live_dashboard.help": (
        "フェーズ5: ターミナルにリアルタイム実行ダッシュボードを表示"
    ),
    "argparse.focus_list.help": (
        "フォーカス回帰テストグループを一覧表示して終了"
    ),
    "argparse.focus_tests.help": (
        "フォーカス回帰テストを実行（improve->verifyイテレーション高速化用）"
    ),
    "argparse.focus_group.help": (
        "実行するフォーカステストグループ（繰り返し指定可）"
    ),
    "argparse.focus_test.help": (
        "フォーカスモード用の追加pytestテストパス/nodeid（繰り返し指定可）"
    ),
    "argparse.focus_fail_fast.help": (
        "フォーカステスト実行時に初回失敗で停止（-x）"
    ),
    "argparse.quality_loop.help": (
        "標準化された改善→検証ループを実行。'short'はフォーカステストを最初に実行し、"
        "その後短縮攻撃ループを実行する。"
    ),
    "argparse.quality_loop_full_scan.help": (
        "--quality-loop shortと併用時、短縮攻撃ループの後に追加のフルスキャンを実行"
    ),

    # ----------------------------------------------------------
    # parser.error() messages
    # ----------------------------------------------------------
    "parser.error.recon_start_step_range": (
        "--recon-start-step は 1 から 8 の間で指定してください"
    ),
    "parser.error.recon_end_step_range": (
        "--recon-end-step は 1 から 8 の間で指定してください"
    ),
    "parser.error.recon_step_order": (
        "--recon-start-step は --recon-end-step 以下でなければなりません"
    ),
    "parser.error.quality_loop_requires_full_scan": (
        "--quality-loop-full-scan は --quality-loop と併用する必要があります"
    ),
    "parser.error.quality_loop_requires_target": (
        "--quality-loop は --target の指定が必要です"
    ),

    # ----------------------------------------------------------
    # Banner (print_banner) -- displayed at mode entry
    # ----------------------------------------------------------
    "banner.deferred": "遅延シナリオバックログ管理",
    "banner.hitl": "HITLチケット管理",
    "banner.resume": "前回セッションの再開",
    "banner.report_list": "レポートリプレイ一覧",
    "banner.report_retry": "レポートリトライ失敗",
    "banner.report_replay": "レポートリプレイ実行",

    # ----------------------------------------------------------
    # print_step messages (progress / stage indicators)
    # ----------------------------------------------------------
    "step.debug_enabled": "デバッグモード有効 - 詳細ログ出力中",
    "step.quality_loop_1": "品質ループ 1/3: フォーカス回帰プリチェック",
    "step.quality_loop_2": "品質ループ 2/3: 短縮攻撃ループ",
    "step.quality_loop_3": "品質ループ 3/3: フルスキャン（明示指定）",
    "step.quality_loop_precheck_unavailable": (
        "フォーカスプリチェックテストがこのランタイムでは利用できません。短縮攻撃ループに進みます。"
    ),
    "step.intervention_gate_mode": "介入ゲートモード: {mode}",
    "step.deferred_mode": "遅延シナリオバックログモード",
    "step.hitl_mode": "HITLチケット管理モード",
    "step.resume_attempting": "前回のセッションを再開しています...",
    "step.resume_restored": "セッションを復元しました: {count} 件のタスクがキューにあります",
    "step.resume_executing": "実行を再開しています...",
    "step.resume_completed": "再開したセッションが完了しました",
    "step.report_list_mode": "レポートリプレイ一覧モード",
    "step.report_retry_mode": "レポートリトライ失敗モード",
    "step.report_replay_mode": "レポートリプレイ実行モード",
    "step.recon_skip": "初回偵察をスキップします（--skip-initial-recon）",
    "step.recon_start": "初回偵察を開始しています（高速フェーズ）...",
    "step.recon_complete": "初回偵察が完了しました。Master Conductorを起動します。",
    "step.quality_loop_precheck_artifact": "プリチェックアーティファクトを保存しました: {path}",

    # ----------------------------------------------------------
    # print_result messages (success / failure / info outcomes)
    # ----------------------------------------------------------
    "result.focus.no_tests": "フォーカスモードで選択されたテストがありません。",
    "result.focus.only_missing": "フォーカスモードで存在しないテストだけが選択されました。",
    "result.focus.stage_passed": "{stage} に成功しました",
    "result.focus.stage_failed": "{stage} に失敗しました (exit={code})",
    "result.focus.resolved_count": "リポジトリルートから {count} 件のフォーカステストを解決しました: {root}",
    "result.focus.skipping_missing": "存在しないフォーカステストをスキップします: {preview}{suffix}",
    "result.focus.running": "実行中 {stage}: groups={groups}, tests={count}",
    "result.debug_not_available": "デバッグロガーが利用できません: {error}",
    "result.quality_loop_completed_full": (
        "品質ループ完了: フォーカステスト → 短縮攻撃ループ → フルスキャン"
    ),
    "result.quality_loop_completed_short": (
        "品質ループ完了: フォーカステスト → 短縮攻撃ループ"
    ),
    "result.quality_loop_next_hint": "次へ: 必要な場合のみフルスキャンを実行してください。",
    "result.deferred.mode_requires_target": (
        "--deferred-* モードには --target または --deferred-file "
        "が必要です（対応: --deferred-list/--deferred-checklist/"
        "--deferred-status/--deferred-resolve）"
    ),
    "result.deferred.no_artifact": "遅延バックログのアーティファクトが見つかりません。",
    "result.deferred.generate_haddix_hint": (
        "ヒント: 最初に `--report --format haddix` でHaddixレポートを生成してください。"
    ),
    "result.deferred.read_failed": "遅延バックログの読み取りに失敗しました: {error}",
    "result.deferred.update_failed": "遅延バックログの更新に失敗しました: {error}",
    "result.deferred.checklist_unwritable": "チェックリストの出力先に書き込めません: {path}",
    "result.deferred.checklist_fallback": "チェックリスト出力先に書き込めないため、代替パスを使用: {path}",
    "result.deferred.checklist_failed": "遅延チェックリストの生成に失敗しました: {error}",
    "result.deferred.scenario_count": "遅延シナリオ数: {count}",
    "result.deferred.no_scenarios": "このアーティファクトに遅延シナリオはありません。",
    "result.deferred.resolved_count": "解決済み遅延シナリオ: {count}",
    "result.deferred.scenario_not_found": "指定されたシナリオIDが見つかりません: {preview}{suffix}",
    "result.deferred.checklist_generated": "遅延チェックリストを生成しました: {path}",
    "result.hitl.no_tickets": "対応可能なHITLチケットが見つかりません。",
    "result.hitl.actionable_count": (
        "HITL対応可能チケット: {actionable} 件 "
        "(done={done}, rejected={rejected}, total={total})"
    ),
    "result.hitl.approved_count": "承認済みHITLチケット: {count}",
    "result.hitl.rejected_count": "却下済みHITLチケット: {count}",
    "result.hitl.ticket_not_found": "選択されたセッションにHITLチケットが見つかりません: {preview}{suffix}",
    "result.hitl.no_approved": "実行する承認済みHITLチケットがありません。",
    "result.hitl.ignoring_pending": (
        "--hitl-run モード: 既存の保留中タスク {count} 件を無視します"
    ),
    "result.hitl.queued": "承認済みHITLタスク {count} 件をキューに投入しました。",
    "result.hitl.completed": "HITL再開タスクが完了しました",
    "result.hitl.saved": "HITLチケットの更新を保存しました",
    "result.hitl.hint_gate_mode": (
        "ヒント: --intervention-gate-mode enforce_hitl で全保留チケットを "
        "確認できます。HITLをスキップするには --intervention-gate-mode observe を指定してください。"
    ),
    "result.hitl.hint_rerun": (
        "ヒント: 新規HITLチケットを発生させるには通常ミッションを実行してください。"
    ),
    "result.resume.tip": (
        "ヒント: 通常ミッションを先に実行し、中断後に --resume を使用してください"
    ),
    "result.session.not_found": "プロジェクト {target} のセッションが見つかりません。",
    "result.session.file_not_found": "セッションファイルが見つかりません ({path})",
    "result.session.load_failed": "セッションの読み込みに失敗しました",
    "result.report.replay_reset": "リプレイレコードをリセットしました: {platform} で {count} 件失敗",
    "result.report.replay_no_support": "設定されたプラットフォームマネージャーはリプレイに対応していません。",
    "result.report.replay_not_configured": "プラットフォームがリプレイ用に設定されていません: {platform}",
    "result.report.replay_processed": "リプレイ処理完了: {platform} で {count} 件",
    "result.report.html_generated": "HTMLレポートを生成しました: {path}",
    "result.report.html_failed": "HTMLレポートの生成に失敗しました: {error}",
    "result.report.haddix_generated": "jHADDIXスタイルレポートを生成しました: {path}",
    "result.report.haddix_ja_en_generated": "ja-enペアレポートを生成しました: {path}",
    "result.report.haddix_failed": "jHADDIXレポートの生成に失敗しました: {error}",
    "result.report.open_browser": "ブラウザで開いています...",
    "result.report.docker_hint": (
        "Docker環境で実行中です。上記のレポートパスをホストのブラウザで手動で開いてください。"
    ),
    "result.report.cannot_open_browser": "ブラウザを自動で開けませんでした。手動で開いてください: {path}",
    "result.report.view_hint": "Markdownレポートはこちらで確認できます: {path}",
    "result.projects.none": "プロジェクトが見つかりません。",
    "result.rag.disabled": "RAGは設定で無効化されています。",
    "result.no_args_help_hint": "\nヒント: python -m src.main --demo",
    "result.no_args_modes": "\n利用可能なモード: --mode bugbounty (デフォルト), vulntest, ctf",
    "result.background_waiting": (
        "\n{count} 件のバックグラウンドタスクの完了を待機中... (Ctrl+Cで強制終了)"
    ),
    "result.interrupted": "\n中断されました。直ちに終了します。",

    # ----------------------------------------------------------
    # Deferred scenario detail output (print)
    # ----------------------------------------------------------
    "deferred.status_summary": (
        "ステータスサマリー: pending={pending}, in_progress={in_progress}, "
        "done={done}, rejected={rejected}, total={total}"
    ),
    "deferred.artifact_path": "アーティファクト: {path}",
    "deferred.next_steps": (
        "次の操作:\n"
        "  1. --deferred-resolve SCENARIO_ID でシナリオを解決済みにする\n"
        "  2. --hitl-list でHITL化されたシナリオを確認する\n"
        "  3. --hitl-run で承認済みHITLチケットを実行する"
    ),
    "deferred.using_latest": "プロジェクト {target} の最新遅延バックログを使用します ({file})",

    # ----------------------------------------------------------
    # HITL detail output (print)
    # ----------------------------------------------------------
    "hitl.using_session": "{reason} でプロジェクト {target} のセッションを使用します ({session})",
    "hitl.resume_using_latest": "プロジェクト {target} の最新セッションを使用します",
    "hitl.resume_valid_session": "プロジェクト {target} の最新有効セッションを使用します ({file})",

    # ----------------------------------------------------------
    # Finding / evidence artifact output
    # ----------------------------------------------------------
    "finding.appended_heuristics": (
        "実行テレメトリから {count} 件のヒューリスティック候補検出を追加しました"
    ),
    "finding.promoted_heuristics": (
        "実行テレメトリから {count} 件のヒューリスティック候補検出を昇格しました"
    ),
    "finding.evidence_saved": (
        "検出証跡アーティファクトを保存しました: {count} 件 → {dir}"
    ),

    # ----------------------------------------------------------
    # Gate / deferred output
    # ----------------------------------------------------------
    "gate.verdict_saved": "初期リリースゲート判定を保存しました: {path}",
    "gate.deferred_saved": "遅延シナリオバックログを保存しました: {path}",
    "gate.status": "初期リリースゲート: {status} (理由コード={codes})",

    # ----------------------------------------------------------
    # Next action hints (print)
    # ----------------------------------------------------------
    "next_action.after_scan": "次へ: 必要な場合のみフルスキャンを実行してください。",
    "next_action.try_demo": "\nヒント: python -m src.main --demo",

    # ----------------------------------------------------------
    # Quality loop outputs
    # ----------------------------------------------------------
    "quality.short_attack_failed": "短縮攻撃ループに失敗しました (exit={code})",
    "quality.full_scan_failed": "フルスキャンに失敗しました (exit={code})",

    # ============================================================
    # Phase 2: src/cli/cli.py -- Interactive REPL interface
    # ============================================================
    "cli.welcome.header": (
        "CAI Clone - サイバーセキュリティAIエージェントフレームワーク"
    ),
    "cli.welcome.body": (
        "[bold cyan]{title}[/bold cyan]\n\n"
        "[yellow]エージェント:[/yellow] {name}\n"
        "[yellow]モデル:[/yellow] {model}\n"
        "[yellow]ツール:[/yellow] {tool_list}\n\n"
        "コマンド一覧は [cyan]/help[/cyan]、終了は [cyan]exit[/cyan] を入力してください。"
    ),
    "cli.error.unknown_command": "[red]不明なコマンド:[/red] {cmd}",
    "cli.error.hint_help": "[dim]使用可能なコマンドは /help で確認できます[/dim]",
    "cli.processing": "[cyan]処理中...[/cyan]",
    "cli.cancelled": "ユーザーによりタスクがキャンセルされました",
    "cli.response": "[bold green]エージェント:[/bold green] {response}",
    "cli.prompt_toolkit_missing": (
        "[yellow]注意: prompt_toolkit が見つかりません。"
        "複数行入力はサポートされません。"
        "より良いエクスペリエンスのためにインストールしてください。[/yellow]"
    ),
    "cli.error.generic": "[red]エラー:[/red] {error}",
    "cli.goodbye": "[cyan]またね！[/cyan]",

    # ============================================================
    # Phase 2: src/cli/commands.py -- Command handler messages
    # ============================================================

    # /help
    "cmd.help.header": "[bold cyan]使用可能なコマンド:[/bold cyan]",
    "cmd.help.usage": "[yellow]{usage:15}[/yellow] - {desc}",

    # /tools
    "cmd.tools.header": "[bold cyan]使用可能なツール:[/bold cyan]",
    "cmd.tools.entry": "[yellow]{name:20}[/yellow] - {desc}",

    # /history
    "cmd.history.count": "[cyan]現在のメッセージ数:[/cyan] {count}",

    # /model
    "cmd.model.current": "[cyan]現在のモデル:[/cyan] {current}",
    "cmd.model.recommended": "[bold cyan]推奨モデル:[/bold cyan]",
    "cmd.model.provider": "[yellow]{provider}:[/yellow]",
    "cmd.model.entry": "- {model}{marker}",
    "cmd.model.changed": "[green]モデルを変更しました:[/green] {model}",
    "cmd.model.usage_hint": "[dim]使用法: /model <モデル名>[/dim]",
    "cmd.model.note": "[dim]注意: litellmがサポートする任意のモデルを使用できます。[/dim]",

    # /agent
    "cmd.agent.header": "[bold cyan]エージェント情報:[/bold cyan]",
    "cmd.agent.name": "名前: {name}",
    "cmd.agent.model": "モデル: {model}",
    "cmd.agent.mode": "モード: {mode}",
    "cmd.agent.tools": "ツール: {tools}",
    "cmd.agent.messages": "メッセージ: {messages}",

    # /mode
    "cmd.mode.current": "[cyan]現在のモード:[/cyan] {current}",
    "cmd.mode.available": "[bold cyan]利用可能なモード:[/bold cyan]",
    "cmd.mode.desc_redteam": "[yellow]redteam[/yellow] - レッドチームオペレーション（インフラ侵入テスト）",
    "cmd.mode.desc_webpentest": "[yellow]webpentest[/yellow] - Webアプリケーション侵入テスト",
    "cmd.mode.desc_bugbounty": "[yellow]bugbounty[/yellow] - バグバウンティハンティング",
    "cmd.mode.desc_ctf": "[yellow]ctf[/yellow] - CTFチャレンジモード",
    "cmd.mode.desc_security": "[yellow]security[/yellow] - 汎用セキュリティ分析",
    "cmd.mode.invalid": "[red]無効なモード:[/red] {mode}",
    "cmd.mode.valid_list": "[dim]有効なモード: {modes}[/dim]",
    "cmd.mode.switched": "[green]✓ モードを切り替えました:[/green] {mode}",
    "cmd.mode.usage_hint": "[dim]使用法: /mode <モード名>[/dim]",

    # /graph
    "cmd.graph.no_graph": "[yellow]実行グラフがありません。[/yellow]",
    "cmd.graph.hint": "[dim]グラフはエージェント実行中に自動生成されます。[/dim]",
    "cmd.graph.summary": "[dim]{summary}[/dim]",

    # /memory
    "cmd.memory.saved": "[green]✓ セッションを保存しました:[/green] ID {session_id}",
    "cmd.memory.cleared": "[green]✓ すべてのメモリをクリアしました[/green]",
    "cmd.memory.stats_header": "メモリ統計",
    "cmd.memory.stats_sessions": "セッション: {count}",
    "cmd.memory.stats_total_steps": "総ステップ: {steps}",
    "cmd.memory.no_sessions": "[yellow]保存されたセッションはありません[/yellow]",
    "cmd.memory.sessions_header": "保存されたセッション",
    "cmd.memory.sessions_col_id": "ID",
    "cmd.memory.sessions_col_summary": "サマリー",
    "cmd.memory.sessions_col_agent": "エージェント",
    "cmd.memory.sessions_col_mode": "モード",
    "cmd.memory.sessions_col_size": "サイズ",
    "cmd.memory.sessions_col_created": "作成日時",
    "cmd.memory.session_row": "{session_id} | {summary} | {agent} | {mode} | {size} | {created}",

    # /agents
    "cmd.agents.header": "[bold cyan]登録済みエージェント:[/bold cyan]",
    "cmd.agents.none": "[dim]エージェントが登録されていません[/dim]",
    "cmd.agents.entry": "{marker} [yellow]{name:15}[/yellow] - {model}",

    # /compact
    "cmd.compact.already": "[yellow]履歴はすでにコンパクトです。[/yellow]",
    "cmd.compact.done": "[green]圧縮完了:[/green] {removed} 件の古いメッセージを削除しました",
    "cmd.compact.current": "[cyan]現在のメッセージ数:[/cyan] {count}",

    # /load
    "cmd.load.no_path": "[red]エラー:[/red] ファイルパスを指定してください",
    "cmd.load.usage": "[dim]使用法: /load <ファイルパス>[/dim]",
    "cmd.load.success": "[green]{count} 件のメッセージを {path} から読み込みました[/green]",
    "cmd.load.not_found": "[red]エラー:[/red] ファイルが見つかりません: {path}",
    "cmd.load.invalid_json": "[red]エラー:[/red] ファイルのJSONが不正です: {error}",
    "cmd.load.error": "[red]エラー:[/red] {error}",

    # /clear
    "cmd.clear.done": "[green]会話履歴をクリアしました。[/green]",

    # /mcp
    "cmd.mcp.usage": "[red]使用法:[/red] /mcp <add|list> [args...]",
    "cmd.mcp.help_add": "  /mcp add <コマンド> [引数...]  - MCPサーバーを追加",
    "cmd.mcp.help_list": "  /mcp list                      - 接続中のMCPサーバーを一覧表示",
    "cmd.mcp.no_command": "[red]エラー:[/red] サーバーコマンドを指定してください",
    "cmd.mcp.example": "[dim]例: /mcp add python mcp_server.py[/dim]",
    "cmd.mcp.connecting": "[cyan]MCPサーバーに接続中:[/cyan] {command}",
    "cmd.mcp.connected": "[green]✓ 接続しました！[/green] {count} 個のツールを検出:",
    "cmd.mcp.tool_entry": "- {tool}",
    "cmd.mcp.error": "[red]エラー:[/red] {error}",
    "cmd.mcp.header": "[bold cyan]MCPサーバー:[/bold cyan]",
    "cmd.mcp.none": "[dim]接続中のMCPサーバーはありません[/dim]",
    "cmd.mcp.entry": "[yellow]{name:15}[/yellow] - {count} ツール",
    "cmd.mcp.unknown_subcommand": "[red]不明なサブコマンド:[/red] {subcommand}",

    # /rag
    "cmd.rag.enabled": "[green]✓ RAGを有効化しました[/green]",
    "cmd.rag.enabled_hint": "[dim]ナレッジベースがクエリに使用されます。[/dim]",
    "cmd.rag.disabled": "[yellow]✓ RAGを無効化しました[/yellow]",
    "cmd.rag.disabled_hint": "[dim]クエリはナレッジベースを使用しません。[/dim]",
    "cmd.rag.status_header": "RAGステータス",
    "cmd.rag.ingester_status": "取り込み状態: {status}",
    "cmd.rag.unknown_action": "[red]不明なアクション:[/red] {action}",
    "cmd.rag.usage": "[dim]使用法: /rag <on|off|status>[/dim]",

    # /sessions
    "cmd.sessions.none": "[yellow]保存されたセッションが見つかりません。[/yellow]",
    "cmd.sessions.hint": "[dim]セッションはMasterConductor実行時に作成されます。[/dim]",
    "cmd.sessions.header": "保存されたセッション",
    "cmd.sessions.col_id": "ID",
    "cmd.sessions.col_project": "プロジェクト",
    "cmd.sessions.col_mode": "モード",
    "cmd.sessions.col_progress": "進捗",
    "cmd.sessions.col_updated": "更新日時",
    "cmd.sessions.resume_hint": "[dim]セッションを再開するには /resume <セッションID> を使用してください。[/dim]",

    # /resume
    "cmd.resume.no_id": "[red]エラー:[/red] セッションIDを指定してください",
    "cmd.resume.usage": "使用法: /resume <セッションID>",
    "cmd.resume.list_hint": "利用可能なセッションは /sessions で確認できます。",
    "cmd.resume.success": "[green]✓ セッションを再開しました:[/green] {session_id}",
    "cmd.resume.pending": "[cyan]保留中のタスク:[/cyan] {count}",
    "cmd.resume.target": "[cyan]ターゲット:[/cyan] {target}",
    "cmd.resume.hint_continue": "[yellow]残りのタスクを実行するには 'continue' を入力してください。[/yellow]",
    "cmd.resume.no_pending": "[dim]保留中のタスクはありません。セッションは完了しています。[/dim]",
    "cmd.resume.failed": "[red]エラー:[/red] セッション '{session_id}' の再開に失敗しました",
    "cmd.resume.failed_hint": "[dim]利用可能なセッションは /sessions で確認できます。[/dim]",

    # /dalfox
    "cmd.dalfox.no_url": "[red]エラー:[/red] ターゲットURLを指定してください",
    "cmd.dalfox.usage": "使用法: /dalfox <URL> [オプション]",
    "cmd.dalfox.example": "例: /dalfox https://example.com/page?q=test",
    "cmd.dalfox.invalid_url": "[red]エラー:[/red] 無効なURL: {url}",
    "cmd.dalfox.url_hint": "[dim]URL は http:// または https:// で始まる必要があります[/dim]",
    "cmd.dalfox.header": "DalFox XSSスキャナー",
    "cmd.dalfox.target": "ターゲット: {target}",
    "cmd.dalfox.framework": "フレームワーク: DalFox (Parameter Analysis and XSS Scanning Engine)",
    "cmd.dalfox.checking": "[dim]DalFoxの利用可否を確認中...[/dim]",
    "cmd.dalfox.not_available": "[red]✗ DalFoxが利用できません[/red]",
    "cmd.dalfox.not_available_hint": "[dim]バイナリがインストールされていないか、設定が不足している可能性があります。[/dim]",
    "cmd.dalfox.available": "[green]✓ DalFoxが利用可能です[/green]",
    "cmd.dalfox.completed": "[green]✓ スキャンが {time:.0f}ms で完了しました[/green]",
    "cmd.dalfox.vulns_found": "[bold red]⚠ {count} 件のXSS脆弱性を検出しました:[/bold red]",
    "cmd.dalfox.no_vulns": "[green]✓ XSS脆弱性は見つかりませんでした[/green]",
    "cmd.dalfox.timeout": "[yellow]⚠ スキャンがタイムアウトしました[/yellow]",
    "cmd.dalfox.timeout_hint": "[dim]タイムアウト値を増やすか、ターゲットの応答性を確認してください。[/dim]",
    "cmd.dalfox.failed": "[red]✗ スキャンに失敗しました[/red]",
    "cmd.dalfox.error": "[red]エラー:[/red] {error}",
    "cmd.dalfox.exec_stats": "実行統計",
    "cmd.dalfox.total_executed": "総実行数: {count}",
    "cmd.dalfox.avg_wait": "平均待機時間: {time}ms",
    "cmd.dalfox.unexpected_error": "[red]✗ 予期しないエラー:[/red] {error}",
    "cmd.dalfox.check_logs": "[dim]詳細はログを確認してください。[/dim]",

    # /nuclei
    "cmd.nuclei.no_url": "[red]エラー:[/red] ターゲットURLを指定してください",
    "cmd.nuclei.usage": "使用法: /nuclei <URL> [--tags <タグ>] [--severity <深刻度>]",
    "cmd.nuclei.example": "例: /nuclei https://example.com --tags xss,sqli --severity critical,high",
    "cmd.nuclei.invalid_url": "[red]エラー:[/red] 無効なURL: {url}",
    "cmd.nuclei.url_hint": "[dim]URL は http:// または https:// で始まる必要があります[/dim]",
    "cmd.nuclei.header": "Nuclei 脆弱性スキャナー",
    "cmd.nuclei.target": "ターゲット: {target}",
    "cmd.nuclei.tags": "タグ: {tags}",
    "cmd.nuclei.severity": "深刻度: {severity}",
    "cmd.nuclei.checking": "[dim]Nucleiの利用可否を確認中...[/dim]",
    "cmd.nuclei.not_available": "[red]✗ Nucleiが利用できません[/red]",
    "cmd.nuclei.not_available_hint": "[dim]バイナリがインストールされていないか、設定が不足している可能性があります。[/dim]",
    "cmd.nuclei.available": "[green]✓ Nucleiが利用可能です[/green]",
    "cmd.nuclei.completed": "[green]✓ スキャンが {time:.0f}ms で完了しました[/green]",
    "cmd.nuclei.vulns_found": "[bold red]⚠ {count} 件の脆弱性を検出しました:[/bold red]",
    "cmd.nuclei.no_vulns": "[green]✓ 脆弱性は見つかりませんでした[/green]",
    "cmd.nuclei.timeout": "[yellow]⚠ スキャンがタイムアウトしました[/yellow]",
    "cmd.nuclei.timeout_hint": "[dim]タイムアウト値を増やすか、ターゲットの応答性を確認してください。[/dim]",
    "cmd.nuclei.failed": "[red]✗ スキャンに失敗しました[/red]",
    "cmd.nuclei.error": "[red]エラー:[/red] {error}",
    "cmd.nuclei.exec_stats": "実行統計",
    "cmd.nuclei.total_executed": "総実行数: {count}",
    "cmd.nuclei.avg_wait": "平均待機時間: {time}ms",
    "cmd.nuclei.unexpected_error": "[red]✗ 予期しないエラー:[/red] {error}",
    "cmd.nuclei.check_logs": "[dim]詳細はログを確認してください。[/dim]",

    # external-tools (function)
    "cmd.external_tools.header": "[bold cyan]外部ツールステータス[/bold cyan]",
    "cmd.external_tools.executor_title": "[bold]実行管理:[/bold]",
    "cmd.external_tools.semaphore": "セマフォ: {status}",
    "cmd.external_tools.max_concurrent": "最大同時実行: {max_concurrent}",
    "cmd.external_tools.current_slots": "使用中スロット: {slots}",
    "cmd.external_tools.total_executed": "総実行数: {executed}",
    "cmd.external_tools.waiting": "待機中: {waiting}",
    "cmd.external_tools.health_title": "[bold]ツール健全性チェック:[/bold]",
    "cmd.external_tools.health_tool": "{tool}: {status}",
    "cmd.external_tools.health_hint": "[dim]ヒント: 利用不可のツールはインストール後に /tools コマンドで再確認してください。[/dim]",
    "cmd.external_tools.error": "[red]ツールチェックエラー:[/red] {error}",

    # ============================================================
    # Phase 2: src/cli/graph.py -- ExecutionGraph strings
    # ============================================================
    "graph.no_steps": "[yellow]実行ステップが記録されていません[/yellow]",
    "graph.ascii_header": "[bold cyan]実行フロー:[/bold cyan]",
    "graph.step_line": "[{i}] {action}",
    "graph.tool_line": "└─ ツール: [yellow]{tool}[/yellow]",
    "graph.result_line": "└─ 結果: [dim]{preview}...[/dim]",
    "graph.connector": "↓",
    "graph.mermaid_empty": "```\ngraph TD\n  Start[ステップなし]\n```",
    "graph.no_steps_summary": "実行ステップなし",
    "graph.summary": "総ステップ数: {steps}\n使用ツール: {tools}",

    # ============================================================
    # Phase 2: src/cli/monitoring_dashboard.py -- Dashboard strings
    # ============================================================
    "dashboard.semaphore_title": "セマフォ統計",
    "dashboard.col_metric": "メトリクス",
    "dashboard.col_value": "値",
    "dashboard.col_status": "状態",
    "dashboard.active": "🟢 有効",
    "dashboard.disabled": "🔴 無効",
    "dashboard.ok": "🟢 正常",
    "dashboard.high": "🟡 高負荷",
    "dashboard.critical": "🔴 危険",
    "dashboard.warning": "🟡 警告",
    "dashboard.tool_stats_title": "ツール統計",
    "dashboard.col_tool": "ツール",
    "dashboard.col_executions": "実行回数",
    "dashboard.col_success_rate": "成功率",
    "dashboard.col_avg_time": "平均時間",
    "dashboard.no_data": "データなし",
    "dashboard.recent_title": "最近の実行 (直近10件)",
    "dashboard.col_time": "時刻",
    "dashboard.col_target": "ターゲット",
    "dashboard.col_result": "結果",
    "dashboard.col_duration": "所要時間",
    "dashboard.no_recent": "最近の実行はありません",
    "dashboard.alert_high_wait": "⚠️ 待機時間が高くなっています: {time:.1f}ms > 500ms しきい値",
    "dashboard.alert_high_wait_hint": "   SHIGOKU_EXTERNAL_TOOL_CONCURRENCY の増加を検討してください",
    "dashboard.alert_high_error": "⚠️ エラー率が高くなっています: {rate:.1%} > 5% しきい値",
    "dashboard.alert_high_error_hint": "   バイナリの健全性と設定を確認してください",
    "dashboard.alert_high_utilization": "⚠️ セマフォ使用率が高くなっています: {utilization:.1%}",
    "dashboard.alert_high_utilization_hint": "   同時実行数の増加または負荷の軽減を検討してください",
    "dashboard.alert_all_ok": "✅ 全システム正常",
    "dashboard.header": "[bold cyan]外部ツール監視ダッシュボード[/bold cyan]",
    "dashboard.exit_hint": "[dim]Ctrl+C で終了[/dim]",
    "dashboard.stopped": "[yellow]監視を停止しました[/yellow]",
    "dashboard.exported": "[green]レポートを出力しました: {path}[/green]",
    "dashboard.exiting": "\n終了しています...",

    # ============================================================
    # Phase 3: src/core/logger.py -- Human-facing logger helpers
    # ============================================================
    "logger.tree.default_title": "実績ツリー",
}


# ============================================================
# Message Resolution Functions
# ============================================================

# Active message catalog (future: can be switched to _MESSAGES_EN)
_active_catalog: Dict[str, str] = _MESSAGES_JA


def msg(key: str, **kwargs: Any) -> str:
    """Resolve a user-facing message by key.

    Args:
        key: Message key in the format module.category.specific_id
        **kwargs: Format parameters for the resolved string

    Returns:
        The resolved message string, or the key itself wrapped in ?? if not found.

    Examples:
        >>> msg("argparse.log.help")
        '統合ハント: プロキシログを解析し攻撃を実行する'
        >>> msg("main.focus.groups_header")
        'テストグループ:'
        >>> msg("result.deferred.scenario_count", count=5)
        '遅延シナリオ数: 5'
    """
    message = _active_catalog.get(key)
    if message is None:
        # Fallback: return the key as-is for missing translations
        return f"??{key}??"

    if kwargs:
        try:
            return message.format(**kwargs)
        except KeyError as exc:
            # Missing format key -- return partial message with key hint
            return f"{message} [missing key: {exc}]"

    return message


def msg_or_none(key: str) -> str | None:
    """Resolve a message key, returning None if not found."""
    return _active_catalog.get(key)


def all_keys() -> list[str]:
    """Return all registered message keys (for auditing)."""
    return sorted(_active_catalog.keys())
