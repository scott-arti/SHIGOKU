---
task_id: SGK-2026-0478
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation.md
- docs/shigoku/reports/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- command-injection
created_at: '2026-09-09'
updated_at: '2026-09-10'
---

# SGK-2026-0478 作業ログ（コマンドインジェクション in-band・本物確定・実DVWA）

## 1. 事実確認（実測・実コードで確定・2026-09-09）
- 実 DVWA /vulnerabilities/exec/ は POST 専用・`ip=127.0.0.1;id` で `uid=33(www-data)` in-band 返却（GET 不発・認証 session+security=low）。
- 確定バーは command_execution 対応済（本文 _CMD_INDICATORS で発火）。壁: エンジン Finding の impact/repro 無し＋再現が GET-only で POST 注入を再現不可。

## 2. 台帳・計画・承認
- SGK-2026-0478 採番・登録。凍結 sealed_reproduction_checker.py 1ファイル改変（command_execution の非破壊コマンドPOST再送許可）はユーザー明示承認。

## 3. 実装（opencode / genuine deepseek-v4-flash・Claude 独立検証）
- B smart_cmd_ssrf: in-band POST 確定時のみ impact/repro＋command_replay(読み取り専用許可リスト id/whoami/uname/pwd/hostname/groups)。delivery に request_headers/body_params 記録。GET/blind/指標なしは byte-identical。
- A sealed_reproduction: _check_command_execution_replay（GET-only ガード前・検証済み command_replay のみ・scope 再検証＋fingerprint 一致＋POST 再送で _CMD_INDICATORS 再出現→matched・許可外/記述子なしは GET フォールバック）。GET-only 緩和は非破壊コマンド POST 再送限定・他マーカー byte-identical。
- インフラ: repo opencode.json 一時 agent→deepseek 上書きで makora 回避、完了後復元。[[opencode-fixer-subagent-makora-fallback]]。

## 4. 独立検証（Claude）
- 実 DVWA E2E: 実注入 uid=→payout_grade=True/command_execution→実 SealedReproductionChecker が DVWA へ ;id を再POSTし uid= 再観測→matched→CONFIRMED。
- fail-closed: 本文に _CMD_INDICATORS 無し→payout_grade=False/missing_impact＝非確定。
- 新規26テスト緑。injection+validation 1008 passed / 2 failed（phase_b 環境依存・無関係）。既存 GET-based command_execution・他マーカー非回帰。
- 凍結: 改変は sealed_reproduction_checker.py のみ。他4凍結 exit 0。denylist 0。

## 5. 完了
- 完了条件1〜8 PASS・in_scope_blocker 0 → done。能力マップ: コマンドインジェクションを実DVWAで◎（SSRFは△継続）。
