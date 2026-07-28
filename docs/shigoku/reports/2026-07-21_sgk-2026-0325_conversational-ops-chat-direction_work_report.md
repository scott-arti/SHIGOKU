---
task_id: SGK-2026-0325-WR
doc_type: work_report
status: done
parent_task_id: SGK-2026-0325
related_docs:
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
  - docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
  - docs/shigoku/worklogs/2026-07-21_sgk-2026-0325_conversational-ops-chat-direction_work_log.md
title: 'SGK-2026-0325 実装報告: 対話型オペレーション軽量版'
created_at: '2026-07-21'
updated_at: '2026-07-28'
---

# SGK-2026-0325 実装報告

## 実施サマリ

自然言語のオペレータ指示を、allowlist 済みの `IntentCommand` preview へ落とす lightweight 導線を完成させた。
`src/cli/intent_parser.py` と `shigoku-ops ops intent` を中心に、preview / confirmation loop、`--attack-targets` / `--wordlist` の入力橋渡し、non-TTY fail-closed、kill switch、timeout、daily budget をそろえ、危険操作を shell 文字列に落とさず構造化 command としてだけ流す形に固定した。

## 判断理由

- 0325 は「入力側」に責務を限定し、実行本体は既存 `shigoku-ops` / `src.main` へ委譲する構成にした。
- attack 系は preview と承認を必須にし、non-TTY では fail-closed または dry-run 限定にすることで、自然言語誤解釈の事故半径を小さくした。
- 0326 が出力する `attack_targets.json` を正本入力として受ける前提に寄せ、自由形式 Markdown の逆解析は初期スコープに含めなかった。

## 検証結果

- targeted / broader regression suite は親ロードマップ側の検証で green を維持した。
- real report artifact に対する `ops intent` preview で `attack_target_count=13` を確認した。
- real TTY で `shigoku-ops ops intent --intent "このレポートから API だけ Fuzz して" --report workspace/projects/127.0.0.1:8888/reports/haddix_report_20260421_020448.md --target http://127.0.0.1:8888 --execute --main-dry-run` を実行し、preview 表示後の `Execute it? [y/N]` 承認を通して `report.export-targets -> main.attack-targets` の限定実行が returncode 0 で完了した。
- failure path は `malformed intent`, `unknown command`, `approval deny`, `non-TTY`, `scope外 target`, `timeout`, `kill_switch on`, `intent_llm_unavailable` を回帰テストで固定した。

## deferred_tasks

なし。本タスクは軽量版の入力導線を対象としており、実行中 MC への重量版動的注入は当初からスコープ外として扱った。
