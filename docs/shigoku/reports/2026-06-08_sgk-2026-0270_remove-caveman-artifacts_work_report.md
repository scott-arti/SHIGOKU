---
task_id: SGK-2026-0270
doc_type: work_report
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-06-08_sgk-2026-0270_remove-unused-caveman-skill-artifacts_plan.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
title: "Remove unused Caveman skill artifacts 実施報告"
created_at: "2026-06-08"
updated_at: '2026-06-30'
---

# 作業報告

## 実施内容
- `.agents/skills/` 配下に残っていた `caveman`, `caveman-commit`, `caveman-compress`, `caveman-help`, `caveman-review`, `caveman-stats`, `cavecrew` を削除した。
- `skills-lock.json` から Caveman 系 skill の lock 情報を削除し、空の `skills` マップへ整理した。
- `AGENTS.md` から Caveman 思考スタイル指示を削除し、節番号を詰め直した。
- SHIGOKU 台帳、計画書、報告書、作業ログを今回の削除作業に合わせて更新した。

## 判断理由
- ユーザーが Caveman plugin/skill 群を実運用しておらず、中途半端に残っている状態だったため、repo 内の関連資産と参照をまとめて消す方が保守しやすい。
- `cavecrew` も `skills-lock.json` 上では同じ `JuliusBrussee/caveman` ソース由来であり、未使用の Caveman 系補助スキルとして合わせて除去した。
- 今後の Git SKILL 設計を考えるうえでも、外部圧縮系 skill への委譲を前提にしない構成へ戻した方が方針が明確になる。

## 変更ファイル
- `AGENTS.md`
- `skills-lock.json`
- `.agents/skills/cavecrew/*`
- `.agents/skills/caveman*/*`
- `docs/shigoku/plans/2026-06-08_sgk-2026-0270_remove-unused-caveman-skill-artifacts_plan.md`

## 検証
- `rg -n "caveman|cavecrew" . -g '!node_modules' -g '!graphify-out' -g '!workspace' -g '!tmp'`
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`

## リスク
- グローバル環境側にインストールされた Caveman plugin 自体は、この repo から関連ファイルを消しても自動ではアンインストールされない。
- 将来 Caveman を再導入したくなった場合は、`skills-lock.json` と `.agents/skills/` をあらためて復元または再インストールする必要がある。

