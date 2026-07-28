---
task_id: SGK-2026-0392
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
title: DVWA low Brute Force CAPTCHA CSP dedicated detection
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / Brute Force CAPTCHA CSP dedicated detection
---

# 実装計画書：DVWA low Brute Force CAPTCHA CSP dedicated detection

## 1. 目的

Brute Force / CAPTCHA / CSP を、単なる fuzzing 対象として放置しない。ただし、DVWA の教材ページに合わせて無理に finding 化しない。

この task では、実アプリでも成立する問題だけを専用評価する。成立しないものは reason-coded non-finding、または XSS など他 finding の補助 evidence として扱う。

## 2. 優先度

この task は Task A〜D の後に実施する。理由は、SQLi / XSS / Command Injection / LFI / AuthBypass の方が SHIGOKU の Initial Release Gate と提出品質に直接効くため。

Task A の期待検知マトリクスで、CAPTCHA / CSP が「DVWA 教材ページ固有」と判断された場合は、実装修正をしないで対象外理由を残す。

## 3. 対象と扱い

| 対象 | 扱い |
|---|---|
| Brute Force: `/vulnerabilities/brute/` | 一般的なログイン画面・認証 API のレート制限、ロックアウト、認証差分として扱える場合のみ専用評価する。 |
| CAPTCHA: `/vulnerabilities/captcha/` | token reuse、server-side validation 不備、state validation 不備として一般化できる場合のみ扱う。DVWA 教材ページ固有なら対象外可。 |
| CSP: `/vulnerabilities/csp/` | 単独 finding ではなく、危険 header policy や XSS 影響の補助 evidence として扱う。DVWA 固有 bypass だけなら対象外可。 |

## 4. 作業内容

- [ ] Brute Force を、一般的な認証フローのレート制限・ロックアウト・認証差分の観点で評価する。
- [ ] CAPTCHA を、一般化できる token reuse / server-side validation / state validation の観点で評価する。
- [ ] CSP を、header policy と XSS 影響の補助 evidence として評価する。
- [ ] DVWA 固有の教材ページ構造や固定文言だけに依存する検知は作らない。
- [ ] fuzzing だけで終わらせず、専用 finding、補助 evidence、または reason-coded non-finding として成果物化する。
- [ ] Task C / D の confirmed 増加を壊さないことを確認する。

## 5. 完了条件

- 3対象が fuzzing だけではなく、専用評価・補助 evidence・対象外理由のいずれかとして記録される。
- Finding にできない場合も、なぜ finding ではないか reason code が残る。
- DVWA 教材機能だけに合わせた検知が追加されていない。
- report/session consistency が PASS する。

## 6. リスク

- [重要度:中] Brute Force は試行回数を増やしすぎると安全性と時間に悪影響がある。決定的な少数試行に限定する。
- [重要度:中] CAPTCHA は教材用の作りだと現実の検知価値が低い。一般化できない場合は対象外にする。
- [重要度:低] CSP は DVWA low では補助的な意味が強い。過大評価しない。
