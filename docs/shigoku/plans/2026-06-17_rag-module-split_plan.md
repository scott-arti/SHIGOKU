---
task_id: SGK-2026-0302
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/modules/RAG_SYSTEM.md
- docs/shigoku/subtasks/2026-06-03_obsidian-rag-kg-recipe_subtask_plan.md
- docs/shigoku/reports/2026-06-17_SGK-2026-0302_work_report.md
- docs/shigoku/worklogs/2026-06-17_SGK-2026-0302_work_log.md
- tests/unit/core/rag_module/test_rag_split.py
- tests/unit/commands/test_rag_commands_split.py
title: '巨大ファイル分割計画: RAG Module 分割'
created_at: '2026-06-17'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/rag_module/rag.py
---

# 実装計画書：巨大ファイル分割計画: RAG Module 分割

## 1. 達成したいゴール（ユーザー視点）
- [x] `src/core/rag_module/rag.py` の公開 import path を維持したまま、RAG 系の責務を facade / model / ingester / switch に分割できること。
- [x] `KnowledgeIngester` / `PDFIngester` / `RAGSwitch` / `get_rag_switch()` / `init_rag()` の公開挙動を変えず、既存の `src/commands/rag.py`、`src/commands/hunt.py`、`src/cli/commands.py` からの利用を壊さないこと。
- [x] 現在 1,078 行の `rag.py` を、facade 200 行未満、主要分割先 200-500 行目安の構成へ整理し、次の改善が入りやすい土台にすること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/rag_module/rag.py`: （修正）互換維持用 facade。既存 import path、re-export、singleton access、初期化 helper だけを保持する。
  - `src/core/rag_module/rag_types.py`: （新規）`RAGDocument` / `RAGResult` などの軽量 model を保持する候補。
  - `src/core/rag_module/rag_ingester.py`: （新規）`KnowledgeIngester` 本体と ingest/query 系 helper を保持する候補。
  - `src/core/rag_module/rag_pdf_ingester.py`: （新規）`PDFIngester` と PDF chunking / parsing 補助を保持する候補。
  - `src/core/rag_module/rag_switch.py`: （新規）`RAGSwitch`、singleton 補助、必要なら `get_rag_switch()` 実装本体を保持する候補。
  - `src/core/rag_module/__init__.py`: （必要時のみ修正）package export の薄い再公開レイヤ。
  - `src/commands/rag.py`: （参照のみ、必要時のみ修正）`src.core.rag` と `src.core.rag_module.rag` の import fallback が維持されるか確認する。
  - `src/commands/hunt.py`: （参照のみ）`get_rag_switch()` 利用の回帰確認対象。
  - `src/cli/commands.py`: （参照のみ）`RAGSwitch` 直接生成パスの回帰確認対象。
  - `tests/unit/core/rag_module/test_rag_split.py`: （新規）import 互換、singleton、初期化、薄い smoke を固定する characterization test 候補。
- **データの流れ / 依存関係:**
  - CLI / command layer (`src/commands/rag.py`, `src/commands/hunt.py`, `src/cli/commands.py`) -> `src.core.rag_module.rag` facade -> `KnowledgeIngester` / `PDFIngester` / `RAGSwitch` -> vector/document store や設定依存へ委譲。

## 2.1 分割境界の基本方針
- `src/core/rag_module/rag.py` と同名サブパッケージ `src/core/rag_module/rag/` は作らない。既存の `from src.core.rag_module.rag import ...` を壊す可能性があるため、 sibling module の平置きで分割する。
- `KnowledgeIngester` は最も大きい責務として単独モジュール化し、PDF 専用分岐は `PDFIngester` に逃がす。
- `RAGSwitch` は singleton / enable-disable / ingester 差し替えの責務に限定し、ingest 実装詳細を持たせない。
- `RAGDocument` / `RAGResult` のような軽量 data carrier は `rag_types.py` へ寄せ、循環参照の火種を減らす。
- `src/commands/rag.py` に残る `src.core.rag` fallback は今回の対象外とし、 first pass では既存互換の維持を最優先する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** command layer から渡される target/path/query、RAG 有効化設定、ingest 対象ファイル、PDF chunking 設定、lazy singleton 初期化要求
- **出力/結果 (Output):** 既存どおりの ingest 結果、query/search 結果、`RAGSwitch` instance、`init_rag()` による初期化済み状態
- **制約・ルール:**
  - `KnowledgeIngester`、`PDFIngester`、`RAGSwitch`、`get_rag_switch`、`init_rag` は引き続き `src.core.rag_module.rag` から import できること。
  - facade 化後も `src/commands/hunt.py` の `get_rag_switch()` 呼び出しと、`src/cli/commands.py` の `RAGSwitch()` 生成が壊れないこと。
  - `rag.py` の行数削減を優先するが、first pass では RAG 挙動の改善や新機能追加を混ぜないこと。
  - optional dependency や外部 store 初期化タイミングは変えない。import 時副作用の増加は禁止する。
  - 目安サイズ:
    - `rag.py`: 200 行未満
    - `rag_ingester.py`: 350-550 行
    - `rag_pdf_ingester.py`: 150-300 行
    - `rag_switch.py`: 150-300 行
    - `rag_types.py`: 120 行以下

## 3.1 先に固定する回帰観点
- import 回帰:
  - `from src.core.rag_module.rag import KnowledgeIngester, PDFIngester, RAGSwitch, get_rag_switch, init_rag`
  - `from src.core.rag_module import ...` を追加する場合は package export の smoke も固定する。
- singleton / 初期化回帰:
  - `get_rag_switch()` が同一 instance を返すこと。
  - `init_rag()` が既存どおり lazy 初期化を行い、再実行で致命的副作用を起こさないこと。
- command layer 回帰:
  - `src/commands/rag.py` の `KnowledgeIngester()` 利用パス。
  - `src/commands/hunt.py` の `get_rag_switch()` 利用パス。
  - `src/cli/commands.py` の `RAGSwitch` 利用パス。
- direct test が薄いため、今回は characterization test の追加を必須とする。compile-only で済ませない。

## 3.2 DeepSeek 向け実装ルール
- 1モジュールずつ分割し、`rag_types.py` -> `rag_switch.py` -> `rag_pdf_ingester.py` -> `rag_ingester.py` の順で外出しする。
- 追加テストは必ず先に書き、少なくとも import/singleton/init の失敗を先に捕捉してから実装に入る。
- `src/commands/rag.py` の old/new import fallback は初手で触らない。facade が吸収できない差分だけ最後に最小修正する。
- 依存注入や構造改善を欲張らず、「行数削減と互換維持」に目的を絞る。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `src/core/rag_module/rag.py` の public symbol、`src/commands/rag.py` / `src/commands/hunt.py` / `src/cli/commands.py` の利用箇所を棚卸しし、互換維持が必要な import surface を一覧化する。
- [x] ステップ2: `tests/unit/core/rag_module/test_rag_split.py` を新設し、import smoke、`get_rag_switch()` singleton、`init_rag()` idempotence、`KnowledgeIngester` / `PDFIngester` の最小 smoke を fail-first で固定する。
- [x] ステップ3: `RAGDocument` / `RAGResult` などの軽量 model を `rag_types.py` へ抽出し、`rag.py` facade から再公開する。ここでは挙動変更を伴う整理を入れない。
- [x] ステップ4: `RAGSwitch` と singleton helper を `rag_switch.py` へ抽出する。`get_rag_switch()` / `init_rag()` は facade に残してもよいが、実装本体は分割先へ逃がして `rag.py` を薄くする。
- [x] ステップ5: `PDFIngester` を `rag_pdf_ingester.py` へ抽出する。PDF 専用 dependency と chunking helper を閉じ込め、`KnowledgeIngester` からの利用だけを維持する。
- [x] ステップ6: `KnowledgeIngester` 本体を `rag_ingester.py` へ抽出し、`rag.py` は import / re-export / 初期化 helper の薄い facade に縮小する。
- [x] ステップ7: `src/core/rag_module/__init__.py` が空のまま問題ないか確認し、必要なら package export を最小追加する。consumer 側 import 書き換えは不要なら行わない。
- [x] ステップ8: command layer の関連パスを再確認し、`src/commands/rag.py` の fallback、`src/commands/hunt.py` の switch 利用、`src/cli/commands.py` の direct construct が分割後も通ることを確認する。

## 4.1 推奨検証コマンド
```bash
.venv/bin/pytest tests/unit/core/rag_module/test_rag_split.py -q
.venv/bin/python -m compileall src/core/rag_module src/commands/rag.py src/commands/hunt.py src/cli/commands.py
```

## 4.2 完了条件
- `rag.py` が facade と互換レイヤ中心へ縮小され、200 行前後まで薄くなっている。
- `KnowledgeIngester` / `PDFIngester` / `RAGSwitch` / `get_rag_switch` / `init_rag` の import path 互換が維持されている。
- characterization test が追加され、import/singleton/init の回帰が自動検出できる。
- command layer での利用パスに追加の大規模 import 書き換えが発生していない。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] direct test が薄く、分割だけ先行すると静かな import 崩れを見落としやすい - 今回は characterization test を先に固定し、compile-only 完了を禁止する。
- [ ] [重要度:中] `src/commands/rag.py` に old/new 両系統の import fallback が残っており、RAG module だけ綺麗にしても全体の責務は散って見える - fallback 整理は別タスクで扱う。
- [ ] [重要度:中] `KnowledgeIngester` 単体でも今後さらに二段分割が必要になる可能性がある - 今回は first pass として class 単位の切り出しまでに留める。
- [ ] [重要度:中] `src/core/rag_module/__init__.py` が空のため package export 方針が未確定 - まず facade 互換を優先し、export 整理は follow-up で検討する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0302-D01
    title: "継続監視: RAG import path と singleton 初期化の互換監視"
    reason: "分割後も command layer と package export の互換監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "consumer import と init path を対象にした回帰 task を active で起票し、次回レビュー日を設定する"
```
