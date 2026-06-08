---
task_id: SGK-2026-0263
doc_type: roadmap
status: active
parent_task_id: null
related_docs:
- docs/shigoku/subtasks/2026-06-03_recon-signal-mc-swarm_subtask_plan.md
- docs/shigoku/subtasks/2026-06-03_recipe-recon-swarm_subtask_plan.md
- docs/shigoku/subtasks/2026-06-03_obsidian-rag-kg-recipe_subtask_plan.md
- docs/shigoku/specs/modules/KNOWLEDGE_GRAPH.md
- docs/shigoku/specs/modules/RAG_SYSTEM.md
- docs/shigoku/roadmaps/future_functions.md
title: '継続学習リファレンス: KG・RAG・MC・Recipe・Recon の理想アーキテクチャ'
created_at: '2026-06-03'
updated_at: '2026-06-03'
tags:
- shigoku
- reference
---

# 継続学習リファレンス: KG・RAG・MC・Recipe・Recon の理想アーキテクチャ

このドキュメントは実装計画書ではない。  
SHIGOKU を「継続的に賢くなりながら、未知のバグも取り逃がさないハンター」にするための設計原則、責務分担、判断基準をまとめた参考資料である。

KG、RAG、MC、Recipe、Recon の各実装は、本資料を判断の基準として参照することを想定する。

---

## 1. 先に結論

SHIGOKU における継続学習は、**過去の正解に近づき続けること**ではない。  
理想は、**過去知識を使って探索効率を上げつつ、新規性や異常性を潰さないこと**である。

そのため、各コンポーネントの理想的な位置づけは次の通り。

### KG

- runtime の事実
- target 固有の記憶
- 実行履歴
- suppression / finding / recipe run

### RAG

- 外部知識
- writeup / notes / playbook / checklist
- 類似事例
- 思考の幅を広げる補助

### MC

- KG を主に見る
- 必要時だけ RAG を引く
- RAG を根拠の一部として扱う
- 最終判断の支配者は signal + KG + deterministic rule

### Recipe

- RAG から直接 trigger されない
- KG と signal で trigger される
- RAG は recipe 設計や follow-up hint に限定する

---

## 2. 何を「賢くなり続ける」と呼ぶか

### 2.1 望ましくない学習

次の状態は、学習ではなく既知例への過学習である。

- writeup に似ている候補だけが優先される
- RAG に出てこない attack path が低評価になる
- payload の再生精度だけが上がる
- 過去に成功した脆弱性タイプに判断が偏る
- Recipe trigger が既知パターンに寄りすぎる
- 「見たことがないから価値が低い」という暗黙ルールが入る

この方向に進むと、SHIGOKU は「賢いハンター」ではなく「既知パターンの再生機」になる。

### 2.2 望ましい学習

理想の継続学習は、次の能力が増えていくことを意味する。

- 何を先に見ると ROI が高いかを学ぶ
- 何を試すと無駄打ちになりやすいかを学ぶ
- どういう状況で誤検知が増えるかを学ぶ
- どういう文脈で specialist や Recipe が効きやすいかを学ぶ
- どの観点を忘れやすいかを学ぶ
- 既知事例と似ていないが怪しい候補を、捨てずに拾う方法を学ぶ

つまり、**答えを覚える**よりも、**良い問いの立て方と調査順序を洗練させる**ことが中心である。

---

## 3. SHIGOKU における 4 種類の記憶

継続学習を 1 つの仕組みに押し込めるのではなく、記憶の種類を分けて扱う。

### 3.1 Observation Memory

「何を観測したか」の記憶。

- URL
- parameter
- form
- auth surface
- workflow surface
- JS surface
- response evidence
- session/auth context

主な保存先:

- `AttackSurfaceSignal`
- KnowledgeGraph

### 3.2 Execution Memory

「何を試してどうなったか」の記憶。

- 実行した Recipe
- follow-up task
- suppression
- finding
- false positive
- retry cost
- failed path

主な保存先:

- KnowledgeGraph
- `LearningRepository`

### 3.3 Strategy Memory

「どういう観点が有効だったか」の記憶。

- similar-case
- checklist
- blind spot
- caution hint
- useful sequence
- anti-pattern

主な保存先:

- RAG
- `LearningRepository`

### 3.4 Bias Control Memory

「過去知識に引っ張られすぎないための記憶」。

- RAG に寄りすぎると missed しやすいケース
- known-good strategy が逆効果だったケース
- novelty budget の消費状況
- counter-example 実行履歴

主な保存先:

- MC policy
- `LearningRepository`
- KnowledgeGraph の provenance / decision history

---

## 4. 理想アーキテクチャ

```text
                   External Knowledge Layer
  +--------------------------------------------------------+
  | Obsidian Notes / Writeups / PDFs / Playbooks / Checks |
  +------------------------------+-------------------------+
                                 |
                                 v
                         +---------------+
                         |      RAG      |
                         | hypothesis    |
                         | advisor       |
                         +------+--------+
                                |
                         RAGHint + Provenance
                                |
                                v
   +--------------------- Runtime Decision Layer ----------------------+
   |                                                                  |
   |  Recon -> AttackSurfaceSignal[] -> MasterConductor -> Swarm      |
   |                   |                    |               \          |
   |                   |                    |                \         |
   |                   v                    v                 v        |
   |            KnowledgeGraph         deterministic       Recipe      |
   |            runtime memory         routing / scoring   execution   |
   |                                                                  |
   +------------------------------+-----------------------------------+
                                  |
                                  v
                    +-------------------------------+
                    | LearningRepository / Feedback |
                    | TP/FP / retry cost / caution |
                    +-------------------------------+
```

### 4.1 最も重要な前提

- runtime の正本は KG と signal に置く
- RAG は runtime facts の正本にならない
- Recipe は再現性ある検証器であり、発想の中心ではない
- MC が最終判断を持つ
- 学習は「既知パターンに寄せる」のではなく「探索の質を上げる」

---

## 5. 各コンポーネントの理想責務

## 5.1 Recon

Recon は「URL をたくさん集めるもの」では足りない。  
理想の Recon は、**攻撃面 signal の正規化器**である。

### Recon が持つべき責務

- raw discovery entry を集める
- endpoint / param / form / auth / workflow / JS を攻撃面として正規化する
- multi-label な仮説候補を持たせる
- evidence を保持する
- auth/session context を残す
- KG に保存可能な粒度へ変換する
- MC / Swarm / Recipe が使える `AttackSurfaceSignal` を出力する

### Recon が持つべきではない責務

- RAG を見て脆弱性の有無を決める
- Recipe を直接 trigger する
- writeup 類似性だけで候補を絞る

### Recon が RAG から受けてもよいもの

- checklist hint
- blind-spot hint
- caution hint

### Recon が RAG から受けてはいけないもの

- suppress ルールの正本
- direct exploit 指示の正本
- 「RAG にないから低優先」という判断

---

## 5.2 KnowledgeGraph

KG は「資産台帳」より強い存在であるべきだが、同時に「外部知識ベース」になってはいけない。  
理想の KG は、**target-specific runtime memory** である。

### KG が持つべきもの

- endpoint / parameter / form / auth surface / workflow surface
- `AttackSurfaceSignal`
- evidence
- `ReconRun`
- `RecipeRun`
- `TaskExecution`
- `Finding`
- `SuppressionDecision`
- `SessionContext`
- provenance

### KG が答えるべき問い

- この endpoint / param / auth flow は以前にも見たか
- 今回の signal は前回より confidence が上がったか
- 類似 signal は近傍にあるか
- この signal から何回 Recipe が走ったか
- suppression 済みか、なぜ抑止されたか
- どの finding / task / recipe がこの signal から出たか

### KG が答えるべきではない問い

- 似た writeup はどれか
- 一般論として何を疑うべきか
- payload を何にすべきか

それらは KG ではなく RAG または MC の思考層の責務である。

---

## 5.3 RAG

RAG は SHIGOKU の「知識の脳」ではない。  
理想の RAG は、**hypothesis advisor** である。

### RAG が持つべき役割

- similar-case を思い出させる
- checklist を補う
- blind spot を思い出させる
- caution / anti-pattern を返す
- strategy sequence を示唆する
- false positive になりやすい条件を補足する

### RAG が持つべきではない役割

- gatekeeper
- final scorer
- runtime facts の正本
- Recipe trigger の正本
- payload 自動再生装置

### RAG の理想出力

RAG は raw chunk をそのまま返すのではなく、少なくとも次の形に正規化して返すのが望ましい。

```json
{
  "hint_type": "checklist|similar_case|caution|strategy",
  "summary": "OAuth callback surface では open redirect と token trust boundary を両方見る",
  "reason": "過去 writeup では callback only 観点だと token exchange 側を見落としやすかった",
  "confidence": 0.68,
  "provenance": {
    "source_note": "OAuth_Writeups.md",
    "chunk_id": "oauth_chunk_07",
    "query": "oauth callback token exchange trust boundary"
  }
}
```

### RAG が返すべき優先情報

- heuristic
- condition
- failure mode
- checklist
- caution

### RAG が返す優先度を下げるべき情報

- payload 文字列
- コード断片の再生
- 一発芸的 bypass のみ

---

## 5.4 Master Conductor

MC は SHIGOKU の policy engine である。  
継続学習において最も重要なのは、「RAG をいつ、何のために使うか」を MC が制御すること。

### MC の基本原則

- まず KG と signal を見る
- KG と signal だけで十分なら RAG を引かない
- RAG は補助的に使う
- RAG の推奨と逆の仮説も少数試す
- 最終判断は deterministic rule を混ぜて行う

### MC が RAG を引くべき局面

- attack surface が曖昧で仮説が多い
- specialist 選定に複数案がある
- recipe に行くほど条件は揃っていないが、観点補完が欲しい
- 過去に似た失敗例や blind spot を確認したい
- auth / workflow / callback のように複合的な文脈を持つ

### MC が RAG を引くべきではない局面

- raw recon 直後の全件一括
- 明らかに deterministic な recipe trigger
- suppression 済み low-value signal
- exploit 実行 payload を決めるためだけの照会

### MC が持つべき制御パラメータ

- novelty budget
- counter-example budget
- rag usage budget
- confidence threshold
- provenance recording policy

---

## 5.5 Recipe

Recipe は「知識の発想器」ではなく、**条件が揃った仮説を再現性高く検証する機構**である。

### Recipe の理想責務

- signal + KG context を見て trigger
- deterministic steps を実行
- evidence / result / follow-up signal を残す
- finding / suppression / rerun history を KG に返す

### Recipe が RAG から受けてもよいもの

- follow-up hint
- caution hint
- variant checklist
- post-check items

### Recipe が RAG から受けてはいけないもの

- primary trigger
- final execution可否判定
- score の正本

### 理想の rule

- trigger は signal + KG
- execution は deterministic steps
- follow-up は RAG を補助利用可

---

## 6. 設計原則として固定したいこと

以下は、実装時にぶらしてはいけない原則である。

### 6.1 RAG は gating しない

- RAG に出ないから却下、を禁止する
- RAG 未ヒットは「未知かもしれない」を意味しうる

### 6.2 RAG は ranking hint まで

- 最終判定は signal + KG + deterministic rules
- RAG の confidence は補助値でしかない

### 6.3 novelty budget を持つ

- 既知パターンに似ない候補も一定割合で探索する
- 低 confidence でも high novelty な signal を一定数残す

### 6.4 counter-example budget を持つ

- RAG 推奨と逆の仮説も少数必ず試す
- 既知の「良さそうな観点」に逆張りする余地を残す

### 6.5 RAG provenance を残す

- どのノートが判断に影響したか記録する
- どの query で引いたか記録する
- 後から「RAG のどの知識が bias source だったか」を監査できるようにする

### 6.6 payload より heuristic を優先

- ノートから直接文字列を抜くより、観点・条件・失敗例を取る
- payload は実行の正本ではなく補助情報

### 6.7 graceful degradation

- RAG が落ちても本流は止めない
- KG が正本として動ける設計を保つ

---

## 7. 実装時の高レベル判断基準

## 7.1 RAG を使うかどうか

RAG を使う前に MC は次を問う。

1. signal と KG だけで十分に route できるか
2. この判断は deterministic rule で閉じられるか
3. 今必要なのは事実か、観点か
4. 未知候補を消す危険はないか

答えが次なら RAG を引いてよい。

- 事実ではなく観点が欲しい
- 類似事例や blind spot を補いたい
- specialist / follow-up の幅を広げたい

## 7.2 KG に保存するかどうか

KG に保存するのは、ターゲットに固有で runtime の意味を持つもの。

- observed endpoint
- parameter
- signal
- evidence
- recipe run
- finding
- suppression
- session context

KG に保存しないか、軽く provenance 化するもの。

- 一般的な writeup 本文
- 汎用 playbook 全文
- outside-target heuristic

## 7.3 LearningRepository に保存するかどうか

`LearningRepository` は短中期の補助メモリとして扱う。

向いているもの:

- TP/FP verdict
- retry cost
- caution hint
- known-bad pattern
- tactic success/failure summary

向いていないもの:

- graph traversal の正本
- target topology の正本
- writeup 原文

---

## 8. 実装に落とすときの推奨データ境界

### 8.1 `AttackSurfaceSignal`

用途:

- Recon -> MC -> Swarm -> Recipe の runtime 正本

保持すべきこと:

- entity type
- labels
- confidence
- evidence
- auth/session context
- novelty score
- KG link key

保持すべきでないこと:

- RAG 原文
- writeup payload の集合

### 8.2 `RAGHint`

用途:

- MC / Swarm / Recipe が一時的に参照する advisor hint

保持すべきこと:

- hint type
- summary
- reason
- confidence
- provenance

保持すべきでないこと:

- runtime fact の正本
- trigger verdict の正本

### 8.3 `SuppressionDecision`

用途:

- low-value suppression
- rerun suppression
- false-positive caution

区別すべきもの:

- Recon 起点 suppression
- Recipe rerun suppression
- learning-based caution

---

## 9. アンチパターン集

### アンチパターン 1

「RAG に出ないから低優先」

なぜ悪いか:

- 新規バグの多くは既知ドキュメント非依存で現れる

### アンチパターン 2

「過去 payload をそのまま実行」

なぜ悪いか:

- 文脈が違うと誤検知・無駄打ち・危険実行を増やす

### アンチパターン 3

「KG に一般論を詰め込む」

なぜ悪いか:

- runtime facts と strategy memory が混ざって汚れる

### アンチパターン 4

「Recipe を知識探索の中心にする」

なぜ悪いか:

- Recipe は高期待値仮説の検証器であり、探索の柔軟性を担う層ではない

### アンチパターン 5

「FP 学習を suppression のみで使う」

なぜ悪いか:

- caution hint として使える知識まで失う

---

## 10. 実装者向けの優先順位

この資料は計画書ではないが、実装判断としては次の順で考えるのが安全である。

1. Recon と KG の runtime 正本を固める
2. MC が KG 主導で判断できるようにする
3. Recipe trigger を signal + KG に寄せる
4. RAG を advisor に縮退・再定義する
5. `LearningRepository` と feedback を統一ポリシーでつなぐ
6. novelty / counter-example / provenance を導入する

この順番を崩して先に RAG を強めると、既知例偏重のバイアスが入りやすい。

---

## 11. 最終判断

最高の SHIGOKU において、RAG は廃止対象ではない。  
ただし、**役割を間違えた RAG** はむしろ精度を落とす。

残すべき RAG は次のようなもの。

- 仮説を広げる
- 観点漏れを減らす
- 類似失敗を思い出させる
- 調査順序を良くする

避けるべき RAG は次のようなもの。

- payload source
- gatekeeper
- final judge
- known-pattern reproducer

したがって、SHIGOKU の理想は **KG 中心・MC 主導・Recipe 検証・RAG 補助** である。
