---
task_id: SGK-2026-0319
doc_type: manual
status: active
parent_task_id: SGK-2026-0289
related_docs:
  - rules/lessons.md
  - rules/shigoku-docs.md
  - rules/report-session-consistency.md
  - rules/python-tests.md
  - AGENTS.md
title: SHIGOKU Learnings
created_at: '2026-06-26'
updated_at: '2026-07-28'
---

# SHIGOKU Learnings

## 運用方針

- このファイルは学習記録（learnings）の一次保管場所。全エントリは「ヘッダ1行 + detail」形式で保持する。
- 活用は AGENTS.md §17 の軽量ロード経由: `rg "^\- \[topic: <キー>]"` で該当トピックのヘッダ行のみ取得し、detail は `when:` が合致する場合のみ個別 `read` する。
- `rules/*.md` および `AGENTS.md` は別個の正規ルール格納先（§17 が直接ロードする）。本ファイルからの「昇格」はユーザー明示指示時のみとし、AI が勝手に rules/*.md や AGENTS.md を編集してはならない。
- 追記は capture 主体。実装完了時や根因確定時に、所定のフィルタ・フォーマットに従い本ファイルへ追記する。

## 追記フォーマット（新規エントリ）

新規エントリは「ヘッダ1行 + detail」の2段で追記する。`topic` キーは AGENTS.md §17 の rules ファイル名（`.md` 不要）と一致させる: `lessons` / `codingrules` / `report-session-consistency` / `reporting` / `cli-ops-routing` / `shigoku-docs` / `task-ledger` / `python-tests`。

例:
```
- [topic: report-session-consistency | when: session findings を集計する時] extract_all_findings() を使え。vulnerabilities_found 単独は取りこぼす。 verify: pytest tests/reporting/test_finding_extractor.py
  detail: SGK-2026-0319。src/reporting/finding_extractor.py:12
```

- ヘッダ行のみ `rg "^\- \[topic:"` で取得され、コンテキスト最小（1エントリ1行）。
- detail 行はインデント済みで grep 対象外。ヘッダだけで足りない時だけ該当1エントリを個別 `read` する（一括ロード禁止）。
- 下記エントリは全てヘッダ形式。新規追記も同じ形式で。

## Raw Learnings

- [topic: codingrules | when: snip 経由で python3 -c を実行する時] snip 経由の `python3 -c` では `;` を使うな。`.venv/bin/python -c` を使うか文字列内を `&&` で chain せよ。 verify: `;` なしで再実行し1プロセスで通ること
  detail: `python3 -c "import x; x.y()"` は `snip` が `-c` 内の `;` をコマンド区切りとして扱うため壊れる。`.venv/bin/python -c`（snip はそのまま通す）か、Python 文字列内を `&&` で繋ぐこと。本環境の `python3 -c` 文字列内で `;` は絶対に使わないこと。

- [topic: shigoku-docs | when: docs/shigoku 配下の Markdown を作成する時] 全 doc_type に `status` を含め、validator 必須 front matter 一式を入れよ。 verify: python3 scripts/validate_shigoku_docs.py が FRONT_MATTER_ISSUES=0
  detail: `validate_shigoku_docs.py` は `rules/shigoku-docs.md` が以前に `task_id, doc_type, created_at, updated_at` しか挙げていなくても、`work_report`/`work_log` の `missing_status` を検出する。SHIGOKU Markdown 全文に `status` + validator 必須 front matter 一式を必ず含めること。

- [topic: lessons | when: MasterConductor に lazily-initialized なインスタンス属性を追加する時] 属性アクセス前に `if not hasattr(self, "attr"): self.attr = None` ガードを置け。 verify: test_master_conductor_recipe_contracts.py 等 の `__new__` 系テストが緑
  detail: 既存テスト（`test_master_conductor_recipe_contracts.py` 等）は `__init__()` を呼ばず `__new__()` で MasterConductor を構築する。クラスに追加した lazily-initialized 属性をガードなしで直接参照すると、これらのテスト経路で `AttributeError` になる。

- [topic: lessons | when: `_execute_recipe_task` の `_step_executor` クロージャに状態を持たせる時] step 間で持続する状態は outer method スコープへ、recipe task 間は MasterConductor instance level（lazy init）へ置け。クロージャ本体内の状態は step ごとに破壊・再生成される。 verify: 複数 step 実行テストで状態が保持されること
  detail: `_step_executor` クロージャは recipe step ごとに1回起動する。クロージャ本体内で作った状態（`ProbeCache()` 等）は毎回破棄・再生成される。1 recipe 実行内で step 間持続する状態は outer method スコープ、recipe task 間で持続する状態は lazy init 付きで MC instance level に置くこと。

- [topic: shigoku-docs | when: plan/subtask_plan を done/ に移動する時] 移動先ファイルを参照する全 `related_docs` エントリを新パスへ一括更新せよ。 verify: validate_shigoku_docs.py が REGISTRY_ISSUES=0
  detail: `validate_shigoku_docs.py` は `primary_doc` だけでなく `related_docs` 内のパスも検査し、1つでも旧パスが残っていると `REGISTRY_ISSUE` になる。

- [topic: task-ledger | when: work_report に deferred_tasks を書く時] `tracking_task_id` は `SGK-YYYY-NNNN` 実ID必須、`TBD` 不可。複数の deferred item を1つの bundle plan の子として追跡してよい。 verify: validate_shigoku_docs.py が DEFERRED_LINK_ISSUES=0
  detail: `work_report` の `deferred_tasks` が `tracking_task_id: TBD` だと台帳ルール違反になる。`SGK-YYYY-NNNN` 形式の実IDが必須。複数 deferred item は1つの bundle plan の子として追跡してよい。

- [topic: lessons | when: reauth 戦略で guard を並べる時] zero-network check を network-dependent check の前に置け。 verify: network_client=None で unsupported auth URL 検出をカバーするテスト
  detail: `if not self.network_client: return ...` を `_detect_unsupported_auth_scheme(...)` の上に置くと、`network_client=None` の時に OIDC/SAML/MFA URL 検出が黙ってスキップする。

- [topic: python-tests | when: main.main() の --report パスをテストする時] `exit_code == 0` でなく生成ファイルの存在と内容で検証せよ（report パスは `None` を返す）。 verify: 生成レポートファイルが存在すること
  detail: `main.main()` は `--report` パスで `None` を返す（`int` でない）。`main()` 後の `assert exit_code == 0` は常に失敗する。生成レポートの存在と内容で検証すること。

- [topic: cli-ops-routing | when: src/cli/messages.py の msg() に新 key を渡す時] 事前に rg で key 文字列の存在を確認せよ（不存在は `??key??` で黙表示され fallback/error がない）。 verify: rg "<key>" src/cli/messages.py
  detail: `msg("some.key")` は key が `src/cli/messages.py` にないと `??some.key??` を黙表示する。fallback も error もない。呼び出し前に必ず正確な key 文字列を grep すること。

- [topic: lessons | when: quarantine 対象 task を取得する時] `completed_tasks` でなく `task_queue.get_all()` を使え。 verify: 該当 quarantine テスト
  detail: `MasterConductor.task_queue` が実行待ち task の正規ソース。`completed_tasks` は既に完了した task のみを含む。

- [topic: codingrules | when: recipe_loader.py に validate_recipe_schema を import する時] module scope でなくメソッド内の lazy import にせよ（TYPE_CHECKING 経由で循環する）。 verify: import が成功すること
  detail: `recipe_contracts.py` は `recipe_loader.py` から `TYPE_CHECKING` 経由で `Recipe` を import するため、`validate_recipe_schema` を `recipe_loader.py` の module scope に import し直すと循環依存になる。メソッド本体内で lazy import すること。

- [topic: python-tests | when: pytest.raises(match=...) を書く時] match は単語でなく部分文字列一致。実例外メッセージを抽出してから正規を書け。 verify: 実メッセージに対するマッチ確認
  detail: `pytest.raises(match=...)` は単語 token でなく部分文字列に一致する。`"zero steps"` は `recipe_validation_failed:zero_steps` にマッチしない。実際の raised message を抽出してから、出力部分文字列に一致する正規を書くこと。

- [topic: codingrules | when: src/config.py の flat config field を削除する時] `getattr(app_settings, "field", default)` の間接消費者を grep して同時に更新せよ。 verify: rg "getattr.*field" src/
  detail: direct field reference は表面の一部に過ぎない。field 削除前に間接消費者を特定し、同一 fixer で更新すること。

- [topic: codingrules | when: モジュール削除を伴う変更を fixer に頼む時] 削除と import 先クリーンアップは同一 fixer に束ねるか順序依存を明示せよ（並列で壊れる）。 verify: 最終 export と依存 import テスト
  detail: parallel fixers は削除が下流 import クリーンアップより先に着地すると失敗する。

- [topic: report-session-consistency | when: session findings を集計する時] `src/reporting/finding_extractor.extract_all_findings()` を使え。`vulnerabilities_found` 単独は実発見を取りこぼす。 verify: pytest tests/reporting/test_finding_extractor.py
  detail: `vulnerabilities_found` や `task["vulnerabilities_found"]` だけを見る formatter は実発見を大量に取りこぼす。

- [topic: report-session-consistency | when: shigoku-ops --report で session を解決した後] consistency verdict をチェックせよ（inconsistent/blocked でも生成が通る）。 verify: verdict が consistent のみ続行
  detail: session パスだけを見て処理を進めると、`status: inconsistent/blocked` でも生成が通ってしまう。

- [topic: codingrules | when: Pydantic @model_validator(mode='after') で collection 依存検証をする時] 空コレクションをガードせよ（`roles={}` のデフォルト構築で全テストが壊れる）。 verify: roles={} での構築テスト
  detail: `self.default_role in self.roles` のような検証は `roles={}` のデフォルト構築で失敗し全テストが壊れる。

- [topic: codingrules | when: LLMClient を role ベースに移行する時] `model=` パラメータを完全削除し `LLMClient(role="...")` のみにせよ（model 指定で role 解析が黙スキップする）。 verify: rg "LLMClient\(" src/ で model= 残存なし
  detail: `LLMClient(role="...", model="...")` は role 解析を黙ってスキップする。role 移行時は `model` パラメータを完全に削除し `LLMClient(role="...")` のみにすること。

- [topic: codingrules | when: 複数 fixer が同一 __init__.py の export を追加する時] 並列実行禁止（read→write で最後の fixer の内容だけ残る）。 verify: 最終 export ファイル内容
  detail: fixer はファイル全体を read→write するため、並列で同一 `__init__.py` のエクスポートを追加すると最後の fixer の内容だけが残る。

- [topic: codingrules | when: secret redaction 境界を設計する時] 最低レベル write API で redact し callsite bypass を防げ。 verify: 深さ>=2 の secret でテスト
  detail: cross-cutting security boundary は最低レベルの write API で強制する。canonical recorder 内で `input_summary`, `error`, ネストした `source_refs` を redact し、どの callsite も境界をバイパスできないようにすること。

- [topic: codingrules | when: content scan で secret を検出する時] ネスト dict/list 含む全 data-bearing field を再帰走査せよ。 verify: 深さ>=2 の secret テスト
  detail: flat な top-level 文字列 scan はネスト dict/list 内の secret を黙って pass する。必ず深さ >= 2 の secret でテストすること。

- [topic: lessons | when: notification の batch helper を書く時] `_mark_sent()` は send 成功後に。`process_batch()` 内では呼ぶな。 verify: 初回 send が発生し再試行のみ dedup されるテスト
  detail: `process_batch()` 内で `_mark_sent()` を呼ぶと通知欠落する。send success が dedup state を更新できる唯一の点。batch helper は候補準備のみを担うこと。

- [topic: codingrules | when: 認証キャッシュのキーを設計する時] 存在有無(bool)でなく値をハッシュ化して含めよ。 verify: 有効→期限切れ変更でキャッシュ再利用されないテスト
  detail: ファサードのキャッシュキーでシークレットの存在有無（bool）ではなく値をハッシュ化して含めよ。credential value 変更でキャッシュを無効化すること。

- [topic: lessons | when: session resume で認証情報を読む時] `metadata["context"]` を先に見て top-level へフォールバックせよ。 verify: 該当 resume テスト
  detail: SHIGOKU の session metadata は `metadata["context"]` 階層に認証情報が格納される。resume 時は `metadata.get("context", {})` を先に見てから top-level へフォールバックすること。

- [topic: codingrules | when: Task.to_dict() に redaction/inject を実装する時] 全 disk-write 境界で同一 sanitize helper を共有し、生参照を rg で検出せよ。 verify: rg "task\.metadata" / rg "to_dict\(\)"
  detail: ドメインモデルの `to_dict()` に掛けた変換（redaction/schema_version inject）は、別モジュールの並列 write 境界には自動伝播しない。`Task.to_dict()` が secret redaction しても `build_async_session_payload()` が `task.metadata` を生書きすれば disk へ秘匿漏洩する。同一オブジェクトを直列化する全 disk-write 境界は `to_dict()` に統一するか単一 sanitizer helper（`_sanitize_metadata_for_session_payload` 相当）を共有し、境界を done 宣言する前に `rg "task\.metadata"` / `rg "to_dict\(\)"` で直参照を検出すること。

- [topic: lessons | when: redaction 完了を宣言する時] 実テストされた経路しか保証しない。各 write 境界単位で assert するテストの存在を確認せよ（件数や文面から推論するな）。 verify: 境界ごとのテスト存在確認
  detail: 完了報告書の「全 write 境界で redaction 済み」は実テストされた経路しか保証しない。Phase 1 報告は universal `[REDACTED]` を主張したが検証されていたのは `to_dict`/`from_dict` のみ。完了判定レビューでは各 write 境界のコードを読み、その境界単位で変換を assert するテストが存在することを確認すること（テスト件数や報告文面からカバレッジを推論しない）。

- [topic: codingrules | when: Task.metadata を永続化する write API を触る時] 全 write 経路で同一 sanitize helper（`_redact_secrets` + schema_version inject）を共通化せよ。 verify: 全 serialization 境界で grep "metadata"
  detail: `Task.to_dict()` に `_redact_secrets` + `schema_version` inject を実装しても、`build_async_session_payload()` が `task.metadata` 生参照で dict を構築すると、disk 上の session JSON だけ redaction/inject 未適用のまま分裂する。`to_dict()` と等価な sanitize helper を全 write 経路で共通化し、実装後は計画書に列挙された全 serialization 境界で `grep "metadata"` して生参照の残存がないか確認すること。

- [topic: lessons | when: 計画書が複数 serialization 境界を列挙している時] grep + 目視で全境界に同一 sanitize が通っているか差分確認せよ。 verify: 境界ごとコード行 grep
  detail: Phase 1 の計画書 section 2 には 6 境界（`Task.to_dict`, `build_async_session_payload`, `serialize_legacy`, `deserialize_legacy`, `restore_task_queue`, `restore_completed_tasks`）が明記されていたが、実装時に 5 境界だけ修正し `build_async_session_payload` の `task.metadata` 生参照を見逃した。全境界で metadata の読み書きが同一 sanitize 経路を通っていることを、コード行単位で grep して差分がないか確認すること。

- [topic: codingrules | when: edit の oldString を作る時] Read 出力の `(End of file - total N lines)` と行頭 `<n>: ` は表示用注記なので oldString に含めるな。 verify: oldString が実際の行内容のみ
  detail: Read ツール末尾の `(End of file - total N lines)` と行頭の `<n>: ` は表示用注記でありファイル内容ではない。これらを `edit` の `oldString` に含めると "oldString not found" になる。oldString には prefix 後の実際の行内容のみを指定すること。

- [topic: codingrules | when: config/shigoku.yaml に新規セクションを追加する時] 対応 model field を settings.py に追加するまで黙無視される。依存ロジック前に model 存在を確認せよ（SGK-2026-0311）。 verify: rg "class <Name>Settings" src/core/config/settings.py
  detail: Pydantic `model_config = ConfigDict(extra="ignore")` の Settings では、新規 YAML セクション（例: `parallelism:`）は対応 model field が追加されるまで黙って無視される。YAML に書いただけでは設定効果ゼロ。設定依存ロジックを書く前に model 存在を確認すること（SGK-2026-0311 で `parallelism` セクション不在でも default 起動した事例）。

- [topic: codingrules | when: origin/URL 正規化関数を書く時] `scheme` と `hostname` 両者を検証し欠落時に `ValueError`。scheme/host なし入力の単体テストを必ず含めよ。 verify: scheme なし / host なし入力の単体テスト
  detail: `urlparse("example.com")` は `.scheme=""`, `.hostname=None` を返す（path 扱い）。origin/URL 正規化関数は両者を検証し欠落時に `ValueError` を raise すること。

- [topic: python-tests | when: 既存テストゼロのモジュールの挙動を変える時] 変更前に現行挙動を固定する baseline (characterization) test を追加せよ（SGK-2026-0311 T-0.1）。 verify: 実装後も baseline が緑
  detail: 既存テストゼロのモジュールへ挙動変更を加える場合は characterization test を先に書くこと。admission gate や budget 強制など挙動を変える変更前には現行挙動を固定する baseline test を最初に追加し、実装後も緑を維持すること。これを省くと後方互換性破壊が回帰テストに検出されない（SGK-2026-0311 の T-0.1）。

- [topic: python-tests | when: factory の pool キャッシュ削除をテストする時] `patch.object(factory, return_value=premade_mock)` でなく実 factory を動かし葉メソッドだけ mock せよ。 verify: assert intercepted[0] is not intercepted[1]
  detail: object-pool caching を factory method から削除する時、`patch.object(factory, return_value=premade_mock)` は pool-reuse 回帰に盲くなる。代わりに `_original(name)` を interceptor 経由で呼び、結果の実 instance の葉メソッド（`.dispatch` 等）だけ mock する。`assert intercepted[0] is not intercepted[1]` で same-instance-reuse を捕捉できる。

- [topic: python-tests | when: pool 再利用を回帰テストで再現する時] factory 先頭に `if name in pool: return pool[name]` を入れないと真の再現にならない。early-return 分岐は `swarm_class(config)` 実体化より上に置け。 verify: 同一インスタンス再利用の assert
  detail: 回帰検証用の一時 pool-reuse 再現は factory 先頭の早期 return が必要。pool への格納を末尾だけで行い、実体生成前に `if name in pool: return pool[name]` を置かないと毎回新 instance ができ真の再現にならない。early-return 分岐は `swarm_class(config)` instantiation 行より上に置くこと。

- [topic: shigoku-docs | when: タスク完了判定で status done を宣言する時] validator は台帳の `status`/`primary_doc` と実配置の整合を検査しない。rg で手動照合せよ（SGK-2026-0311）。 verify: rg "SGK-<id>" docs/shigoku/registry/task_ledger.* task_registry.yaml
  detail: `validate_shigoku_docs.py` は台帳(`task_ledger.md/.csv`, `task_registry.yaml`)の `status`/`primary_doc` と実ファイル配置の整合を検査しない。`status: done`+`done/` 配置でも台帳が `active`+旧パスのままだと validator は GREEN になる。完了判定レビューでは `rg "SGK-<id>" docs/shigoku/registry/task_ledger.* task_registry.yaml` で status・path が実体と一致するか手動照合すること（SGK-2026-0311 で発覚）。

- [topic: lessons | when: pooled manager を per-dispatch instance 化する時] ContextVar/compatibility shim より per-dispatch instance を優先し、`try/finally close()` 導入前に `SwarmManager.close()`/`Specialist.close()` が shared network/llm client を閉じないことを実コードで確認せよ。 verify: base.py:150-152/244-253 が shared client を close しないこと
  detail: singleton dispatcher が shared client を inject する pooled manager を per-dispatch instance 化する場合、shim が `self.current_context` へ書き戻す設計は並列汚染を再導入する。close は per-manager 一時リソース(`_ephemeral_network_clients` 等)のみ解放する前提で追加する（base.py:150-152/244-253 が shared client を close しないことを確認済み）。

- [topic: lessons | when: dispatch の context 隔離を設計する時] `self.current_context` だけでなく dispatch メソッド内の全 `self.<attr> = ...` reset 行を grep 対象にせよ（SGK-2026-0312 LB-2）。 verify: 全 reset 行の棚卸し
  detail: 「`current_context` を隔離する」計画でも `self.history`/`self.total_tools_executed`/`self._phase2_detection_mode` 等 dispatch 冒頭で reset される全 per-dispatch mutable instance state を列挙対象に含めること。1属性だけ隔離しても sibling 状態で同時 dispatch 汚染が残る。

- [topic: lessons | when: 計画書の判定を Ready に反転させる時] 参照した全 Blocker の `[ ]`→`[x]` 反転と具体解決設計を同一編集パスで反映せよ（SGK-2026-0313）。 verify: rg で Ready 判定なのに未解決 Blocker 残存なし
  detail: 6.2 だけ Ready にして 6.3 を未解決のまま残す内部矛盾が実装をブロックする。編集後に `rg "\- \*\\*判定.*Ready"` と `rg "\- \[ \] \*\\*LB"` で「Ready 判定なのに未解決 Blocker 残存」がないか自己チェックすること（SGK-2026-0313 レビューで発覚）。

- [topic: lessons | when: specialist の lane 分類を設計する時] mutation-safety / statefulness / rate-limit / exclusivity を別 boolean field で持ち、単一 lane enum に圧縮するな（SGK-2026-0313 6.3.1/6.3.2）。 verify: 該当テスト
  detail: `rate_limited` を lane に畳むと `parallel_safe=false` 過剰直列化を起こす。`CATEGORY_TO_LANE.get(category,"read_only")`（`src/core/engine/parallel_orchestrator.py:39-46`）は unknown を read_only の危険側へ倒すため、shadow は Phase 0 specialist 分類（`load_inventory()["specialist_classification"]`）を権威とし unknown→`sequential_required` へ正す。

- [topic: codingrules | when: build_async_session_payload に構造化 payload を通す時] safe-by-construction で設計し auto-redaction に依存するな（SGK-2026-0313 LB-4）。 verify: cookie/token/header 実値を field に持たないこと
  detail: `build_async_session_payload()` の `decision_traces` / `run_ledger_payload` 等の構造化 payload 引数は `copy.deepcopy` のみで `_sanitize` 対象外（`src/core/engine/master_conductor_session_service.py:141-156`）。redaction が効くのは `Task.metadata` 経由の `_sanitize_metadata_for_session_payload` のみ。新規に構造化 payload を同関数へ通す場合は safe-by-construction（cookie/token/header 実値を field に持たない）で設計すること。

- [topic: lessons | when: swarm→specialist マッピングを構築する時] `name` 一致でなく YAML の `file` フィールドの path prefix から導出せよ（SGK-2026-0313）。 verify: name 硬直マッチを使っていないこと
  detail: `concurrency_map.yaml` の specialist `name` フィールドには rationale が混入するケースがある（例: `"DiscoverySwarm specialists (visual_recon, github_recon)"`）。`name` による硬直マッチは inventory 更新で黙って破壊される。

- [topic: lessons | when: build_async_session_payload 呼び出しに shadow decision を渡す時] 既存 `decision_traces=self.decision_tracer.to_list()` リストと `+` で結合し置換するな（SGK-2026-0313）。 verify: rg で呼び出し元確認
  detail: `master_conductor.py` の `build_async_session_payload` 呼び出しには既存 `decision_traces=self.decision_tracer.to_list()` が既に渡っている。Phase 4 shadow の `_shadow_decisions` list は既存リストと `+` で結合し、置換しないこと。既存 sink がある場合は `grep` で呼び出し元を確認してから値を渡す。

- [topic: lessons | when: working-tree に大規模未整理変更がある時に commit する時] `git add .` を禁止し、`git diff --staged --stat` で差分サイズを毎回確認せよ（SGK-2026-0317 N-001/NF-001）。 verify: staged --stat で想定行数のみ
  detail: 目的の変更が 2 insertions でも、unstaged の 1670+ insertions を含むファイルを誤って stage すると成果物境界が崩れる。安全手順: `git reset HEAD -- <file>`, `git checkout HEAD -- <file>`（必要な場合）、外科的 edit 適用、`git add <file>`、`git diff --staged --stat -- <file>` で想定行数のみであることを確認。

- [topic: task-ledger | when: Phase plan でタスクを Deferred する時] 7.5 Local Deferred 表への D-N 行追加と 7.8 TDD チェックリスト checkbox 更新の両方が必須（SGK-2026-0317 B-002）。 verify: 両方の更新
  detail: どちらか一方だけではレビューで Not Complete 判定になる（`validate_shigoku_docs.py` は TDD checkbox 状態を検査しないため、手動照合のみが検出手段）。checkbox は `[ ]` → `[ ] **Phase 9 Deferred (D-N)**` に書き換える。

- [topic: lessons | when: staged 成果物を検証する時] `git diff --cached --numstat` と `git diff --numstat` の両方で staged 境界と検証環境を分けて報告せよ（SGK-2026-0317 NF-002）。 verify: 両 numstat 確認
  detail: `git diff --cached` は staged 成果物だけを検査し、pytest は working tree 全体を実行する。staged を最小 hunk に絞っても unstaged 側にテスト前提の大規模差分が残ると broad validation 結果が変わる。

- [topic: lessons | when: SwarmResult.to_dict() に field を追加する時] MC の独自 dict 変換経路も grep し model `to_dict()` と MC payload の両方に同じ field を通せ（SGK-2026-0317 B-001）。 verify: rg "result\.to_dict\(|data\": \{" src/core/engine/master_conductor.py
  detail: MasterConductor が独自 dict へ変換する経路（`data={...}`）は model serializer を通らないため、replay metadata 追加時は直列化境界を探し、model `to_dict()` と MC payload の両方に同じ field を通すテストを追加すること。

- [topic: codingrules | when: edit で関数末尾に新コードを追記する時] read で関数境界全体（`def`〜次 `def`/`class`）を確認し、`return` 以降の unreachable 重複コードを削除してから追記せよ（SGK-2026-0318 F-1）。 verify: 関数境界全体の read
  detail: Python は `return` 以降のコードを黙って無視するため、linter や pytest は検出しない。重複コードを oldString に含めずに新コードだけ追記すると、元の死にコードがそのまま残留する。安全手順: `read` で次関数定義まで読む → `return` 直後から次 `def` 直前に不要な行があれば削除 → 新規関数を追記。

- [topic: lessons | when: Fixer が private helper を実装した時] public dispatch 経路に配線し統合テストで helper が実経路から到達可能であることを assert せよ（SGK-2026-0318 B-3）。 verify: 統合テストで helper が実 dispatch 経由で呼ばれること
  detail: helper 単体テストだけでは「実 dispatch で使われていない」コードが完成扱いされる。Fixer への指示に「実 dispatch 経路への配線と統合テスト」を明示的に含めること。

- [topic: lessons | when: get_execution_safeguard() の mode を変更する時] `get_request_guard()` singleton getter を無条件呼ぶな、`RequestGuard(mode=new_mode)` で独立インスタンスを直接生成せよ（SGK-2026-0330 レビュー）。 verify: singleton がグローバル状態を mutate しないこと
  detail: Shared-safeguard ファサード（`get_execution_safeguard()`）の mode 変更パスで `get_request_guard()` singleton getter を無条件呼び出しすると、グローバル RequestGuard singleton の `mode` が書き換わり、既存の Bug Bounty safeguard が保持する参照を経由して fail-closed が黙って無効化される。singleton を返す getter を mode 変更後に呼ぶ設計では、その getter がグローバル状態を mutate しないことを実コードで確認すること。

- [topic: task-ledger | when: provisional タスクを registry に登録する時] `primary_doc: null` 不可。実 plan ドキュメントを作成しパスを設定せよ。deferred の追跡タスクは `status: active`（SGK-2026-0330 レビュー）。 verify: validate_shigoku_docs.py が REGISTRY_ISSUES=0
  detail: `task_registry.yaml` の `primary_doc: null` は `validate_shigoku_docs.py` で `REGISTRY_ISSUE`（`task_N_missing_primary_doc`）になる。provisional タスクでも必ず実 plan ドキュメントを作成し `primary_doc` にパスを設定すること。`work_report` の `deferred_tasks` から参照する追跡タスクは `status: active` で登録すること（task-ledger rule の「継続監視は別タスクとして起票し、active で追跡する」に反するため `backlog` 不可）。

- [topic: lessons | when: resolve_resume_start_step を実装する時] override の早期 return で state load をスキップするな。resume フラグ時は先に `validate_for_resume()` を呼べ。 verify: 該当 resume テスト
  detail: Checkpoint/resume resolver では state-load と step-override を分離し、override の早期 return で state をスキップしないこと。`resolve_resume_start_step(recon_resume=True, recon_start_step=5)` の実装で `recon_start_step` が early return すると `resume_state_path` が空になり、MasterConductor が前回 state を復元できない。resume フラグが立っている場合は必ず最初に `validate_for_resume()` を呼び、step だけ後から上書きする構造にすること。

- [topic: lessons | when: resume step 算出を実装する時] `current_step += 1` でなく `STEP_MARKER_GROUPS` で内部マーカー→ユーザー向け step を定義し OR/AND 両論理を扱え。 verify: OR/AND 両論理のテスト
  detail: `mark_step_complete()` は内部マーカー（subdomain_discovery, url_discovery, port_scan_phase1, port_scan_phase2 等）ごとに current_step を +1 するが、ユーザー向け step 1-8 の数とは一致しない。`STEP_MARKER_GROUPS: dict[int, list[frozenset[str]]]` で内部マーカー→ユーザー向け step を定義し、OR 論理（skip marker）と AND 論理（複数サブステップ）の両方を正しく扱うこと。

- [topic: codingrules | when: dataclass で resume 用 ID 再生成を実装する時] `default_factory`/`__post_init__` は初回のみ。明示的再生成メソッド（`rebind_for_resume()`）を用意せよ。 verify: resume 後に新 ID が生成されるテスト
  detail: dataclass の `field(default_factory=...)` は `__init__` 時しか発火しないため、resume で `run_id = ""` にしても save() は再生成しない。`__post_init__` も dataclass 生成時のみ。手動で新しい ID が必要な場合は明示的な再生成メソッド (`rebind_for_resume()`) を用意すること。

- [topic: lessons | when: resume の skip 判定を書く時] `update_parallel_task_progress(task, "skipped")` で status を上書きするな。entry dict に直接 `resume_reason`/`updated_at`/`last_resume_decision` のみ書き込め。 verify: 同 task 連続2回 resume で両方 skip されるテスト
  detail: Checkpoint/resume の skip 判定で `update_parallel_task_progress(task, "skipped")` を呼ぶと status が "completed"→"skipped" に上書きされ、次回 resume で `status != "completed"` と判定されて再実行ループになる。

- [topic: lessons | when: artifact refs の merge を実装する時] path 既存時は append でなく既存 entry の size/mtime/exists/kind を上書きせよ。 verify: 再実行後 metadata が古値でないことの exact equality テスト
  detail: `existing_paths` set を使った重複排除（`if path not in existing_paths: append`）は、同一出力パスに再実行された新しい size/mtime を黙って捨てる。再実行後の metadata が古い値ではないことを exact equality で assert するテストを追加すること。

- [topic: codingrules | when: gate 判定で float デフォルトを sentinel 扱いする時] `metadata.get("field") is not None` で明示指定と区別せよ。 verify: 0.0 と未設定の区別テスト
  detail: dataclass の `float` デフォルト値 `0.0` は sentinel として使えない（未設定と明示的ゼロの区別不可）。gate 判定では metadata dict への key 存在確認で明示指定とデフォルトを区別し、デフォルト時は「制約なし」として扱うこと。`data.budget_remaining if data.budget_remaining > 0 else metadata.get(...)` のような他段階フォールバックは 0.0 を誤判定する。

- [topic: cli-ops-routing | when: main.py の共通 sink 関数に新パラメータを追加する時] 全呼び出し元を rg で grep し漏れを確認せよ。 verify: rg "start_interactive_session\(" src/main.py
  detail: 複数コードパス（`args.recon` / `args.target` / `args.log` 等）が同じ sink 関数（`start_interactive_session`）を呼ぶ main.py では、新規パラメータ追加時に全呼び出し元を grep し漏れを確認せよ。1箇所だけ追加すると残りのコードパスがサイレントにデフォルト値で実行され、CLI 完了条件を満たさない。

- [topic: lessons | when: bugbounty/ctf mode 固有の process-global state を読む時] 全 read site で `mode == "bugbounty"` gate するか mode change で clear せよ。 verify: shared context set 後に CTF instance でテスト
  detail: `_shared_guard_context` set by MC leaked bug bounty policy into CTF `AsyncNetworkClient`, `BaseExternalAdapter`, and `BaseManagerAgent` read paths. Default parameters (`mode: str = "bugbounty"`) silently mask this — add `if self.mode.lower() / self._mode.lower() != "bugbounty": return None` at EVERY fallback-to-shared read site. Verify with tests that set shared context then create CTF-mode instances.

- [topic: lessons | when: process-global な mutable state を扱う constructor を書く時] `__init__` で global を snapshot するな。runtime で毎回再評価せよ。 verify: set/clear が既存 instance に影響するテスト
  detail: Constructor `__init__` must NOT snapshot process-global mutable state into instance variables: `self._default_guard_context = guard_context or _shared_guard_context` at construction time froze stale policy forever. Instance defaults should store only explicit constructor args; runtime reads must re-evaluate `_shared_guard_context` at every call. Add tests verifying that `set_shared_guard_context(updated)` and `clear_shared_guard_context()` affect existing instances created before the update.

- [topic: lessons | when: コンストラクタ chain に mode デフォルト引数を追加する時] 全 instantiation site を rg で grep し mode 伝播を確認せよ（デフォルトで隠れる）。 verify: rg "ClassName\(" src/
  detail: Adding `mode: str = "bugbounty"` as a default parameter to every class in a constructor chain masks missing propagation at caller sites: the default silently hides that callers (factories, providers, bridges, specialist `__init__`, `FuzzingSwarm.__init__`) are not passing mode through. After adding the parameter to base classes, `rg "ClassName\("` across `src/` to find all instantiation sites and ensure each one passes the mode from its own parameter or from the run context. Default parameters enable silent mode divergence.

- [topic: codingrules | when: compiled policy の hash field を設計する時] deterministic payload hash と file-integrity hash は別 field にせよ。 verify: write_compiled_policy_artifact が sha256(file_bytes) を別途計算
  detail: `_compute_compiled_policy_hash()` produces a payload hash (excludes `compiled_at_utc` for idempotency), but `compiled_guard_loader.load_active_policy_from_bundle_dir()` verifies `active_bundle.json.compiled_policy_hash` against raw file bytes. If the compiler writes its deterministic hash into active_bundle.json, every load fails with `policy_integrity_error`. The writer function (`write_compiled_policy_artifact()`) must compute `sha256(file_bytes)` separately and store it in active_bundle.json; the deterministic payload hash stays in the YAML for spec compliance.

- [topic: codingrules | when: bundle import の write path を設計する時] 対応する validation を file write 前に呼べ。 verify: raw 入力の secret scan が copy/write 前に走ること
  detail: Every import/persistence boundary must call its corresponding validation BEFORE any file write occurs: `BundleRegistry.validate_bundle_import()` and `scan_for_credentials()` existed but were not wired into `BundleManager.import_bundle()`'s write path, allowing secrets in raw policy.md/scope_assets.* to be persisted. Scan raw input content at the earliest possible point (before `copy`/`write_text`/`mkdir`), not just structured YAML fields, and raise `ValueError` to reject the entire import atomically.

- [topic: python-tests | when: guard_metrics.py に新 metric を追加する時] 実 pipeline 関数を呼び `count >= 1` を assert する統合テストを書け。 verify: snapshot()["metric_name"]["count"] >= 1
  detail: New metrics counters/histograms MUST have at least one integration test asserting `count > 0` or equivalent after the production code path runs: `bundle_import_to_ready_seconds` had `start_import_timer()`/`record_import_to_ready()` methods defined but zero callsites wired — the spec claimed it was hooked while `rg` found no non-test references. For every metric added to `guard_metrics.py`, write an integration test that calls the real pipeline function (e.g., `BundleManager.compile_bundle()`) and asserts `snapshot()["metric_name"]["count"] >= 1`.

- [topic: task-ledger | when: タスクを done にする時] 7-step を省略するな。各 step 後に `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` を実行せよ。 verify: validate_shigoku_docs.py が GREEN
  detail: SHIGOKU task closeout is a 7-step atomic procedure; skipping any step breaks `validate_shigoku_docs.py`: (1) `status: done` in front matter, (2) move file to `done/` directory, (3) update `primary_doc` path in `task_registry.yaml` to new `done/` path, (4) update status + path in `task_ledger.md`, (5) create `work_report` in `docs/shigoku/reports/`, (6) create `work_log` in `docs/shigoku/worklogs/`, (7) `rg` old path across `docs/shigoku/` and update every `related_docs` reference.

- [topic: reporting | when: evaluate_gate_separated の confirmed/candidate count を実装する時] `session_raw_unique` でなく `report_findings_summary` を使え。 verify: acceptance criteria のデータソース照合
  detail: Gate separation refactor: `evaluate_gate_separated()` MUST use `report_findings_summary` for Finding Policy Gate confirmed/candidate counts, not `session_raw_unique`: session has pre-evidence-quality-gate raw counts that differ from the report's actual output (e.g. session=10 confirmed but evidence quality demoted 9 → report=1 confirmed). Cross-check acceptance criteria assertions like "Confirmed 1 < 3 でFAIL" against the implementation's data source, not just unit test pass/fail.

- [topic: reporting | when: output 構造が変わる formatter 移行をする時] downstream テストの old section heading / evidence template を dispatch 前に grep せよ。 verify: 旧見出しパターンの rg
  detail: When migrating a formatter class that changes output structure (e.g. HaddixFormatter→HaddixSubmissionInternalFormatter), grep ALL downstream test assertions for old section headings and evidence template patterns BEFORE dispatch: this session's migration silently changed `## 🔒 Vulnerability Report`→`# 提出用レポート`, `### ✅ Confirmed Findings`→`### 1. emoji [SEVERITY] title`, and removed the Evidence Template table entirely. The plan's risk section warned "ファイル分離で既存--format haddix利用者への影響" but no proactive grep was done, causing 7 downstream test regressions that required post-hoc assertion rewrites.

- [topic: lessons | when: プリフライト(CaidoCheck)や MC 起動前に `AsyncNetworkClient()` を生成する時] コンパイルガードの policy_unavailable fail-close はガード条件の緩和でなくモード伝播で直せ。verify: .venv/bin/python -m pytest tests/unit/core/agents/swarm/injection/test_specialist_mode.py tests/core/security/test_guard_enforcement_phase2.py -q
  detail: `set_shared_guard_context()` は MC の `_try_resolve_bugbounty_bundle()` 内（＝プリフライト後）でしか呼ばれず、プリフライト中は `_shared_guard_context=None`。CaidoCheck が作る裸 `AsyncNetworkClient()` はデフォルト `mode="bugbounty"`（network_client.py:334 でガード活性）で `policy=None` → fail-close する。却下アプローチ: ガード条件へ「context が None なら skip」を入れる案 → `test_network_client_fail_closed_when_no_context` と fail-closed 安全設計を壊すため却下（lessons.md の network-guard CAUTION にも反する）。正解: `src/core/config/settings.py` の `resolve_run_mode()`（明示>get_settings().mode>bugbounty）で全クライアントの mode を解決し、`src/main.py` でプリフライト前に `config.mode=mode`（get_settings シングルトン＝cm.config）を設定する。106-108 の「呼び出し元へ mode をスレッド」方針は42サイトで非実用的なため中央 resolver で解決した（specialist 4種＋auth/injection manager の硬直 `mode="bugbounty"` も同 helper へ統一）。

- [topic: lessons | when: プリフライトが `CAIDO_HTTP_UNREACHABLE` を報告する時] TCP 到達成功でも HTTP 失敗なら Caido を疑う前にログの `policy_unavailable` / `Guard BLOCKED` を grep せよ。verify: <プリフライト実行コマンド> 2>&1 | rg "policy_unavailable|Guard BLOCKED|CAIDO_HTTP_UNREACHABLE|CaidoCheck TCP.*reachable"
  detail: `CaidoCheck._check_caido_identity()` の例外は caido_check.py:263 で一律 `CAIDO_HTTP_UNREACHABLE` に丸められ、TCP 成功・Caido 稼働中でもガード遮断が「HTTP 到達不能」に見える。本件は Caido 正常・mode 伝播欠落でガード自爆ブロックだった。実機再現レシピ: `get_settings().mode='vulntest'` + `clear_shared_guard_context()` で `CaidoCheck(caido_url='http://127.0.0.1:8080').run()` が `all_ok=True`（bugbounty のままなら policy_unavailable で fail）になることで、Caido の生死とガンド遮断を分離確認できる。

- [topic: lessons | when: AuthProbe が AUTH_WAF_CHALLENGE を報告し標的が DVWA 等の脆弱性テストアプリの場合] ステータス 200 の WAF_CHALLENGE は false positive（正規ページテキストがマーカーに一致）なので _classify_deterministic Rule 7 に status_code >= 400 を加えよ。verify: rg -n "has_challenge" src/core/preflight/auth_probe.py
  detail: _CHALLENGE_MARKERS の blocked と _WAF_MARKERS の security check が DVWA の正規ページテキストに部分一致する（auth_probe.py:51-73）。Rule 7（has_challenge → WAF_CHALLENGE）は Rule 9（is_login_page → LOGIN_PAGE）より先に評価されるため（auth_probe.py:640-643 vs 651-653）、200 OK のログインページでも challenge marker が優先されて誤分類される。却下アプローチ: (1) User-Agent 追加 → 本件は WAF 実ブロックではなく false positive なので無効。(2) network_client.py への loopback bypass → preflight と guard のタイミング問題と誤認。(3) main.py への preflight skip env var → 問題を迂回するだけで根本原因を潰していない。

- [topic: lessons | when: ProjectManager の default `workspace/projects` または auto report artifact path を変更する時] コンテナ内コード配置ルートではなく `SHIGOKU_WORKSPACE_ROOT` / `SHIGOKU_WORKSPACE_PROJECTS_DIR` を保存先正本にせよ。verify: .venv/bin/pytest tests/core/test_project_manager.py::test_default_base_dir_prefers_configured_workspace_root tests/unit/main/test_main_auto_report_bundle.py::test_print_auto_report_bundle_summary_maps_runtime_workspace_to_host_path -q
  detail: SGK-2026-0361。`src/core/project/project_manager.py:42-60` の default base 解決がコード配置ルート基準だと、Docker/DevContainer の `/app` に引っ張られて内部保存先と表示が `/app/workspace/projects/...` になる。`src/main.py:245-257` の表示だけ直す案は、`Source Session` 等の内部artifact metadataに `/app` が残るため却下。保存先は runtime workspace、表示は `SHIGOKU_HOST_WORKSPACE_ROOT` で host-facing path へ分離する。

- [topic: report-session-consistency | when: `verify_report_session_consistency.py --report` が `/app/workspace/.../haddix_report_*.md` または `Source Session: /app/workspace/...` を含む report を扱う時] report引数入口と source_session header の両方で workspace互換解決を実行せよ。verify: python3 scripts/verify_report_session_consistency.py --report /app/workspace/projects/localhost:4280/reports/haddix_report_20260714_114645.md
  detail: SGK-2026-0361。`src/reporting/report_session_consistency.py:150-190` と `:355-359`。提示reportは最初 `/app/...` 指定で `report_not_found`、host path指定でもreport内 `Source Session: /app/workspace/...` により `source_session_not_found` になった。却下アプローチ: source_session header だけ互換解決する修正 → report引数自体が `/app/workspace/...` の場合に入口で止まるため不十分。実reportで `status=consistent`, `reason_codes=[]` を確認する。

- [topic: codingrules | when: `src/core/conductor/interactive_bridge.py` で CLI runtime option（例: `intervention_gate_mode`）を読む時] `src.core.config.settings.get_settings()` ではなく `src.config.settings` を正本として読め。 verify: rg 'getattr\(settings, "intervention_gate_mode"|_current_intervention_gate_mode' src/core/conductor/interactive_bridge.py

- [topic: codingrules | when: task_expander で subtask の _context evidence（forms_by_url, url_evidence_by_url）をコピーする時] 外側 dict の shallow copy では不十分。中の list/dict 値は親と共有され mutation が他 subtask に漏洩するため `copy.deepcopy` を使え。 verify: .venv/bin/pytest tests/core/engine/test_task_expander.py -v
  detail: SGK-2026-0367。task_expander._create_subtask() の `sub_params = parent.params.copy()` は外側 dict のみ複製し、`_context` 以下の forms_by_url[target]・url_evidence_by_url[target] は親と同一オブジェクトのまま。片方の subtask で forms リストに要素追加や dict キー変更をすると他方にも伝播する。却下アプローチ: dict(_context) で shallow copy しただけでは forms_by_url の値（list/dict）は依然共有される。正解: `copy.deepcopy(per_url_forms)` / `copy.deepcopy(per_url_evidence)` で subtask ごとに完全独立させる。

- [topic: lessons | when: Phase2 no-signal suppression にカテゴリ分岐を追加する時] `_should_force_phase2_for_exception_target` で非対象カテゴリに `return True`（force=止めない）すると既存 lane2 ゲート（ssrf の score-based skip 等）を破壊する。非対象カテゴリは `return False` にして既存判定を素通しせよ。 verify: .venv/bin/pytest tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py -q
  detail: SGK-2026-0367。xss_candidate 限定の suppress 追加時に `category != "xss_candidate" → return True` で force_phase2=True にしてしまい、ssrf_candidate の lane2_score_eligible=False による skip を阻止した。test_dispatch_skips_phase2_when_ssrf_score_below_lane2_threshold_without_override が mock_super_dispatch.await_count == 1 で失敗。正解: 非対象カテゴリは `return False` とし、既存の `not phase2_on_empty_phase1` 条件で自然に判定させる。

- [topic: lessons | when: edit ツールで YAML の dict 内キーを修正する時] oldString に含まれない既存行が残って重複キーになることがある。修正後に `rg -n "キー名" <file>` で同一 scope 内にキーが2つ以上ないか確認せよ。 verify: rg -n "selection_origin" <file>
  detail: SGK-2026-0367。master_conductor.py の CSRF backfill `csrf_task_params` dict 追加時に、`"selection_origin": "coverage_backfill"` を挿入したが、既存行 `"selection_origin": "coverage_backfill_guard"` が oldString 外のため残留し、2つ目の値で1つ目が常に上書きされていた。detect: `rg -n "selection_origin" src/core/engine/master_conductor.py` で隣接行の重複を発見した。

- [topic: python-tests | when: InjectionManager.dispatch() を mock なしでテストする時] Phase 2 が `super().dispatch()`（BaseManagerAgent LLM think loop）へ進むため、LLM 認証エラーで `status="running"` になる。`patch.object(BaseManagerAgent, "dispatch", new=AsyncMock(return_value=SwarmResult(status="success")))` で Phase 2 境界を mock せよ。 verify: .venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py -k "dispatch" -q
  detail: SGK-2026-0367。`manager.set_llm_client(mock_llm)` だけでは `dispatch()` 内の `super().dispatch()` 経路での LLM 再初期化を阻止できず、本番 API キー未設定環境では常に `litellm.BadRequestError` で失敗する。却下アプローチ: `manager.llm = MagicMock()` 直接代入 → `BaseManagerAgent` の `self.llm` チェックで再初期化される。正解: `patch.object(BaseManagerAgent, "dispatch", ...)` で親クラスの Phase 2 境界を確定 mock する。
  detail: SGK-2026-0362。`src/main.py:2604-2606` は `--intervention-gate-mode` を `src.config.settings.intervention_gate_mode` に書き込む一方、InteractiveBridge には preflight 用の `src.core.config.settings.get_settings()` 由来 `settings` もあり、後者を読むと CLI 上書きを拾えず強制モード/observe の判定がずれる。却下アプローチ: `InteractiveBridge.ask_for_approval()` を抑止するだけの対症療法 → ExecutionSafeguard/RequestGuard の HITL callback 登録経路に設定が伝わらない根本原因を残すため却下。`src/core/conductor/interactive_bridge.py:93-129` の helper で runtime settings を正規化して callback 生成に渡す。

- [topic: python-tests | when: InjectionManager.dispatch の Phase1 metadata を dispatch 完了後に検証する時] `manager.current_context["url_results"]` を正本にするな。`result.execution_log` の `phase1_summary.url_results` を参照せよ。 verify: .venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py -k "dispatch_records_priority_score or dispatch_records_selection_origin or dispatch_timeout_records_last_stage_before_timeout" -q
  detail: SGK-2026-0367。下流 reader は `src/main.py:747`、`src/commands/report.py:147`、`src/dashboard/api/main.py:67` のように execution_log 内の `url_results` を読む。却下アプローチ: dispatch 完了後に `manager.current_context["url_results"]` を直接 assert する方法。Phase 2 経路を通ると観測点がずれて false red になり、`tests/core/agents/swarm/test_injection_manager.py:845`、`1001`、`1059` のように `result.execution_log` へ寄せる修正が必要になった。

- [topic: python-tests | when: `src/recon/pipeline.py` の `_base_context` 共有や `cmd_focus` sibling task 生成を変更する時] core/engine 側の targeted pytest だけで完了判定するな。`tests/recon/test_tagged_uncategorized_promotion.py` も必ず実行せよ。 verify: .venv/bin/pytest tests/recon/test_tagged_uncategorized_promotion.py -q
  detail: SGK-2026-0367。`src/recon/pipeline.py:4177` と `4231` では main task と `cmd_focus` task の `_context` を別 object に保つ必要がある。却下アプローチ: injection 周辺の targeted pytest だけで deep-copy 修正を完了扱いする方法。兄弟 task 間の `_context` 非共有は `tests/recon/test_tagged_uncategorized_promotion.py:530`-`585` でしか直接保証できない。

- [topic: lessons | when: dataclass の `__init__` パラメータ名/型を変更する時] 変更後に `rg "ClassName\(old_param=" --include "*.py"` で全コールサイトを grep し、テストファイルも含めて一括更新せよ。verify: rg "TaskPruningPolicy\(shadow_only" tests/ src/
  detail: SGK-2026-0287。`TaskPruningPolicy.__init__` の `shadow_only: bool` を `mode: str` に変えた際、`test_master_conductor_pruning.py`、`test_master_conductor_event_marshaling.py` の 2 ファイルで `TaskPruningPolicy(shadow_only=True)` が残留し、TypeError で 8 件のテストが全滅した。dataclass の `__init__` は型チェックが静的に効かず、旧パラメータ名が実行時エラーになるまで発見できない。却下アプローチ: テスト実行だけに頼る → 全テストを毎回走らせるまで検出されない。

- [topic: lessons | when: ある属性を別属性の lazy alias として設計し、かつ `__new__` で最小インスタンスを作るテストがある時] alias 元（正本）だけを pre-set し、alias 先は lazy init に任せよ。両方 pre-set すると独立した list になり同期が切れる。verify: .venv/bin/pytest tests/core/engine/test_master_conductor_pruning.py -q
  detail: SGK-2026-0287。`_pruning_decisions` を正本リスト、`_shadow_decisions` を `_evaluate_pruning_policy()` 内で `self._shadow_decisions = self._pruning_decisions` と遅延エイリアスする設計にした。テストヘルパー `_new_minimal_conductor()` が `mc._pruning_decisions = []` と `mc._shadow_decisions = []` の両方を pre-set していたため、`_evaluate_pruning_policy()` が `_pruning_decisions` に追記しても `_shadow_decisions` は空のままになり、`len(mc._shadow_decisions) > 0` の assertion が失敗した。正解: alias 元だけ pre-set し、alias 先は `_evaluate_pruning_policy()` の lazy init に任せる。

- [topic: task-ledger | when: 実装 task を `done` 化する時点で runbook/work_log に `shadow review` や `promotion pending` が残る時] 残監視は同一 task に抱えず別の active follow-up SGK を起票し、`deferred_tasks.tracking_task_id` と `related_docs` を follow-up 側へ張り替えよ。 verify: rg -n 'status: done|shadow review|promotion pending|tracking_task_id: SGK-2026-0287' docs/shigoku/subtasks/done/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md docs/shigoku/worklogs/2026-07-17_sgk-2026-0287_implementation_work_log.md docs/shigoku/manuals/2026-07-17_sgk-2026-0287_pruning-operator-runbook.md docs/shigoku/registry/task_ledger.md docs/shigoku/registry/task_registry.yaml
  detail: SGK-2026-0287。`docs/shigoku/subtasks/done/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md:20-26` は実装完了と `status: done` を示す一方で「本タスクは `active` を維持」「shadow review 5 件 + active promotion」を残していた。`docs/shigoku/worklogs/2026-07-17_sgk-2026-0287_implementation_work_log.md:35-74` でも D01/D02 の `tracking_task_id` が同じ `SGK-2026-0287` のままで、done task と運用継続 task の境界が曖昧になった。却下アプローチ: 実装完了 task のまま deferred 監視を続ける運用。完了判定と追跡主体が衝突し、review 時に closed か active かを一意に判断できないため却下。

- [topic: shigoku-docs | when: `plan/subtask_plan` の Step 11 や完了条件で real session/report artifact 検証を必須にした時] `106 passed` などの targeted pytest だけで `[x]` にするな。work_log/report に実 artifact の session↔report 照合証跡を残すか、未実施なら checkbox を戻して follow-up へ切り出せ。 verify: rg -n '11-3|11-4|real session/report artifact|106 passed|No reviews recorded yet|shadow review' docs/shigoku/subtasks/done/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md docs/shigoku/worklogs/2026-07-17_sgk-2026-0287_implementation_work_log.md
  detail: SGK-2026-0287。`docs/shigoku/subtasks/done/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md:181-186` は real artifact 検証と昇格証跡作成を完了条件にしているのに、同ファイル `:77` は「実 session/report artifact 確認は shadow review フェーズに deferred」と明記していた。`docs/shigoku/worklogs/2026-07-17_sgk-2026-0287_implementation_work_log.md:33-46` も `Tests: 106 passed` と `No reviews recorded yet (2026-07-17)` を併記しており、pytest 緑だけでは Step 11 の artifact 条件を満たしていなかった。却下アプローチ: targeted pytest 緑を根拠に 11-3/11-4 をそのまま完了扱いすること。実 artifact を前提にした受け入れ条件の未消化が残るため却下。

- [topic: codingrules | when: `_load_step_json`の呼び出し元や`robust_json_loads`の戻り型を変更する時] `_load_step_json`の`len(data)==1: return data[0]`単一要素unwrapは`robust_json_loads`が常に`list[Any]`を返す前提に依存しているため、片方だけ変更するな。verify: `.venv/bin/pytest tests/recon/test_step6_8_final.py -k 'classify_by_status or waf' -q`
  detail: SGK-2026-0261。`src/recon/pipeline.py:2897-2899`。`robust_json_loads`は常に`list[Any]`を返す（dictも`[{...}]`にラップ）。`_load_step_json`の`if len(data)==1: return data[0]`はこの性質に依存してdict入力をdictのまま返している。unwrapを単純削除するとwafw00f等のdictデータがlist`[{...}]`として返り`'list' object has no attribute 'get'`が発生（`test_step6_waf_integration`、`test_step6_cloud_classification`がAttributeErrorで失敗）。却下アプローチ: 単に`if len(data)==1: return data[0]`を削除 → dict consumerが全滅。正解: テスト側で1件対策（entriesを2件以上にする）か、list/dict両対応の呼び出し元修正。

- [topic: codingrules | when: `edit`でPythonクラスのメソッド群の末尾にmodule-level関数を挿入する時] 必ずクラスと同じindent（4-space）を維持せよ。0-indentの`def`はクラスを即座に終了させ、後続のクラスメソッドをその関数のネスト関数にしてしまう。verify: `import ast; ast.parse()`で構文エラーなし + `hasattr(ClassName, "method_name")`でメソッド到達性確認
  detail: SGK-2026-0261。`src/recon/pipeline.py:3290`付近。`_build_step8_signal_bundle`（クラスメソッド）の直後に`def _infer_surface_info(...)`を0-indentで挿入した結果、後続の`_generate_tech_tags`、`_map_tagged_category_to_tags`、`_promote_uncategorized_tagged_file`が全て`_infer_surface_info`のネスト関数になり`ReconPipeline`クラスから消失。`hasattr()`がFalseになり26件のAttributeError。修正: `@staticmethod`付きで4-space indentのクラスメソッドに変更。ast.parse()は通過した（関数は構文的に有効）がhasattrで初めて検出された罠。

- [topic: codingrules | when: `src/core/infra/knowledge_graph.py` の `store_signal_bundle()` で recon signal を永続化する時] signal は `Endpoint` に上書きするな。`signal_id` 単位の `AttackSurfaceSignal` ノードとして保存し `Endpoint` へ関連付けよ。 verify: `rg -n 'MERGE \\(s:AttackSurfaceSignal \\{signal_id: \\$signal_id\\}\\)|TARGETS_ENDPOINT' src/core/infra/knowledge_graph.py`
  detail: SGK-2026-0261。`src/core/infra/knowledge_graph.py:333-353`。却下した案は `MERGE (e:Endpoint {url, method}) SET e.signal_* = ...` で signal を `Endpoint` へ直書きする方法。param/auth surface signal が endpoint signal と同じ `url+method` を共有すると最後の1件で上書きされ、`why_suspicious` と signal 粒度の追跡が消えた。`AttackSurfaceSignal(signal_id)` を正本にして `(:AttackSurfaceSignal)-[:TARGETS_ENDPOINT]->(:Endpoint)` へ分離するのが再発防止策。

- [topic: lessons | when: `src/recon/pipeline.py` の `_build_step8_signal_bundle()` で `host_surface_summary` の集計を変える時] endpoint 件数と signal 件数を同じカウンタで数えるな。`1 endpoint + 2 params` の最小再現で `total_endpoints == 1` と `total_signals == 3` を確認せよ。 verify: `.venv/bin/python - <<'PY'\nimport asyncio, json, tempfile\nfrom pathlib import Path\nfrom src.recon.pipeline import ReconPipeline\nasync def main():\n    tmp = Path(tempfile.mkdtemp(prefix='sgk0261_check_'))\n    p = ReconPipeline(config={'recon': {'max_concurrent_tasks': 4}}, project_manager=None, target='*.example.com', workspace_root=tmp)\n    f = tmp / 'live_200.json'\n    f.write_text(json.dumps([{'url': 'https://app.example.com/search?q=test&id=42', 'status_code': 200, 'method': 'GET'}]))\n    result = await p.step8_return_to_mc({'live_200': f})\n    summary = result['_signal_bundle']['_host_surface_summary']\n    assert summary['total_endpoints'] == 1 and summary['total_signals'] == 3 and summary['category_counts']['live_200'] == 1\nasyncio.run(main())\nPY`
  detail: SGK-2026-0261。`src/recon/pipeline.py:3356-3458`。却下した案は `category_total` を endpoint signal と param signal の両方で増やし、そのまま `category_counts` と `total_endpoints` に流す実装。これだと host summary が「endpoint 要約」ではなく「signal 総数」へ崩れ、完了判定でも誤って green に見える。`category_endpoint_counts` と `category_signal_counts` を分離し、互換 `category_counts` は endpoint 件数だけに戻す必要がある。

- [topic: codingrules | when: `AttackSurfaceSignal` の runtime field を増やす時] `pipeline` の dict 生成、`url_context.py` の dataclass、`knowledge_graph.py` の writer を同一パッチで同期せよ。1か所だけ直して情報落ちを起こすな。 verify: `rg -n 'auth_context|params' src/recon/pipeline.py src/core/models/url_context.py src/core/infra/knowledge_graph.py`
  detail: SGK-2026-0261。field 追加漏れで `auth_context` と `params` が KG へ保存されず、選抜時に全 parameter 欠損・auth_context 偽陰性になる。pipeline/recon→dataclass→KG の3レイヤを同時に grep して追加漏れがないこと。

- [topic: codingrules | when: knowledge_graph.py の Cypher SET 句に `$param` 参照を追加する時] 同じ `session.run(query, **kwargs)` 呼び出しに同名の named argument を追加せよ。Neo4j は欠損を null に黙って埋め、エラーも警告も出さない。 verify: fake session で session.run() の kwargs を capture し追加した param が存在するか assert
  detail: SGK-2026-0260。`store_recipe_run()` の Cypher に `$suppression_key_signal` / `$suppression_key_endpoint` の SET 句を追加したが、`session.run(...)` の引数に追加し忘れた。Neo4j は不足 param を null で黙って処理するため、テストが通っても実データが保存されない。`tests/unit/engine/test_recipe_selector.py::test_store_recipe_run_passes_suppression_keys` で fake driver + 引数 capture による検証を追加。

- [topic: codingrules | when: RecipeRun の suppression key を永続化して別の run で読む時] selector が照合する key format (`signal:{recipe}:{signal_id}`, `endpoint:{recipe}:{url}`) をそのまま保存し、復元時も fabricated せず生 key を読み戻せ。verify: 前回 run の saved key と今回 run の matching key が文字列一致することを assert するテスト
  detail: SGK-2026-0260。`src/core/engine/master_conductor.py` と `src/core/infra/knowledge_graph.py` の境界。却下案は `endpoint:{recipe}:{target_domain}` という粗いキーを保存側も復元側もそれぞれ自作する実装。これだと保存側が `endpoint:auth_recipe:app.example.com` を保存し、selector が `signal:auth_recipe:sig-auth-1` で照合するため決して一致しない。`store_recipe_run()` に `suppression_key_signal` / `suppression_key_endpoint` を追加し、`get_recipe_runs_for_domain()` が `suppression_keys` リストを返し、MC がそのまま `active_suppression_keys` に投入するように修正。

- [topic: codingrules | when: `recipes/auth/*.yaml` の Recipe 完了判定で `success_condition` / `stop_condition` を確認する時] top-level ではなく `trigger.success_condition` / `trigger.stop_condition` を正本として確認せよ。 verify: `python3 - <<'PY'\nfrom pathlib import Path\nimport yaml\nfor p in Path('recipes/auth').glob('*.yaml'):\n    d=yaml.safe_load(p.read_text()); t=d.get('trigger') or {}\n    assert t.get('type') == 'signal' and t.get('success_condition') and t.get('stop_condition'), p\nPY`
  detail: SGK-2026-0259。`recipes/auth/oauth_binding_drift.yaml:4-13`、`recipes/auth/session_invariant.yaml:4-10`、`recipes/auth/jwt_claim_enforcement.yaml:4-11`、`recipes/auth/refresh_rotation.yaml:4-11` などは条件を `trigger` 配下に置く。却下した確認方法: YAML top-level の `success_condition` / `stop_condition` だけを見る方法。これだと全 Recipe が条件欠落に見える false red になるが、`src/core/engine/recipe_loader.py:479-480` / `:562-563` は `trigger.get(...)` を `RecipeCandidate` へ渡すため、`trigger` 配下が正しい確認位置。

- [topic: task-ledger | when: work_report に `deferred_tasks` を記録する時] `deferred_tasks` を fenced code block に入れず、validator が読める構造化ブロックとして書け。 verify: `rg -n '```yaml|deferred_tasks:|tracking_task_id:' docs/shigoku/reports/2026-07-20_sgk-2026-0259_auth-jwt-oauth-recipe_work_report.md && python3 scripts/validate_shigoku_docs.py`
  detail: SGK-2026-0259。`docs/shigoku/reports/2026-07-20_sgk-2026-0259_auth-jwt-oauth-recipe_work_report.md:75-83` は `deferred_tasks` を ```yaml fenced code block 内に置いたため、`tracking_task_id: SGK-2026-0259-D01` が registry に存在しなくても `validate_shigoku_docs.py` は `DEFERRED_LINK_ISSUES=0` になった。却下した運用: fenced block 内の YAML を構造化 deferred とみなすこと。validator が本文コードブロックをリンク検証対象として読まないため、完了判定では手動 `rg` と registry 照合が必要になる。

- [topic: shigoku-docs | when: plan/subtask_plan を done/ に移動して追加リンク破損を検出する時] `related_docs` の front matter 更新だけでは不十分。本文中の本文中の相対リンク（link-textとパスを持つ角括弧・丸括弧形式）も新パスへ更新せよ。verify: `python3 scripts/validate_shigoku_docs.py | grep BROKEN_LINK`
  detail: SGK-2026-0259。`docs/shigoku/subtasks/2026-06-03_sgk-2026-0259_recipe-auth-jwt-oauth_subtask_plan.md` を `done/` へ移動後、`related_docs` front matter は全更新したが、`2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md:84` と `2026-06-03_sgk-2026-0261_recon-signal-mc-swarm_subtask_plan.md:83` の in-body 相対リンクが旧パスを指したまま残り、`BROKEN_LINK=3` として検出された。`rg -l "0259_recipe" docs/shigoku/` でファイル名一致を全件確認し、front matter 外の本文リンクも更新する必要がある。

- [topic: lessons | when: OptimizedRecipeRunner の DAG 実行で失敗 step の後続をテスト設計する時] `_finalize_results()` は失敗 step を DAG 完了扱いするため、後続 step は実行され success 判定が通る。単一 step 失敗だけでは recipe 全体失敗にならない。verify: `.venv/bin/pytest tests/unit/engine/test_optimized_runner.py::test_auth_recipe_stops_at_confirm_failure -q`
  detail: SGK-2026-0259。`tests/unit/engine/test_optimized_runner.py` の `test_auth_recipe_stops_at_confirm_failure` は当初 3-step DAG で step_1 (confirm) が失敗する設計だったが、`OptimizedRecipeRunner._execute_step_with_semaphore()` は失敗 step も `completed` として DAG ノードを完了扱いし、`step_2 (evidence)` が依存解決されて実行された。`_finalize_results()` は全 step の aggregate success/failure 比で判定するため `success=True` が返り、テスト期待値と不一致になった。却下した設計: 3-step DAG の confirm 失敗 → recipe 全体失敗を期待するテスト。runner の DAG 完了セマンティクスに合わせ、全 step が失敗する scenario で recipe 全体失敗を検証するよう修正した。

- [topic: lessons | when: `src/core/engine/master_conductor.py` の recon 実行ブロックで resume 判定を挿し込む時] 実行用 `task.params["target"]` と resume 検証用 `context.target_info["target"]` を同じ変数で上書きするな; `pipeline.run()` へ渡す target は task 起点の値を保持し、resume 判定用は別名へ分離せよ。 verify: `rg -n 'target = task.params.get\\("target"|resume_target = str\\(self.context.target_info.get\\("target"|pipeline.run\\(target' src/core/engine/master_conductor.py`
  detail: SGK-2026-0281。`src/core/engine/master_conductor.py:9380-9456`。完了判定レビューで、`target = task.params.get("target", ...)` の直後に `context.target_info["target"]` を同じ `target` へ再代入すると、context 側が空の run で `pipeline.run("")` になる罠が見つかった。却下アプローチ: resume 判定のために `context.target_info["target"]` をそのまま `target` に上書きする実装。`task.params` にしか target が無い経路を壊すため却下。

- [topic: python-tests | when: `src/core/engine/recon_importer.py` の import-recon fail-closed 契約を変更する時] 指紋付き fixture だけの targeted pytest で完了判定するな。`target_fingerprint` なし `recon_state.json` を `load_imported_recon_dir()` に直接通し、`accepted=False` と `missing_target_fingerprint` を確認せよ。 verify: `.venv/bin/python - <<'PY'\nfrom pathlib import Path\nimport json, tempfile\nfrom src.core.engine.recon_importer import load_imported_recon_dir\nwith tempfile.TemporaryDirectory() as td:\n    p = Path(td)\n    (p / 'recon_state.json').write_text(json.dumps({'target': 'example.com', 'live_subs': ['a.example.com']}), encoding='utf-8')\n    b = load_imported_recon_dir(p, target='example.com')\n    assert b.accepted is False and 'missing_target_fingerprint' in b.artifacts[0].reason_codes\nPY`
  detail: SGK-2026-0281。`src/core/engine/recon_importer.py:289-308`。レビュー時点では `tests/unit/engine/test_master_conductor_import_recon.py` と `tests/unit/engine/test_recon_importer.py` の既存 fixture を全部 fingerprint 付きに直しただけで targeted pytest が緑になり、指紋欠落 reject が未検証のまま残り得た。却下アプローチ: fixture 全件を fingerprint 付きへ寄せた pytest 緑だけで fail-closed 実装を完了扱いすること。欠落ケースを直接 loader へ流さないと誤判定するため却下。

- [topic: lessons | when: `_create_attack_tasks_from_recon()` の decision matrix に新分岐を追加する時] `decision_stats` の宣言とログ書式だけを更新するな。`tasks.append(...)` や `continue` の実分岐点で対応 counter を必ず increment せよ。 verify: `rg -n 'decision_stats|swarm_fallback|recipe_to_swarm_reason|gate_rejected' src/core/engine/master_conductor.py`
  detail: SGK-2026-0281。`src/core/engine/master_conductor.py:10637-10941`。完了判定レビューで `swarm_fallback` が辞書宣言とログ出力には存在するのに増分がなく、常に 0 のままになる罠が見つかった。却下アプローチ: 分岐名を dict と logger に追加した時点で「可観測化できた」とみなすこと。signal→swarm task 生成点に `decision_stats["swarm_fallback"] += 1` が無いと運用メトリクスが嘘になるため却下。

- [topic: lessons | when: `_create_attack_tasks_from_recon()` で compiled guard の `requires_hitl` を category-level pending HITL ticket に変換する時] `requires_hitl` をログだけ残して通過させるな。既存 `pending_hitl` 経路へ登録して task 作成を止め、dedupe が必要な synthetic task は `task_id + scenario_id` を安定化せよ。 verify: `rg -n 'elif bv.verdict == "requires_hitl"|_register_pending_hitl_ticket|task_id = str\\(|scenario_id = str\\(' src/core/engine/master_conductor.py`
  detail: SGK-2026-0370。`src/core/engine/master_conductor.py:11096-11125` と `:5065-5080`。最初の実装は `_bridge_can_proceed = True` のまま attack task 作成へ流れ、完了判定レビューで「HITL なのに止まらない」として却下された。修正後は category-level placeholder task を `_register_pending_hitl_ticket()` へ渡す案に切り替えたが、この helper の重複判定は `task_id + scenario_id` を使うため、synthetic `Task.id` を毎回乱数にすると同一カテゴリ再評価で ticket dedupe が効かなくなる罠がある。

- [topic: codingrules | when: `guard_enforcement.resolve_policy_from_context()` に `target_info` を渡して compiled guard policy を解決する時] `bundle_dir` が設定されている場合は `compiled_guard_policy_path` より優先される。テストで policy を解決させたいなら `bundle_dir` を指す `active_bundle.json` を含むディレクトリパスを設定せよ。 verify: `.venv/bin/python -c "
from src.core.security.guard_enforcement import resolve_policy_from_context
ctx = {'bundle_dir': 'tests/fixtures/bugbounty_guard/tiktok', 'compiled_guard_policy_path': '/nonexistent'}
p = resolve_policy_from_context(ctx)
assert p is not None and p.bundle_id.startswith('bbp-'), f'unexpected: {p}'
"`
  detail: SGK-2026-0370。`src/core/security/guard_enforcement.py:260-290`。`resolve_policy_from_context()` は `bundle_dir` キーを先にチェックし、存在すれば `load_active_policy_from_bundle_dir()` を呼び出す。`compiled_guard_policy_path` だけが設定され `bundle_dir` が設定されていない場合のみ `compiled_guard_policy_path` の親ディレクトリから解決を試みる。テストで `compiled_guard_policy_path` だけ設定して解決を期待すると None が返る。却下アプローチ: `compiled_guard_policy_path` だけ `target_info` に入れて `resolve_policy_from_context()` を呼ぶこと。`bundle_dir` 未設定かつ `compiled_guard_policy_path` の親ディレクトリに `active_bundle.json` が無いと解決失敗する。

- [topic: lessons | when: `_register_pending_hitl_ticket()` を呼び出してカテゴリ単位や attack-surface 単位の HITL 保留を登録する時] `_register_pending_hitl_ticket()` は実 `Task` オブジェクトを要求する。カテゴリ単位の保留でも最小限 `Task(id=..., name=..., agent_type="hitl_gate", action="pending_approval", params={...})` のプレースホルダを構築せよ。 verify: `rg -n 'agent_type.*hitl_gate' src/core/engine/master_conductor.py`
  detail: SGK-2026-0370。`src/core/engine/master_conductor.py:5065-5095`、`:11096-11136`。compiled guard が `requires_hitl` を返したカテゴリの攻撃タスク作成を停止し HITL ticket を登録する際、実タスクは未生成だが `_register_pending_hitl_ticket()` API は `Task` 引数必須。却下アプローチ: HITL 理由だけログ出力して通常通り task を流す実装（`_bridge_can_proceed = True`）。queue から黙って理由が消え、review 指摘で差し戻し。`agent_type="hitl_gate"` の最小 Task を構築して `_register_pending_hitl_ticket()` に渡し、pending HITL store へ登録する形がプロジェクトの現行パターン。

- [topic: lessons | when: `MasterConductor.context.target_info` に新しい構造化データ（guard decision summary / gate stats など）を保存する時] `build_async_session_payload()` が `context.target_info` を session JSON へ自動で運ぶが、report formatter は追加されたキーを黙って無視する。データを operator 向けレポートに表示するには `src/reporting/target_profile_formatter.py` など対応 formatter に明示的な読み出しと表示ロジックを追加せよ。 verify: `rg -n '_guard_bridge' src/reporting/target_profile_formatter.py && rg -n '_guard_bridge' src/core/engine/master_conductor.py`
  detail: SGK-2026-0370。`src/core/engine/master_conductor.py:12415-12429` で `_guard_bridge_summary` と `_guard_bridge_decision_stats` を `context.target_info` に保存したが、初期実装では report formatter がこれらを読み出さず、完了判定レビューで「session までは見えるが report までは未証明」と指摘された。`src/reporting/target_profile_formatter.py:203-240` にガード・ブリッジ判定サマリーセクションを追加し、`tests/unit/reporting/test_target_profile_formatter.py` に表示確認テストを追加して解決。却下アプローチ: `context.target_info` への保存だけで「session/report に残る」とみなすこと。session JSON には確かに残るが report markdown には表示されない。

- [topic: lessons | when: `DecisionTreeSummary` に新しい集計フィールド（e.g. `degraded_nodes`）を追加し、Markdown レンダリングで使い始める時] `format_json()` の summary dict にも同一フィールドを追加せよ。Markdown と JSON で情報非対称になると reviewer に指摘される。 verify: `rg -n '"total_nodes|"linked_nodes|"degraded_nodes' src/reporting/decision_tree_formatter.py` で両方の dict keys を比較
  detail: SGK-2026-0334。`src/reporting/decision_tree_formatter.py:129` で `degraded_nodes` を `DecisionTreeSummary` に追加し、`:712` で Markdown レンダリングにも追加したが、`format_json()` の summary dict（`:202-212`）への追加を忘れた。reviewer が「JSON だけまだ新しい集計項目に追いついていません」と指摘。1行追加で済むが、Markdown output と JSON output が別 return 文で定義されているため見落としがちな罠。

- [topic: lessons | when: ツリー構築後に `_attach_supplemental()` や `_attach_auxiliary_edges()` でノードの `link_status` を変更し、その後 re-count する時] 再集計ループは `degraded` を含む全 status をカウントし、合計が `total_nodes` と一致することを回帰テストで assert せよ。 verify: `.venv/bin/pytest tests/unit/reporting/test_decision_tree_formatter.py::TestDecisionTreeDegradation::test_degraded_nodes_counted_in_summary -q`
  detail: SGK-2026-0334。`src/reporting/decision_tree_formatter.py:338-350`。初期実装では `degraded` ノードを `continue` でスキップしていたため、`linked + unlinked + estimated == 2 < total_nodes == 4` の不整合が発生。reviewer が「total_nodes=4 なのに集計の合計は 2」と指摘。修正後は `degraded_nodes` カウンタを追加し `elif` 順序を調整して全 status をカウント。さらに `degrade_reasons` の重複除去（`:352-369`、`_seen_reasons` set で dedup）も同時に要修正となった。

- [topic: cli-ops-routing | when: `scripts/shigoku_ops_cli.py` に新しい `report` サブコマンドを追加し、非 JSON（stdout）出力を実装する時] Markdown などの生テキスト出力は `print(content)` を直接呼び、dict payload に埋め込むな。`_emit_command_payload()` は dict を `key: value` 行形式で出力するため `markdown: # Title...` のようにラベル付きになる。 verify: `.venv/bin/pytest tests/unit/scripts/test_shigoku_ops_cli.py::test_ops_cli_decision_tree_json_basic -q`
  detail: SGK-2026-0334。`scripts/shigoku_ops_cli.py:508-516`。最初の実装で非 JSON モードの payload を `{"status": "ok", "markdown": markdown}` とした結果、`_emit_command_payload`（`:139-148`）が dict を `markdown: # Decision Tree ...` とラベル付き出力し、reviewer に「ほかの report コマンドと揃っていません」と指摘された。`_run_report_narrative`（`:337`）や `_run_report_target_profile`（`:387`）は `print(markdown)` 直接呼び出しが正解パターン。新規 `report` サブコマンドは既存実装の出力パターンをコピーせよ。

- [topic: task-ledger | when: `plan/subtask_plan` を `done/` へ移動した直後に完了判定をする時] `validate_shigoku_docs.py` だけで閉じるな。旧パス文字列を `docs/shigoku/` と `docs/shigoku/registry/task_registry.yaml` へ literal grep し、0 hit を確認せよ。 verify: `rg -n 'docs/shigoku/subtasks/2026-07-01_sgk-2026-0334_p1b-shigoku-ops-decision-tree-cli_subtask_plan.md' docs/shigoku docs/shigoku/registry/task_registry.yaml`
  detail: SGK-2026-0334。review round 4 時点で `python3 scripts/validate_shigoku_docs.py` は 0 errors だったが、旧 path が `docs/shigoku/registry/task_registry.yaml:3754`、`docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md:13`、`docs/shigoku/reports/2026-07-01_SGK-2026-0322_work_report.md:9` に残っていた。却下アプローチ: validator green だけで「done 移動は完了」とみなすこと。文字列参照の残骸は validator では取りこぼし、literal grep でしか見つからなかった。

- [topic: python-tests | when: review round で targeted pytest の件数が増減した後に `work_report` / `work_log` の検証欄を確定する時] 検証欄の pass 件数は最終 rerun 結果へ更新せよ。途中ラウンドの件数を残すな。 verify: `.venv/bin/pytest tests/unit/reporting/test_decision_tree_formatter.py tests/unit/scripts/test_shigoku_ops_cli.py -q && rg -n '83 passed' docs/shigoku/reports/2026-07-21_sgk-2026-0334_work_report.md docs/shigoku/worklogs/2026-07-21_sgk-2026-0334_work_log.md`
  detail: SGK-2026-0334。review 修正のたびに regression test が増え、`80 passed` で書いた `docs/shigoku/reports/2026-07-21_sgk-2026-0334_work_report.md` と `docs/shigoku/worklogs/2026-07-21_sgk-2026-0334_work_log.md` が、最終 rerun の `83 passed` とずれたまま残った。却下アプローチ: `validate_shigoku_docs.py` が通っているので検証欄の数値も正しいとみなすこと。docs validator は本文の pass 件数整合まで見ないため、最終 rerun と `rg` の両方で照合しないと誤判定する。

- [topic: cli-ops-routing | when: `shigoku-ops ops intent` の preview/confirmation loop を完了判定する時] `--approve` 経路だけで閉じるな。PTY で `[y/N]` 承認を実際に1回通せ。 verify: `script -q /dev/null zsh -lc '.venv/bin/shigoku-ops --json ops intent --intent "このレポートから API だけ Fuzz して" --report workspace/projects/127.0.0.1:8888/reports/haddix_report_20260421_020448.md --target http://127.0.0.1:8888 --execute --main-dry-run'`
  detail: SGK-2026-0325。`docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md:80-83`、`docs/shigoku/reports/2026-07-21_sgk-2026-0325_conversational-ops-chat-direction_work_report.md:31-34`。却下アプローチ: `--approve --main-dry-run` の成功だけで Step 7 完了とみなすこと。これは `Execute it? [y/N]` をバイパスし、confirmation loop の本番導線を一度も証明しないため却下。

- [topic: shigoku-docs | when: `ops_intent` の rollout/stop condition を完了条件に含む plan を close する時] `config/shigoku.yaml` の値だけで `[x]` にするな。operator manual に `feature_flag` / `kill_switch` / `daily_llm_budget` / preview-only への戻し条件を書いてから閉じよ。 verify: `rg -n 'ops_intent\\.feature_flag|ops_intent\\.kill_switch|ops_intent\\.daily_llm_budget|preview-only' docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md`
  detail: SGK-2026-0320。`docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md:107-118`、`docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md:490-493`。却下アプローチ: `config/shigoku.yaml` の `ops_intent.*` 設定値と targeted pytest だけで Step 7 完了とみなすこと。operator が停止手順を文書から引けず、運用導線の完了条件を満たさないため却下。

- [topic: python-tests | when: `src/reporting/attack_review_formatter.py` の完了判定で `attack_review.md` の自己完結性を確認する時] synthetic fixture に `profile=` / `trail=` / `candidates=` を直渡しした pytest だけで閉じるな。実 session JSON を `format_attack_review(session)` に直接通し、5章出力と secret leak 0 を確認せよ。 verify: `.venv/bin/python - <<'PY'\nimport json\nfrom pathlib import Path\nfrom src.reporting.attack_review_formatter import format_attack_review\npaths=[Path('workspace/projects/127.0.0.1:8888/sessions/session_20260415_154233.json'),Path('workspace/projects/127.0.0.1:8888/sessions/session_20260428_044543.json'),Path('workspace/projects/127.0.0.1:8888/sessions/session_20260423_140325.json')]\nrequired=['## 1. 今回わかったこと','## 2. 根拠つきレビュー履歴','## 3. 未確認','## 4. 次にやる候補','## 5. 制約 / 不完全情報']\nleaks=['token=','cookie=','Bearer ','Authorization: ','password']\nfor p in paths:\n    out=format_attack_review(json.loads(p.read_text()))\n    assert all(s in out for s in required) and not any(t.lower() in out.lower() for t in leaks), p\nPY`
  detail: SGK-2026-0293。`src/reporting/attack_review_formatter.py:289-322`、`tests/unit/reporting/test_attack_review_formatter.py:239-344`。最初は kwargs 注入型の unit test だけが緑で、`format_attack_review(session)` 単体では session 内の `target_system_profile` / `attack_review_trail` / `scenario_candidates` を拾わず「概要情報なし」「レビュー履歴なし」になった。却下アプローチ: `profile=` / `trail=` / `candidates=` を毎回明示渡しする synthetic pytest だけで完了扱いすること。実運用の呼び出しは session 1引数が正本なので、実 session 3件での自己完結確認が必要。

- [topic: cli-ops-routing | when: `shigoku-ops report *` に `--session` と `--report` を同時に渡す時] `_resolve_session_from_args()` で `--session` を先に short-circuit するな。`--report` が存在する限り常に `verify_report_session_consistency()` を走らせよ。 verify: `.venv/bin/pytest tests/unit/scripts/test_shigoku_ops_attack_review_cli.py -k consistency_checked_with_both_flags`
  detail: SGK-2026-0324。`scripts/shigoku_ops_cli.py:271-322`。元実装は `if args.session:` → early return で `args.report` を完全無視。偽 report（存在しない source session を指す）と正常 session JSON を同時に渡しても整合性チェックが走らず `status: ok` になった。却下アプローチ: `args.session` と `args.report` の同時指定を禁止すること。運用上両方指定する導線（report から session 解決 + 明示的 session 上書き）があるため、ゲートを飛ばすより常時チェック設計に修正。

- [topic: reporting | when: 新規 report formatter を作成する時] formatter は `session_data` dict 単体で完結させよ。kwargs (`profile=`, `trail=`, `candidates=`) は override 用に留め、未指定時は `session_data` から同名 key を自動読み取りせよ。全 field 未指定時は `build_all_review_fields()` で再構築する fallback も入れること。 verify: `format_<name>(session)` 1引数呼出しで全セクションが埋まる pytest
  detail: SGK-2026-0293/0324。`src/reporting/attack_review_formatter.py:289-322`（修正後）。最初の実装は `format_attack_review(session_data, profile=..., trail=..., candidates=...)` の kwargs 任せで、`format_attack_review(session)` 単体では session 内の `target_system_profile` などを読み取らず全セクションが空になった。却下アプローチ: 常に kwargs 明示渡しを呼び出し側の責務にすること。shigoku-ops CLI や他 formatter との一貫性のため、session_data 自己完結がプロジェクト標準。

- [topic: reporting | when: `target_profile_formatter.py` で persisted `target_system_profile` と旧 `context.target_info` が両方存在する時] persisted profile data を主表示にし旧 data は fallback と明示せよ。セクション末尾への追加表示では新旧が混在し、ユーザーは最初に古い data を読んでしまう。 verify: 新旧食い違う session で新 data が先に出現し旧 data が fallback ラベル付きかを assert する pytest
  detail: SGK-2026-0293。`src/reporting/target_profile_formatter.py:143-268`（修正後）。最初の実装は Section 1 冒頭で `context.target_info.url` を表示した後、末尾に `#### persisted target_system_profile` を補足追加するだけだった。新旧の URL が食い違う session では、レポート先頭に古い URL が先に出て persisted profile は後ろに埋もれた。却下アプローチ: 両方併記して読者に判断させること。確定した persisted profile を正本とし旧 data は不足時のみ参照すべき。

- [topic: codingrules | when: additive field を個別に fallback build する時] 各 field を個別に None 判定し欠落分だけ補完せよ。`if a is None and b is None and c is None:` の all-or-nothing 論理では、1 field だけ保存済みの部分 session で残りが欠落し出力が空になる。 verify: 1 field 保存済み + 残り None の session で全 field が埋まる pytest
  detail: SGK-2026-0324。`src/reporting/attack_review_formatter.py:309-325`（修正後）。元実装は `if profile is None and trail is None and candidates is None` で 3 つ揃わないと `build_all_review_fields()` を呼ばなかった。実 session では `target_system_profile` だけ保存済みで `attack_review_trail` と `scenario_candidates` が None になるケースが頻出し、raw session data に `decision_traces` や `scenario_coverage` が存在しても「レビュー履歴なし」「次回候補なし」のまま出力された。却下アプローチ: 保存時に必ず 3 つ揃えることを呼び出し側の責務にすること。移行期や古い artifact で必ず破綻するため formatter 側で防御すべき。

- [topic: cli-ops-routing | when: `tests/unit/scripts/test_shigoku_ops_*_cli.py` を新規作成する時] `scripts/shigoku_ops_cli.py` の `VALIDATION_SUITES["ops_cli"]` に新テストファイルパスを追記せよ。未登録では標準 `ops_cli` 検証スイートで回らず、新コマンドの回帰が検出されない。 verify: `rg test_shigoku_ops_<新>.py scripts/shigoku_ops_cli.py`
  detail: SGK-2026-0324。`scripts/shigoku_ops_cli.py:83-89`（修正後）。`test_shigoku_ops_attack_review_cli.py` を作成したが `VALIDATION_SUITES["ops_cli"]` に未登録だったため、`ops_cli` スイート実行時に新コマンドのテストが一切走らず、consistency check bypass と per-field fallback の 2 つのバグが個別テスト実行まで見えなかった。

- [topic: codingrules | when: `attack_paths.json` の `Endpoint` ノードを Neo4j ingest する時] `Endpoint` の identity には `display_label` ではなく `extra.url` の raw URL を使え。 verify: `.venv/bin/pytest tests/unit/core/knowledge/test_attack_path_ingestor.py -k endpoint_url_identity -q`
  detail: SGK-2026-0324。`src/core/knowledge/attack_path_ingestor.py:166-175` は `node_type=Endpoint` の identity を `extra["url"]` 優先で解決し、`src/reporting/attack_path_formatter.py:260-272` は短縮表示用 `display_label` と別に raw URL を `extra.url` へ保持する。`tests/unit/core/knowledge/test_attack_path_ingestor.py:102-135` でも `MERGE (n:Endpoint {url: ...})` を固定化した。却下アプローチ: `display_label` や sanitised `node_id` を identity に使うこと。URL 短縮や ID 正規化で別 endpoint が同一視され、Neo4j の `MERGE` が誤るため却下。

- [topic: reporting | when: `shigoku-ops report attack-paths` に `--json-output` / `--cypher-output` / `--neo4j-ingest` を足すか直す時] graph payload を CLI 側で再構築するな。`AttackPathFormatter.build_json_payload()` を正本にして JSON/Cypher/ingest の全経路で共有せよ。 verify: `rg -n "build_json_payload|_ensure_graph_payload" src/reporting/attack_path_formatter.py scripts/shigoku_ops_cli.py`
  detail: SGK-2026-0324。`src/reporting/attack_path_formatter.py:146-158` が payload 正本で、`scripts/shigoku_ops_cli.py:537-587` は `_ensure_graph_payload()` 経由で `--json-output` / `--cypher-output` / `--neo4j-ingest` の全分岐に同じ payload を流す。却下アプローチ: CLI で JSON/Cypher/Neo4j 用のノード・エッジ配列を別々に組み直すこと。`Endpoint` raw URL identity や `evidence_state` の扱いが経路ごとにずれて artifact 契約が壊れるため却下。

- [topic: reporting | when: DVWA low の `Total Tasks` 増減を検知回帰として評価する時] タスク数を検知品質の合否に使わず、同一report/session組のrequired confirmed・candidate reason code・scenario coverageを照合せよ。 verify: `.venv/bin/shigoku-ops --json report expected-detections --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md && python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
  detail: SGK-2026-0385/0393。signal-first task生成・重複統合・evidence quality判定により、DVWA lowの `Total Tasks` は13、57、110と変動したが、検知品質は `expected-detections` とHaddix gateで判断する必要がある。`haddix_gate_20260727_095226.json:92-106` はreport candidate=5に対しraw findings=28を示し、単なるタスク数やraw件数では提出用のconfirmed/candidate状態を表せない。却下アプローチ: 過去の83件や57件へタスク数を戻すこと自体をゴールにすること。実発見の証拠・重複・未証明候補を混同するため却下。

- [topic: reporting | when: consistentなDVWA low reportが `candidate_above_maximum` と候補5件を返す時] 2アカウント・状態変化・機密性の実証を伴わない限り、候補昇格・候補抑制・閾値緩和・広域dedupでFAILをPASSへ変えようとするな。 verify: `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md && python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
  detail: SGK-2026-0393/0394。`haddix_report_20260727_095226.md:1445,1476,1545-1549` の5候補は、`untested_no_second_account`、`authz_impact_not_proven`、`public_data_cross_origin_read`、`state_change_not_verified` で未証明理由が明示されている。API候補の重複は `:1599` で11件を1件へ統合済みであり、残り5件は重複ではない。却下アプローチ: candidate_maxを緩和する、confirmedへ昇格する、またはURLをまたぐ広域dedupを追加すること。不確実性を隠して安全側のgateを壊すため却下。

- [topic: report-session-consistency | when: `docker compose run --rm` の表示時刻とhost側の実行時刻が食い違うDVWA reportを比較する時] 表示時刻だけで実行順や修正反映有無を判定せず、reportから解決したsource sessionで比較せよ。 verify: `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
  detail: SGK-2026-0393のDVWA検証。`haddix_gate_20260727_095226.json:34-36` では `generated_at=18:52:26+09:00` と `report_timestamp=09:52:26` が9時間ずれる一方、`source_session` は同じ実行IDを指す。却下アプローチ: Dockerログの時刻だけで「修正前の実行」「古い結果」と結論づけること。コンテナのタイムゾーン差で誤判定するため却下。

- [topic: reporting | when: フォーム起点の検出器またはHaddix confirmed findingの重複統合を変更して完了判定する時] targeted pytestだけで完了にせず、新しい実行のreport/session組で、フォーム送信値・PoC・confirmed件数を同時に照合せよ。 verify: `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_222834.md && rg -n 'Submit=Submit&ip=127\.0\.0\.1%7Cid|uid=33\(www-data\)|os_command_injection' /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_222834.md`
  detail: SGK-2026-0396。`src/core/agents/swarm/injection/smart_cmd_ssrf.py:425-458` は観測済みformのinputを実送信bodyの正本とし、`src/reporting/haddix_formatter.py:2086-2169` はconfirmedを脆弱性種別・endpoint path・HTTP method・attack parameterで統合する。unit testや短い単発probeだけでは、raw sessionに重複観測が残る一方でreportが1件へ統合されること、また実PoCがフォーム外のtask metadataを混入させず最小入力になったことを同時に判定できない。却下アプローチ: unit testまたはraw finding件数だけで完了とすること。report層の統合結果と実送信の証拠を誤判定するため却下。

- [topic: reporting | when: `initial_release_gate.py` が `quality_baseline_lock.json` の基準線を再利用する時] Securityレベルはsession内の`cookie`/`cookies`だけから抽出して照合し、session全体を文字列検索するな。 verify: `uv run --with pytest pytest -q tests/unit/reporting/test_initial_release_gate.py tests/unit/reporting/test_expected_detection_matrix.py`
  detail: SGK-2026-0400。`src/reporting/initial_release_gate.py:824-872` は共通の`extract_session_security_level()`を使い、現在sessionとbaseline sessionが異なるSecurityレベルなら古い基準線を使わない。却下アプローチ: `json.dumps(session)`全体で`security=`を検索すること。レスポンス本文・証拠・ログに偶然含まれる文字列をSecurity設定と誤認し、`regression_confirmed_drop`の比較先を誤るため却下。
