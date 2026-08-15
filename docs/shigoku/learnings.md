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
updated_at: '2026-08-15'
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

- [topic: lessons | when: Caido Preflight が明示ポートで PASS するのに HTTP History が空の時] Preflight 成功を実通信のプロキシ通過証明に使わず、Caido の待受種別とコンテナ内の `settings.caido.url` / `settings.get_proxy_url()` を別々に照合してから実リクエストを確認せよ。 verify: `ss -ltnp | rg '127\\.0\\.0\\.1:8081.*caido-cli' && rg 'Listening on 127\\.0\\.0\\.1:8081 \\(Proxy, UI\\)' ~/.local/share/caido/logs/logging.*.log && env -u SHIGOKU_SCAN__PROXY SHIGOKU_CAIDO__URL=http://127.0.0.1:8081 docker compose run --rm --no-deps --workdir /app --entrypoint python3 shigoku -c 'from src.core.config.settings import settings; print(settings.caido.url); print(settings.get_proxy_url())'`
  detail: SGK-2026-0409〜0412。`src/core/preflight/caido_check.py` のTCP/GraphQL成功はCaidoの生存と識別だけを証明し、対象HTTP通信の経路は証明しない。実通信側は `src/core/config/settings.py:525-531` の `get_proxy_url()`、`src/core/swarm/worker/recon_workers.py:31,56`、`src/core/intel/caido_crawler.py:59-66` を通るため、API設定とプロキシ解決が分断されるとPreflightだけ成功して直接接続になる。Caidoログの `Listening on 127.0.0.1:8081 (Proxy, UI)` により同一ポートがProxy/UI共用と判明した。却下アプローチ: GraphQL redirect対応だけで直ったとみなす、MasterConductorへのCaido設定伝播だけで直ったとみなす、APIとProxyを別ポートだと推測して `SHIGOKU_SCAN__PROXY` を二重設定する、Workerが `proxy=` を受け取るunit testだけで実経路完了とみなすこと。いずれも実行時のURL解決と実HTTP Historyを証明しないため却下。

- [topic: task-ledger | when: 完了済みplanの最終監査で計画外のhardeningを新規blockerとして指摘する時] 実装開始時の完了条件とNOT in scopeを完了契約として固定し、どの条件にも対応しない指摘は追跡ID付き後続タスクへ移して元タスクを閉じよ。 verify: `rg -n '## 8\. 完了条件|## 9\. NOT in scope' docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md && rg -n 'tracking_task_id: SGK-2026-0422|tracking_task_id: SGK-2026-0423' docs/shigoku/reports/2026-08-01_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_work_report.md`
  detail: SGK-2026-0419。`docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md:100-114` はM0契約、互換性、安全、保存回復を完了条件とし、report表示・hidden holdoutを対象外にした。一方、完了後の監査でproof正規化や本番鍵運用まで同タスクのblockerへ繰り返し追加され、完了判定が移動し続けた。却下アプローチ: 将来enforce段階のhardeningを見つけるたびにSGK-2026-0419を再度ACTIVEへ戻すこと。現在の攻撃通信を有効化しておらずM0成果を無効にしないため却下し、`docs/shigoku/reports/2026-08-01_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_work_report.md:117-132` からSGK-2026-0422/0423へ分離追跡した。

- [topic: codingrules | when: `vdp_contract.py` のconfirmed `validation_proof`生成またはEvidence Validator署名境界を変更する時] 区切り文字連結を使わずversion付きcanonical構造へstatus・reason codes・EvidenceRecordのcontent hashを結合し、署名機能をEvidence Validator専用境界へ分離せよ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_real_integration.py -k 'canonical_payload_collision or proof_rejects_evidence_content_tamper or non_validator_signer_rejected' -q`
  detail: SGK-2026-0419-D01 / SGK-2026-0422。`src/core/models/vdp_contract.py:88-113` は `verdict_id|hypothesis_id|comma-joined evidence_ids|validator_version` をHMAC化するため、ID内の `|` / `,` による直列化衝突を区別できず、EvidenceRecord本文・raw hash・reason codesもproofへ結合していない。さらに`src/core/models/vdp_contract.py:1100-1115`のunderscore付きfactoryとmodule外参照scanは誤用防止にはなるが、同一process内の暗号学的な署名境界にはならない。却下アプローチ: private命名、frozen dataclass、caller名検査、任意validator名だけでconfirmedの正当性を保証すること。Python同一processからは迂回可能で証拠内容改変も検出できないため却下し、canonical payload・EvidenceRecord内容結合・署名provider分離を`docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md:98-105,138-157`へ実装条件として移した。

- [topic: lessons | when: `graphify update .` で新規または未追跡のPythonファイルを索引へ追加する時] exit 0や処理件数だけで更新済みと判断せず、新規symbolが`graphify-out/graph.json`に存在しartifactの更新時刻も進んだことを確認せよ。 verify: `rg -n 'build_unavailable_source_inventory|TestRealDispatchConnection' graphify-out/graph.json && stat -c '%y %n' graphify-out/graph.json graphify-out/GRAPH_REPORT.md`
  detail: SGK-2026-0420。`src/core/engine/vdp_hypothesis_generator.py:575`と`tests/core/engine/test_master_conductor_vdp_hypothesis.py:632`を追加した後、`graphify update .`は1993/1993 files・exit 0と報告されたが、上記symbolの`rg`は0件で、`graphify-out/graph.json`と`GRAPH_REPORT.md`の更新時刻も2026-07-31のままだった。却下アプローチ: graphifyの処理件数とexit codeだけを根拠にN-02を解消済みと判定すること。新規・未追跡ファイルが索引へ反映されないまま成功終了する経路を見落とすため却下。


- [topic: codingrules | when: recon `signal_bundle` の `auth_context` を仮説生成器へ渡す時] Authorization/Cookie/tokenの生値は生成器入力境界で完全に破棄し、`has_auth_header` / `has_cookie` / `has_second_actor_evidence` 等の安全な真偽値だけを渡せ。保存時のredactは二重防御であり入力境界の破棄に代わらない。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_observation_adapter.py -k 'secret or auth_context' -q`
  detail: SGK-2026-0420（監査I-01）。`src/recon/pipeline.py:3205-3212` はCaido由来の`auth_context`へAuthorization/Cookieの値をそのまま入れ、`src/core/engine/vdp_observation_adapter.py` の`_split_auth_flags`/`_split_actor_evidence`で鍵名だけを判定して値を捨てる。却下アプローチ: 保存時`redact_secrets_deep`だけで足りるとしたこと。値はObservation→HypothesisRecord→session payloadへ残り、監査の実測で`URL_TOKEN_SECRET_IN_SESSION_PAYLOAD=True`になったため却下。

- [topic: lessons | when: `signal_id` や `created_at` を含むrecon観測から決定論的IDを生成する時] UUID・現在時刻・乱数を正規化データから除外し、canonical JSONのバイト列をSHA-256へ渡してID・dedup key・並び順を決めよ。signal_id/created_atは別フィールドのprovenanceとしてのみ保持せよ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_observation_adapter.py -k 'uuid_time_only_change_same_id or deterministic' -q`
  detail: SGK-2026-0420（監査I-02）。`src/recon/pipeline.py:3265` の`signal_id`は`run_id`（実行ごとのUUID）を含み、同:3282 の`created_at`は現在時刻を持つ。`src/core/engine/vdp_observation_adapter.py` の`_canonical_observation_payload`から両者を除外した。却下アプローチ: signal_idをそのまま観測IDの素材にすること。実行ごとにIDが変わり、同一入力なのに仮説集合が一致しないため却下。

- [topic: codingrules | when: `normalize_url()` でURLから秘密値を除去する時] userinfo（user:pass@host）は拒否し、`token-*`/`secret-*`/`session-*`等の秘密プレフィックス付きパス要素とUUID・長hex・長base64urlは固定の`:opaque`へ変換し、例外メッセージへraw URLを含めるな。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_observation_adapter.py -k 'userinfo or opaque or three_stage' -q`
  detail: SGK-2026-0420（監査I-01）。`src/core/engine/vdp_observation_adapter.py` の`normalize_url`/`_sanitize_path_segments`で実装。却下アプローチ: 例外文に`{raw!r}`を残すこと。`adapt_signal_bundle`のskip detailへURLごと秘密値が保存されartifactに残るため却下。3段階（Observation→HypothesisRecord→実session payload）で同一秘密文字列が存在しないことを確認する。

- [topic: lessons | when: MasterConductorへadditive hook（仮説生成等）を既存attack task生成の直前に挿入する時] hook全体を例外境界で包み、失敗時はVDP状態をinactiveへ戻してdegraded reasonをdecision traceへ保存してから既存attack task生成へ継続せよ。非off実行では成功・空入力・全拒否・例外の全経路でVDP状態を置換せよ。 verify: `.venv/bin/pytest tests/core/engine/test_master_conductor_vdp_hypothesis.py -k 'replaces_state or recon_dispatch' -q`
  detail: SGK-2026-0420（監査I-03）。`src/core/engine/master_conductor.py:9850`のhook呼出しは`try/except Exception`で保護し、非off実行の開始時に`vdp_active=False`・各recordリストをクリアしてから処理する。実測では成功→空入力を連続実行すると前回のhypotheses/verdictsが残り`vdp_active=False`なのにM0がFAILした。却下アプローチ: 例外をそのまま伝播させること。既存attack task生成が停止し「generator失敗が既存実行を壊す」ため却下。

- [topic: lessons | when: 入力順にdedup/diversity上限を適用してから仮説をsortする時] 全候補を先に構築・検証し、canonical key（dedup_key, hypothesis_id）でsortした後にdedup/diversity上限を適用し、最後にpriority sortせよ。入力順で採用仮説が変わらない。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_hypothesis_generator.py -k 'reverse_order or diversity or dedup' -q`
  detail: SGK-2026-0420（監査I-02）。`src/core/engine/vdp_hypothesis_generator.py`の`generate_hypotheses`はPhase A（構築）→Phase B（canonical sort）→Phase C（dedup/diversity）→Phase D（priority sort）の順。却下アプローチ: 入力順にdiversity上限を適用してからsortすること。同じ5観測を逆順にすると採用される3件のIDが異なり、`SAME_COLLECTION=False`になったため却下。

- [topic: lessons | when: 仮説の挙動（preconditions等）に影響する観測フィールドをObservationへ追加する時] そのフィールドもcanonical observation payloadへ必ず含めよ。含めないと同一正規化入力でも入力順で先に来た観測が採用され、preconditionsとpriority traceが変化する。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_hypothesis_generator.py -k 'actor_evidence_differs_observation_id or reverse_order' -q`
  detail: SGK-2026-0420（監査I-02）。`src/core/engine/vdp_observation_adapter.py`の`_canonical_observation_payload`へ`has_second_actor_evidence`/`has_admin_evidence`を追加し、`infer_actors`がauthB/adminを決定論的に展開する。却下アプローチ: 正規化対象をURL/method等だけに限定すること。同じobservation_idの観測がactor証拠の違いで採用され、`AUTHZ_PRECONDITIONS={}`と不足記録が消えたため却下。

- [topic: python-tests | when: 秘密値不在をテストする時] Observation段階だけでなく、HypothesisRecord（`build_hypothesis().to_dict()`）と実session payload（`inject_vdp_section_to_session_payload`経由）の3段階すべてで同じ秘密文字列が存在しないことを検証せよ。最初の段階だけでは監査の「3段階で不在」要求を満たさない。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_observation_adapter.py -k 'three_stage' -q`
  detail: SGK-2026-0420（監査I-01）。`tests/unit/engine/test_vdp_observation_adapter.py`の`TestThreeStageSecretAbsence._run_3stage`はObservation→hypothesis→session payloadを一つのhelperで通す。前回報告ではObservation段階のテストしかなく、監査の実測で`URL_TOKEN_SECRET_IN_SESSION_PAYLOAD=True`が検出された。

- [topic: python-tests | when: MasterConductorのVDP hookを「実経路」でテストする時] private helper（`_generate_vdp_hypotheses`）の直呼び出しだけでなく、最小のrecon_master taskを`await mc._dispatch(task)`へ渡し、recon実行結果（`ReconPipeline.run`）だけをmockして本番hookはspyで1回呼び出しを確認し、その後`async_save_session()`→M0 gateまで通せ。task queue・finding・network・LLMの前後不変も同一テストで検証せよ。 verify: `.venv/bin/pytest tests/core/engine/test_master_conductor_vdp_hypothesis.py -k 'recon_dispatch' -q`
  detail: SGK-2026-0420（監査I-08）。`tests/core/engine/test_master_conductor_vdp_hypothesis.py`の`TestRealDispatchConnection`は`Task(agent_type='recon_master')`を`_dispatch`へ渡し、`phase_gate.can_create_task=(False,'test-locked')`で既存attack task生成を空に保ちつつ実hookを通過させる。AST確認で`_dispatch`/`run`呼出しが無いテストは「実経路」として認められなかった。

- [topic: lessons | when: 仮説0件（空signal bundle・全拒否・generator例外）のdegraded状態を記録する時] M0 gateは`vdp_active=False`+データ（run_health含む）を拒否するため、degraded理由と観測源のunavailable記録はVDP sectionでなく既存のdecision trace（`_shadow_decisions`）へ保存し、早期return経路でも必ず記録せよ。 verify: `.venv/bin/pytest tests/core/engine/test_master_conductor_vdp_hypothesis.py -k 'unavailable' -q && .venv/bin/pytest tests/unit/engine/test_vdp_real_integration.py -k 'Inactive' -q`
  detail: SGK-2026-0420（監査I-03b）。`src/core/engine/vdp_m0_gate.py:162-174`はinactive+dataをrejectする。`src/core/engine/master_conductor.py`の`_generate_vdp_hypotheses`はno_signal_bundle/no_observationsの早期return前に`_record_vdp_observation_status()`を呼び、`build_unavailable_source_inventory()`（`src/core/engine/vdp_hypothesis_generator.py`）の7観測源・理由`not_wired_in_0420`・追跡`SGK-2026-0421`を記録する。実測で空signal bundle時に`SOURCE_TRACE_COUNT=0`だったため追加した。

- [topic: codingrules | when: VDP仮説生成でreason code・action class・stop conditionを設定する時] private定数（`_VALID_ACTION_CLASSES`等）をimportせず、`recipe_contracts.py`の公開vocabulary（`VDP_ACTION_CLASSES`/`VDP_REASON_CODES`/`VDP_STOP_CONDITIONS`等）で検証し、生成する値も公開vocabulary内のものだけにせよ。新規reason code（`generated_candidate`等）は公開vocabularyへadditive追加する。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_hypothesis_generator.py -k 'vocabulary' tests/unit/engine/test_recipe_contracts.py -q`
  detail: SGK-2026-0420（監査I-07）。`src/core/engine/recipe_contracts.py:190-245`に公開vocabularyを追加し、`src/core/engine/vdp_hypothesis_generator.py`の`build_shadow_proposals`は`generated_candidate`/action/stopをvocabulary内か検証してからrecordを生成する。却下アプローチ: private `_VALID_*`を直接importすること。監査で`generated_candidate`が`VDP_REASON_CODES`に無いことが検出されたため却下。

- [topic: shigoku-docs | when: plan/subtask_planを`done/`へ移動する時] 移動先パスのrelated_docs一括更新に加え、移動したファイル自身のfront matter `status` も `active`→`done`へ更新せよ。 `validate_shigoku_docs.py` は実配置とfront matter statusの不一致を `REGISTRY_ISSUE` として検出する。 verify: `python3 scripts/validate_shigoku_docs.py | rg 'status_mismatch|REGISTRY_ISSUES' && rg -n 'status: done' docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md`
  detail: SGK-2026-0420文書クローズ。`docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md`を移動直後はfront matterが`status: active`のままで、`validate_shigoku_docs.py`が`REGISTRY_ISSUE task_423_status_mismatch`を返した。front matterを`done`へ更新し、台帳（task_registry.yaml / task_ledger.md / task_ledger.csv）のstatus・primary_doc・related_docsと揃えて0エラーにした。

- [topic: lessons | when: `vdp_observation_adapter.py`でform/crawler等の観測源を既存artifactから接続する時] 同名のharvester/crawlerを受動producerと見なさず、VDP hook実行時点ですでに存在する`_signal_bundle`までproducerとpayload shapeを遡り、新規通信が必要なsourceは理由付き`unavailable`のままにせよ。 verify: `rg -n '_generate_vdp_hypotheses|_create_attack_tasks_from_recon|location.*form|AsyncNetworkClient|urllib.request.urlopen' src/core/engine/master_conductor.py src/recon/pipeline.py src/core/agents/swarm/injection/form_harvester.py src/core/intel/cartographer.py`
  detail: SGK-2026-0421。`src/core/engine/master_conductor.py:9854-9863`ではVDP hookがattack task生成より先に走るため、後段のtask `_context`/`forms_by_url`は取得元にできない。formの受動artifactは`src/recon/pipeline.py:3247`の`_endpoint_signals[*].params[*].location == "form"`だった。却下アプローチ: `src/core/agents/swarm/injection/form_harvester.py:75-101`や`src/core/intel/cartographer.py:64-106`を名前だけでproducer候補にすること。前者は新しい`AsyncNetworkClient`によるGETに加えて`urllib` fallbackも行い、後者もcrawl通信を開始するため、既存artifact変換だけを許す0421の境界に反する。

- [topic: lessons | when: task_queue の mutation 系メソッド（add/add_batch 等）の main-thread 強制や存在を確認する時] docstring 内に書かれた assert は実行されない。AST で実 assert ノード数を数えてから trust し、実行コードへ移動せよ。 verify: `.venv/bin/python -c "import ast;print(len([n for n in ast.walk(ast.parse(open('src/core/engine/task_queue.py').read())) if isinstance(n, ast.Assert)]))"`（実効 assert は10件）
  detail: SGK-2026-0421（C23, in_scope_blocker）。`src/core/engine/task_queue.py` の `add`(L382-385)/`add_batch` 等6メソッドは「PCR-P1: main thread」assert を docstring 内に持ち、AST assert_nodes に現れず実行されていなかった（実効 assert は remove_by_id/remove_by_ids/remove_matching/prune_by_decisions の4つのみ）。目視では「assert がある」と誤認するため AST カウントが必須。修正は assert を docstring 外へ移動し、非main thread からの mutation を AssertionError で拒否するテスト（tests/unit/engine/test_task_queue_main_thread.py）を追加した。

- [topic: lessons | when: MasterConductor に `_vdp_*` のような getter メソッドと同名のキャッシュ属性を追加する時] キャッシュ属性名はメソッド名と別名にし、`hasattr(self, '<メソッド名>')` ガードが常に真にならないようにせよ。 verify: `.venv/bin/pytest tests/core/engine/test_master_conductor_vdp_follow_up.py -q`
  detail: SGK-2026-0421。`master_conductor.py` の `_vdp_capability_matrix()` メソッドが同名属性 `self._vdp_capability_matrix` を hasattr で判定したため常に真になり、メソッド自身（function）が返って `'function' object has no attribute 'get_level'` で実経路テストが落ちた。既存の「hasattr ガード」レッスンは満たしていても名前衝突で防げない。`_vdp_matrix` 等の別名キャッシュへ変更し解決。同型の罠は `_vdp_budget`/`_vdp_writer`/`_vdp_idem`/`_vdp_state_guard` にもあった。

- [topic: lessons | when: vdp_scope_validator / revalidate_scope_for_request の scope 判定結果を通信ゲートとして使う時] グローバル singleton の scope parser を信頼するな。scope 未設定・空 in_scope_domains・「No scope defined」は既存 guard が ALLOWED を返すため、明示 scope snapshot を専用 EthicsGuard インスタンスへ渡す純粋判定で fail-closed にせよ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_scope_failclosed.py -q`
  detail: SGK-2026-0421（C1）。`src/core/security/ethics_guard.py:185-186` は `self.scope` が None のとき `ALLOWED, "No scope defined"` を返し、L222 は空 `in_scope_domains` のとき全URLをALLOWEDにする。旧 `vdp_scope_validator.py` は `scope_definition=None` で singleton parser に委譲し、さらに `parser._guard.scope` を一時変更する並行不安全な実装だった。専用 `EthicsGuard(scope=deepcopy)` の純粋判定へ書換え、scope不明は `scope_revalidation_blocked` へ写像した。二つの異なる scope を並行評価して結果が交差しない反証テスト（TestScopeParallelIsolation）も追加。

- [topic: lessons | when: NextActionRecord から hypothesis_id や asset（URL）を引こうとする時] NextActionRecord は verdict_id しか持たない。hypothesis は verdicts の hypothesis_id 経由で解決せよ。直接 `na.get('hypothesis_id')` は常に空になる。 verify: `rg -n "class NextActionRecord" -A 12 src/core/models/vdp_contract.py && .venv/bin/pytest tests/core/engine/test_master_conductor_vdp_follow_up.py -q`
  detail: SGK-2026-0421。`src/core/models/vdp_contract.py:1271` のフィールドは next_action_id/verdict_id/evidence_gap/required_preconditions/action_class/risk_class/expected_information_gain/stop_condition で hypothesis_id が無い（ID系列は verdict_id -> next_action_id）。0421 の `_queue_vdp_follow_ups` が `na.get('hypothesis_id')` を使い、URL が空の follow-up spec が生成されて dispatch が scope:out_of_scope で止まった。`verdict_hypothesis = {v['verdict_id']: v['hypothesis_id']}` マップ経由に変更して解決。

- [topic: codingrules | when: vdp_contract の `_VALID_ATTEMPT_STATES` / `_VALID_EVIDENCE_TYPES` 等の状態語彙を拡張する時] 語彙拡張は additive にし、`validate_attempt_record` / `validate_evidence_record` 経由で M0 gate の session 保存検証が通ることをテストで確認せよ。新状態を入れるだけでは M0 が保存を拒否する。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_real_integration.py tests/core/engine/test_master_conductor_vdp_follow_up.py -q`
  detail: SGK-2026-0421（C7/C21）。`src/core/models/vdp_contract.py` の `_VALID_ATTEMPT_STATES={"attempted","failed","retried"}` に `queued/sending/sent/evidence_saved` を、`_VALID_EVIDENCE_TYPES` に `out_of_band_callback` を additive 追加した。`vdp_m0_gate.py` の `_check_schema` は validate_* 経由で語彙を検査するため、拡張なしでは「queue済み/送信済み/証拠保存済み」の区別（制約I）を保存できなかった。既存語彙の削除・改名は旧 session 互換を壊すため禁止。

- [topic: codingrules | when: レスポンス body の excerpt を redact して EvidenceRecord へ保存する時] 文字列への正規表現 redact だけでは JSON キーの secret（`session_token` 等）が漏れる。JSON はパースして key ベース再帰 redact し、キー集合は additive に拡張せよ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_follow_up_executor.py -k 'excerpt or Secrets' -q`
  detail: SGK-2026-0421。`src/core/models/vdp_contract.py` の `_SECRET_KEY_PATTERNS_LOWER` に `session_token` が無く（`session`/`session_id` は resume 用に意図的除外済み）、regex `session(?:id)?[=:]` も `"session_token":` に不適合で、body `{"session_token": "abc123def456"}` が excerpt に平文で残った。`vdp_follow_up_executor.py` の `_redact_body_text` で JSON パース→`redact_secrets_deep`→dumps に変更し、キー集合へ `session_token` を追加。却下アプローチ: 文字列への regex 適用を増やすこと。JSON key を網羅できず、key ベース置換（`[REDACTED]`）とも表示が不統一になるため却下。

- [topic: python-tests | when: 新規ファイルの whitespace 検査を `git diff --no-index --check /dev/null <file>` で行う時] exit code は差分の有無で1になるため whitespace 判定に使うな。stdout の `trailing whitespace` / `space before tab` 行の有無で判定せよ。 verify: `git diff --no-index --check /dev/null <new-file> | rg 'trailing whitespace|space before tab'`
  detail: SGK-2026-0421。`git diff --no-index --check` は `/dev/null` とファイルの差分が存在する限り whitespace エラーが無くても exit 1 を返すため、13新規ファイルすべてが「CHECK FAILED」に見えた。stdout の whitespace メッセージ行のみを rg で判定する方式へ変更し、全ファイル CLEAN と確認した。AGENTS.md はこのコマンドを新規ファイル検査に指定しているが、exit code 解釈はこの罠を踏む。

- [topic: python-tests | when: 広域テストの失敗が自分の変更起因か既存環境依存かを証明する時] 自分の変更した tracked ファイルのみを一時 stash して同一テスト群を流し、失敗集合を diff せよ。stash は新規（untracked）テストを含まないため、変更前実行に出る自分の新規テストの失敗は除外して比較せよ。 verify: `git stash push -m baseline -- <自分の変更ファイル> && pytest <対象> -q && git stash pop`
  detail: SGK-2026-0421。`tests/core/engine` の30失敗（LLM API key 認証・Caido 未達・bundle 欠如・既存スキーマ不一致）が変更起因でないことを、0421差分の tracked ファイル（src 12件）だけを stash した baseline 実行で同一30件が再現することにより証明した。stash 実行では自分の新規テスト（untracked）が旧ソース相手に失敗するため、失敗リストから新規テストを除外して diff しないと誤って「変更起因」と判定する。stash pop で確実に復元すること。

- [topic: codingrules | when: snip 経由の rg / ファイル読取出力でパス・識別子・行番号を確定する時] snip ラッパーは特定トークン（例: `forms_by_url`）を別語へ置換・欠落させることがある。ファイルパス・シンボル名・行番号の確定は snip なしの生 rg で再確認せよ。 verify: 生 `rg -n 'location' recon/pipeline.py`（snip なし）で `"form"` の生成行を確認
  detail: SGK-2026-0421。snip 経由の rg 出力で `forms_by_url` が `ln` に化け、producer の場所を誤読した（`recon/pipeline.py` はリポジトリルート配下であり `src/core/recon/` ではない）。監査で「form は task _context/forms_by_url から取得」という誤った経路を一度提案し、ユーザー指摘と生 rg で `_endpoint_signals[*].params[*].location == "form"`（`src/recon/pipeline.py:3247`）へ修正した。既存の「snip で `;` を使うな」とは別種の罠。

- [topic: lessons | when: VdpExecutionBudget.consume / VdpAdmissionGate.evaluate の budget 消費を実装・検証する時] consume は全次元のチェック後に一括コミットする原子的2段階（peek→commit）にし、admission は budget を最後に消費せよ。後段拒否で前段の per-key カウントが残る部分消費と、capability 拒否時の token 焼却を防ぐ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_hitl_and_admission.py -k 'Budget or Idempotency' tests/unit/engine/test_vdp_budget.py -q`
  detail: SGK-2026-0421（C3/C5, 制約G）。旧 `vdp_budget.py` の `consume` は asset→actor→hypothesis を順次加算し、後段（hypothesis burst）で拒否されると前段分が消費済みになる。旧 `vdp_admission.py` は capability 判定より先に budget を消費し、PROHIBITED 拒否でも request token を焼いた。`_check_limits`（非破壊）→ 全通過後の `_commit_key_budget` へ分離し、gate は budget peek → capability/HITL → consume の順に変更した。0419 の「budget 枯渇が capability より優先」reason コードは peek で保持したまま「拒否時に消費0」を両立した。

- [topic: lessons | when: VDP follow-up executor が EvidenceRecord の execution_result を記録する時] 応答受信・http_status・request_count など中立的な事実だけを保存し、`success_condition_met` のような blanket marker を絶対に設定するな。成功条件の証明は構造化 marker（`_REQUIREMENT_MARKERS` の gap token→marker 対応）で validator が判定し、全 required_evidence を明示満足するまで candidate を維持せよ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_evidence_validator.py tests/core/engine/test_master_conductor_vdp_evidence_validator.py -q`
  detail: SGK-2026-0422（監査I-07 round 3, blocker 1）。初回実装は `vdp_follow_up_executor.py:501` が全 EvidenceRecord へ `execution_result={"success_condition_met": "true"}` を無条件設定し、validator がその値を信用したため、通常の 200 OK 応答だけで confirmed へ誤昇格した（`ordinary_http_response_marker {'success_condition_met': 'true'}` → `confirmed ['evidence_contract_satisfied']`）。却下アプローチ: marker を validator 側で継続利用すること。executor が「応答受信」を「脆弱性の証明」と誤って主張できる構造そのものが原因のため、marker 生成側を排除した。修正後は `vdp_evidence_validator.py:58` の `_REQUIREMENT_MARKERS`（`authz_impact_not_proven`→`authz_impact_proven` 等9組）で token ごとに専用 marker を要求し、`_has_structured_success_marker`（L338）は marker 語彙外の blanket 値を無視する。

- [topic: report-session-consistency | when: main.py のレポート生成経路（haddix / haddix-ja-en）で evaluate_vdp_gate を呼ぶ時] `consistency_status` をハードコードするな。生成済みレポートへ `verify_report_session_consistency()` を実行し、実測した status / reason_codes を real VDP gate へ渡せ。index 欠損・不一致レポートは main 経路でも No-Go になる。 verify: `.venv/bin/pytest tests/unit/main/test_main_report_haddix_vdp_gate.py -q`
  detail: SGK-2026-0422（監査I-07 round 3, blocker 2）。初回実装は `main.py:3489`（haddix）と `main.py:3837`（ja-en）が `consistency_status="consistent"` 固定で real gate へ渡し、formatter が index を落としても gate は pass してしまった。check_initial_release_gate.py 単体の修正だけでは通常レポート生成経路の不一致を検出できない。修正後は `main.py:3497` / `main.py:3864` で生成済み output_path / tmp_path を対象に consistency を実測し、実測値を `evaluate_vdp_gate("real", ..., consistency_status=<実測>, consistency_reason_codes=<実測>)` へ渡す。index 埋め込みを無効化した統合テストで decision=no_go / `report_session_inconsistent` を確認した。

- [topic: reporting | when: separated report の manifest 検証を実装・強化する時] 「manifest に記録されたファイルだけ」を検証する方式では、記録から2ファイルを削除すると残り1ファイルで検証が通る。キー集合が `{submission, internal_md, internal_json}` と完全一致し、manifest 内 path を信用せず group stem から期待 path を計算して一致し、3ファイルすべての存在と hash が一致するまで正式成果物として扱うな。 verify: `.venv/bin/pytest tests/unit/reporting/test_vdp_report_projection.py tests/unit/reporting/test_vdp_separated_report_manifest.py -q`
  detail: SGK-2026-0422（監査I-07 round 4, D10）。`verify_separated_group`（`vdp_report_projection.py:367`）は当初 `recorded` のキーが1件以上あれば有効とし、`files` も記録済み項目だけから生成したため、manifest から2ファイル分の記録を削除した trimmed manifest（`{'submission': ...}` のみ）が `separated_manifest_verified` を通り、実 CLI も exit 3 で拒否せず次段へ進んだ。修正後は `separated_manifest_keys_invalid`（キー集合完全一致必須）、`separated_manifest_path_mismatch:<key>`（stem 由来期待 path 照合）、3ファイル全検証を必須化した。汎用 `verify_manifest` は単一ファイル用途を壊さないよう3件制約を入れず、`verify_separated_group` 側へ置いた。

- [topic: python-tests | when: main.main() 経由の canonical VDP レポート生成テストを書く時] session に `scenario_coverage`（カタログ全シナリオ分）を明示付与しないと、report builder が計算する coverage と session 側の coverage が食い違い `scenario_missing_set_mismatch` で consistency が inconsistent になる。canonical session fixture には report builder と一致する scenario_coverage を載せよ。 verify: `.venv/bin/pytest tests/unit/main/test_main_report_haddix_vdp_gate.py -q`
  detail: SGK-2026-0422。`test_main_haddix_canonical_index_present_is_consistent` が index を正しく埋め込んでも `scenario_missing_set_mismatch`（legacy 比較）で inconsistent になった。`_base_session` には scenario_coverage が無いため、report 側は `_build_scenario_coverage_for_report` がカタログ12件を missing として埋め込む一方、session 側は missing 0件と解釈した。`_write_canonical_session`（`tests/unit/main/test_main_report_haddix_vdp_gate.py:35`）で `covered_count=0 / required_count=12 / missing_scenarios=<カタログID>` を session へ付与して一致させた。VDP index だけ直しても legacy 比較で落ちる点に注意。

- [topic: lessons | when: コード変更後に graphify update . を完了証拠として報告する時] exit 0 だけで完了扱いにするな。graph.json と GRAPH_REPORT.md の更新時刻が実際に進んだことと、追加した主要 symbol が graph.json に登録されたことを確認せよ。 verify: `ls -la --time-style=full-iso graphify-out/graph.json graphify-out/GRAPH_REPORT.md && rg -c 'VdpEvidenceValidator|verify_separated_group' graphify-out/graph.json`
  detail: SGK-2026-0422 最終監査。ユーザー指示「graphify の exit 0 だけで完了扱いにしてはいけません」に従い、`graph.json mtime 2026-08-04 08:53:44` / `GRAPH_REPORT.md 08:53:54`（更新時刻が進捗）と、`VdpEvidenceValidator`・`Ed25519EvidenceSigner`・`verify_separated_group`・`extract_vdp_canonical`・`evaluate_vdp_gate`・`verify_report_session_consistency`・`VdpCanonicalSummary`・`vdp_canonical_index_v1` の8 symbol が graph.json に登録済みであることを python スクリプトで確認した。graph が未更新（キャッシュ・失敗）でも exit 0 を返し得るため、時刻と symbol 登録の実確認が必須。

- [topic: report-session-consistency | when: proof付きconfirmedを含むsession/reportに対して verify_report_session_consistency.py や `shigoku-ops vdp gate` をCLIで実行する時] `--vdp-key-registry <registry.json>` を渡せ。providerなしではconfirmedが未検証扱いになり、provider付きで生成したreportとCLI側再抽出でverdict件数が食い違い、inconsistent・gate blockedになる。 verify: `.venv/bin/python scripts/verify_report_session_consistency.py --report <r> --session <s> --vdp-key-registry <registry.json>`（status=consistent を確認）
  detail: SGK-2026-0423最終クローズ。extract_vdp_canonical は public_key_provider なしでは proof を検証できず confirmed を candidate 相当へ落とすため、provider付きレポート（confirmed 1）とCLI再抽出（confirmed 0）の間で `vdp_verdict_count_mismatch:confirmed` / `vdp_summary_digest_mismatch` が生じ、real gate は blocked になった。`scripts/verify_report_session_consistency.py:36` と `scripts/shigoku_ops_cli.py`（_run_vdp_gate）へ `--vdp-key-registry` を additive 追加して解消。registry は `{"keys": {key_id: {"public_key": hex}}}` の公開データのみを直接 parse（engine import なし）。provider なしは fail-closed（confirmed を信用しない）が「件数不一致」として現れる点が誤判定の罠。

- [topic: reporting | when: holdout評価の凍結閾値artifact（ThresholdMetric）を定義する時] 各指標の `direction` を明示し、recall は minimum・false_promotion_rate/untested_rate は maximum にせよ。自明境界（0.0/1.0）や方向誤りは全runがPASSする偽装合格になり、「成績が良く見えるまで閾値を調整する」運用と区別できない。 verify: `.venv/bin/pytest tests/unit/reporting/test_vdp_holdout_runner.py -k direction -q`
  detail: SGK-2026-0423（監査）。初回のholdout閾値構成が `recall: direction=maximum, value=1.0`（recall=0でも合格）と全指標0.0/1.0の自明境界で outcome=pass を作り、「閾値調整による偽装pass」と指摘された。`src/reporting/vdp_dataset.py` の ThresholdMetric に `direction`（Literal minimum/maximum、default minimum）を追加し、runner は方向ベースで met 判定する（legacy artifact は fp/untested を maximum 扱い）。却下アプローチ: 指標名prefixで方向を特殊扱いすること（fp専用分岐）。direction フィールド追加とし、名前ベース分岐は legacy fallback のみに限定した。

- [topic: lessons | when: 進級gate（M4等）がholdout結果をGo証拠として参照する時] 現在のthresholds fingerprint ≒ holdout結果の `threshold_fingerprint` 一致、判断記録の eval_version・artifact_hash 照合、最新エントリ（recorded_at順）のみ採用（古いGoの後にHoldが来たら不採用）を全て要求せよ。eval_version比較だけでは評価後の閾値変更を防げない。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_rollout.py -k M4GoEvidenceBinding -q`
  detail: SGK-2026-0423（監査round 3/4）。`vdp_rollout.py` の `_m4_go_evidence_ready()` は当初 eval_version 一致のみで、holdout評価後に同一 eval_version の閾値を変更しても effective_stage=m4・cap_reasons=[] になった（実測）。`m4_threshold_fingerprint_mismatch` / `m4_decision_eval_version_mismatch` / `m4_decision_artifact_hash_mismatch` を追加し、判断記録は recorded_at 最新のみ採用（`m4_decision_record_not_go`）とした。

- [topic: lessons | when: 状態変更attemptのWAL遷移（StateChangeJournal）を実装・検証する時] network_error は応答喪失の曖昧性があるため in_flight のまま Hold（state_change_outcome_unknown）にし、mark_failed は通信開始前に確定した拒否（blocked/manual_review）だけに限定せよ。statusやreason文字列ベースの遷移は「送信済み+応答喪失」を not_sent 化して再送を招く。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_failure_drill.py -k drill_18 -q`
  detail: SGK-2026-0423（監査round 4/5）。`master_conductor.py` の `_journal_transition_after_dispatch` が当初 `reason=="network_error"` を mark_failed 対象とし、fake transport で「通信先は変更を実行したが応答だけ喪失」を再現すると remote_applied=1・wal=not_sent・新プロセスが再送した。`FollowUpExecutionResult.state_change_sent`（mark_sent呼出=送信完了の事実）を追加し、送信事実ベースの遷移へ変更。drill 18 で「送信完了→応答喪失→新MC再開→通信0件」を検証した。

- [topic: lessons | when: 隔離M3a環境でconfirmedを期待する時] cross-account実レスポンス比較（A/B認証GETでowner帰属+敏感フィールド共有を実観測）以外からconfirmedを作るな。fingerprint/timing marker単独での昇格は禁止で、全capabilityのrequired_evidenceが観測不能トークンを含みfingerprint-only分岐は到達不能な構造を理解して設計せよ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_cross_account.py -q`
  detail: SGK-2026-0423最終クローズ（P-1）。`vdp_hypothesis_generator.py` の `_REQUIRED_EVIDENCE_BY_CAPABILITY`（L145-155）は全capabilityがauthz/semantic/readback等の観測不能トークンを含み、fingerprint-onlyのdefault分岐（L521）は `classify_capability`（L196-220）が常にmapped capabilityを返すため到達不能。`vdp_follow_up_executor.py` に `account_credentials` / `_COMPARISON_GAPS` / `_send_with_auth` を追加し、granted比較のみ `authz_impact_proven`+`semantic_diff_observed`、denied/public/比較不能はmarkerなしとした。却下アプローチ: fingerprint/timing markerのみでconfirmed可能にすること（「fingerprintだけでconfirmed」は監査で明示禁止）。

- [topic: lessons | when: holdout評価用のDocker隔離環境を構築する時] runtimeコンテナへrepo全体やlabel pathをmountするな（src/config/.venv/uv-python/driver/private out/logsのみ）。holdoutのopaque URLは起動時ランダム生成し、runtimeドライバはroute非依存（source scanで検証）、secretsはrepo外のmktemp private dirに置き、`docker exec`でENOENTを実証せよ。repo全体mount+URL分岐のfixtureはholdoutとして合わせ込みになる。 verify: `docker exec <runtime> sh -c 'cat /secrets/secret.json; ls /repo/tests'`（ENOENT期待）と `rg 'records|/public|owner' tests/fixtures/vdp_holdout_env/holdout_runtime_driver.py`
  detail: SGK-2026-0423最終クローズ。静的fixture（`vdp_isolated_env`）はrepo全体mountでlabels.jsonを読める上、`/readonly-ok` 等のURLをif/elif分岐しており、holdoutとして再利用不可と監査指摘。`vdp_holdout_env` はランダム15-hex不透明URL・route非依存ドライバ・repo外$PRIV secrets・runtime非mount（`/secrets/secret.json`→ENOENT・`/repo/tests`→ENOENTをコンテナ内で実証）とした。

- [topic: lessons | when: 不透明URLのholdout route名を生成する時] 16桁以上のhex・24桁以上のbase64url・UUIDのパスセグメントは観測adapterが `:opaque` へマスクするため、区別可能なopaque routeには15桁hexを使え。16桁hexにすると全routeが同一観測へ潰れて仮説が1本に集約される。 verify: `rg -n 'opaque' src/core/engine/vdp_observation_adapter.py` と `.venv/bin/pytest tests/unit/engine/test_vdp_holdout_env.py -q`
  detail: SGK-2026-0423（P-2の実測制約）。16桁hexのrouteを3本生成するとadapterのsanitizerが全て `:opaque` へ正規化し、観測が1本に潰れた。15桁hexへ変更して3本を区別可能にした。コードを読まないと分からない正規化仕様。

- [topic: lessons | when: 仮説generator用のfixture観測数を設計する時] 同一target（capability, host）の仮説はdiversity budgetで3件に上限されるため、全routeを仮説化したいfixtureは3件以内に設計し、超過分は suppressed（diversity_budget_exceeded）として扱え。 verify: `rg -n 'diversity_bucket_limit' src/core/engine/vdp_hypothesis_generator.py` と `.venv/bin/pytest tests/unit/engine/test_vdp_drill_extended.py -k infinite -q`
  detail: SGK-2026-0423（P-2の実測制約）。5本のopaque routeを生成すると同一hostで仮説が3件にcapされ、残りがsuppressedされて期待したconfirmed件数が得られなかった。granted/denied/publicの3本設計に変更し、全routeが仮説化されることを確認した。

- [topic: codingrules | when: コンテナでホストの .venv/bin/python を動かす時] .venv/bin/python のsymlink先（uv管理python）のディレクトリをコンテナ内の同一絶対パスへbind mountしないとsymlinkが解決せず起動失敗する。venv単体のmountでは不十分で、`readlink -f .venv/bin/python` の実体を同一パスでmountせよ。 verify: `docker compose run --rm <svc> .venv/bin/python -c 'import httpx, cryptography, pydantic'`
  detail: SGK-2026-0423（P-2）。`.venv/bin/python` は `/home/bbb/.local/share/uv/python/cpython-3.13.5-.../bin/python3.13` へのsymlinkで、venvだけmountすると「No such file or directory」になった。compose の `UV_PYTHON_DIR`（`/home/bbb/.local/share/uv/python/cpython-3.13.5-linux-x86_64-gnu`）を同一絶対パスへ :ro mount して解決した。

- [topic: lessons | when: confirmedを含むsessionを手動生成・保存する時] M0 gateはconfirmed verdictのevaluated_evidence_idsとsessionのevidence_recordsの一致を要求するため、confirmedの証拠チェーン（そのverdictが評価したevidence）をsessionへ必ず含めよ。全evidenceを落とす・他verdictのevidenceだけ載せるとM0がfailし、verdict件数が合っていても通らない。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_holdout_env.py -q`
  detail: SGK-2026-0423（P-2の実測）。confirmedを含むsessionでevidenceを検証対象外まで含めるとM0のexact-set契約に違反してfailした。runtimeドライバはconfirmed verdictのevaluated_evidence_idsに該当するevidenceだけをsessionへ載せる方式にした。

- [topic: lessons | when: VDP/diagnostic で秘密・値の取り扱いを変更する時] 秘密取り扱いの正本は PIIMasker のマスク＆復元（`src/core/security/pii_masker.py`：`[PII:TYPE:TOKEN]`＋メモリ内 run スコープの token_map＋実行時 `unmask()` で元値復元）。`vdp_observation_adapter.py` の「値破棄」は逸脱であり仕様ではない（param 依存＝注入系を撃てなくする副作用）。token_map/元値は session/report/log/checkpoint へ絶対に永続化しない。 verify: 変更の根拠として pii_masker を参照し、secret-scan で永続化物に平文秘密0
  detail: SGK-2026-0439。観測アダプタ1ファイルだけ見て「値破棄が仕様」と誤断した（PIIMasker は LLM/ログ経路にのみ配線され VDP 攻撃経路に未配線だったのを見落とし）。修正方向は「新設計を作る」ではなく「VDP 攻撃経路を PIIMasker に合わせる」。

- [topic: lessons | when: 計画書やDeepSeek指示で「仕様/設計はこうだ」と述べる時・原因を述べる時] 単一ファイルの挙動を仕様と断定するな。概念を所有するモジュール＋仕様書（docs/shigoku/specs）＋他の呼び出し元を照合し、参照した正本を明記せよ。示せない時は「未確認・要確認」と書いて止まる。原因は根拠が出るまで「仮説」と明示し断定しない。 verify: 指示/計画に照合した正本の参照が明記され、原因が confirmed/仮説 で区別されている
  detail: SGK-2026-0438/0439。admission・dedup を確認前に断定して後で却下され、値破棄を仕様と誤断した。事実と仮説を分離せず断定口調で提示したのが根因。

- [topic: lessons | when: finding_funnel_v1 のカバレッジを封印 run で確認する時] レポートの Candidate 行数と funnel entries 数は粒度が違う（同一 finding_id が複数タスクの result.findings に重複記録される）。カバレッジ照合はユニーク finding_id の集合で diff せよ（行数で比較しない）。 verify: `.venv/bin/python -c "import json; s=json.load(open('workspace/projects/localhost:3000/sessions/session_*.json')); ids={f['id'] for t in s['completed_tasks'] for f in (t.get('result') or {}).get('findings') or []}; print(len(ids))"`
  detail: SGK-2026-0440。17 finding dict がユニーク id 8 に縮退し、funnel entries 8 = 全ユニーク候補をカバー（raw NOT in funnel: [] で確認）。レポート「Candidate: 16」は dict 行数で、funnel の total_candidates 8 と見かけが乖離するが計測欠落ではない。行数で比較すると誤って「カバレッジ不足」と誤判定する。

- [topic: report-session-consistency | when: 封印 run の funnel before/after で「検証段への進行」を判定する時] first_failure_stage は最も早い停止点で固定され後の進行を上書きしないため、進行の実測は max_stage_reached と by_stage の増加で見よ（first_failure_stage の変化では判定しない）。 verify: `rg -o '"max_stage_reached": "[^"]*"' workspace/projects/localhost:3000/sessions/session_20260811_223709.json | sort | uniq -c`
  detail: SGK-2026-0441。0440→0441 で F4 by_stage 3→8・全エントリ max_stage F4 に到達（Phase 2 ThoughtLoop 実動）したが、first_failure_stage は F3×5/F0×3 のまま。first-failure 規約（finding_funnel_trace.py:125-131）は最初の失敗を保持するため、before/after 比較は first_failure 分布でなく max_stage/by_stage で行う。

- [topic: lessons | when: PIIMasker で秘密マスクの新経路を設計する時] 既存 `mask()` は正規表現パターン認識ベースで fail-open（未認識の値は素通し）。deny-by-default には値全体をトークン化するプリミティブ（`mask_url_query_values()` 相当）を明示追加せよ。 verify: `.venv/bin/pytest tests/test_pii_masker.py -q` と `rg -n "PATTERNS" src/core/security/pii_masker.py`
  detail: SGK-2026-0439。`?id=12345` のような短い値はどの PATTERNS にも一致せず `mask()` で素通し（test_pii_masker.py:15-21 が masked==original を実証）。VDP 攻撃経路の値保持には既存 mask の上に「既知秘密型は型付け・残りは全体トークン化」の deny-by-default レイヤーが必要だった。既存エントリ（PIIMasker が正本）は言及していない罠。

- [topic: lessons | when: session/diagnostic に新しいイベントフィールドやセクションを足す時] `DiagnosticEventV1.from_dict` は未知キーで TypeError を投げる strict スキーマなので、新フィールドは既存イベントへ足さず `vdp_contract` の新トップレベルキー（finding_funnel_v1 等）として additive に追加せよ。 verify: `.venv/bin/pytest tests/unit/engine/test_vdp_diagnostic_trace.py tests/unit/reporting/test_finding_funnel_reporting.py -q`
  detail: SGK-2026-0440。vdp_diagnostic_trace.py:403-441 の from_dict が未知キーで raise するため、funnel セクションを vdp_contract 新キーとして追加した（injector の inject_vdp_section_to_session_payload と read_session_compat は未知キーを許容・保持する）。イベントスキーマ拡張だと既存の M0 ゲート検証を壊す。

- [topic: lessons | when: swarm 経路の finding 確定・検証機構を探す・実装する時] `validate_findings`/`filter_valid_findings`（FindingValidator ゲート）は呼び出し元のないデッドコードで、swarm の「confirmed」はレポートタイム推論のみ。実装前に grep で実在の呼び出し元を確認し、「存在する機構」と「見た目だけの機構」を区別せよ。 verify: `rg -n "validate_findings|filter_valid_findings|ExploitVerifier" src/ | rg -v "def |class "`
  detail: SGK-2026-0441。manager.py:3915/3960 の FindingValidator ゲートは dispatch 経路から呼ばれておらず（0440 run の F4 reached は auto_reverified タグ経由のみ）、ExploitVerifier（exploit_verifier.py:56）も src/ 内に呼び出しゼロ。swarm の確定は haddix_formatter.py:308-315 のレポートタイム推論だけ。このギャップが 0441 の賞金級 PoC 判定器の新設理由。

- [topic: lessons | when: Phase 2 検証ループの停止条件・時間予算を変更する時] Phase 2 の実体は thought_loop.py でなく `BaseManagerAgent.dispatch`（base_manager.py:218・max_turns=5）なので、予算/早期停止フックは base_manager のループ境界へ接続せよ（thought_loop.py は専門家用の別ループ・max_turns=10）。 verify: `rg -n "while turn < self.max_turns" src/core/agents/swarm/base_manager.py src/core/agents/swarm/thought_loop.py`
  detail: SGK-2026-0441。計画段階では thought_loop.py を Phase 2 と誤認したが、診断で base_manager.py:120 の dispatch が実体と判明。manager.py:2997 の asyncio.wait_for が既存の唯一の時間予算。変更対象を間違えると効果が無い（0441 では両方に接続した）。

- [topic: lessons | when: swarm 検証ループの送信に read-only（GET-only）制約を課す時] `vdp_readonly_guard` の GET-only は VDP follow-up 経路のみに適用され swarm thought_loop 経路は対象外（ExecutionSafeguard の MethodRiskPolicy のみ）。検証ループの追加送信には GET-only ガード（assert_read_only_probe 相当）を明示配線せよ。 verify: `rg -n "evaluate_readonly_request" src/core/engine/ | rg -v "def "` と `.venv/bin/pytest tests/core/agents/swarm/injection/test_payout_grade.py -q`
  detail: SGK-2026-0441。vdp_readonly_guard.py:111-204 の適用は vdp_follow_up_executor.py:572/1302 のみで、swarm 専門家は POST を送れる（smart_sqli.py:1045-1052）。read-only エンベロープの担保は「ガード関数を用意した」だけでは不十分で、呼び出し元まで確認する（本タスクは新規送信を追加しない方針で構造的に充足 + 封印 run で GET 38 件全てを実測）。

- [topic: reporting | when: preflight の token_scan_changed_files が fail した時] changed-files に含まれる既存ファイルの denylist トークンは `git show HEAD:<file>` で既存を証明してから manifest hits[] へ pre-existing 分類登録し、content_hash を canonical body（content_hash キー除く・sort_keys・ensure_ascii=False の sha256）で再計算せよ。新規トークンを manifest 登録で隠すのは禁止。 verify: `.venv/bin/python scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt --changed-files <file> 2>&1 | tail -3`
  detail: SGK-2026-0441。execution_policy.py:39 / smart_cmd_ssrf.py:184 の `/vulnerabilities/` は HEAD に存在する既存コード（git show HEAD | rg -c = 1・diff の + 行ではない）で、ファイルを変更したことで changed-files スキャンに晒された。smart_xss.py と同型の pre-existing 登録（SGK-2026-0426 委譲・deferred_classified）で正規解決。content_hash は scripts/check_vdp_product_independence.py:74-83 の canonical_manifest_body と同一方式で再計算する。

- [topic: python-tests | when: 並列実装後の HEAD 回帰比較（失敗集合の一致確認）をする時] 同一ツリーでの `git stash` 比較は並列 fixer 稼働中は無効（他レーンの変更が混在・HEAD 側で collection が壊れる）。`git worktree add --detach <dir> HEAD` で pristine HEAD を切り、gitignore された実行時モジュール（src/core/workspace）をコピーしてから同一サブセットを実行し、FAILED 集合を diff せよ。 verify: `git worktree add --detach /tmp/wt HEAD && cp -r src/core/workspace /tmp/wt/src/core/ && cd /tmp/wt && PYTHONPATH=/tmp/wt pytest <subset> -q 2>&1 | rg '^FAILED' | sort > /tmp/f.txt && diff /tmp/f.txt <(cd /home/bbb/Documents/App/Shigoku && .venv/bin/pytest <subset> -q 2>&1 | rg '^FAILED' | sort)`
  detail: SGK-2026-0440。stash 比較で HEAD 側が 82 collection errors（src/core/workspace が .gitignore:24 で worktree に無く import 不能）となり比較不能だった。worktree へ workspace をコピー + PYTHONPATH 指定で HEAD 実行が可能になり、38 failed が IDENTICAL と確定（0440/0441 両方で使用）。stash は 0439 がコミット済みだったため 0440 分しか退避されず無効だった。既存 stash レシピ（0421）は単一レーン時の話。

- [topic: lessons | when: デッドコード/復活対象モジュールの API を置換しようとする時] モジュール関数が「呼び出し元ゼロ」でも、インスタンスメソッドは他モジュールからコールバック配線（validate_one 等）で消費されていることがある。置換前にインスタンスメソッドの実呼び出しを grep し、レガシー意味論は byte-identical 温存、新契約は追加メソッド/モジュール関数に載せよ。 verify: `rg -n "validate_one|_finding_validator" src/core/agents/swarm/injection/manager.py` と `.venv/bin/pytest tests/unit/engine/test_finding_funnel_swarm_hooks.py tests/core/agents/swarm/injection/test_manager_result_normalizer_character.py -q`
  detail: SGK-2026-0443。0441 エントリの「FindingValidator はデッドコード」は dispatch 経路の話に過ぎず、manager.py:3987/4026 は `validate_one=self._finding_validator.validate` で instance validate() を消費し、funnel ゲート reason_code `finding_validator_rejected`（test_finding_funnel_swarm_hooks.py:374）が actions+metadata の意味論に依存する。旧 API 全置換（当初の設計案 D7）は funnel テストを壊すため却下し、instance API 温存＋evaluate()/validate_finding() を新契約として追加した。

- [topic: lessons | when: 実装委譲タスクの指示文を書く時・バックグラウンドライターが無応答になった時] 委譲先に git stash / checkout -- / reset 等の作業ツリー破壊的操作を許可するな（ベースライン調査は read-only・worktree 法に限定）。ライターが沈黙したら `git status`・`git stash list`・ファイル mtime で「作業の退避」を先に確認し、退避済みなら回収してから再開せよ。 verify: `git stash list` が空、かつ `git status --porcelain` が期待状態（対象ファイルが M/?? のまま）であること
  detail: SGK-2026-0443。fixer への指示に「git stash は必要な場合のみ」と書いたのが誤解され、既存失敗の調査で自分の実装5ファイルを stash へ退避したまま無応答（作業ツリーは HEAD に見える＝状態の罠・ハング）。stash@{0} に全実装が生存していたため回収・統合（欠損なし）。作業報告書 §5 に記録。回帰比較の手法は既存の worktree レシピ（0440）を併用せよ。

- [topic: python-tests | when: フルスイートの失敗数を見て回帰を判定する時] 本リポジトリのフルスイートには pre-existing 383 failed / 5 collection errors（欠落モジュール: report_refiner_agent / taint_analysis_agent 等）と、tests/core/validation/test_phase_b_readiness.py の2件（workspace/projects/juice_shop_demo/ アーティファクト存在チェック・単体実行で必ず落ちる）が常に含まれる。回帰は失敗「件数」でなく変更前後の FAILED 集合 diff（worktree 法・既存レシピ）で判定せよ。 verify: `.venv/bin/pytest tests/ -m "not slow and not requires_api" -q --continue-on-collection-errors 2>&1 | tail -1`（0443 実測: 変更前 6783 passed/383 failed → 修正後 6795 passed/383 failed、+12 は追加テスト分のみ）
  detail: SGK-2026-0443。実装直後と oracle 対応後の2回のフル実行で failed 383 が不変・passed は追加テスト12件分のみ増加＝回帰ゼロと確定。test_phase_b_readiness の2件は対象ファイル外の checkout 状態依存で、この「2 failed」を見た fixer が stash 誤用の引き金にした（上記 lessons エントリ参照）。

- [topic: codingrules | when: LLMClient.generate() の応答をパースするアダプタを書く時] 戻り値は str / dict / DictToObject（キャッシュ）等の複数形状を取り得るため、形状を正規化してからフィールドを取出し、空 choices でも IndexError でなく明示エラー（ValueError 等）にせよ。 verify: `.venv/bin/pytest tests/core/validation/test_hybrid_verdict_selfcheck.py -q`（TestPoCJudgeDefensiveParsing）
  detail: SGK-2026-0443（ora-1 レビュー指摘）。`response.get("choices", [{}])[0]` は choices が空リストのとき IndexError（呼び出し側の契約は ValueError）だった。PoCJudge._extract_content（finding_validator.py:422-432）を `(response.get("choices") or [{}])[0]` に修正し、実形状（litellm.ModelResponse / DictToObject）で検証。コードフェンス包み JSON はフェンス内のみ再試行（捏造はしない・失敗時は ValueError）。

- [topic: lessons | when: テスト fixture の製品非依存を preflight の pass で裏取ろうとする時] preflight（check_vdp_product_independence.py）の token_scan_changed_files は src/, scripts/, config/, recipes/, prompts/, data/ のみをスキャンし、tests/ は対象外。fixture の非依存性は目視・自前チェックで担保せよ（preflight 0 hit を fixture の裏取りに使うな）。 verify: `python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt 2>&1 | tail -2` の files_scanned に tests/ が含まれないことを確認
  detail: SGK-2026-0443。fixture は target.example 等の汎用ドメインで作成し製品非依存を満たしたが、preflight の total_token_hits 0（files_scanned 4 = src/・prompts/ 分のみ）は tests/ 配下の fixture を検査しておらず、裏取りにはならない。

- [topic: lessons | when: preflight/エントリゲートのプローブが AsyncNetworkClient 経由でネットワークに出ない時] 既定構成では `request()` の compiled guard（bugbounty・policy=None → policy_unavailable fail-closed block）に全プローブが呑まれる。preflight 内部プローブは `request(skip_guard=True)` を**唯一の呼び出し箇所**として使い、`skip_guard=True` の実呼び出しが 1 箇所のみであることを grep で検証せよ。 verify: `rg -n "skip_guard=True" src/ | grep -v "def request\|: bool = False"`
  detail: SGK-2026-0447 B1。network_client.py:364 は bugbounty モードで evaluate_at_layer(policy=None) → fail-closed するため、ガードなしでは転送プローブが常に PROXY_FORWARD_CHECK_FAILED になる（テストの evaluate_at_layer allow patch が本番挙動を隠蔽していた）。

- [topic: lessons | when: プロキシ転送検証（check_forwarding）の canned 判定を実装・変更する時] canned 判定は「全応答 status==200 かつ byte-identical かつ ≤512B」に限定せよ。非 200 の同一応答（全パス 302 / API 404）は誤検知するため PASS とし、200 identical >512B は PASS + WARNING で false-negative を可視化せよ。 verify: `.venv/bin/pytest tests/unit/preflight/test_caido_check.py -k "302 or 404 or Forward" -q`
  detail: SGK-2026-0447 B2。当初の「全応答 identical かつ ≤512B → FAIL」は本物ターゲットでも全パス 302（http→https）やルート無し API 404（FastAPI デフォルト）で FAIL する（実測）。status==200 限定により実測ダミー（200+30B）は検知維持・誤検知解消。

- [topic: codingrules | when: caido.url / 任意の settings 値を run 単位で上書きする時] settings の優先順位は init > env > YAML（settings_customise_sources）なので、環境変数設定済みの値は YAML 追記では変わらない。run コマンドに `SHIGOKU_<FIELD>`（ネストは `__`）を付与して上書きせよ。 verify: `env SHIGOKU_CAIDO__URL=http://127.0.0.1:8081 .venv/bin/python -c "from src.core.config.settings import settings; print(settings.caido.url)"`
  detail: SGK-2026-0447 Part B。環境に SHIGOKU_CAIDO__URL が設定済みのため config/shigoku.yaml の caido: セクション追記（url: 8081）が無視され 8080 のままだった（実測）。settings.py:750-807 の sources 順序を確認してから設定変更すること。

- [topic: lessons | when: finding_funnel_v1（F0〜F6）を session で確認・計測する時] funnel レコーダーは `diagnostics.enabled=true` のときのみ有効（get_finding_funnel が None を返す）なので、funnel 計測 run は `SHIGOKU_DIAGNOSTICS__ENABLED=true` で実行せよ。 run 後に `finding_funnel_v1` キーの存在を確認せよ。 verify: run 後 `.venv/bin/python -c "import json; d=json.load(open('<session>')); print('finding_funnel_v1' in d)"` → True
  detail: SGK-2026-0447 B3。finding_funnel_trace.py:346-360 は cfg.enabled False で None を返す。run1 は diagnostics off のため session に funnel が記録されず「funnel before/after 計測不能」になった（run6 は m5 harness が一時有効化していた）。

- [topic: lessons | when: 封印 run / read-only エンベロープの GET-only を検証する時] 状態変更メソッドはネットワーク境界（`sealed_run_get_only` + `use_proxy=True` 限定）で強制し、session の evidence `request_method` を集計して PATCH/POST/PUT が 0 件であることを確認せよ（finding の有無だけで GET-only を断定するな）。 verify: session の task_execution_records → vulnerabilities_found → evidence.request_method を Counter 集計
  detail: SGK-2026-0447 B4。manager.py:1933-1937 の mass_assignment は probe_method に PATCH を選び recheck を送る（run1 実測 PATCH 13 件・response 200）。run6 の「GET-only 20/20」は偽的（canned 応答）では recheck が発動しなかっただけ＝偽の的の数字。

- [topic: lessons | when: ネットワーク境界ガード（GET-only 等）を AsyncNetworkClient.request() に追加する時] ガードは `use_proxy=True`（ターゲット攻撃面・全通信プロキシ化契約 network_client.py:326）に限定せよ。`use_proxy=False` は Caido コントロールプレーン専用（preflight identity / caido_auth / caido_sitemap）で、巻き込むと entry gate が abort する。 verify: `rg -n "use_proxy=False" src/ | rg -v test` が caido_check / caido_auth / caido_sitemap のみ
  detail: SGK-2026-0447 run2 実測。全リクエストに GET-only を掛けたら preflight の POST /graphql（use_proxy=False）までブロックされ「Preflight entry gate failed — aborting」。ターゲット攻撃は AsyncNetworkClient デフォルト use_proxy=True で proxy 経由のため、use_proxy=True 限定で目的を満たす。

- [topic: codingrules | when: 境界ガードの専用例外（ReadonlyEnforcedError 等）を呼び出し側で処理する時] 専用ブロック例外は汎用 `except Exception: continue` より**前に**捕捉せよ。汎用 except が飲むと写像・ログが一切発動しない（サイレントスキップ）。 verify: `rg -n "except Exception: continue" src/core/agents/swarm/injection/manager.py` と同ファイル内の ReadonlyEnforcedError 捕捉箇所の順序を確認
  detail: SGK-2026-0447 D-B4-1。manager.py:2017-2028 の discovery ループが ReadonlyEnforcedError をサイレントに飲み、needs_human 写像が欠落（送信ゼロで安全・検知のみ欠落 → deferred 追跡）。専用例外は汎用ハンドラより先に except すること。

- [topic: shigoku-docs | when: plan を done/ へ移動する時] ファイル移動に加えて front matter の `status: active → done` も更新せよ。移動だけでは validator が `REGISTRY_ISSUES=task_*_status_mismatch` を出す。 verify: `python3 scripts/validate_shigoku_docs.py | rg "REGISTRY_ISSUES"` が 0
  detail: SGK-2026-0447 閉鎖時。git mv で done/ へ移しても front matter status が active のままだと status_mismatch（既存エントリの related_docs 一括更新と併用すること）。validator は配置と front matter の両方を検査する。

- [topic: codingrules | when: snip 経由で環境変数付きコマンドを実行する時] `VAR=x cmd` プレフィックスは snip の passthrough で「executable file not found」になる。`env VAR=x cmd` の形で実行せよ。 verify: `env SHIGOKU_MODE=vulntest .venv/bin/python -c "print(1)"` が通ること
  detail: SGK-2026-0447 Part B。`SHIGOKU_MODE=vulntest .venv/bin/python ...` は snip がプレフィックスを実行ファイル名として扱い失敗。既存の snip 系エントリ（python3 -c の `;`）と同系統の別罠。

- [topic: lessons | when: SmartSQLiHunter / decide の tool-calling 化後に「発火ペイロードを送信した」と判定する時] decide が `tool call 'request' with payload` を返したログだけでは実 HTTP 送信を断定するな。session の sqli url_result に `probe_sent=true` が 1 件以上あることを確認せよ（0 なら未送信）。`q=',` は session 内 Python repr のクロージング誤読で実 payload ではない。 verify: `python3 -c "import json,glob; raw=json.dumps(json.load(open(sorted(glob.glob('workspace/projects/localhost:3000/sessions/session_*.json'))[-1]))); print(raw.count('\"probe_sent\": true'))"` → 0 なら未送信
  detail: SGK-2026-0450 STEP3 独立検証の訂正。3 run とも probe_sent=true=0/68（各 sqli url_result で 0）＝ SmartSQLiHunter は `q` へのシングルクォート発火 payload を一度も送っていない。`q` に届いた実リクエストは CORS 検査の空 `q=`（Origin: evil.com）のみ。tool_calls の返却と実プローブ送信は別レイヤーで、発火経路欠陥は SGK-2026-0451 へ移管。

- [topic: codingrules | when: LLMClient.generate / agenerate に tools= を渡してツール実行を期待する時] LLMClient の内部 tool_calls ループはダミー文字列（`f"Result from {function_name}"`）を返すだけで**実実行しない**。ツール実行が必要なら `tool_loop=False` で tool_calls を含む生応答を受け取り、呼び出し側で実行して `role: tool` メッセージを履歴へ戻せ。 verify: `rg -n "Result from" src/core/models/llm.py` でダミー実装の存在を確認
  detail: SGK-2026-0450 A。llm.py:426,616 のダミー実行。tools= を渡しても実行されないため、base_manager は `agenerate(history, tools=schemas, tool_loop=False)` → `_handle_tool_calls` で実行する設計にした（既定 tool_loop=True は既存呼び出し元のバイト等価を維持）。

- [topic: codingrules | when: LLMClient.generate / agenerate にツール関連パラメータ（tool_loop 等）を追加する時] 認証エラーのフォールバック再帰呼び出しにも新パラメータを伝播せよ。伝播しないとフォールバック先で黙って既定（ダミー実行）モードに戻り、フラグの意味論が壊れる。 verify: `rg -n "return self.generate|return await self.agenerate" src/core/models/llm.py` に `tool_loop=tool_loop` が渡っていること
  detail: SGK-2026-0450 A。llm.py:478,667。tool_loop=False で呼んだのに AuthenticationError フォールバック先が tool_loop 未指定（=True）だと、リトライがダミー実行モードに戻る。仕様に明記は無かったがフラグ伝播を追加した。

- [topic: lessons | when: モック LLM 応答の message.tool_calls を検査して tool-calling 分岐を書く時] MagicMock は未知属性 `tool_calls` を自動生成して truthy になるため、`if tool_calls:` 単独では既定 OFF パスが tool-calling 経路へ誤進入する。機能オプトイン（`self._use_tool_calling`）と AND でガードせよ。 verify: `.venv/bin/pytest tests/core/agents/swarm/test_auth_manager.py tests/unit/agents/swarm/test_base_manager_tool_calling.py -q` が全 pass
  detail: SGK-2026-0450。base_manager.py think loop は `if self._use_tool_calling and _tool_calls:` に修正。初回実装は `if _tool_calls:` のみで、MagicMock の自動属性生成により test_auth_manager_ninja_delegation が回帰（オプトイン OFF でも tool-calling 分岐へ誤進入）した。

- [topic: report-session-consistency | when: finding_funnel_v1 の F5 / F4 から「検出された / されなかった」を判定する時] F5 は apply_verdict 後のライフサイクル状態（confirmed/refuted/parked/needs_human）の記録であり、F5:0 は検出 0 を意味しない。F4 reached の candidate がどの vuln_type かを session の finding_id → completed_tasks で追跡してから判定せよ。 verify: `python3 -c "import json; s=json.load(open('<session>')); [print(e['finding_id'], e['stages'].get('F4'), e.get('first_failure_reason')) for e in s['finding_funnel_v1']['entries']]"` と completed_tasks の vuln_type を突き合わせ
  detail: SGK-2026-0450 STEP3。manager.py:1215 付近で F5 emit は apply_verdict 後。3 run とも F5:0 だったが、F4 reached の candidate は cors_misconfiguration / broken_access_control で SQLi は 0（finding_id 追跡で判明）。F5:0 のみで「sql_error 候補なし」と断定するのは不足だった。
