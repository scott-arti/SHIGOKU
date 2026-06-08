---
task_id: SGK-2026-0150
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 2.5: Dynamic Wordlist Generation 仕様書

## 概要

**機能名**: `DynamicWordlistGenerator`

**目的**:
Reconnaissance や Crawling で発見したアプリケーション固有のパラメータ名やパスを学習し、
後続の Fuzzing フェーズで使用するカスタムワードリストを自動生成・拡張する。

---

## 変更範囲

| ファイル                                | 変更内容                                        |
| --------------------------------------- | ----------------------------------------------- |
| `src/core/wordlist/wordlist_manager.py` | 📝 修正 - 動的学習機能追加                      |
| `src/core/engine/context_propagator.py` | 📝 修正 - WordlistManagerへのフィードバック経路 |

---

## 機能詳細

### 1. WordlistManager 拡張

発見したパラメータを蓄積し、ファイルに永続化あるいはインメモリで管理する。

```python
class WordlistManager:
    def __init__(self):
        self.learned_params: Set[str] = set()
        self.learned_paths: Set[str] = set()

    def learn_params(self, params: List[str]):
        """パラメータを学習"""
        new_params = set(params) - self.learned_params
        if new_params:
            self.learned_params.update(new_params)
            self._save_learning_data()

    def get_fuzzing_wordlist(self, base_wordlist: List[str]) -> List[str]:
        """ベースのワードリストに学習データをマージして返す"""
        return list(set(base_wordlist) | self.learned_params)
```

### 2. ContextPropagator 連携

Phase 1.2 で実装した `ContextPropagator` は既にパラメータ抽出を行っている (`discovered_params`)。
これを `WordlistManager` に渡すフローを確立する。

**Master Conductor Loop**:

```python
# execution loop
new_context = self.context_propagator.extract(result)
if new_context.discovered_params:
    self.wordlist_manager.learn_params(new_context.discovered_params)
```

---

## 完了条件

- タスクAで見つかったパラメータ（例: `user_role_id`）が、タスクBのFuzzingパラメータリストに含まれるようになること
