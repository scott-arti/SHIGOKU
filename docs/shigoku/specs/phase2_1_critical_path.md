---
task_id: SGK-2026-0146
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Phase 2.1: Critical Path Analysis 仕様書

## 概要

**機能名**: `CriticalPathAnalyzer`

**目的**:
脆弱性スキャン中に「決定的な手がかり」（Admin Panel, JWT, API Keyなど）を発見した場合、
それに関連する攻撃タスクの優先度を動的かつ大幅に引き上げ、攻撃の効率を最大化する。

**背景**:

- Phase 1.2 で `DynamicTaskQueue` (メカニズム) は実装されたが、何をトリガーにするかの判断ロジックは単純なルールベースのみ。
- より高度な「文脈判断」を行い、例えば「Admin Panelが見つかったら、そこへの認証試行だけでなくFuzzingも優先する」といった戦略的判断を行いたい。

---

## 変更範囲

| ファイル                                    | 変更内容                   |
| ------------------------------------------- | -------------------------- |
| `src/core/engine/critical_path_analyzer.py` | 🆕 新規作成 - 分析ロジック |
| `src/core/engine/master_conductor.py`       | 📝 修正 - Analyzer統合     |
| `tests/unit/engine/test_critical_path.py`   | 🆕 新規作成 - テスト       |

---

## 機能詳細

### 1. CriticalPathAnalyzer

Finding（発見事項）を入力とし、推奨されるアクション（優先度変更、タスク追加）を出力する。

```python
@dataclass
class CriticalAction:
    action_type: str  # "boost_priority", "add_task", "notify"
    target_filter: Dict[str, Any]  # タスクフィルタ条件
    params: Dict[str, Any]  # アクションパラメータ (priority=999, etc)
    reason: str

class CriticalPathAnalyzer:
    def analyze(self, finding: Finding) -> List[CriticalAction]:
        """
        Findingを分析し、クリティカルパスがあればアクションを返す
        """
        pass
```

### 2. トリガー条件（例）

| トリガー (Finding)        | アクション           | 対象タスク                    | 理由                                   |
| ------------------------- | -------------------- | ----------------------------- | -------------------------------------- |
| **Admin Panel**           | Boost Priority (999) | `auth`, `fuzz` (target=admin) | 管理画面は最優先攻略対象               |
| **JWT Token**             | Boost Priority (900) | `jwt_attack`, `auth_bypass`   | トークン解析・改ざんは高確率でCritical |
| **Debug Endpoint**        | Boost Priority (800) | `info_leak`, `rce_probe`      | デバッグ機能は脆弱性の宝庫             |
| **File Upload**           | Boost Priority (850) | `file_upload`, `rce`          | シェルアップロードのチャンス           |
| **Old Version** (CVEあり) | Boost Priority (950) | `cve_exploit`                 | 既知の脆弱性は即座に検証               |

### 3. MasterConductor 統合

`execute_with_replan` ループ内で:

1. タスク完了 -> Finding 発生
2. `CriticalPathAnalyzer.analyze(finding)`
3. アクション実行
   - `priority_boost`: `task_queue.boost_priority()`
   - `add_task`: 新規タスク作成して `task_queue.add()`

---

## 実装ステップ

1. `CriticalPathAnalyzer` 実装
2. テスト作成
3. `MasterConductor` への統合

## 完了条件

- Admin Panel等のFindingが発生した際、関連タスクの優先度が自動的に上昇すること
- テストケースで各トリガーが正しく動作すること
