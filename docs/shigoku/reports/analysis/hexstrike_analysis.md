---
task_id: SGK-2026-0024
doc_type: work_report
status: done
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# HexStrike vs SHIGOKU 比較分析

**作成日:** 2026-02-07  
**対象:** HexStrike (150+ツール) vs SHIGOKU (Master Conductor アーキテクチャ)

---

## 1. ツール数の比較

| プロジェクト  | ツール数          | アーキテクチャ               |
| ------------- | ----------------- | ---------------------------- |
| **HexStrike** | **150+ツール**    | ルールベース＋AI補助         |
| **SHIGOKU**   | **約50-60ツール** | Master Conductor (LLM自律型) |

---

## 2. HexStrikeの優れた点

### 2.1 IntelligentDecisionEngine (AI駆動型ツール選択)

```python
class IntelligentDecisionEngine:
    """
    - TargetType の自動分類 (Web/Network/API/Cloud/Binary)
    - TechnologyStack のフィンガープリント (Apache/Nginx/WordPress...)
    - AttackChain の自動生成 (成功確率 × 実行時間の最適化)
    - ツール有効性スコア (各ツール × ターゲットタイプの相性)
    """
```

**メリット:**

- LLMに頼らない高速な初期判断
- 既知の攻撃パターンの再利用
- ツール実行順序の最適化

**SHIGOKUへの応用案:**
→ **ToolProfileManager を拡張して `AttackChainOptimizer` を追加**

### 2.2 専門分野別攻撃パターンの事前定義

HexStrikeは以下のような専門パターンを持っている:

```python
attack_patterns = {
    "bug_bounty_reconnaissance": [...],
    "bug_bounty_vulnerability_hunting": [...],
    "ctf_pwn_challenge": [...],
    "aws_security_assessment": [...],
    "kubernetes_security_assessment": [...],
    "iac_security_assessment": [...],
}
```

**メリット:**

- Bug Bountyモードでの即座のワークフロー実行
- CTFモード特化の効率化
- Cloud環境専用のツールチェーン

**SHIGOKUへの応用案:**
→ **`docs/recipes/` に専門分野別Recipeを追加**

### 2.3 ModernVisualEngine (視覚的な美しさ)

```python
class ModernVisualEngine:
    """
    - リアルタイムダッシュボード
    - プログレスバーアニメーション
    - 脆弱性カード表示 (Severity別カラー)
    - コマンド実行ステータス表示
    """
```

**メリット:**

- ユーザー体験の向上
- 進捗の可視化
- 問題の即座の把握

**SHIGOKUへの応用案:**
→ **LiveDashboard の強化 (現在は基本的な表示のみ)**

---

## 3. 質問への回答: ツールを150+に増やすべきか?

### ❌ **単純なツール数の増加は推奨しません**

**理由:**

1. **SHIGOKU は Master Conductor アーキテクチャ**
   - LLMが自律的にツールを選択・組み合わせる
   - 重要なのはツールの**量**ではなく、**質とコンテキスト認識**
   - 150+ツール = LLMのFunction Calling時のトークン増大

2. **セキュリティリスクの増大**
   - 150+ツール = 攻撃面の増大 (各ツールがRCEやSSRFの可能性)
   - EthicsGuard でのスコープチェックコスト増加
   - 各ツールの安全性監査が困難

3. **メンテナンスコスト**
   - 150+ツールの依存関係管理
   - 破損時のデバッグ工数
   - Docker イメージサイズの爆発

4. **選択肢の過多による麻痺**
   - "Jam Experiment" 効果: 選択肢が多すぎると決断できない
   - LLMの判断精度低下の可能性

### ✅ **代わりに取り入れるべきアイデア**

#### **戦略A: 専門分野別Recipeの強化**

| 専門分野       | 現在のSHIGOKU  | 改善案                                                    |
| -------------- | -------------- | --------------------------------------------------------- |
| **Bug Bounty** | 汎用Recipeのみ | `bug_bounty_recon.yaml`, `bug_bounty_exploit.yaml` を追加 |
| **CTF**        | なし           | `ctf_pwn.yaml`, `ctf_web.yaml` を追加                     |
| **Cloud**      | ScoutSuiteのみ | AWS/GCP/k8s 専用Recipeを追加                              |
| **Binary**     | なし           | Binary解析用Recipeを追加 (将来的)                         |

**実装例:**

```yaml
# docs/recipes/bug_bounty_recon.yaml
name: "Bug Bounty - Reconnaissance Phase"
description: "Optimized for responsible disclosure programs"
mode: "bugbounty"
steps:
  - agent: "ReconBot"
    tool: "subfinder"
    profile: "thorough"
  - agent: "ReconBot"
    tool: "httpx"
    profile: "speed"
  - agent: "ReconBot"
    tool: "katana"
    profile: "default"
  - agent: "BizLogicHunter"
    tool: "nuclei"
    profile: "stealth" # Bug Bounty ではステルスが重要
```

#### **戦略B: AttackChainOptimizer の追加**

HexStrikeの `IntelligentDecisionEngine` を参考に、SHIGOKUに以下を追加:

```python
# src/core/optimizer/attack_chain_optimizer.py
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class AttackStep:
    """攻撃ステップ"""
    agent: str
    tool: str
    profile: str
    priority: int
    success_probability: float  # 0.0 ~ 1.0
    execution_time_estimate: int  # seconds
    dependencies: List[str]

class AttackChainOptimizer:
    """
    Master Conductor が RecipeExecutor を実行する前に、
    最適な攻撃チェーンを生成する。

    機能:
    - ターゲットタイプの自動分類
    - 技術スタックのフィンガープリント
    - 攻撃チェーンの成功確率計算
    - ツール実行順序の最適化
    """

    def optimize_recipe(
        self,
        recipe_steps: List[Dict[str, Any]],
        target_profile: Dict[str, Any]
    ) -> List[AttackStep]:
        """Recipeを最適化して AttackStep のリストを返す"""
        pass
```

**メリット:**

- Master Conductor がより賢くツールを選択
- LLMの負荷軽減 (事前最適化済みチェーンを渡す)
- Recipeの再利用性向上

#### **戦略C: ToolProfiles の拡張**

現在のSHIGOKUは6ツールのみプロファイル定義:

```python
# src/tools/tool_profiles.py
TOOL_PROFILES = {
    "nuclei": ...,
    "httpx": ...,
    "ffuf": ...,
    "subfinder": ...,
    "sqlmap": ...,
}
```

**拡張案:**

- **全50ツール**にプロファイルを定義
- HexStrikeのような `tool_effectiveness` スコアを追加

```python
TOOL_EFFECTIVENESS = {
    "web_application": {
        "nuclei": 0.95,
        "sqlmap": 0.9,
        "dalfox": 0.93,
        ...
    },
    "network_host": {
        "nmap": 0.95,
        "rustscan": 0.9,
        ...
    },
}
```

#### **戦略D: LiveDashboard の強化**

現在のLiveDashboardは基本的な表示のみ。HexStrikeのように:

- **リアルタイムプログレスバー**
- **脆弱性カード表示** (Severity別カラー)
- **ツール実行ステータス** (RUNNING/SUCCESS/FAILED)

---

## 4. 推奨される実装プラン

### **Phase 1: 専門分野別Recipeの追加** (優先度: 高)

- [ ] `docs/recipes/bug_bounty_recon.yaml`
- [ ] `docs/recipes/bug_bounty_exploit.yaml`
- [ ] `docs/recipes/ctf_web.yaml`
- [ ] `docs/recipes/aws_security_assessment.yaml`

**工数:** 2-3日  
**効果:** Bug BountyとCTFでの生産性が3-5倍向上

### **Phase 2: AttackChainOptimizer の追加** (優先度: 中)

- [ ] `src/core/optimizer/attack_chain_optimizer.py`
- [ ] Master Conductor との統合
- [ ] TargetProfile の自動分類ロジック

**工数:** 5-7日  
**効果:** LLM負荷軽減、ツール実行順序の最適化

### **Phase 3: ToolProfiles の全ツール拡張** (優先度: 中)

- [ ] 全50ツールのプロファイル定義
- [ ] `tool_effectiveness` スコアの追加
- [ ] ProfileManager の強化

**工数:** 3-4日  
**効果:** コンテキストに応じた自動プロファイル選択

### **Phase 4: LiveDashboard の強化** (優先度: 低)

- [ ] ModernVisualEngine の統合
- [ ] リアルタイムプログレスバー
- [ ] 脆弱性カード表示

**工数:** 4-5日  
**効果:** ユーザー体験の向上

---

## 5. 結論

### **ツール数を150+に増やすことは推奨しません。**

代わりに:

1. **専門分野別Recipeの強化** → Bug Bounty/CTF/Cloud 特化
2. **AttackChainOptimizer の追加** → ツール選択の自動最適化
3. **ToolProfiles の拡張** → 全ツールのコンテキスト対応
4. **LiveDashboard の強化** → 視覚的な美しさ

**この戦略により:**

- ツール総数は50-60のまま
- 専門性と品質が向上
- セキュリティリスクとメンテナンスコストを抑制
- Master Conductor の自律性を維持

---

## 6. 次のアクション

ユーザーの意思決定を待つ:

1. **Phase 1 (専門分野別Recipe)** の実装を開始するか?
2. **Phase 2 (AttackChainOptimizer)** の設計を先に行うか?
3. **現状維持** (ツールを増やさない) を確認するか?

**推奨:** Phase 1 の実装を先に行い、効果を確認してから Phase 2 に進む。
