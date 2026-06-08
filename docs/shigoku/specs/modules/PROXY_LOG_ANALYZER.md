---
task_id: SGK-2026-0042
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# ProxyLogAnalyzer - プロキシログ解析エンジン

**モジュールパス**: `src/intelligence/proxy_log_analyzer.py`

---

## 概要 (Overview)

**ProxyLogAnalyzer** は、Burp Suite、Caido、ブラウザ開発ツールなどからエクスポートされた HTTP トラフィックログを解析し、攻撃候補（Candidate）を抽出するモジュールです。人間のハッカーが手動で行う「怪しいリクエストの選別」を自動化します。

**主な機能**:

1. プロキシログ（HAR、Caido JSON）の解析
2. ノイズ除去（静的ファイル、CDN、広告などをフィルタリング）
3. 「怪しい匂い」(Smell) の検出
4. 攻撃計画 (AttackPlan) の生成

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ProxyLogAnalyzer                                │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Log Parser                                 │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │   │
│  │  │  HAR Parser  │  │ Caido Parser │  │ Burp Parser  │        │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Noise Reducer                              │   │
│  │  - Remove static files (.js, .css, .png, etc.)               │   │
│  │  - Remove CDN/Analytics (google, facebook, etc.)             │   │
│  │  - Remove duplicate requests                                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Smell Detector                             │   │
│  │  ┌──────────────────────────────────────────────────────┐    │   │
│  │  │ IDOR候補 | 隠しパラメータ | Auth異常 | JWT | Admin   │    │   │
│  │  └──────────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   AttackPlan Generator                        │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Smell (怪しい匂い) 検出パターン

### 検出カテゴリ

| Smell Type         | 説明                                    | 検出例                                 |
| :----------------- | :-------------------------------------- | :------------------------------------- |
| **IDOR_CANDIDATE** | 連番 ID、UUID が URL またはボディに存在 | `/api/users/123`, `?order_id=456`      |
| **HIDDEN_PARAM**   | 権限関連の隠しパラメータ                | `role=user`, `is_admin=false`          |
| **AUTH_ANOMALY**   | 認証関連の異常                          | エンドポイントごとに異なるトークン形式 |
| **JWT_PRESENT**    | JWT トークンの検出                      | `Authorization: Bearer eyJhbG...`      |
| **OAUTH_FLOW**     | OAuth フローのリクエスト                | `/oauth/authorize`, `redirect_uri=...` |
| **MFA_ENDPOINT**   | MFA 関連のエンドポイント                | `/mfa/verify`, `/2fa/code`             |
| **ADMIN_ENDPOINT** | 管理画面関連のパス                      | `/admin/`, `/dashboard/`, `/manage/`   |
| **SENSITIVE_DATA** | 機密データの送受信                      | `password=`, `credit_card=`            |

### 検出ロジック

```python
class SmellDetector:
    def detect(self, request: ParsedRequest) -> List[SmellType]:
        smells = []

        # IDOR候補: URLまたはボディにIDパターン
        if self._has_sequential_id(request):
            smells.append(SmellType.IDOR_CANDIDATE)

        # JWT検出: Authorizationヘッダー
        if self._has_jwt_token(request):
            smells.append(SmellType.JWT_PRESENT)

        # 隠しパラメータ: 権限関連キーワード
        if self._has_privilege_params(request):
            smells.append(SmellType.HIDDEN_PARAM)

        return smells
```

---

## ノイズ除去 (Noise Reduction)

### 除外対象

| カテゴリ           | パターン                                                          |
| :----------------- | :---------------------------------------------------------------- |
| **静的ファイル**   | `.js`, `.css`, `.png`, `.jpg`, `.gif`, `.svg`, `.woff`, `.woff2`  |
| **CDN/Analytics**  | `google-analytics.com`, `facebook.com`, `cloudflare.com`, `cdn.*` |
| **広告**           | `doubleclick.net`, `adsense`, `adservice`                         |
| **追跡スクリプト** | `hotjar`, `mixpanel`, `segment.io`                                |
| **メディア**       | `youtube.com`, `vimeo.com`                                        |

### カスタム除外設定

```python
analyzer = ProxyLogAnalyzer(
    exclude_patterns=[
        r".*\.stripe\.com.*",  # 決済は除外
        r".*/api/v1/health$",  # ヘルスチェックは除外
    ]
)
```

---

## API リファレンス

### クラス: `ProxyLogAnalyzer`

#### `__init__(self, exclude_patterns: List[str] = None)`

アナライザーを初期化します。

#### `parse_har(self, file_path: str) -> List[ParsedRequest]`

HAR 形式のログファイルを解析します。

#### `parse_caido(self, file_path: str) -> List[ParsedRequest]`

Caido JSON 形式のログを解析します。

#### `analyze(self, requests: List[ParsedRequest]) -> AttackPlan`

リクエストリストを解析し、攻撃計画を生成します。

#### `analyze_and_dispatch(self, file_path: str) -> Dict[str, List[FindingCandidate]]`

ログ解析から攻撃候補の分類までを一括実行します。

### データクラス

```python
@dataclass
class ParsedRequest:
    method: str              # HTTP メソッド
    url: str                 # 完全なURL
    headers: dict            # リクエストヘッダー
    body: str                # リクエストボディ
    response_status: int     # レスポンスステータス
    response_body: str       # レスポンスボディ

@dataclass
class FindingCandidate:
    request: ParsedRequest   # 元のリクエスト
    smell_types: List[SmellType]  # 検出されたSmell
    priority: int            # 優先度 (1=高, 5=低)
    recommended_agent: str   # 推奨エージェント
    # 例: "AuthNinja", "BizLogicHunter"

@dataclass
class AttackPlan:
    candidates: List[FindingCandidate]  # 攻撃候補リスト
    stats: dict                         # 解析統計
```

---

## 使用例 (Usage Examples)

### 基本的な使用法

```python
from src.intelligence import ProxyLogAnalyzer

analyzer = ProxyLogAnalyzer()

# HARファイルを解析
requests = analyzer.parse_har("traffic.har")
print(f"Parsed {len(requests)} requests")

# Smell検出 & 攻撃計画生成
plan = analyzer.analyze(requests)

print(f"Found {len(plan.candidates)} attack candidates")
for candidate in plan.candidates[:10]:  # Top 10
    print(f"  [{candidate.priority}] {candidate.request.url}")
    print(f"      Smells: {[s.name for s in candidate.smell_types]}")
    print(f"      Recommended: {candidate.recommended_agent}")
```

### Master Conductor との統合

```python
def run_hybrid_hunt(log_file: str, scope_file: str):
    analyzer = ProxyLogAnalyzer()
    plan = analyzer.analyze(analyzer.parse_har(log_file))

    # 優先度順にエージェントを派遣
    for candidate in plan.candidates:
        if "AuthNinja" in candidate.recommended_agent:
            auth_ninja.execute(candidate.request.url, {...})
        elif "BizLogicHunter" in candidate.recommended_agent:
            biz_hunter.verify_idor(candidate.request, {...})
```

---

## 出力フォーマット

### AttackPlan 統計 (`stats`)

```json
{
  "total_requests": 1523,
  "after_noise_reduction": 342,
  "candidates_found": 47,
  "smell_distribution": {
    "IDOR_CANDIDATE": 23,
    "JWT_PRESENT": 15,
    "HIDDEN_PARAM": 7,
    "ADMIN_ENDPOINT": 2
  },
  "priority_distribution": {
    "1": 5,
    "2": 12,
    "3": 18,
    "4": 8,
    "5": 4
  }
}
```

---

## 優先度スコアリング

候補は以下のルールで優先度付けされます：

| 優先度       | 条件                    | 例                    |
| :----------- | :---------------------- | :-------------------- |
| **1 (最高)** | 複数の Smell が同時検出 | IDOR + JWT + Admin    |
| **2**        | 認証関連の Smell        | JWT, OAuth, MFA       |
| **3**        | 権限昇格の可能性        | Hidden Param, Admin   |
| **4**        | 単一の IDOR 候補        | 連番 ID のみ          |
| **5 (最低)** | 低リスクの Smell        | 一般的な API 呼び出し |

---

## トラブルシューティング

### 症状: HAR ファイルが解析できない

**原因**: ファイル形式が HAR 1.2 準拠でない
**解決策**: Burp Suite や Chrome DevTools から正しくエクスポート

### 症状: 候補が多すぎる

**原因**: ノイズフィルターが不十分
**解決策**: `exclude_patterns` にターゲット固有のパターンを追加

### 症状: 重要なリクエストがフィルターされる

**原因**: 静的ファイル拡張子に誤って分類
**解決策**: URL を確認し、必要に応じてフィルターを調整
