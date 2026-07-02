---
task_id: SGK-2026-0048
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Reconnaissance Pipeline シナリオ設計書

**最終更新**: 2026-01-12

## 1. 現状の課題

- 現在の `--recon` は、スコープタイプに関わらず **Cartographer (クローラー) → Fingerprinter** の固定フローのみ
- Wildcard や複数サブドメイン指定など、実戦的なバグバウンティのスコープに対応していない
- 各ステップで LLM を挟むため、API コストと不確実性が高い

## 2. 新設計方針

- Recon は **定型処理** なので、**スクリプト駆動型パイプライン（確定的なツールチェーン）** で実行
- LLM は、パイプライン完了後の「結果解釈」「後続エージェント振り分け」にのみ使用
- ツールは **起動時に全チェック** し、不足があればエラー終了（フォールバックなし）

---

## 3. スコープ分類

ScopeParser がターゲット入力を解析し、以下のいずれかに分類：

| タイプ            | 例                               | 処理開始点                |
| :---------------- | :------------------------------- | :------------------------ |
| **Wildcard**      | `*.example.com`                  | Subdomain Discovery から  |
| **Explicit List** | `[a.example.com, b.example.com]` | Live Check から           |
| **Single Host**   | `target.com`                     | Port Scan / Web Scan から |
| **CIDR / Range**  | `192.168.1.0/24`                 | Network Scan から         |

---

## 4. Wildcard Recon フロー

```
0. 入力正規化（全フロー共通）
   └─ スコープ入力形式に従いパース → ターゲットリスト化

1. Subdomain Discovery
   ├─ subfinder -d target.com -all -silent -o YYYYMMDD_subfinder.txt
   ├─ amass enum -d target.com -active -json -o YYYYMMDD_amass.json
   │      → サブドメイン抽出 + ASN/DNS名も別途保存
   ├─ bbot -t target.com -p subdomain-enum -f asn -f cloud-enum
   │      → SUBDOMAIN, ASN, STORAGE_BUCKET を抽出
   └─ 統合 → YYYYMMDD_all_subs.txt

2. Historical Discovery
   └─ gau --subs target.com -o YYYYMMDD_gau_urls.txt
          → URLリストをそのまま保存
          → ホスト部抽出 → all_subs.txt に追加

3. Live Check & Technology
   ├─ shuffledns -d target.com -r resolvers.txt -o YYYYMMDD_resolved.txt
   ├─ httpx -l resolved.txt -o YYYYMMDD_httpx.json -json
   │      → YYYYMMDD_live_subs.txt も生成
   └─ whatweb（補完として Tech Stack 特定）→ YYYYMMDD_whatweb.json

4. WAF Detection
   └─ wafw00f -l live_subs.txt → YYYYMMDD_wafw00f.json

5. Port Scan (Responsive Hosts)
   ├─ Phase 1 (高速): naabu top20 + nmap → YYYYMMDD_naabu_top20.json
   └─ Phase 2 (網羅): naabu 全ポート（バックグラウンド実行）

6. 分類ファイル生成（サブドメイン分類）
   ※ httpx/wafw00f/naabu/whatweb の結果を統合し、サブドメインを分類
   ※ 各エントリに WAF/Tech 情報を統合

   ┌─ HTTPステータスベース
   ├─ live_200.json（200 OK）
   ├─ live_403.json（403 Forbidden → BypassAgent）
   ├─ live_401_302.json（認証系 401/302/307 → AuthAgent）
   │
   ┌─ サブドメイン名ベース
   ├─ dev_staging.json（dev/staging/test/uat/qa/sandbox）
   ├─ internal_names.json（internal/corp/intranet/vpn/private）
   ├─ high_value.json（payment/billing/admin/secret）
   │
   ┌─ ポートベース
   ├─ web_ports.json（80, 443, 8080, 8443, 3000, 5000）
   ├─ database_ports.json（3306, 5432, 1433, 27017, 6379）
   ├─ other_ports.json（不明ポート）
   │
   ┌─ テクノロジーベース
   ├─ tech_nginx.json
   ├─ tech_apache.json
   ├─ tech_iis.json
   ├─ tech_other.json
   │
   ┌─ クラウド/CDNベース（WAF/Tech情報から判定）
   ├─ cloud_aws.json（AWS/CloudFront）
   ├─ cloud_azure.json（Azure/FrontDoor）
   ├─ cloud_gcp.json（GCP/CloudStorage）
   ├─ cloud_cloudflare.json（Cloudflare）
   │
   ┌─ 特殊（Step 1-3 で生成済み）
   ├─ takeover_candidates.json（NXDOMAIN/Dead → TakeoverAgent）
   ├─ buckets.json（S3/GCS/Azure）
   ├─ asn.json（ASN情報）
   └─ live_uncategorized.json（分類に入らなかったLiveサブドメイン）

   各エントリ形式:
   {
     "subdomain": "dev.example.com",
     "url": "https://dev.example.com",
     "status_code": 200,
     "ports": [80, 443],
     "waf": "Cloudflare",
     "tech": ["nginx", "PHP"]
   }

7. ProjectManager に保存
   ├─ 分類JSONファイルを ~/.shigoku/workspace/projects/<project>/recon/ に保存
   └─ 命名規則: YYYYMMDD_<project>_<category>.json

8. MasterConductor へ結果返却
   └─ メタデータ付き辞書を返却:
      {
        "live_200": {
          "file": "/path/to/20260112_example_com_live_200.json",
          "count": 45,
          "description": "200 OKを返すライブサブドメイン"
        },
        ...
      }
```

---

## 5. 出力ファイル規則

### 保存先

```
~/.shigoku/workspace/projects/<project_name>/recon/
```

### 命名規則

```
YYYYMMDD_<project>_<type>.json
例: 20260112_example_com_live_200.json
```

---

## 6. MasterConductor 連携

### トリガー方式

- Recon Pipeline 完了後、**関数戻り値で直接結果を渡す**（ポーリングなし）

### 処理フロー

```
[MasterConductor]
    ↓ 「Reconを実行」
[Recon Pipeline Script] (Python + subprocess)
    ↓ 結果（分類ファイル群 + メタデータ）
[MasterConductor] 結果受け取り
    ↓ カテゴリ名と description で振り分け判断
    ├─ live_403 → BypassAgent
    ├─ database_ports → 通知（要確認）
    └─ live_200 → GeneralWebAgent（Nuclei/ffuf等）
[サブエージェント] 実行
    ↓ 結果
[MasterConductor] 集約 → ProjectManager に保存
```

**注意：**

- 分類ファイルが存在しない or 空（count=0）の場合は **MC に渡さない**（タスク生成しない）
- 各エントリの `waf` フィールドを見てサブエージェントが対応を変更

---

## 7. 決定済み事項一覧

| #   | 項目                 | 決定                                                 |
| :-- | :------------------- | :--------------------------------------------------- |
| 1   | EthicsGuard          | all_subs.txt 生成後にスコープ外を除外                |
| 2   | タイムアウト/上限    | 設定ファイルで上限設定可能                           |
| 3   | Resolvers            | Fresh-Resolvers から 25 件取得、都度上書き           |
| 4   | httpx Tech Stack     | whatweb で代替/補完                                  |
| 5   | ツール未インストール | 起動時全チェック、不足でエラー終了                   |
| 6   | 中断・再開           | チェックポイントファイル（recon_state.json）         |
| 7   | 完了判定             | 全ツール完了、ツール別件数を集計出力                 |
| 8   | 分類方式             | サブドメイン分類（HTTP ステータス/名前/ポート/Tech） |
| 9   | WAF 情報             | 独立ファイルではなく各 JSON エントリに統合           |
| 10  | MC 返却形式          | メタデータ付き辞書（file, count, description）       |
| 11  | データ保存           | ProjectManager でプロジェクト単位でファイル保存      |

---

## 8. 実装状況

| ステップ                     | 状態    | 実装ファイル            |
| ---------------------------- | ------- | ----------------------- |
| Step 1: Subdomain Discovery  | ✅ 完了 | `src/recon/pipeline.py` |
| Step 2: Historical Discovery | ✅ 完了 | `src/recon/pipeline.py` |
| Step 3: Live Check           | ✅ 完了 | `src/recon/pipeline.py` |
| Step 4: WAF Detection        | ✅ 完了 | `src/recon/pipeline.py` |
| Step 5: Port Scan            | ✅ 完了 | `src/recon/pipeline.py` |
| Step 6: Classification       | ✅ 完了 | `src/recon/pipeline.py` |
| Step 7: PM Save              | ✅ 完了 | `src/recon/pipeline.py` |
| Step 8: MC Return            | ✅ 完了 | `src/recon/pipeline.py` |
