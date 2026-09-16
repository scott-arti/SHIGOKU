---
task_id: SGK-2026-0314
doc_type: manual
status: draft
parent_task_id: null
related_docs: []
title: 'SGK-2026-0314 amass / bbot 実行不能の原因と修正指示'
created_at: '2026-09-16'
updated_at: '2026-09-16'
tags:
- shigoku
- recon
- tool-integration
target: src/tools/custom/amass.py, src/tools/custom/bbot.py
---

# 実装指示書: amass / bbot の実行不能修正（SGK-2026-0314）

> この文書は別エージェントが実装するための実行指示である。
> 2026-09-16 に Kokuu 側で実機検証した結果に基づく。**推測ではなく実測ログを根拠としている。**

## 0. 結論（先に要点）

| ツール | 状態 | 根本原因 |
|---|---|---|
| **amass** | **一度も動作していない** | `-json` フラグが存在しない。`check=False` でエラーが黙殺されていた |
| **bbot** | **依存導入に失敗して無音で 0 件** | bbot 自身の `pip install` が PEP 668 で拒否される |

両方に共通する問題は **「外部ツールの失敗を成功として扱う」** 構造である（Section 3）。
これが原因で、**失敗が「結果なし」として正常に表示され、誰も気づけなかった。**

---

## 1. amass の不具合

### 1.1 対象箇所

`src/tools/custom/amass.py:52`

```python
cmd = ["amass", "enum", "-d", domain, "-json", "-silent"]
```

### 1.2 原因（4 点）

**(1) `-json` は存在しない**

実機の amass v4.2.0 / v5.1.1 の**どちらにも `-json` フラグが無い**。

```
$ amass enum -d example.com -json -silent
flag provided but not defined: -json
```

`enum` の出力系フラグは `-o`（テキスト）と `-oA`（全形式）のみ。

**(2) エラーが黙殺される（最重要）**

`src/tools/custom/amass.py:60-67`

```python
result = subprocess.run(cmd, capture_output=True, text=True,
                        timeout=timeout_minutes * 60, check=False)
return result.stdout or "No results found."
```

`check=False` で returncode が捨てられ、`-json` エラーで stdout が空でも
**「No results found.」と表示される**。呼び出し側は「サブドメインが無かった」と解釈する。

**(3) amass が 2 つインストールされている**

| パス | バージョン | リリース日 | 状態 |
|---|---|---|---|
| `/home/bbb/go/bin/amass` | v4.2.0 | 2023-09-10 | **3 年前で更新停止** |
| `/home/linuxbrew/.linuxbrew/bin/amass` | v5.1.1 | 2026-04-07 | 現行ライン |

PATH では linuxbrew が先に解決されるため、`amass` は **v5.1.1** になる。
同じコマンド名でバージョンが違うため、手動実行と自動実行で挙動が変わる。

**(4) v5.1.1 は engine 常駐が必須で、ポートが衝突して起動できない**

v5 は client/server 構成（`amass engine` + `amass enum`）に変更された。
engine は **ポート 4000 を固定で bind** するが、**litellm が 4000 を占有している**ため起動しない。

```
$ amass engine
Failed to start the engine: listen tcp :4000: bind: address already in use
```

**ポート変更手段は存在しない（3 方式すべて実機検証済み）:**

| 試行 | 結果 |
|---|---|
| `AMASS_ENGINE_PORT=4001 amass engine` | 効果なし（4000 に bind しようとする） |
| `config.yaml` に `engine: "http://127.0.0.1:4001"` | 効果なし |
| `config.yaml` に `options.engine: "http://127.0.0.1:4001"` | 効果なし |
| `amass engine -h` のオプション | `-log-dir` のみ（ポート指定なし） |

なお `AMASS_ENGINE_PORT` 等の環境変数は**クライアントが接続先を決めるため**のもので、
engine の bind ポートには影響しない。

### 1.3 実測した追加価値（判断材料）

omnicell.com で amass と subfinder を比較した結果:

```
amass が見つけた omnicell.com の FQDN : 173
subfinder が見つけたホスト             : 598
amass のみ（差分）                     :  13
  内訳: _autodiscover._tcp / _sip._tcp / _citrixreceiver._tcp / _collab-edge._tls ...
```

**差分 13 件はすべて SRV / autodiscover レコードで、実ホストはゼロ。**
さらに 300 秒でも完走せず（timeout 到達）、`~/.config/amass/datasources.yaml` は
**183 行すべてコメントアウトされた雛形**で API キーは未設定。

### 1.4 修正方針（選択肢）

**A. amass を一旦無効化する（推奨）**

現状の実測価値がゼロであり、ポート競合が解消できない限り v5 は使えない。
Kokuu はこの方針を採り、除外理由をコード内コメントに残している。

**B. litellm を 4000 から移す**

litellm は LLM ゲートウェイであり、全クライアントの設定変更が必要。
影響範囲が大きく、Shigoku 側だけで完結しない。

**C. v4.2.0 を使い、関連（association）形式パーサーを実装する**

v4 は engine 不要でワンショット実行できる。ただし:

- 出力が `omnicell.com (FQDN) --> ns_record --> ns4.savvis.net (FQDN)` という関連形式
- `-o /dev/stdout` で拾えるが、**そのままホスト一覧として扱うと NS レコードなど
  サブドメイン以外を混入させる**（`ns4.savvis.net` は omnicell.com のサブドメインではない）
- 300 秒超かかる

実装する場合は「`-->` で分割し、`(FQDN)` で終わる要素のうち対象ドメイン配下のものだけ採用」
というフィルタが必須。

**D. API キーを設定してから再評価する**

`~/.config/amass/datasources.yaml` にキーを入れると amass の実力は変わる。
ただし**ポート競合（v5）とフラグ不正は別問題**なので、先に 1.4-A か 1.4-C を決める必要がある。

### 1.5 修正する場合の最小手順

1. `check=False` をやめる（Section 3 の共通修正を適用）
2. `-json` を削除し、採用した出力形式に応じたパーサーを実装
3. どのバイナリを使うか**絶対パスで明示**（PATH 依存をやめる）
4. 無効化する場合は「なぜ無効なのか」をコード内コメントに残す（復帰条件を含める）

---

## 2. bbot の不具合

### 2.1 対象箇所

`src/tools/custom/bbot.py:54`

```python
cmd = ["bbot", "-t", target, "-o", "/tmp/bbot_out", "-y"]
```

### 2.2 原因

**(1) bbot 自身の `pip install` が PEP 668 で拒否される**

bbot はモジュール依存を自前で導入する
（`bbot/core/helpers/depsinstaller/installer.py:271`）:

```python
command = [sys.executable, "-m", "pip", "install", "--upgrade"] + packages
```

`--break-system-packages` が無いため、Debian/Ubuntu 系の
**externally-managed-environment（PEP 668）** で拒否される。

```
[WARN] Failed to install pip packages asyncpg (return code 1): error: externally-managed-environment
[WARN] Setup failed for module "crt_db"
[WARN] Failed to install pip packages baddns~=1.12.294 (return code 1): error: externally-managed-environment
[WARN] Setup failed for module "baddns_direct"
[WARN] Setup failed for module "baddns_zone"
[ERRR] Failed to install dependencies for 4 modules: baddns_direct,baddns_zone,crt_db,sslcert
```

失敗するモジュールと依存:

| モジュール | 依存 | 種別 |
|---|---|---|
| `baddns_direct` / `baddns_zone` | `baddns~=1.12.294` | pip |
| `crt_db` | `asyncpg` | pip |
| `sslcert` | `openssl`（apt）+ `pyOpenSSL~=25.3.0`（pip） | apt + pip |

**(2) `sslcert` が root を要求し、非対話環境で落ちる**

`sslcert` は `deps_apt = ["openssl"]` を持つため、bbot は
`ensure_root()` を呼ぶ（`installer.py:198`）。非対話環境では:

```
File ".../installer.py", line 438, in ensure_root
    _sudo_password = getpass.getpass(prompt="[USER] Please enter sudo password: ")
EOFError
```

**`sudo -v` では解決しない。** bbot は `can_sudo_without_password()` で
`sudo -n true` を試すが、`sudo -v` のキャッシュは**期限付き**（既定 15 分）であり、
bbot 実行時点で切れていれば `getpass` に落ちる。
恒久的に回避するには `BBOT_SUDO_PASS`（秘密情報・各自で設定）か
passwordless sudo が必要。

**(3) bbot はこれを exit 0 で終える**

`src/tools/custom/bbot.py:69-72` が `check=False` + `stdout or stderr or "Scan complete..."` 
のため、**依存導入に失敗しても「スキャン完了」として扱われる**。

### 2.3 修正手順（検証済み）

**(a) `PIP_BREAK_SYSTEM_PACKAGES=1` を bbot 実行時に注入する**

bbot の subprocess に環境変数を渡す。実機で
**`externally-managed-environment` エラーが 0 件になることを確認済み。**

**(b) `--ignore-failed-deps` を付ける**

root を要求する `sslcert` を飛ばして続行する。
`--no-deps` とは**排他**（併用すると argparse エラー）なので注意。

**(c) 結果の確認**

```
$ PIP_BREAK_SYSTEM_PACKAGES=1 bbot -t example.com -p subdomain-enum --ignore-failed-deps --json
[SUCC] Setup succeeded for 46/65 modules.
```

`No API key set` で soft-fail するモジュール（c99 / censys_dns / otx / passivetotal 等）は
API キー未設定によるもので、正常な状態。

**(d) `check=False` をやめる**（Section 3）

---

## 3. 共通の根本原因（最重要）

amass と bbot に共通するのは **「外部ツールの失敗を成功として扱う」** 構造である。

| 箇所 | 問題のあるコード |
|---|---|
| `amass.py:60-67` | `check=False` + `result.stdout or "No results found."` |
| `bbot.py:69-72` | `check=False` + `result.stdout or result.stderr or "Scan complete..."` |

`check=False` で returncode が捨てられ、stdout が空でも既定メッセージが返る。
そのため**エージェントは「結果なし」を受け取り、ツールが壊れていることに気づけない。**

### 推奨する共通修正

```python
result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

# exit code を必ず評価する（check=False にしない）
if result.returncode != 0:
    return (f"Error: {cmd[0]} failed (exit={result.returncode}): "
            f"{result.stderr.strip()[-500:]}")

# exit 0 でも無出力なら「成功」と言わない
if not result.stdout.strip():
    return (f"Warning: {cmd[0]} returned no output (exit=0). "
            f"stderr: {result.stderr.strip()[-500:]}")

return result.stdout
```

**「exit 0 かつ無出力」を成功として扱わない**ことが要点である。
Kokuu 側ではこの状態を `empty` という専用 status にして可視化した。

---

## 4. 検証手順

```bash
# amass: -json が存在しないことの確認（現行コードが壊れている証拠）
amass enum -h 2>&1 | grep -E "^\s+-json" \
  && echo "NG: -json が存在する（前提が変わった。再調査）" \
  || echo "OK: -json は存在しない（現行コードは壊れている）"

# amass: engine が起動できないことの確認
amass engine 2>&1 | head -1
# → Failed to start the engine: listen tcp :4000: bind: address already in use

# ポート 4000 の占有者
ss -ltnp 2>/dev/null | grep ':4000'
# → users:(("litellm",...))

# bbot: 外部管理エラーが出ないことの確認
PIP_BREAK_SYSTEM_PACKAGES=1 bbot -t example.com -p subdomain-enum --ignore-failed-deps --json 2>&1 \
  | grep -c externally-managed
# → 0 であること

# bbot: モジュール導入結果
PIP_BREAK_SYSTEM_PACKAGES=1 bbot -t example.com -p subdomain-enum --ignore-failed-deps --json 2>&1 \
  | grep "Setup succeeded"
# → [SUCC] Setup succeeded for 46/65 modules.
```

---

## 5. 参考: Kokuu 側で実施した修正（2026-09-16 / commit `38dedc8`）

同一の問題を Kokuu でも検出し、以下を実施済み。判断の参考として記載する。

| 修正 | 内容 |
|---|---|
| amass の除外 | 列挙ツールから除外し、除外理由と復帰条件をコード内コメントに記載 |
| bbot の env 注入 | `PIP_BREAK_SYSTEM_PACKAGES=1` を subprocess に注入 |
| bbot のフラグ | `--ignore-failed-deps` を追加 |
| 段の status | `partial` を導入し「一部失敗」を成功と区別 |
| ツールの status | `empty` を導入し「exit 0 かつ 0 件」を `ok` と区別 |
| エラー抽出 | stderr 先頭 200 字を切る方式をやめ、定型ノイズ（警告/guard/info）を除いた末尾を採用。**先頭を切ると実エラーが消え、ラッパーの警告だけが残っていた** |

検証結果（実走）:

```
WARNING: 列挙が一部不全: bbot=empty(exit=0)。結果は成功分のみ
  01-enumerate -> partial
      subfinder ok    count=425
      bbot      empty count=0  err="[ERRR] Error loading module baddns: No module named..."
```

テスト: recon_run 15/15 / recon_profiles 23/23 / guard 33/33 / caido_check 5/5

---

## 6. 作業順序の推奨

1. **Section 3 の共通修正**（`check=False` の廃止）を先に適用する
   - これをやらないと、以降の修正が正しく効いたか判定できない
2. **Section 2 の bbot 修正**（env 注入 + `--ignore-failed-deps`）
   - 検証済みで確実に動く。成功体験として先に潰す
3. **Section 1 の amass 方針決定**（1.4 の A〜D から選択）
   - ポート競合が解消できない限り v5 は使えない。方針決定に飼い主の判断が必要
