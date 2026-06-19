---
task_id: SGK-2026-0139
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Spec: サブプロセス実行の最適化

## 概要

SHIGOKU の外部ツール（Nuclei、ffuf、Katanaなど）実行における**プロセス起動オーバーヘッドの削減**と**並列実行制御の改善**を行う。

## 背景

### 現状の問題点

指摘を受けた内容:

1. **プロセス起動オーバーヘッド**: 毎回新規プロセスを作成するため、起動コストが高い
2. **リソース管理の欠如**: 同時実行数の制限がなく、大量のプロセスが起動される可能性
3. **タイムアウト制御の不統一**: ツールごとにタイムアウト設定が異なり、ハングする場合がある

### コードベースの分析結果

#### 同期実行パターン (`subprocess.run`)

- **対象**: 44箇所
- **主なツール**: nuclei, ffuf, katana, nmap, sqlmap, etc.
- **現状**: `subprocess.run()` を毎回新規プロセスで実行
- **問題**:
  - プロセス起動オーバーヘッドが毎回発生
  - 同時実行数制限なし

#### 非同期実行パターン (`asyncio.create_subprocess_exec`)

- **対象**: 13箇所
- **主なツール**: nuclei_wrapper, nmap_wrapper, arjun_wrapper, leak_detector, parallel_tasks
- **現状**: 非同期でプロセスを起動するが、プール管理なし
- **問題**:
  - バッファサイズが未指定（デフォルト: 64KB）→ 大量出力でハング
  - 同時実行数制限なし

## 改善策の選択肢

### 選択肢1: ProcessPool方式（指摘された方法）

```python
class ProcessPool:
    def __init__(self, max_workers=20):
        self._semaphore = asyncio.Semaphore(max_workers)

    async def execute(self, cmd, timeout=300):
        async with self._semaphore:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024*1024  # 1MBバッファ
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                return stdout, stderr
            except asyncio.TimeoutError:
                proc.kill()
                raise
```

**メリット**:

- ✅ 同時実行数制御（Semaphore）
- ✅ タイムアウト制御の統一
- ✅ バッファサイズの最適化
- ✅ 既存コードの変更が少ない

**デメリット**:

- ❌ プロセス起動オーバーヘッド自体は残る
- ❌ 頻繁に実行されるツールには不向き

### 選択肢2: ライブラリバインディング方式

各ツールをPythonバインディング経由で実行:

| ツール     | Pythonバインディング | 備考                     |
| ---------- | -------------------- | ------------------------ |
| **Nmap**   | `python-nmap`        | ✅ 利用可能              |
| **Nuclei** | ❌ なし              | Go製、バインディング不可 |
| **ffuf**   | ❌ なし              | Go製、バインディング不可 |
| **Katana** | ❌ なし              | Go製、バインディング不可 |
| **sqlmap** | ✅ APIモード         | HTTP API利用可能         |

**メリット**:

- ✅ プロセス起動オーバーヘッドゼロ
- ✅ Pythonから直接制御可能

**デメリット**:

- ❌ 大半のツール（Go製）はバインディング不可
- ❌ 実装コストが高い
- ❌ メンテナンス負荷が増大

### 選択肢3: サーバーモード方式

一部のツールが対応している常駐型モード:

| ツール         | サーバーモード対応      |
| -------------- | ----------------------- |
| **Nuclei**     | ❌ 非対応               |
| **ffuf**       | ❌ 非対応               |
| **sqlmap**     | ✅ API Server (`--api`) |
| **Burp Suite** | ✅ REST API             |

**メリット**:

- ✅ 起動オーバーヘッドなし（1回だけ起動）
- ✅ HTTP API経由で柔軟に制御

**デメリット**:

- ❌ 対応ツールが限定的
- ❌ サーバー管理の複雑性が増す

## 推奨アプローチ: **ハイブリッド戦略**

> [!IMPORTANT]
> **結論**: プロセス起動オーバーヘッドをゼロにする理想論よりも、**実用性と保守性を重視**し、**ProcessPool方式を基本とし、一部ツールのみサーバーモードを検討**する段階的アプローチを採用する。

### 理由

1. **大半のツールがGo製** → Pythonバインディング不可
2. **Nuclei、ffufなどの主要ツールがサーバーモード非対応**
3. **プロセス起動は1スキャンあたり数回程度** → オーバーヘッドは許容範囲内
4. **実装コストとメンテナンス性のトレードオフ**

### 段階的移行計画

#### Phase 1: ProcessPool導入（全ツール対象）🎯

- **対象**: 全外部ツール（同期/非同期）
- **手段**:
  - `ProcessPool` クラスを `src/core/infra/process_pool.py` に実装
  - 既存の `subprocess.run` を `ProcessPool.execute_sync` に置換
  - 非同期版は `ProcessPool.execute_async` に置換
- **優先度**: **高**（すぐに実装可能で効果大）

#### Phase 2: Sqlmap API Server統合（オプション）

- **対象**: Sqlmapのみ
- **手段**: `--api` モードで起動し、HTTPリクエスト経由で制御
- **優先度**: **低**（必要性が出てから検討）

## 変更範囲

### 新規作成

- `src/core/infra/process_pool.py` - ProcessPoolクラス

### 変更対象

#### 非同期ツール（高優先）

- `src/tools/scanners/nuclei_wrapper.py`
- `src/tools/scanners/nmap_wrapper.py`
- `src/tools/fuzzing/arjun_wrapper.py`
- `src/tools/osint/leak_detector.py`
- `src/recon/parallel_tasks.py`
- `src/recon/tool_runner.py`

#### 同期ツール（中優先）

- `src/tools/custom/nuclei.py`
- `src/tools/custom/ffuf.py`
- `src/tools/custom/katana.py`
- `src/tools/custom/nmap.py`
- `src/tools/custom/sqlmap.py`
- その他42ファイル

## 実装内容

### 1. ProcessPool クラスの実装

```python
# src/core/infra/process_pool.py
import asyncio
import subprocess
import logging
from typing import List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ProcessConfig:
    """プロセス実行設定"""
    timeout: int = 300
    buffer_limit: int = 1024 * 1024  # 1MB
    max_workers: int = 20

class ProcessPool:
    """
    外部プロセス実行用のプール管理クラス。

    機能:
    - 同時実行数制限（Semaphore）
    - タイムアウト制御の統一
    - バッファサイズの最適化
    - プロセスのクリーンアップ
    """

    def __init__(self, config: Optional[ProcessConfig] = None):
        self._config = config or ProcessConfig()
        self._semaphore = asyncio.Semaphore(self._config.max_workers)

    async def execute_async(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        env: Optional[dict] = None
    ) -> Tuple[str, str, int]:
        """
        非同期でコマンドを実行。

        Args:
            cmd: コマンドとその引数のリスト
            timeout: タイムアウト（秒）、Noneの場合はデフォルト値
            env: 環境変数

        Returns:
            (stdout, stderr, returncode)

        Raises:
            asyncio.TimeoutError: タイムアウト時
        """
        timeout = timeout or self._config.timeout

        async with self._semaphore:
            logger.debug(f"Starting process: {cmd[0]} (limit: {self._semaphore._value})")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=self._config.buffer_limit,
                env=env
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
                return (
                    stdout.decode('utf-8', errors='replace'),
                    stderr.decode('utf-8', errors='replace'),
                    proc.returncode
                )
            except asyncio.TimeoutError:
                logger.warning(f"Process timed out after {timeout}s: {cmd[0]}")
                proc.kill()
                await proc.wait()
                raise
            except Exception as e:
                logger.error(f"Process execution failed: {e}")
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                raise

    def execute_sync(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None
    ) -> subprocess.CompletedProcess:
        """
        同期的にコマンドを実行（subprocess.runのラッパー）。

        Note:
            同期版は現状維持（subprocess.run）。
            将来的に asyncio.run() でラップして Semaphore 適用も可能。
        """
        timeout = timeout or self._config.timeout

        logger.debug(f"Starting sync process: {cmd[0]}")

        return subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
            shell=False,
            env=env
        )

# グローバルインスタンス（シングルトン的に使用）
_default_pool: Optional[ProcessPool] = None

def get_process_pool() -> ProcessPool:
    """デフォルトのProcessPoolインスタンスを取得"""
    global _default_pool
    if _default_pool is None:
        _default_pool = ProcessPool()
    return _default_pool
```

### 2. 非同期ツールの修正例

```python
# src/tools/scanners/nuclei_wrapper.py (修正後)
from src.core.infra.process_pool import get_process_pool

async def run_nuclei(target: str) -> str:
    cmd = ["nuclei", "-u", target, "-json", "-silent"]

    pool = get_process_pool()
    stdout, stderr, returncode = await pool.execute_async(
        cmd,
        timeout=3600
    )

    if returncode != 0:
        logger.error(f"Nuclei failed: {stderr}")

    return stdout
```

### 3. 同期ツールの修正例

```python
# src/tools/custom/ffuf.py (修正後)
from src.core.infra.process_pool import get_process_pool

def run(self, url: str, wordlist: str, ...) -> str:
    cmd = [self.FFUF_PATH, "-u", url, "-w", wordlist]

    pool = get_process_pool()
    result = pool.execute_sync(cmd, timeout=600)

    if result.returncode != 0:
        return f"Error: {result.stderr}"

    return result.stdout
```

## 検証方法

### 1. ユニットテスト

```python
# tests/core/infra/test_process_pool.py
import pytest
import asyncio
from src.core.infra.process_pool import ProcessPool, ProcessConfig

@pytest.mark.asyncio
async def test_concurrent_execution_limit():
    """同時実行数制限のテスト"""
    pool = ProcessPool(ProcessConfig(max_workers=2))

    async def slow_cmd():
        return await pool.execute_async(["sleep", "1"])

    # 3つの並列タスクを起動（制限は2）
    start = asyncio.get_event_loop().time()
    await asyncio.gather(*[slow_cmd() for _ in range(3)])
    elapsed = asyncio.get_event_loop().time() - start

    # 最低2秒かかるはず（2つずつ実行されるため）
    assert elapsed >= 2.0

@pytest.mark.asyncio
async def test_timeout_handling():
    """タイムアウト処理のテスト"""
    pool = ProcessPool()

    with pytest.raises(asyncio.TimeoutError):
        await pool.execute_async(["sleep", "10"], timeout=1)
```

### 2. パフォーマンス測定

```bash
# 改善前
time python -m src.main --target example.com --mode bugbounty

# 改善後
time python -m src.main --target example.com --mode bugbounty
```

**期待される改善**:

- 同時実行数制限によるリソース消費の安定化
- バッファサイズ最適化によるハング減少
- タイムアウト統一による予測可能な実行時間

## 非機能要件

### セキュリティ

- ✅ `safe_subprocess.safe_run()` との互換性を維持
- ✅ `shell=False` を強制

### パフォーマンス

- ✅ 同時実行数: デフォルト20（調整可能）
- ✅ バッファサイズ: 1MB（大量出力対応）
- ✅ タイムアウト: ツールごとに適切な値を設定

### 保守性

- ✅ 既存コードへの影響を最小化
- ✅ シングルトンパターンで一元管理

## 将来の拡張性

### Phase 3以降の検討事項（優先度: 低）

1. **プロセスキャッシュ** (選択肢1の「長時間実行ツール用」)
   - 頻繁に使うツールのプロセスを再利用
   - 対象: sqlmap（API Server）、Burp Suite（REST API）

2. **適応的ワーカー調整**
   - CPU/メモリ使用状況に応じて `max_workers` を動的調整

3. **ツールプロファイリング**
   - 各ツールの平均実行時間を記録し、スケジューリングに活用

## まとめ

> [!NOTE]
> **選択した戦略**: ProcessPool方式（Phase 1）を最優先で実装する。
>
> **理由**:
>
> - ✅ 実装コストが低い
> - ✅ 全ツールに適用可能
> - ✅ プロセス起動オーバーヘッドは許容範囲内（1スキャン数回程度）
> - ✅ 同時実行制御とタイムアウト統一で十分な改善効果

**ライブラリバインディングやサーバーモードは、特定ツールで明確なボトルネックが確認されてから検討する**。

## 制約と注意事項

1. **EthicsGuard との統合**
   - ProcessPool は `safe_subprocess` を経由せず直接実行する
   - セキュリティチェックは各ツールクラスの `run()` 内で実施

2. **イベントループの寿命**
   - `AsyncNetworkClient` と同様、ループが切り替わる可能性に対応
   - ProcessPool はループごとに再作成しない（グローバルSemaphore）

3. **Docker環境対応**
   - Dockerコンテナ内でのプロセス数制限を考慮
   - `max_workers` は環境変数で上書き可能にする
