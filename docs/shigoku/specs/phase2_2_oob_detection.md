---
task_id: SGK-2026-0147
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 2.2: OOB (Out-of-Band) Detection 仕様書

## 概要

**機能名**: `LocalOOBListener`

**目的**:
外部のパブリックサーバー (`interactsh`など) を使用せず、ローカル環境内で完結する Out-of-Band 検出基盤を提供する。
主に Blind SSRF, Blind RCE などの「外部への通信」をトリガーとする脆弱性を検出する。

**方針変更**:

- Public Interactsh は使用しない（情報漏洩リスク回避）。
- `aiohttp` を使用した軽量な HTTP リスナーサーバーをローカルで立ち上げる。
- DNS Listener は特権ポートが必要なため、今回は **HTTP Only** とする。

---

## 変更範囲

| ファイル                               | 変更内容                             |
| -------------------------------------- | ------------------------------------ |
| `src/core/utils/oob_listener.py`       | 📝 全面改修 - Local HTTP Server 実装 |
| `src/core/agents/spec/oob_verifier.py` | 🆕 新規 - 検証Agent                  |
| `tests/unit/utils/test_oob.py`         | 🆕 新規 - テスト                     |

---

## 機能詳細

### 1. LocalHttpListener

`aiohttp.web` を使用して、バックグラウンドで HTTP サーバーを起動する。

```python
class LocalOOBListener:
    def __init__(self, host="0.0.0.0", port=13337):
        self.host = host
        self.port = port
        self.callback_url = f"http://{host}:{port}/callback"
        self._app = web.Application()
        self._runner = None
        self._site = None
        self._interactions = asyncio.Queue()

    async def start(self):
        """サーバー起動"""
        self._app.router.add_get('/callback/{token}', self._handle_callback)
        self._app.router.add_post('/callback/{token}', self._handle_callback)
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()

    async def _handle_callback(self, request):
        token = request.match_info['token']
        # インタラクション記録
        await self._interactions.put({
            "token": token,
            "remote": request.remote,
            "method": request.method,
            "timestamp": time.time()
        })
        return web.Response(text="OK")

    async def wait_for_token(self, token: str, timeout: float = 10.0) -> bool:
        """指定したトークンの着信を待つ"""
        start = time.time()
        while time.time() - start < timeout:
            # キューから探す実装（実際はもう少し効率的に）
            pass
```

### 2. Payload Generator

ローカルサーバーに向けたペイロードを生成する。
※ ターゲットサーバーからローカルへのアクセスが可能である前提（イントラネット診断やSSRFでlocalhostを叩ける場合など）。
※ コンテナ環境やクラウドの場合、外部から到達可能なIP/ドメインを設定できるようにする。

```python
class OOBPayloadGenerator:
    def __init__(self, listener_url: str):
        self.base_url = listener_url

    def generate_ssrf_payload(self) -> Tuple[str, str]:
        token = secrets.token_hex(4)
        url = f"{self.base_url}/{token}"
        return url, token
```

### 3. 注意点

- **到達可能性**: ターゲットが `localhost` やプライベートIPにアクセスできない場合（Firewall等）、この検証は失敗する。
  - ユーザーに「OOB Listener Host」を設定させるオプション (`--oob-host`) を追加する。
  - デフォルトは、ローカル実行なら `127.0.0.1` またはLAN IP。

---

## 完了条件

- ローカルサーバーが起動し、`curl` で叩いて検知できること。
- テストコードでサーバー起動・検知・終了が正しく動作すること。
