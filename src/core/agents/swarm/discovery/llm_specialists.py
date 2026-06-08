
import logging
import asyncio
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity
from src.core.models.llm import LLMClient
from src.core.agents.specialized.js_mine import JSMineAgent, SecretFinding
from src.core.security.pii_masker import get_pii_masker

logger = logging.getLogger(__name__)

class LLMSecretScanner(Specialist):
    """
    LLM ベースのシークレットスキャナー
    
    JSMineAgent (正規表現) を使用して初期検知を行い、その後 LLM を使用して
    そのシークレットが本物（機密情報）か、あるいは偽陽性（テストデータ、サンプル等）かを確認します。
    """
    name = "LLMSecretScanner"
    description = "JS/HTML 内のハードコードされたシークレットを検出し、LLM で監査して偽陽性を削減します。"
    is_aggressive = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        from src.config import settings
        default_model = getattr(settings, "model_output", None) or getattr(settings, "model", "deepseek/deepseek-chat")
        model = config.get("model", default_model) if isinstance(config, dict) else getattr(config, "model", default_model)
        self.llm = LLMClient(model=model)
        
    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        target = task.target
        js_urls = task.params.get("js_urls", [])
        
        # ターゲットの決定
        if not js_urls and target.endswith(".js"):
            js_urls = [target]
            
        if not js_urls:
            logger.warning("[%s] JS URL が指定されていません", self.name)
            return findings
            
        logger.info("[%s] %d 個の JS ファイルを LLM 監査でスキャン中", self.name, len(js_urls))
        
        masker = get_pii_masker()

        for js_url in js_urls[:10]: # パフォーマンスのため 10 ファイルに制限
            try:
                content = await self._fetch_content(js_url)
                if not content:
                    continue
                    
                # 1. 高速な正規表現スキャン
                agent = JSMineAgent()
                result = agent.analyze(content, js_url)
                raw_secrets_dicts = result.get("secrets", [])
                
                if not raw_secrets_dicts:
                    continue
                    
                # 2. LLM 監査
                for secret_dict in raw_secrets_dicts:
                    # 辞書を SecretFinding オブジェクトに戻す
                    secret = SecretFinding(**secret_dict)
                    is_valid = await self._audit_with_llm(secret, content)
                    if is_valid:
                        # Finding への変換とマスク処理
                        title_masked = masker.mask(f"Confidential Secret: {secret.type}").masked
                        desc_masked = masker.mask(f"Found {secret.type} in {js_url}.\nContext: {secret.context}").masked
                        
                        f = Finding(
                            title=title_masked,
                            description=desc_masked,
                            vuln_type=VulnType.SECRET_LEAK,
                            severity=Severity.HIGH,
                            evidence=secret.value, # 証拠としてのシークレット値
                            target_url=js_url
                        )
                        findings.append(f)
                    else:
                        logger.debug("[%s] %s を偽陽性として破棄しました", self.name, secret.type)
                        
            except Exception as e:
                logger.error("[%s] %s の分析中にエラーが発生しました: %s", self.name, js_url, e)
                
        return findings

    async def _fetch_content(self, url: str) -> Optional[str]:
        try:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                response = await client.request("GET", url, timeout=30.0, follow_redirects=True)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            logger.error("[%s] %s のコンテンツ取得に失敗しました: %s", self.name, url, e)
            pass
        return None

    async def _audit_with_llm(self, secret: SecretFinding, full_content: str) -> bool:
        """
        LLM にシークレットが本物のように見えるか尋ねます。
        """
        prompt = f"""
あなたはセキュリティ監査人です。以下のコードスニペットを分析し、検出されたシークレットが本物の機密情報（資格情報）か、あるいは偽陽性（テストデータ、プレースホルダー、サンプル値、非機密文字列）かを判断してください。

コードの文脈:
```javascript
{secret.context}
```

検出されたシークレット値: "{secret.value}"
タイプ: {secret.type}

本物のシークレットの基準:
- エントロピー（複雑さ）が高い
- 'apiKey', 'password', 'secret' といった変数に割り当てられている
- 'EXAMPLE', 'TEST', '12345', 'placeholder' ではない（ただし[PII:...]トークンは例外）
- もし値が `[PII:...]` の形式でマスクされている場合、それは既にPIIフィルターによって検出されたシークレットであるため、**本物である可能性が高い**と判断し、Trueを返してください。

JSON 形式のみで回答してください:
{{
  "is_real_secret": boolean,
  "reason": "短い説明"
}}
"""
        try:
            # PIIマスクを有効（デフォルト）にし、クラウドへはマスク済みデータを送る
            response = await self.llm.agenerate([{"role": "user", "content": prompt}])
            
            # 必要に応じて ModelResponse からコンテンツを抽出
            content = str(response)
            if hasattr(response, "choices"):
                content = response.choices[0].message.content
                
            # JSON を安全にパース
            import json
            # 軽微なクリーンアップ
            json_str = content.replace("```json", "").replace("```", "").strip()
            data = json.loads(json_str)
            return data.get("is_real_secret", False)
            
        except Exception as e:
            logger.warning("[%s] LLM 監査に失敗しました: %s", self.name, e)
            # 失敗時は安全側に倒すか、ノイズを避けるかの戦略が必要
            # ここでは偽陽性を減らすという目的に基づき、LLM が確認できない場合は False を返す
            return False
