"""
File Upload Specialist
LogicSwarmの一部として動作し、ファイルアップロード脆弱性検査を担当する。
Core Attack Module (FileUploadTester) を利用して攻撃を実行し、
結果をFinding形式で報告する。
"""

import logging
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.attack.file_upload_tester import FileUploadTester
from src.core.infra.network_client import AsyncNetworkClient

# ProxyManager連携のため
from src.core.infra.proxy_manager import get_proxy_manager

logger = logging.getLogger(__name__)

class FileUploadSpecialist(Specialist):
    """
    Unrestricted File Upload Vulnerability Specialist
    ファイルアップロード機能に対する攻撃（RCE狙い）を実行する
    """
    name = "FileUploadSpecialist"
    description = "Detects Unrestricted File Upload vulnerabilities leading to RCE"
    timeout_seconds = 300 # アップロードは時間がかかる場合がある
    is_aggressive = True  # 書き込みを伴うため
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # クライアント初期化 (ProxyManager連携)
        proxy_manager = None
        try:
            proxy_manager = get_proxy_manager()
        except (ImportError, AttributeError, ValueError):
            pass
        except Exception:
            logger.debug("Failed to initialize proxy manager for FileUploadSpecialist")

        self._client = AsyncNetworkClient(proxy_manager=proxy_manager)
        self._tester = FileUploadTester(client=self._client)

    async def close(self):
        """リソースを解放する"""
        if self._client:
            await self._client.close()
        await super().close()

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """
        タスクを実行し、脆弱性を検出する
        
        Args:
            task: ターゲット情報を含むタスク
            
        Returns:
            List[Finding]: 検出された脆弱性リスト
        """
        findings = []
        
        # 1. Katana URL の収集 (コンテキスト)
        katana_urls = []
        try:
            from src.core.project.project_manager import get_project_manager
            # プロジェクト名を取得（タスクパラメータ、またはターゲットURLから）
            project_name = task.params.get("project_name")
            if not project_name:
                from urllib.parse import urlparse
                project_name = urlparse(task.target).netloc
            
            pm = get_project_manager(project_name)
            tagged_dir = pm.project_dir / "tagged_urls"
            
            if tagged_dir.exists():
                import json
                # .jsonl ファイル（Katana等の出力）を読み込む
                for jsonl_file in tagged_dir.glob("*.jsonl"):
                    try:
                        with open(jsonl_file, "r", encoding="utf-8") as f:
                            for line in f:
                                if not line.strip(): continue
                                entry = json.loads(line)
                                if "url" in entry:
                                    katana_urls.append(entry["url"])
                    except Exception as e:
                        logger.debug("Failed to read %s: %s", jsonl_file, e)
                
                logger.info("Loaded %d contextual URLs from project %s", len(katana_urls), project_name)
        except (ImportError, ValueError) as e:
            logger.debug("Project context loading aborted: %s", e)
        except Exception as e:
            logger.debug("Project context loading failed: %s", e)

        # 2. Tester の初期化と実行
        # タスクごとに Katana URL を反映させるため、ここで作成
        tester = FileUploadTester(client=self._client, katana_urls=katana_urls)
        
        # パラメータの抽出
        param_name = task.params.get("param_name", "file")
        extra_params = task.params.get("extra_params", {})
        
        # 実行 (Aggressive=True 必須)
        results = await tester.test_upload(
            target_url=task.target,
            param_name=param_name,
            extra_params=extra_params,
            auth_headers=task.params.get("headers"),
            aggressive=self.is_aggressive
        )
        
        # 3. 結果の Finding 化
        for res in results:
            if res.success:
                # 脆弱性情報の構築
                path_summary = "\n".join([f"- {p.url} (Score: {p.score})" for p in res.suggested_paths[:5]])
                
                title = f"Unrestricted File Upload: {res.technique}"
                description = (
                    f"Successfully uploaded '{res.filename}' using {res.technique} technique.\n\n"
                    f"Predicted storage locations:\n{path_summary}"
                )
                
                findings.append(Finding(
                    vuln_type=VulnType.FILE_UPLOAD,
                    severity=Severity.HIGH,
                    title=title,
                    description=description,
                    evidence=Evidence(
                        request_method="POST",
                        request_url=task.target,
                        response_body=f"Status: {res.status_code}\nEvidence: {res.evidence}\n\nTop Suggested Path: {res.suggested_paths[0].url if res.suggested_paths else 'Unknown'}"
                    ),
                    target_url=task.target,
                    source_agent=self.name
                ))
                
        return findings
