"""
Deserialization Tester - デシリアライズ脆弱性検出

Java/PHP/Python/Ruby等のシリアライズデータを検知し、
デシリアライズ脆弱性の可能性を評価する。

⚠️ 高リスク機能: 検知のみ、実際のGadget Chain実行は禁止
"""

import logging
import re
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class SerializationFormat(Enum):
    """シリアライズフォーマット"""
    JAVA = "java"
    PHP = "php"
    PYTHON_PICKLE = "python_pickle"
    RUBY_MARSHAL = "ruby_marshal"
    DOTNET = "dotnet"
    JSON = "json"
    XML = "xml"
    UNKNOWN = "unknown"


class VulnerabilityLevel(Enum):
    """脆弱性レベル"""
    CONFIRMED = "confirmed"   # 確認済み（エラーレスポンス等）
    LIKELY = "likely"         # 可能性高（シリアライズデータ検出）
    POSSIBLE = "possible"     # 可能性あり（パターンマッチ）
    UNKNOWN = "unknown"


@dataclass
class DeserializationResult:
    """デシリアライズ検出結果"""
    url: str
    parameter: str
    format: SerializationFormat
    level: VulnerabilityLevel
    evidence: str = ""
    detected_data: str = ""
    gadget_candidates: List[str] = field(default_factory=list)
    severity: str = "critical"
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "format": self.format.value,
            "level": self.level.value,
            "gadgets": self.gadget_candidates,
            "severity": self.severity,
        }


class DeserializationTester:
    """
    Deserialization Tester
    
    機能:
    - シリアライズデータ自動検出
    - フォーマット識別（Java/PHP/Python/Ruby/.NET）
    - Gadget Chain候補の提示（実行なし）
    - エラーベース検証
    
    ⚠️ 安全対策:
    - 検知のみ、実際のペイロード実行禁止
    - 非破壊的なプローブのみ使用
    - EthicsGuard統合必須
    """
    
    # シリアライズデータ識別パターン
    SERIALIZATION_SIGNATURES = {
        # Java (ObjectInputStream)
        SerializationFormat.JAVA: [
            (b'\xac\xed\x00\x05', "Java serialized object (magic bytes)"),
            (b'rO0AB', "Java serialized object (base64)"),
            (b'H4sIAAAA', "Java serialized + gzip (base64)"),
        ],
        # PHP (serialize/unserialize)
        SerializationFormat.PHP: [
            (b'O:', "PHP object"),
            (b'a:', "PHP array"),
            (b's:', "PHP string"),
            (b'i:', "PHP integer"),
        ],
        # Python (pickle)
        SerializationFormat.PYTHON_PICKLE: [
            (b'\x80\x03', "Python pickle v3"),
            (b'\x80\x04', "Python pickle v4"),
            (b'\x80\x05', "Python pickle v5"),
            (b'(dp0', "Python pickle (dict)"),
        ],
        # Ruby (Marshal)
        SerializationFormat.RUBY_MARSHAL: [
            (b'\x04\x08', "Ruby Marshal"),
            (b'BAh', "Ruby Marshal (base64)"),
        ],
        # .NET
        SerializationFormat.DOTNET: [
            (b'AAEAAAD', ".NET BinaryFormatter (base64)"),
            (b'\x00\x01\x00\x00\x00', ".NET BinaryFormatter"),
        ],
    }
    
    # Java Gadget Chain クラス名（情報提供のみ）
    JAVA_GADGET_CLASSES = [
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.InvokerTransformer",
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "org.springframework.beans.factory.ObjectFactory",
        "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
        "org.hibernate.tuple.component.PojoComponentTuplizer",
        "com.alibaba.fastjson.JSON",
        "org.jboss.interceptor.proxy.DefaultInvocationContext",
    ]
    
    # PHP Gadget クラス名
    PHP_GADGET_CLASSES = [
        "Monolog\\Handler\\SyslogUdpHandler",
        "GuzzleHttp\\Psr7\\FnStream",
        "Symfony\\Component\\Routing\\Generator\\UrlGenerator",
        "Larvel\\SerializableClosure",
    ]
    
    # 非破壊的プローブペイロード（エラー誘発のみ）
    SAFE_PROBES = {
        SerializationFormat.JAVA: [
            # 不正なマジックバイト（エラー検出用）
            base64.b64encode(b'\xac\xed\x00\x00INVALID').decode(),
            # 切り詰めデータ
            "rO0ABX",
        ],
        SerializationFormat.PHP: [
            # 不正なPHPオブジェクト
            'O:8:"_INVALID":0:{}',
            # 壊れたシリアライズ
            'a:1:{s:4:"test";s:999:"',
        ],
        SerializationFormat.PYTHON_PICKLE: [
            # invalid opcode
            base64.b64encode(b'\x80\x03X\x00\x00\x00\x00INVALID.').decode(),
        ],
    }
    
    # エラーパターン
    DESERIALIZATION_ERROR_PATTERNS = {
        SerializationFormat.JAVA: [
            r"java\.io\.InvalidClassException",
            r"java\.io\.StreamCorruptedException",
            r"java\.lang\.ClassNotFoundException",
            r"java\.io\.ObjectInputStream",
            r"readObject",
            r"serialVersionUID",
        ],
        SerializationFormat.PHP: [
            r"unserialize\(\)",
            r"unserialize_callback_func",
            r"__wakeup",
            r"__destruct",
            r"allowed_classes",
        ],
        SerializationFormat.PYTHON_PICKLE: [
            r"pickle\.UnpicklingError",
            r"_pickle\.UnpicklingError",
            r"could not find MARK",
            r"invalid load key",
        ],
        SerializationFormat.RUBY_MARSHAL: [
            r"Marshal\.load",
            r"ArgumentError",
            r"incompatible marshal file format",
        ],
    }
    
    def __init__(
        self,
        timeout: float = 10.0,
    ):
        self.timeout = timeout
        self.results: List[DeserializationResult] = []
    
    def detect_serialized_data(
        self,
        data: str,
    ) -> Optional[Tuple[SerializationFormat, str]]:
        """
        シリアライズデータを検出
        
        Args:
            data: 検査対象データ（パラメータ値等）
        
        Returns:
            (フォーマット, 説明) または None
        """
        # Base64デコード試行
        try:
            decoded = base64.b64decode(data)
        except Exception:
            decoded = data.encode() if isinstance(data, str) else data
        
        # シグネチャチェック
        for fmt, signatures in self.SERIALIZATION_SIGNATURES.items():
            for sig, desc in signatures:
                if isinstance(sig, bytes):
                    if sig in decoded or sig in data.encode():
                        return (fmt, desc)
                else:
                    if sig in data:
                        return (fmt, desc)
        
        return None
    
    def scan_parameters(
        self,
        url: str,
        parameters: Dict[str, str],
    ) -> List[DeserializationResult]:
        """
        パラメータ内のシリアライズデータをスキャン
        
        Args:
            url: 対象URL
            parameters: パラメータ名と値の辞書
        
        Returns:
            検出結果リスト
        """
        results = []
        
        for param, value in parameters.items():
            detection = self.detect_serialized_data(value)
            
            if detection:
                fmt, desc = detection
                result = DeserializationResult(
                    url=url,
                    parameter=param,
                    format=fmt,
                    level=VulnerabilityLevel.LIKELY,
                    evidence=desc,
                    detected_data=value[:100] + "..." if len(value) > 100 else value,
                    gadget_candidates=self._get_gadget_candidates(fmt),
                )
                results.append(result)
                logger.warning(
                    "Serialized data detected: %s in param '%s' (%s)",
                    fmt.value, param, desc
                )
        
        self.results.extend(results)
        return results
    
    def probe_endpoint(
        self,
        url: str,
        parameter: str,
        method: str = "POST",
        detected_format: Optional[SerializationFormat] = None,
    ) -> Optional[DeserializationResult]:
        """
        エンドポイントをプローブしてデシリアライズ脆弱性を確認
        
        ⚠️ 非破壊的プローブのみ使用
        
        Args:
            url: 対象URL
            parameter: テスト対象パラメータ
            method: HTTPメソッド
            detected_format: 検出済みフォーマット
        
        Returns:
            検出結果またはNone
        """
        if detected_format is None:
            detected_format = SerializationFormat.JAVA  # デフォルト
        
        probes = self.SAFE_PROBES.get(detected_format, [])
        
        for probe in probes:
            result = self._send_probe(
                url=url,
                parameter=parameter,
                probe_payload=probe,
                format=detected_format,
                method=method,
            )
            
            if result and result.level in (VulnerabilityLevel.CONFIRMED, VulnerabilityLevel.LIKELY):
                self.results.append(result)
                return result
        
        return None
    
    def _send_probe(
        self,
        url: str,
        parameter: str,
        probe_payload: str,
        format: SerializationFormat,
        method: str,
    ) -> Optional[DeserializationResult]:
        """
        プローブ送信（プレースホルダー）
        
        NOTE: 実際はrequestsでリクエスト送信
        """
        logger.info(
            "Probing deserialization: %s=%s... on %s",
            parameter, probe_payload[:20], url
        )
        
        # プレースホルダー
        # 実際:
        # 1. プローブペイロード送信
        # 2. エラーパターン検出
        # 3. 脆弱性判定
        
        return DeserializationResult(
            url=url,
            parameter=parameter,
            format=format,
            level=VulnerabilityLevel.POSSIBLE,
        )
    
    def _analyze_error_response(
        self,
        response_text: str,
        format: SerializationFormat,
    ) -> Tuple[bool, str]:
        """エラーレスポンス分析"""
        patterns = self.DESERIALIZATION_ERROR_PATTERNS.get(format, [])
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return (True, match.group(0))
        
        return (False, "")
    
    def _get_gadget_candidates(
        self,
        format: SerializationFormat,
    ) -> List[str]:
        """Gadget Chain候補を取得（情報提供のみ）"""
        if format == SerializationFormat.JAVA:
            return self.JAVA_GADGET_CLASSES[:3]  # 上位3つ
        elif format == SerializationFormat.PHP:
            return self.PHP_GADGET_CLASSES[:3]
        return []
    
    def get_vulnerable(self) -> List[DeserializationResult]:
        """脆弱と判定された結果のみ"""
        return [
            r for r in self.results 
            if r.level in (VulnerabilityLevel.CONFIRMED, VulnerabilityLevel.LIKELY)
        ]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_format = {}
        by_level = {}
        
        for r in self.results:
            by_format[r.format.value] = by_format.get(r.format.value, 0) + 1
            by_level[r.level.value] = by_level.get(r.level.value, 0) + 1
        
        return {
            "total_detections": len(self.results),
            "likely_vulnerable": len(self.get_vulnerable()),
            "by_format": by_format,
            "by_level": by_level,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"Deserialization Scan: {summary['total_detections']} detections\n"
            f"Likely vulnerable: {summary['likely_vulnerable']}\n"
            f"By format: {summary['by_format']}\n"
            f"By level: {summary['by_level']}"
        )


def create_deserialization_tester(
    timeout: float = 10.0,
) -> DeserializationTester:
    """DeserializationTester作成ヘルパー"""
    return DeserializationTester(timeout=timeout)
