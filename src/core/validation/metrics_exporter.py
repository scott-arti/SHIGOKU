"""
Metrics Exporter - CTO推奨対応#5

Juice Shopテストメトリクスの収集・エクスポート
Prometheus/CloudWatch対応を想定した構造
"""
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path


@dataclass
class TestMetric:
    """単一テストメトリクス"""
    timestamp: float
    endpoint: str
    method: str
    status_code: int
    latency_ms: float
    response_size: int
    error_type: Optional[str] = None
    finding_detected: bool = False
    finding_severity: Optional[str] = None


@dataclass
class TestMetricsBatch:
    """テストメトリクスバッチ"""
    test_id: str
    target_url: str
    start_time: float
    end_time: float
    total_requests: int
    successful: int
    errors: int
    findings: int
    avg_latency_ms: float
    metrics: List[TestMetric] = field(default_factory=list)
    
    def to_prometheus_format(self) -> str:
        """Prometheus exposition formatに変換"""
        lines = []
        lines.append(f"# HELP juice_shop_test_latency_ms Request latency in milliseconds")
        lines.append(f"# TYPE juice_shop_test_latency_ms gauge")
        
        for m in self.metrics:
            lines.append(
                f'juice_shop_test_latency_ms{{endpoint="{m.endpoint}",method="{m.method}"}} {m.latency_ms}'
            )
        
        lines.append(f"# HELP juice_shop_test_status HTTP status code")
        lines.append(f"# TYPE juice_shop_test_status gauge")
        
        for m in self.metrics:
            lines.append(
                f'juice_shop_test_status{{endpoint="{m.endpoint}",method="{m.method}"}} {m.status_code}'
            )
        
        lines.append(f"# HELP juice_shop_test_findings Total findings detected")
        lines.append(f"# TYPE juice_shop_test_findings counter")
        lines.append(f'juice_shop_test_findings{{target="{self.target_url}"}} {self.findings}')
        
        return "\n".join(lines)
    
    def to_cloudwatch_format(self) -> List[Dict[str, Any]]:
        """CloudWatch PutMetricData formatに変換"""
        metrics = []
        
        # 集計メトリクス
        metrics.append({
            "MetricName": "TestTotalRequests",
            "Value": self.total_requests,
            "Unit": "Count",
            "Timestamp": datetime.fromtimestamp(self.end_time).isoformat(),
        })
        
        metrics.append({
            "MetricName": "TestFindings",
            "Value": self.findings,
            "Unit": "Count",
            "Timestamp": datetime.fromtimestamp(self.end_time).isoformat(),
        })
        
        metrics.append({
            "MetricName": "TestAvgLatency",
            "Value": self.avg_latency_ms,
            "Unit": "Milliseconds",
            "Timestamp": datetime.fromtimestamp(self.end_time).isoformat(),
        })
        
        # 個別メトリクス
        for m in self.metrics:
            metrics.append({
                "MetricName": "RequestLatency",
                "Value": m.latency_ms,
                "Unit": "Milliseconds",
                "Timestamp": datetime.fromtimestamp(m.timestamp).isoformat(),
                "Dimensions": [
                    {"Name": "Endpoint", "Value": m.endpoint},
                    {"Name": "Method", "Value": m.method},
                ],
            })
        
        return metrics
    
    def to_json(self) -> str:
        """JSON形式に変換"""
        return json.dumps(asdict(self), indent=2, default=str)
    
    def save(self, output_dir: Path) -> Path:
        """メトリクスをファイルに保存"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON保存
        json_file = output_dir / f"metrics_{self.test_id}.json"
        json_file.write_text(self.to_json())
        
        # Prometheus format保存
        prom_file = output_dir / f"metrics_{self.test_id}.prom"
        prom_file.write_text(self.to_prometheus_format())
        
        return json_file


class MetricsCollector:
    """メトリクス収集器"""
    
    def __init__(self, test_id: str, target_url: str):
        self.test_id = test_id
        self.target_url = target_url
        self.start_time = time.time()
        self.metrics: List[TestMetric] = []
    
    def record(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        latency_ms: float,
        response_size: int,
        error_type: Optional[str] = None,
        finding_detected: bool = False,
        finding_severity: Optional[str] = None,
    ) -> None:
        """メトリクスを記録"""
        metric = TestMetric(
            timestamp=time.time(),
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            latency_ms=latency_ms,
            response_size=response_size,
            error_type=error_type,
            finding_detected=finding_detected,
            finding_severity=finding_severity,
        )
        self.metrics.append(metric)
    
    def finalize(self) -> TestMetricsBatch:
        """メトリクス収集を完了し、バッチを生成"""
        end_time = time.time()
        
        total = len(self.metrics)
        errors = sum(1 for m in self.metrics if m.error_type)
        findings = sum(1 for m in self.metrics if m.finding_detected)
        avg_latency = sum(m.latency_ms for m in self.metrics) / total if total > 0 else 0
        
        return TestMetricsBatch(
            test_id=self.test_id,
            target_url=self.target_url,
            start_time=self.start_time,
            end_time=end_time,
            total_requests=total,
            successful=total - errors,
            errors=errors,
            findings=findings,
            avg_latency_ms=avg_latency,
            metrics=self.metrics,
        )


def export_metrics(metrics_batch: TestMetricsBatch, output_base: Path) -> Dict[str, Path]:
    """メトリクスを複数形式でエクスポート"""
    output_dir = output_base / "metrics"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    result = {
        "json": metrics_batch.save(output_dir),
        "prometheus": output_dir / f"metrics_{metrics_batch.test_id}.prom",
    }
    
    # 集計レポート
    summary = {
        "test_id": metrics_batch.test_id,
        "target": metrics_batch.target_url,
        "duration_seconds": metrics_batch.end_time - metrics_batch.start_time,
        "total_requests": metrics_batch.total_requests,
        "successful": metrics_batch.successful,
        "errors": metrics_batch.errors,
        "findings": metrics_batch.findings,
        "avg_latency_ms": metrics_batch.avg_latency_ms,
        "generated_at": datetime.now().isoformat(),
    }
    
    summary_file = output_dir / f"summary_{metrics_batch.test_id}.json"
    summary_file.write_text(json.dumps(summary, indent=2))
    result["summary"] = summary_file
    
    return result
