"""
DNS History - DNS履歴収集

SecurityTrails/PassiveTotal統合
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """DNS履歴レコード"""
    domain: str
    record_type: str  # A, AAAA, CNAME, MX, NS, TXT
    value: str
    first_seen: str = ""
    last_seen: str = ""
    count: int = 1


@dataclass
class DNSHistoryResult:
    """DNS履歴結果"""
    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    historical_ips: List[str] = field(default_factory=list)
    subdomains_found: List[str] = field(default_factory=list)
    mx_servers: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)


class DNSHistoryCollector:
    """
    DNS履歴収集
    
    機能:
    - SecurityTrails API
    - PassiveTotal API
    - 過去のDNSレコード取得
    - IP変遷追跡
    """
    
    def __init__(
        self,
        securitytrails_api_key: str = "",
        passivetotal_username: str = "",
        passivetotal_api_key: str = ""
    ):
        self.st_api_key = securitytrails_api_key
        self.pt_username = passivetotal_username
        self.pt_api_key = passivetotal_api_key
        self.results: List[DNSHistoryResult] = []
    
    def collect(self, domain: str) -> DNSHistoryResult:
        """
        DNS履歴収集
        
        Args:
            domain: 対象ドメイン
        """
        result = DNSHistoryResult(domain=domain)
        
        # SecurityTrails
        if self.st_api_key:
            st_data = self._query_securitytrails(domain)
            self._merge_result(result, st_data)
        
        # PassiveTotal
        if self.pt_username and self.pt_api_key:
            pt_data = self._query_passivetotal(domain)
            self._merge_result(result, pt_data)
        
        self.results.append(result)
        return result
    
    def get_historical_ips(self, domain: str) -> List[str]:
        """過去のIPアドレス取得"""
        result = self.collect(domain)
        return result.historical_ips
    
    def track_ip_changes(self, domain: str) -> List[Dict]:
        """
        IP変遷追跡
        
        Returns:
            時系列でのIP変更履歴
        """
        result = self.collect(domain)
        
        changes = []
        a_records = [r for r in result.records if r.record_type == "A"]
        
        for record in sorted(a_records, key=lambda r: r.first_seen):
            changes.append({
                "ip": record.value,
                "first_seen": record.first_seen,
                "last_seen": record.last_seen,
            })
        
        return changes
    
    def _query_securitytrails(self, domain: str) -> DNSHistoryResult:
        """
        SecurityTrails API クエリ（プレースホルダー）
        """
        logger.info("Querying SecurityTrails for %s", domain)
        
        # プレースホルダー
        # API: https://api.securitytrails.com/v1/history/{domain}/dns/{type}
        # headers = {"APIKEY": self.st_api_key}
        # response = requests.get(url, headers=headers)
        
        return DNSHistoryResult(domain=domain)
    
    def _query_passivetotal(self, domain: str) -> DNSHistoryResult:
        """
        PassiveTotal API クエリ（プレースホルダー）
        """
        logger.info("Querying PassiveTotal for %s", domain)
        
        # プレースホルダー
        # API: https://api.passivetotal.org/v2/dns/passive
        # auth = (self.pt_username, self.pt_api_key)
        # response = requests.get(url, auth=auth, params={"query": domain})
        
        return DNSHistoryResult(domain=domain)
    
    def _merge_result(
        self,
        target: DNSHistoryResult,
        source: DNSHistoryResult
    ):
        """結果マージ"""
        target.records.extend(source.records)
        target.historical_ips.extend(source.historical_ips)
        target.subdomains_found.extend(source.subdomains_found)
        
        # 重複除去
        target.historical_ips = list(set(target.historical_ips))
        target.subdomains_found = list(set(target.subdomains_found))
    
    def get_summary(self) -> Dict:
        """サマリー"""
        total_records = sum(len(r.records) for r in self.results)
        total_ips = sum(len(r.historical_ips) for r in self.results)
        
        return {
            "domains_analyzed": len(self.results),
            "total_records": total_records,
            "total_historical_ips": total_ips,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"DNS History: {summary['domains_analyzed']} domains\n"
            f"Records: {summary['total_records']}\n"
            f"Historical IPs: {summary['total_historical_ips']}"
        )


def create_dns_history_collector(
    securitytrails_api_key: str = "",
    passivetotal_username: str = "",
    passivetotal_api_key: str = ""
) -> DNSHistoryCollector:
    """DNSHistoryCollector作成ヘルパー"""
    return DNSHistoryCollector(
        securitytrails_api_key,
        passivetotal_username,
        passivetotal_api_key
    )
