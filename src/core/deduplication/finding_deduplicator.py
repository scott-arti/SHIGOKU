"""
Finding Deduplicator

類似Finding自動統合・重複排除
"""

import logging
from typing import Any, Dict, List, Tuple, Set
from difflib import SequenceMatcher
from collections import defaultdict
from urllib.parse import urlsplit

from src.core.models.finding import Finding, VulnType

logger = logging.getLogger(__name__)


class FindingDeduplicator:
    """Finding重複排除クラス"""

    _REASON_CODE_LIST_KEYS = (
        "reason_codes",
        "candidate_reason_codes",
        "demotion_reason_codes",
        "evidence_quality_reason_codes",
    )
    _REASON_CODE_SINGLE_KEYS = (
        "reason_code",
        "candidate_reason_code",
        "demotion_reason_code",
    )
    
    # 類似度閾値
    URL_SIMILARITY_THRESHOLD = 0.8
    DESCRIPTION_SIMILARITY_THRESHOLD = 0.7
    
    def __init__(self):
        pass
    
    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Finding一覧から重複を排除
        
        Args:
            findings: Finding一覧
        
        Returns:
            重複排除されたFinding一覧
        """
        if len(findings) <= 1:
            return findings
        
        logger.info("Deduplicating %d findings...", len(findings))
        
        # 脆弱性タイプごとにグループ化
        grouped = self._group_by_vuln_type(findings)
        
        deduplicated = []
        total_merged = 0
        
        for _, group in grouped.items():
            if len(group) == 1:
                deduplicated.extend(group)
                continue
            
            # グループ内で重複排除
            unique, merged_count = self._deduplicate_group(group)
            deduplicated.extend(unique)
            total_merged += merged_count
        
        logger.info(
            "Deduplication complete: %d → %d (%d merged)",
            len(findings),
            len(deduplicated),
            total_merged,
        )
        
        return deduplicated
    
    def _group_by_vuln_type(self, findings: List[Finding]) -> dict:
        """脆弱性タイプごとにグループ化"""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.vuln_type].append(finding)
        return grouped
    
    def _deduplicate_group(self, findings: List[Finding]) -> Tuple[List[Finding], int]:
        """
        同じ脆弱性タイプのFindingを重複排除
        
        Returns:
            (重複排除後のFinding, マージされた数)
        """
        if len(findings) <= 1:
            return findings, 0
        
        merged_indices: Set[int] = set()
        result = []
        merged_count = 0
        
        for i, finding1 in enumerate(findings):
            if i in merged_indices:
                continue
            
            # 類似Finding検索
            similar_indices = [i]
            
            for j, finding2 in enumerate(findings[i+1:], start=i+1):
                if j in merged_indices:
                    continue
                
                if self._are_similar(finding1, finding2):
                    similar_indices.append(j)
                    merged_indices.add(j)
            
            # 類似Findingをマージ
            if len(similar_indices) > 1:
                merged = self._merge_findings([findings[idx] for idx in similar_indices])
                result.append(merged)
                merged_count += len(similar_indices) - 1
            else:
                result.append(finding1)
        
        return result, merged_count
    
    def _are_similar(self, finding1: Finding, finding2: Finding) -> bool:
        """
        2つのFindingが類似しているか判定
        
        判定基準:
        - 脆弱性タイプが同じ
        - 同一endpoint（正規化URLキー一致）
        - 説明が類似
        """
        # 脆弱性タイプチェック
        if finding1.vuln_type != finding2.vuln_type:
            return False

        # file_upload は手法違いが大量重複しやすいため、URL基準で統合
        if finding1.vuln_type == VulnType.FILE_UPLOAD:
            return self._normalized_url_key(finding1.target_url) == self._normalized_url_key(finding2.target_url)

        # XSS は endpoint と parameter が一致する場合のみ統合
        # （xss_r / xss_d / xss_s のような別ページ検出を潰さない）
        if finding1.vuln_type == VulnType.XSS:
            if self._normalized_url_key(finding1.target_url) != self._normalized_url_key(finding2.target_url):
                return False
            if self._extract_xss_parameter_key(finding1) != self._extract_xss_parameter_key(finding2):
                return False
            return self._calculate_similarity(finding1.description, finding2.description) >= self.DESCRIPTION_SIMILARITY_THRESHOLD

        # それ以外の脆弱性タイプは、別pathの誤統合を防ぐため同一endpointのみ統合対象
        if self._normalized_url_key(finding1.target_url) != self._normalized_url_key(finding2.target_url):
            return False

        # 説明類似度
        desc_similarity = self._calculate_similarity(
            finding1.description,
            finding2.description
        )

        is_similar = desc_similarity >= self.DESCRIPTION_SIMILARITY_THRESHOLD
        
        if is_similar:
            logger.debug(
                "Similar findings detected: Desc=%.2f",
                desc_similarity,
            )
        
        return is_similar

    def _normalized_url_key(self, target_url: str) -> str:
        """重複判定用に URL を正規化（scheme/host/path のみ、query は除外）"""
        if not target_url:
            return ""

        split = urlsplit(target_url)
        path = split.path.rstrip("/").lower() or "/"
        scheme = (split.scheme or "http").lower()
        netloc = (split.netloc or "").lower()
        return f"{scheme}://{netloc}{path}"

    def _extract_upload_technique(self, finding: Finding) -> str:
        """ファイルアップロード系タイトルから手法名を抽出"""
        title = (finding.title or "").strip()
        if ":" in title:
            return title.split(":", 1)[1].strip()
        return title

    def _extract_xss_parameter_key(self, finding: Finding) -> str:
        """XSS finding の重複判定用パラメータ名を抽出"""
        if finding.additional_info:
            param = finding.additional_info.get("parameter")
            if param:
                return str(param).strip().lower()

        title = (finding.title or "").strip()
        marker = "XSS in parameter '"
        if marker in title and title.endswith("'"):
            return title.split(marker, 1)[1][:-1].strip().lower()

        return ""
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        2つのテキストの類似度を計算（0.0-1.0）
        
        SequenceMatcherを使用した編集距離ベースの類似度
        """
        return SequenceMatcher(None, text1, text2).ratio()

    @staticmethod
    def _reason_code_tokens(raw_value: Any) -> List[str]:
        """Normalize a reason-code field without filtering domain-specific codes."""
        if isinstance(raw_value, set):
            values = sorted(raw_value, key=lambda value: str(value or ""))
        elif isinstance(raw_value, (list, tuple)):
            values = raw_value
        else:
            values = [raw_value]
        tokens: List[str] = []
        for value in values:
            token = str(value or "").strip()
            if token and token not in tokens:
                tokens.append(token)
        return tokens

    def _merge_reason_code_metadata(
        self,
        base_info: Dict[str, Any],
        findings: List[Finding],
    ) -> None:
        """Keep every hold-back reason when similar findings collapse to one.

        ``reason_codes`` is the canonical downstream field.  The specialised
        evidence-quality field is retained separately so report renderers can
        continue to distinguish evidence-quality verdicts from other reasons.
        """
        merged_codes: List[str] = []
        evidence_quality_codes: List[str] = []
        for finding in findings:
            info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
            for key in self._REASON_CODE_LIST_KEYS:
                tokens = self._reason_code_tokens(info.get(key))
                for token in tokens:
                    if token not in merged_codes:
                        merged_codes.append(token)
                    if key == "evidence_quality_reason_codes" and token not in evidence_quality_codes:
                        evidence_quality_codes.append(token)
            for key in self._REASON_CODE_SINGLE_KEYS:
                for token in self._reason_code_tokens(info.get(key)):
                    if token not in merged_codes:
                        merged_codes.append(token)

        if merged_codes:
            base_info["reason_codes"] = merged_codes
            base_info["reason_code"] = merged_codes[0]
        if evidence_quality_codes:
            base_info["evidence_quality_reason_codes"] = evidence_quality_codes
    
    def _merge_findings(self, findings: List[Finding]) -> Finding:
        """
        複数のFindingをマージ
        
        マージポリシー:
        - 最高確信度を採用
        - タイトル・説明は最初のもの
        - 証拠は統合
        - 再現手順は統合
        """
        # 確信度が最も高いものをベースに
        base = max(findings, key=lambda f: f.confidence)
        
        # 再現手順を統合
        all_steps = []
        for finding in findings:
            all_steps.extend(finding.reproduction_steps)
        # 重複削除
        unique_steps = list(dict.fromkeys(all_steps))
        base.reproduction_steps = unique_steps
        
        # 追加情報に統合情報を記録
        if not base.additional_info:
            base.additional_info = {}

        self._merge_reason_code_metadata(base.additional_info, findings)

        base.additional_info['merged_count'] = len(findings)
        base.additional_info['merged_ids'] = [f.id for f in findings if f != base]

        # file_upload の場合、バイパス手法を集約して root cause を 1 件に統合
        if base.vuln_type == VulnType.FILE_UPLOAD:
            techniques = []
            for finding in findings:
                technique = self._extract_upload_technique(finding)
                if technique:
                    techniques.append(technique)
            unique_techniques = list(dict.fromkeys(techniques))
            if unique_techniques:
                base.additional_info["bypass_techniques"] = unique_techniques
                base.additional_info["root_cause"] = "unrestricted_file_upload"

        logger.info("Merged %d similar findings into one", len(findings))
        
        return base


# ヘルパー関数
def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Finding一覧を重複排除（便利関数）"""
    deduplicator = FindingDeduplicator()
    return deduplicator.deduplicate(findings)
