"""
Program-Aware Memory (PAM): ターゲット企業ごとの戦略記憶

企業別の:
- 採択/却下パターン
- 期待報酬額
- トリアージ速度
を記録し、戦略を最適化。

Duplicate Shield: 公開レポートとの類似度検出機能も搭載。
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timedelta
import json
import os


@dataclass
class SubmissionRecord:
    """レポート提出記録"""
    program: str
    vuln_type: str
    severity: str
    outcome: str  # "accepted", "rejected", "duplicate", "informative", "pending"
    bounty_amount: float = 0.0
    submitted_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None


@dataclass
class ProgramProfile:
    """プログラムプロファイル"""
    name: str
    platform: str = "hackerone"  # hackerone, bugcrowd, etc.
    
    # 統計
    total_submissions: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    duplicate_count: int = 0
    
    # 報酬統計
    total_bounty: float = 0.0
    average_bounty: float = 0.0
    
    # トリアージ速度（日数）
    avg_triage_days: float = 7.0
    avg_payout_days: float = 30.0
    
    # トリアージャー傾向
    preferred_vuln_types: list[str] = field(default_factory=list)
    rejected_patterns: list[str] = field(default_factory=list)
    
    def acceptance_rate(self) -> float:
        """採択率を計算"""
        if self.total_submissions == 0:
            return 0.0
        return self.accepted_count / self.total_submissions


class ProgramAwareMemory:
    """
    Program-Aware Memory (PAM)
    
    ターゲット企業ごとの過去データを記録し、
    ROI最適化のための戦略を提供する。
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or os.path.expanduser("~/.shigoku/pam.json")
        self.programs: dict[str, ProgramProfile] = {}
        self.submissions: list[SubmissionRecord] = []
        self._load()
        
        # Duplicate Shield用のベクトルDB (ChromaDB)
        self._chroma_client = None
        self._duplicate_collection = None
    
    def _to_dict(self) -> dict:
        """データを辞書形式に変換"""
        return {
            "programs": {
                name: {
                    k: v.isoformat() if isinstance(v, datetime) else v
                    for k, v in asdict(profile).items()
                }
                for name, profile in self.programs.items()
            },
            "submissions": [
                {
                    k: v.isoformat() if isinstance(v, datetime) else v
                    for k, v in asdict(record).items()
                }
                for record in self.submissions
            ]
        }

    def _from_dict(self, data: dict) -> None:
        """辞書データから復元"""
        # Load Programs
        self.programs = {}
        for name, p_data in data.get("programs", {}).items():
            # Convert specialized fields if necessary
            self.programs[name] = ProgramProfile(**p_data)
            
        # Load Submissions
        self.submissions = []
        for s_data in data.get("submissions", []):
            # Convert datetime strings back to datetime objects
            if "submitted_at" in s_data and s_data["submitted_at"]:
                s_data["submitted_at"] = datetime.fromisoformat(s_data["submitted_at"])
            if "resolved_at" in s_data and s_data["resolved_at"]:
                s_data["resolved_at"] = datetime.fromisoformat(s_data["resolved_at"])
            self.submissions.append(SubmissionRecord(**s_data))

    def _load(self) -> None:
        """ストレージからロード"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._from_dict(data)
            except Exception as e:
                # logger.error(f"Failed to load PAM: {e}")
                pass
    
    def _save(self) -> None:
        """ストレージに保存"""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(self._to_dict(), f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def check_duplicate_risk(self, finding_hash: str) -> bool:
        """
        重複リスクをチェック（簡易版）
        
        Args:
            finding_hash: Findingの一意なハッシュまたは識別子
            
        Returns:
            bool: 重複リスクがある場合 True
        """
        # TODO: 本来はベクトル検索や詳細な類似度判定を行うが、
        # ここでは簡易的に実装。
        return False
    
    def record_submission(
        self,
        program: str,
        vuln_type: str,
        severity: str,
        outcome: str,
        bounty: float = 0.0,
        rejection_reason: Optional[str] = None,
    ) -> None:
        """
        レポート提出結果を記録
        
        Args:
            program: プログラム名
            vuln_type: 脆弱性タイプ（sqli, xss, idor, etc.）
            severity: 重要度（critical, high, medium, low）
            outcome: 結果（accepted, rejected, duplicate, informative）
            bounty: 報酬額（USD）
            rejection_reason: 却下理由
        """
        record = SubmissionRecord(
            program=program,
            vuln_type=vuln_type,
            severity=severity,
            outcome=outcome,
            bounty_amount=bounty,
            rejection_reason=rejection_reason,
        )
        self.submissions.append(record)
        
        # プログラムプロファイルを更新
        if program not in self.programs:
            self.programs[program] = ProgramProfile(name=program)
        
        profile = self.programs[program]
        profile.total_submissions += 1
        
        if outcome == "accepted":
            profile.accepted_count += 1
            profile.total_bounty += bounty
            profile.average_bounty = profile.total_bounty / profile.accepted_count
            if vuln_type not in profile.preferred_vuln_types:
                profile.preferred_vuln_types.append(vuln_type)
        elif outcome == "rejected":
            profile.rejected_count += 1
            if rejection_reason:
                profile.rejected_patterns.append(rejection_reason)
        elif outcome == "duplicate":
            profile.duplicate_count += 1
        
        self._save()
    
    def get_acceptance_rate(self, program: str) -> float:
        """プログラムの採択率を取得"""
        if program not in self.programs:
            return 0.5  # デフォルト
        return self.programs[program].acceptance_rate()
    
    def estimate_reward(self, program: str, vuln_type: str, severity: str = "medium") -> float:
        """
        期待報酬額を推定
        
        過去データから同種の脆弱性の平均報酬を計算。
        """
        matching = [
            s for s in self.submissions
            if s.program == program
            and s.vuln_type == vuln_type
            and s.outcome == "accepted"
        ]
        
        if not matching:
            # デフォルト値（重要度ベース）
            defaults = {
                "critical": 5000.0,
                "high": 1500.0,
                "medium": 500.0,
                "low": 100.0,
            }
            return defaults.get(severity, 500.0)
        
        return sum(s.bounty_amount for s in matching) / len(matching)
    
    def get_triage_speed(self, program: str) -> timedelta:
        """トリアージ速度を取得"""
        if program not in self.programs:
            return timedelta(days=7)
        return timedelta(days=self.programs[program].avg_triage_days)
    
    def get_payout_speed(self, program: str) -> timedelta:
        """支払い速度を取得"""
        if program not in self.programs:
            return timedelta(days=30)
        return timedelta(days=self.programs[program].avg_payout_days)
    
    def get_preferred_vulns(self, program: str) -> list[str]:
        """プログラムが好む脆弱性タイプを取得"""
        if program not in self.programs:
            return []
        return self.programs[program].preferred_vuln_types
    
    def get_rejection_patterns(self, program: str) -> list[str]:
        """却下パターンを取得"""
        if program not in self.programs:
            return []
        return self.programs[program].rejected_patterns
    
    # ===== Duplicate Shield =====
    
    def init_duplicate_shield(self, chroma_host: str = "localhost", chroma_port: int = 8000) -> bool:
        """Duplicate Shield用のChromaDB接続を初期化"""
        try:
            import chromadb
            self._chroma_client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
            self._duplicate_collection = self._chroma_client.get_or_create_collection(
                name="public_reports",
                metadata={"description": "Public bug bounty reports for duplicate detection"}
            )
            return True
        except Exception as e:
            print(f"Duplicate Shield init failed: {e}")
            return False
    
    def ingest_public_reports(self, reports: list[dict]) -> int:
        """
        公開レポートをベクトルDBに取り込む
        
        Args:
            reports: [{"id": str, "title": str, "description": str, "program": str}, ...]
        
        Returns:
            取り込んだレポート数
        """
        if not self._duplicate_collection:
            return 0
        
        ids = [r["id"] for r in reports]
        documents = [f"{r['title']}\n{r.get('description', '')}" for r in reports]
        metadatas = [{"program": r.get("program", "unknown")} for r in reports]
        
        self._duplicate_collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )
        return len(reports)
    
    def check_duplicate_risk(
        self,
        finding_title: str,
        finding_description: str,
        program: Optional[str] = None,
        threshold: float = 0.85
    ) -> dict:
        """
        自前のFindingと公開レポートの類似度をチェック
        
        Args:
            finding_title: 自分のFindingタイトル
            finding_description: 自分のFinding説明
            program: プログラム名（フィルタ用）
            threshold: 類似度閾値（デフォルト0.85）
        
        Returns:
            {
                "is_duplicate_risk": bool,
                "similarity_score": float,
                "similar_reports": list[dict],
                "warning": str
            }
        """
        if not self._duplicate_collection:
            return {
                "is_duplicate_risk": False,
                "similarity_score": 0.0,
                "similar_reports": [],
                "warning": "Duplicate Shield not initialized"
            }
        
        query_text = f"{finding_title}\n{finding_description}"
        
        # ChromaDBで類似検索
        where_filter = {"program": program} if program else None
        results = self._duplicate_collection.query(
            query_texts=[query_text],
            n_results=5,
            where=where_filter
        )
        
        similar_reports = []
        max_similarity = 0.0
        
        if results and results.get("distances"):
            # ChromaDBのdistanceをsimilarityに変換（L2距離）
            for i, distance in enumerate(results["distances"][0]):
                # L2距離が小さいほど類似度が高い
                # 簡易的に: similarity = 1 / (1 + distance)
                similarity = 1 / (1 + distance)
                
                if similarity > max_similarity:
                    max_similarity = similarity
                
                if similarity >= threshold:
                    similar_reports.append({
                        "id": results["ids"][0][i] if results.get("ids") else f"report_{i}",
                        "similarity": round(similarity, 3),
                        "program": results["metadatas"][0][i].get("program") if results.get("metadatas") else None,
                    })
        
        is_risk = max_similarity >= threshold
        
        return {
            "is_duplicate_risk": is_risk,
            "similarity_score": round(max_similarity, 3),
            "similar_reports": similar_reports,
            "warning": f"⚠️ HIGH DUPLICATE RISK ({max_similarity:.0%} similar)" if is_risk else ""
        }
    
    def calculate_roi(
        self,
        program: str,
        vuln_type: str,
        severity: str,
        estimated_time_hours: float
    ) -> float:
        """
        ROIスコアを計算
        
        ROI = (Expected_Bounty * Success_Probability) / Time_Cost
        """
        expected_bounty = self.estimate_reward(program, vuln_type, severity)
        success_prob = self.get_acceptance_rate(program)
        
        if success_prob == 0:
            success_prob = 0.3  # デフォルト
        
        # 時間コスト（時間 → 正規化）
        time_cost = max(estimated_time_hours, 0.5)  # 最低0.5時間
        
        roi = (expected_bounty * success_prob) / time_cost
        return round(roi, 2)
