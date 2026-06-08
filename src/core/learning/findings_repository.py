"""
FindingsRepository: 脆弱性の永続化管理

全てのFindingsをSQLiteデータベースに保存し、
検索、統計、エクスポート機能を提供する。
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from src.core.models.finding import Finding, Severity, VulnType, Evidence

logger = logging.getLogger(__name__)

# デフォルトのDBパス
DEFAULT_DB_PATH = Path.home() / ".shigoku" / "findings.db"


@dataclass
class FindingRecord:
    """DBから取得したFindingレコード"""
    id: str
    vuln_type: str
    severity: str
    title: str
    description: str
    target_url: str
    target_program: str
    evidence_json: str
    reproduction_steps_json: str
    impact: str
    discovered_at: str
    source_agent: str
    confidence: float
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    verified: bool
    created_at: float
    updated_at: float

    def to_finding(self) -> Finding:
        """FindingオブジェクトJ変換"""
        evidence_data = json.loads(self.evidence_json) if self.evidence_json else {}
        steps = json.loads(self.reproduction_steps_json) if self.reproduction_steps_json else []
        
        finding = Finding(
            vuln_type=VulnType(self.vuln_type),
            severity=Severity(self.severity),
            title=self.title,
            description=self.description,
            target_url=self.target_url,
            target_program=self.target_program,
            evidence=Evidence(**evidence_data) if evidence_data else Evidence(),
            reproduction_steps=steps,
            impact=self.impact,
            discovered_at=datetime.fromisoformat(self.discovered_at) if self.discovered_at else datetime.now(),
            source_agent=self.source_agent,
            confidence=self.confidence,
            cwe_id=self.cwe_id,
            cvss_score=self.cvss_score,
        )
        finding.id = self.id
        return finding


class FindingsRepository:
    """
    脆弱性のCRUD操作を提供するリポジトリ
    
    使用例:
        repo = FindingsRepository()
        
        # 保存
        repo.save(finding)
        
        # 取得
        finding = repo.get(finding_id)
        
        # 検索
        findings = repo.search(severity="critical", target="example.com")
        
        # 統計
        stats = repo.get_statistics()
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        初期化
        
        Args:
            db_path: SQLiteデータベースパス
        """
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """データベーステーブルを初期化"""
        with self._get_connection() as conn:
            # WALモード有効化（読み書き並行化）
            conn.execute("PRAGMA journal_mode=WAL;")
            
            # 🆕 キャッシュサイズ最適化（デフォルト2000ページ → 10000ページ ≈ 40MB）
            conn.execute("PRAGMA cache_size=10000;")
            
            # 🆕 一時テーブルをメモリに配置（ディスクI/O削減）
            conn.execute("PRAGMA temp_store=MEMORY;")
            
            # 🆕 メモリマップI/O有効化（大規模DB向け、128MB）
            conn.execute("PRAGMA mmap_size=134217728;")
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    target_url TEXT NOT NULL,
                    target_program TEXT,
                    evidence_json TEXT,
                    reproduction_steps_json TEXT,
                    impact TEXT,
                    discovered_at TEXT,
                    source_agent TEXT,
                    confidence REAL DEFAULT 0.0,
                    cwe_id TEXT,
                    cvss_score REAL,
                    verified INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            
            # インデックス作成
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at)")
            
            conn.commit()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """データベース接続を取得"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def save(self, finding: Finding) -> str:
        """
        Findingを保存
        
        Args:
            finding: 保存するFinding
            
        Returns:
            保存されたFindingのID
        """
        now = time.time()
        # Finding.to_dict() を使用して証拠データを取得（モデル側で安全に処理されているため）
        evidence_dict = finding.evidence.to_dict() if hasattr(finding.evidence, 'to_dict') else (finding.evidence if isinstance(finding.evidence, dict) else {})
        evidence_json = json.dumps(evidence_dict)
        steps_json = json.dumps(finding.reproduction_steps)
        
        with self._get_connection() as conn:
            # UPSERT
            conn.execute("""
                INSERT INTO findings (
                    id, vuln_type, severity, title, description,
                    target_url, target_program, evidence_json, reproduction_steps_json,
                    impact, discovered_at, source_agent, confidence,
                    cwe_id, cvss_score, verified, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    vuln_type=excluded.vuln_type,
                    severity=excluded.severity,
                    title=excluded.title,
                    description=excluded.description,
                    evidence_json=excluded.evidence_json,
                    reproduction_steps_json=excluded.reproduction_steps_json,
                    impact=excluded.impact,
                    confidence=excluded.confidence,
                    cwe_id=excluded.cwe_id,
                    cvss_score=excluded.cvss_score,
                    updated_at=excluded.updated_at
            """, (
                finding.id,
                finding.vuln_type.value,
                finding.severity.value,
                finding.title,
                finding.description,
                finding.target_url,
                finding.target_program,
                evidence_json,
                steps_json,
                finding.impact,
                finding.discovered_at.isoformat(),
                finding.source_agent,
                finding.confidence,
                finding.cwe_id,
                finding.cvss_score,
                0,  # verified
                now,
                now,
            ))
            conn.commit()
        
        logger.info(f"Finding saved: {finding.id} - {finding.title}")
        return finding.id

    def save_batch(self, findings: list[Finding]) -> list[str]:
        """
        複数のFindingを一括保存（バッチ処理）
        
        Args:
            findings: 保存するFindingのリスト
            
        Returns:
            保存されたFindingのIDリスト
        """
        if not findings:
            return []
        
        now = time.time()
        records = []
        
        for finding in findings:
            # Finding.to_dict() または安全なフォールバックを使用
            evidence_dict = finding.evidence.to_dict() if hasattr(finding.evidence, 'to_dict') else (finding.evidence if isinstance(finding.evidence, dict) else {})
            evidence_json = json.dumps(evidence_dict)
            steps_json = json.dumps(finding.reproduction_steps)
            records.append((
                finding.id,
                finding.vuln_type.value,
                finding.severity.value,
                finding.title,
                finding.description,
                finding.target_url,
                finding.target_program,
                evidence_json,
                steps_json,
                finding.impact,
                finding.discovered_at.isoformat(),
                finding.source_agent,
                finding.confidence,
                finding.cwe_id,
                finding.cvss_score,
                0,  # verified
                now,
                now,
            ))
        
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT INTO findings (
                    id, vuln_type, severity, title, description,
                    target_url, target_program, evidence_json, reproduction_steps_json,
                    impact, discovered_at, source_agent, confidence,
                    cwe_id, cvss_score, verified, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    vuln_type=excluded.vuln_type,
                    severity=excluded.severity,
                    title=excluded.title,
                    description=excluded.description,
                    evidence_json=excluded.evidence_json,
                    reproduction_steps_json=excluded.reproduction_steps_json,
                    impact=excluded.impact,
                    confidence=excluded.confidence,
                    cwe_id=excluded.cwe_id,
                    cvss_score=excluded.cvss_score,
                    updated_at=excluded.updated_at
            """, records)
            conn.commit()
        
        logger.info(f"[FindingsRepo] Batch saved {len(findings)} findings")
        return [f.id for f in findings]

    def get(self, finding_id: str) -> Optional[Finding]:
        """
        IDでFindingを取得
        
        Args:
            finding_id: FindingのID
            
        Returns:
            Finding、見つからない場合はNone
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?",
                (finding_id,)
            ).fetchone()
            
            if row:
                record = FindingRecord(**dict(row))
                return record.to_finding()
        return None

    def list_all(
        self, 
        limit: int = 100, 
        offset: int = 0,
        order_by: str = "created_at",
        desc: bool = True
    ) -> list[Finding]:
        """
        全Findingsを取得
        
        Args:
            limit: 最大取得数
            offset: オフセット
            order_by: ソートカラム
            desc: 降順ソート
            
        Returns:
            Findingのリスト
        """
        order = "DESC" if desc else "ASC"
        with self._get_connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings ORDER BY {order_by} {order} LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()
            
            return [FindingRecord(**dict(row)).to_finding() for row in rows]

    def search(
        self,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
        target: Optional[str] = None,
        source_agent: Optional[str] = None,
        verified_only: bool = False,
        limit: int = 100,
    ) -> list[Finding]:
        """
        条件でFindingsを検索
        
        Args:
            severity: 重要度フィルタ
            vuln_type: 脆弱性タイプフィルタ
            target: ターゲットURLの部分一致
            source_agent: エージェント名
            verified_only: 検証済みのみ
            limit: 最大取得数
            
        Returns:
            マッチしたFindingのリスト
        """
        conditions = []
        params = []
        
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        
        if vuln_type:
            conditions.append("vuln_type = ?")
            params.append(vuln_type)
        
        if target:
            conditions.append("target_url LIKE ?")
            params.append(f"%{target}%")
        
        if source_agent:
            conditions.append("source_agent = ?")
            params.append(source_agent)
        
        if verified_only:
            conditions.append("verified = 1")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)
        
        with self._get_connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings WHERE {where_clause} ORDER BY created_at DESC LIMIT ?",
                params
            ).fetchall()
            
            return [FindingRecord(**dict(row)).to_finding() for row in rows]

    def mark_verified(self, finding_id: str, verified: bool = True) -> bool:
        """
        Findingを検証済みにマーク
        
        Args:
            finding_id: FindingのID
            verified: 検証済みフラグ
            
        Returns:
            更新成功ならTrue
        """
        with self._get_connection() as conn:
            result = conn.execute(
                "UPDATE findings SET verified = ?, updated_at = ? WHERE id = ?",
                (1 if verified else 0, time.time(), finding_id)
            )
            conn.commit()
            return result.rowcount > 0

    def delete(self, finding_id: str) -> bool:
        """
        Findingを削除
        
        Args:
            finding_id: FindingのID
            
        Returns:
            削除成功ならTrue
        """
        with self._get_connection() as conn:
            result = conn.execute(
                "DELETE FROM findings WHERE id = ?",
                (finding_id,)
            )
            conn.commit()
            return result.rowcount > 0

    def get_statistics(self) -> dict:
        """
        統計情報を取得
        
        Returns:
            統計情報の辞書
        """
        with self._get_connection() as conn:
            # 総数
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            
            # 重要度別
            by_severity = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
            ).fetchall():
                by_severity[row["severity"]] = row["cnt"]
            
            # タイプ別
            by_type = {}
            for row in conn.execute(
                "SELECT vuln_type, COUNT(*) as cnt FROM findings GROUP BY vuln_type ORDER BY cnt DESC LIMIT 10"
            ).fetchall():
                by_type[row["vuln_type"]] = row["cnt"]
            
            # ターゲット別
            by_target = {}
            for row in conn.execute(
                "SELECT target_url, COUNT(*) as cnt FROM findings GROUP BY target_url ORDER BY cnt DESC LIMIT 10"
            ).fetchall():
                by_target[row["target_url"]] = row["cnt"]
            
            # 検証状況
            verified_count = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE verified = 1"
            ).fetchone()[0]
            
            return {
                "total": total,
                "verified": verified_count,
                "unverified": total - verified_count,
                "by_severity": by_severity,
                "by_type": by_type,
                "by_target": by_target,
            }

    def export_all(self, format: str = "json") -> str:
        """
        全Findingsをエクスポート
        
        Args:
            format: 出力形式 ("json")
            
        Returns:
            エクスポート結果
        """
        findings = self.list_all(limit=10000)
        
        if format == "json":
            return json.dumps(
                [f.to_dict() for f in findings],
                indent=2,
                ensure_ascii=False
            )
        
        raise ValueError(f"Unsupported format: {format}")


# シングルトンインスタンス
_repo_instance: Optional[FindingsRepository] = None


def get_findings_repository() -> FindingsRepository:
    """FindingsRepositoryのシングルトンインスタンスを取得"""
    global _repo_instance
    if _repo_instance is None:
        _repo_instance = FindingsRepository()
    return _repo_instance
