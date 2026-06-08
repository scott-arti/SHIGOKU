"""
HuntingLogger: AIエージェントの思考プロセスを記録

AIハンティング中の思考、判断、根拠、確信度、仮説を構造化して記録し、
後で人間がレビューできるようにする。
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)


class LogPhase(Enum):
    """ハンティングログのフェーズ"""
    THINKING = "thinking"        # 思考: 何を考えているか
    TRIAL = "trial"              # 試行: 何を試しているか
    JUDGMENT = "judgment"        # 判断: 何を決定したか
    HYPOTHESIS = "hypothesis"    # 仮説: 何を仮定しているか
    DISCOVERY = "discovery"      # 発見: 何を見つけたか
    OUTPUT = "output"            # アウトプット: 何を出力したか


@dataclass
class LogEntry:
    """ハンティングログエントリ"""
    timestamp: datetime
    phase: LogPhase
    content: str                           # 内容
    reasoning: str = ""                    # 根拠・理由
    evidence_paths: List[str] = field(default_factory=list)  # 証拠ファイルパス
    confidence: float = 0.0                # 確信度 (0.0-1.0)
    hypothesis: str = ""                   # 仮説
    output: str = ""                       # アウトプット
    agent_name: str = ""                   # エージェント名
    target_url: str = ""                   # ターゲットURL
    additional_context: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["phase"] = self.phase.value
        return data
    
    def to_markdown(self) -> str:
        """Markdown形式で出力"""
        lines = [
            f"## {self.phase.value.upper()}: {self.content}",
            f"**時刻**: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        
        if self.agent_name:
            lines.append(f"**エージェント**: {self.agent_name}")
        
        if self.target_url:
            lines.append(f"**ターゲット**: {self.target_url}")
        
        if self.confidence > 0:
            lines.append(f"**確信度**: {self.confidence:.2%}")
        
        if self.reasoning:
            lines.append(f"\n**根拠・理由**:\n{self.reasoning}")
        
        if self.hypothesis:
            lines.append(f"\n**仮説**:\n{self.hypothesis}")
        
        if self.output:
            lines.append(f"\n**アウトプット**:\n```\n{self.output}\n```")
        
        if self.evidence_paths:
            lines.append("\n**証拠ファイル**:")
            for path in self.evidence_paths:
                lines.append(f"- `{path}`")
        
        return "\n".join(lines)


class HuntingLogger:
    """
    AIハンティングの思考プロセスを記録するロガー
    
    使用例:
        logger = HuntingLogger(project_name="target.com")
        logger.log(
            phase=LogPhase.THINKING,
            content="JWT認証のalg=none攻撃を試行すべきか検討中",
            reasoning="ターゲットはJWT認証を使用しており、alg=noneが許可される可能性がある",
            confidence=0.7
        )
    """
    
    def __init__(
        self,
        project_name: str,
        output_dir: str = "projects",
        auto_flush: bool = True
    ):
        self.project_name = project_name
        self.output_dir = Path(output_dir)
        self.auto_flush = auto_flush
        
        # ログエントリのバッファ
        self.entries: List[LogEntry] = []
        
        # 出力先ディレクトリの作成
        self.log_dir = self.output_dir / project_name / "hunting_log"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # セッションID（タイムスタンプベース）
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        logger.info(f"HuntingLogger initialized for project: {project_name}")
    
    def log(
        self,
        phase: LogPhase,
        content: str,
        reasoning: str = "",
        evidence_paths: Optional[List[str]] = None,
        confidence: float = 0.0,
        hypothesis: str = "",
        output: str = "",
        agent_name: str = "",
        target_url: str = "",
        **kwargs
    ) -> LogEntry:
        """
        ログエントリを記録
        
        Args:
            phase: ログのフェーズ
            content: 内容
            reasoning: 根拠・理由
            evidence_paths: 証拠ファイルのパスリスト
            confidence: 確信度 (0.0-1.0)
            hypothesis: 仮説
            output: アウトプット
            agent_name: エージェント名
            target_url: ターゲットURL
            **kwargs: 追加コンテキスト
        
        Returns:
            作成されたLogEntry
        """
        entry = LogEntry(
            timestamp=datetime.now(),
            phase=phase,
            content=content,
            reasoning=reasoning,
            evidence_paths=evidence_paths or [],
            confidence=confidence,
            hypothesis=hypothesis,
            output=output,
            agent_name=agent_name,
            target_url=target_url,
            additional_context=kwargs
        )
        
        self.entries.append(entry)
        
        # 即座にフラッシュ
        if self.auto_flush:
            self.flush()
        
        return entry
    
    def flush(self) -> None:
        """エントリをファイルに書き出す"""
        if not self.entries:
            return
        
        # JSON形式で保存
        json_path = self.log_dir / f"{self.session_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                [entry.to_dict() for entry in self.entries],
                f,
                ensure_ascii=False,
                indent=2
            )
        
        # Markdown形式でも保存（人間が読みやすい）
        md_path = self.log_dir / f"{self.session_id}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# Hunting Log: {self.project_name}\n\n")
            f.write(f"**Session ID**: {self.session_id}\n\n")
            f.write("---\n\n")
            
            for entry in self.entries:
                f.write(entry.to_markdown())
                f.write("\n\n---\n\n")
        
        logger.debug(f"Flushed {len(self.entries)} entries to {json_path}")
    
    def get_entries_by_phase(self, phase: LogPhase) -> List[LogEntry]:
        """指定フェーズのエントリを取得"""
        return [e for e in self.entries if e.phase == phase]
    
    def get_high_confidence_entries(self, threshold: float = 0.7) -> List[LogEntry]:
        """高確信度のエントリを取得"""
        return [e for e in self.entries if e.confidence >= threshold]
    
    def clear(self) -> None:
        """エントリをクリア"""
        self.entries.clear()


# グローバルインスタンス管理
_logger_instances: dict[str, HuntingLogger] = {}


def get_hunting_logger(project_name: str) -> HuntingLogger:
    """
    プロジェクト名に対応するHuntingLoggerを取得（シングルトン）
    
    Args:
        project_name: プロジェクト名
    
    Returns:
        HuntingLogger インスタンス
    """
    if project_name not in _logger_instances:
        _logger_instances[project_name] = HuntingLogger(project_name)
    
    return _logger_instances[project_name]
