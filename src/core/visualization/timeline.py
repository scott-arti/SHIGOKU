"""
Timeline Generator

ハンティング進捗のタイムライン表示
"""

from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
import json

from src.core.models.finding import Finding


class TimelineEvent:
    """タイムラインイベント"""
    
    def __init__(
        self,
        timestamp: datetime,
        event_type: str,
        title: str,
        description: str = "",
        metadata: Dict[str, Any] = None
    ):
        self.timestamp = timestamp
        self.event_type = event_type  # scan, finding, report, etc.
        self.title = title
        self.description = description
        self.metadata = metadata or {}
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "metadata": self.metadata
        }


class TimelineGenerator:
    """タイムライン生成クラス"""
    
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir
        self.events: List[TimelineEvent] = []
    
    def add_event(
        self,
        event_type: str,
        title: str,
        description: str = "",
        metadata: Dict[str, Any] = None
    ) -> None:
        """イベントを追加"""
        event = TimelineEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            title=title,
            description=description,
            metadata=metadata
        )
        self.events.append(event)
    
    def from_findings(self, findings: List[Finding]) -> None:
        """Findingからイベントを生成"""
        for finding in findings:
            self.add_event(
                event_type="finding",
                title=f"{finding.severity.value.upper()}: {finding.title}",
                description=finding.description,
                metadata={
                    "severity": finding.severity.value,
                    "vuln_type": finding.vuln_type.value,
                    "target_url": finding.target_url,
                    "confidence": finding.confidence
                }
            )
    
    def generate_markdown(self) -> str:
        """Markdown形式のタイムラインを生成"""
        lines = []
        lines.append("# 🕐 Hunting Timeline")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # イベントを時系列順にソート
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        # 日付ごとにグループ化
        events_by_date = {}
        for event in sorted_events:
            date_key = event.timestamp.strftime('%Y-%m-%d')
            if date_key not in events_by_date:
                events_by_date[date_key] = []
            events_by_date[date_key].append(event)
        
        # 日付ごとに表示
        for date, events in events_by_date.items():
            lines.append(f"## 📅 {date}")
            lines.append("")
            
            for event in events:
                time_str = event.timestamp.strftime('%H:%M:%S')
                icon = self._get_icon(event.event_type)
                lines.append(f"### {icon} {time_str} - {event.title}")
                if event.description:
                    lines.append(f"> {event.description}")
                lines.append("")
        
        return "\n".join(lines)
    
    def generate_json(self) -> str:
        """JSON形式のタイムラインを生成"""
        data = {
            "generated_at": datetime.now().isoformat(),
            "events": [event.to_dict() for event in self.events]
        }
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    def save(self, filename: str = None) -> Path:
        """タイムラインを保存"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"timeline_{timestamp}.md"
        
        output_path = self.project_dir / filename
        markdown = self.generate_markdown()
        
        output_path.write_text(markdown, encoding='utf-8')
        return output_path
    
    def _get_icon(self, event_type: str) -> str:
        """イベントタイプに応じたアイコン"""
        icons = {
            "scan": "🔍",
            "finding": "🎯",
            "report": "📄",
            "attack": "⚔️",
            "success": "✅",
            "error": "❌",
        }
        return icons.get(event_type, "📌")


def generate_timeline(project_dir: Path, findings: List[Finding]) -> Path:
    """タイムライン生成（便利関数）"""
    generator = TimelineGenerator(project_dir)
    generator.from_findings(findings)
    return generator.save()
