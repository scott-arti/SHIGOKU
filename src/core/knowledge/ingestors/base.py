"""
Base Ingestor

Abstract base class for all data ingestors.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from neo4j import Driver
from src.core.knowledge.driver import get_db

class BaseIngestor(ABC):
    def __init__(self):
        self.driver: Driver = get_db()
        
    @abstractmethod
    def ingest(self, file_path: Path, project_name: str):
        """Parse file and update Knowledge Graph."""
        pass
