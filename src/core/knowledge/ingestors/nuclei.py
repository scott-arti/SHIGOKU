"""
Nuclei Ingestor

Parses Nuclei Scan output and populates the Graph.
Constructs Finding nodes and links them to Endpoints.
"""

import json
import logging
import hashlib
from pathlib import Path
from urllib.parse import urlparse
from typing import Union

from src.core.knowledge.ingestors.base import BaseIngestor

logger = logging.getLogger(__name__)

class NucleiIngestor(BaseIngestor):
    def ingest(self, file_path: Union[str, Path], project_name: str) -> bool:
        """NucleiのJSON出力をIngest"""
        file_path = Path(file_path)
        if not file_path.exists():
            logger.warning(f"Nuclei output not found: {file_path}")
            return

        with self.driver.session() as session:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        self._process_entry(session, entry, project_name)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error processing Nuclei entry: {e}")

    def _process_entry(self, session, entry: dict, project_name: str):
        # Basic fields
        info = entry.get('info', {})
        template_id = entry.get('template-id')
        matched_at = entry.get('matched-at')
        
        if not matched_at or not template_id:
            return

        # Generate unique Finding ID
        # e.g. sha256(template-id + matched-at)
        finding_id = hashlib.sha256(f"{template_id}_{matched_at}".encode()).hexdigest()
        
        # Extract Rich Metadata
        curl_command = entry.get('curl-command', '')
        request = entry.get('request', '')
        response = entry.get('response', '')
        extracted = json.dumps(entry.get('extracted-results', []))
        
        title = info.get('name', template_id)
        severity = info.get('severity', 'info')
        description = info.get('description', '')

        # 1. Create or Update Finding Node
        session.run(
            """
            MERGE (f:Finding {id: $id})
            ON CREATE SET 
                f.title = $title,
                f.severity = $severity,
                f.description = $description,
                f.curl_command = $curl,
                f.request = $req,
                f.response = $res,
                f.extracted = $ext,
                f.project = $project,
                f.tool = 'nuclei',
                f.created_at = datetime()
            ON MATCH SET
                f.severity = $severity,
                f.curl_command = $curl,
                f.updated_at = datetime()
            """,
            id=finding_id, title=title, severity=severity, description=description,
            curl=curl_command, req=request, res=response, ext=extracted,
            project=project_name
        )

        # 2. Link to Endpoint
        # Ensure Endpoint exists (Nuclei might find new URLs)
        parsed = urlparse(matched_at)
        domain = parsed.netloc
        
        session.run(
            """
            MERGE (e:Endpoint {url: $url})
            ON CREATE SET e.project = $project
            MERGE (a:Asset {domain_name: $domain})
            MERGE (e)-[:BELONGS_TO]->(a)
            WITH e
            MATCH (f:Finding {id: $id})
            MERGE (f)-[:AFFECTS]->(e)
            """,
            url=matched_at, domain=domain, project=project_name, id=finding_id
        )
