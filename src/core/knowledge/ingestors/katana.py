"""
Katana Ingestor

Parses Katana (Spider) output and populates the Graph.
Constructs Endpoint, Parameter, and Technology nodes.
"""

import json
import logging
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import hashlib
from typing import Union

from src.core.knowledge.ingestors.base import BaseIngestor

logger = logging.getLogger(__name__)

class KatanaIngestor(BaseIngestor):
    def ingest(self, file_path: Union[str, Path], project_name: str) -> bool:
        """KatanaのJSON出力をIngest"""
        file_path = Path(file_path)
        if not file_path.exists():
            logger.warning(f"Katana output not found: {file_path}")
            return False

        with self.driver.session() as session:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Handle both JSON array and JSON Lines
                try:
                    content = f.read().strip()
                    if not content:
                        return
                    
                    if content.startswith('['):
                        data_list = json.loads(content)
                    else:
                        # Parse line by line
                        f.seek(0)
                        data_list = []
                        for line in f:
                            if line.strip():
                                try:
                                    data_list.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    logger.error(f"Failed to parse Katana output: {e}")
                    return

                for entry in data_list:
                    self._process_entry(session, entry, project_name)

    def _process_entry(self, session, entry: dict, project_name: str):
        url = entry.get('endpoint')
        if not url:
            return

        parsed = urlparse(url)
        domain = parsed.netloc
        method = entry.get('request', {}).get('method', 'GET')
        
        # 1. Ensure Asset (Domain)
        session.run(
            """
            MERGE (a:Asset {domain_name: $domain})
            ON CREATE SET a.project = $project
            """,
            domain=domain, project=project_name
        )

        # 2. Ensure Endpoint
        session.run(
            """
            MERGE (e:Endpoint {url: $url})
            ON CREATE SET e.method = $method, e.project = $project
            MERGE (a:Asset {domain_name: $domain})
            MERGE (e)-[:BELONGS_TO]->(a)
            """,
            url=url, method=method, domain=domain, project=project_name
        )

        # 3. Process Parameters (Query params)
        query_params = parse_qs(parsed.query)
        for param_name in query_params.keys():
            param_id = hashlib.sha256(f"{url}_{param_name}".encode()).hexdigest()
            session.run(
                """
                MERGE (p:Parameter {id: $id})
                ON CREATE SET p.name = $name, p.type = 'query', p.project = $project
                WITH p
                MATCH (e:Endpoint {url: $url})
                MERGE (e)-[:ACCEPTS]->(p)
                """,
                id=param_id, name=param_name, url=url, project=project_name
            )

        # 4. Process Technologies
        technologies = entry.get('technologies', [])
        for tech in technologies:
            session.run(
                """
                MERGE (t:Technology {name: $name})
                WITH t
                MATCH (e:Endpoint {url: $url})
                MERGE (e)-[:BUILT_WITH]->(t)
                """,
                name=tech, url=url
            )
