"""
Graph Schema Definitions

Defines constraints and indexes for the Knowledge Graph.
Essential for performance and data integrity (e.g. preventing duplicate nodes).
"""

import logging
from src.core.knowledge.driver import get_db

logger = logging.getLogger(__name__)

class GraphSchema:
    @staticmethod
    def apply_constraints():
        """Apply uniqueness constraints and indexes to the database."""
        driver = get_db()
        
        constraints = [
            # Asset Constraints
            "CREATE CONSTRAINT asset_domain_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.domain_name IS UNIQUE",
            "CREATE INDEX asset_ip_index IF NOT EXISTS FOR (a:Asset) ON (a.ip_address)",
            
            # Application Logic Constraints
            "CREATE CONSTRAINT endpoint_url_unique IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.url IS UNIQUE",
            "CREATE CONSTRAINT tech_name_unique IF NOT EXISTS FOR (t:Technology) REQUIRE t.name IS UNIQUE",
            
            # Parameter Constraints
            # Composite constraint might not be available in Community Edition, 
            # so we might rely on MERGE logic or a generated ID.
            "CREATE CONSTRAINT param_id_unique IF NOT EXISTS FOR (p:Parameter) REQUIRE p.id IS UNIQUE",

            # Finding Constraints
            "CREATE CONSTRAINT finding_id_unique IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
        ]
        
        with driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.info(f"Applied constraint: {constraint}")
                except Exception as e:
                    logger.warning(f"Failed to apply constraint '{constraint}': {e}")

if __name__ == "__main__":
    # Allow running this script directly to init schema
    logging.basicConfig(level=logging.INFO)
    GraphSchema.apply_constraints()
