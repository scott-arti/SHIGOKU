"""
Neo4j Driver Manager

Handles connection to the Neo4j database using the official neo4j python driver.
Implements singleton pattern for driver instance.
"""

import os
import logging
from typing import Optional
from neo4j import GraphDatabase, Driver, Record

# Get logger
logger = logging.getLogger(__name__)

class Neo4jDriver:
    _instance: Optional[Driver] = None
    
    @classmethod
    def get_driver(cls) -> Driver:
        """Get or create the global Neo4j driver instance."""
        if cls._instance is None:
            uri = os.getenv("SHIGOKU_NEO4J_URI", "bolt://localhost:7687")
            user = os.getenv("SHIGOKU_NEO4J_USER", "neo4j")
            password = os.getenv("SHIGOKU_NEO4J_PASSWORD", "shigoku2024")
            
            try:
                # SHIGOKU-MOD: Suppress noisy informational notifications (like index already exists)
                cls._instance = GraphDatabase.driver(
                    uri, 
                    auth=(user, password),
                    notifications_min_severity="WARNING"
                )
                cls._instance.verify_connectivity()
                logger.info(f"Connected to Neo4j at {uri}")
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
                # In development, we might want to fail hard?
                # User requested Neo4j is mandatory.
                raise e
                
        return cls._instance

    @classmethod
    def close(cls):
        """Close the driver connection."""
        if cls._instance:
            cls._instance.close()
            cls._instance = None
            logger.info("Neo4j driver closed")

    @classmethod
    def verify_connectivity(cls) -> bool:
        """Check if Neo4j is accessible."""
        try:
            driver = cls.get_driver()
            driver.verify_connectivity()
            return True
        except Exception as e:
            logger.error(f"Neo4j connectivity check failed: {e}")
            return False

def get_db():
    return Neo4jDriver.get_driver()
