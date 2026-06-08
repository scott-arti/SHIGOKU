import pytest
from src.core.attack.graphql_crafter import GraphQLCrafter
import json

class TestGraphQLCrafter:
    
    @pytest.fixture
    def crafter(self):
        return GraphQLCrafter()
    
    def test_introspection_query(self, crafter):
        query = crafter.get_introspection_query()
        assert "__schema" in query
        assert "queryType" in query
        
    def test_generate_nested_query(self, crafter):
        query = crafter.generate_nested_query("user", depth=3)
        # Should look like: query DeepNest { user { user { user { id } } } }
        assert query.count("user {") == 3
        assert "DeepNest" in query
        
    def test_extract_sensitive(self, crafter):
        mock_schema = {
            "data": {
                "__schema": {
                    "types": [
                        {
                            "name": "User",
                            "fields": [
                                {"name": "username"},
                                {"name": "hashedPassword"}, # Sensitive
                                {"name": "apiToken"}      # Sensitive
                            ]
                        }
                    ]
                }
            }
        }
        
        sensitive = crafter.extract_sensitive_fields(mock_schema)
        assert "User.hashedPassword" in sensitive
        assert "User.apiToken" in sensitive
        assert "User.username" not in sensitive
