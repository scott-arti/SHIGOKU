
import pytest
import json
from src.core.agents.swarm.logic.body_mutator import BodyMutator

def test_detect_content_type():
    # 1. Header based
    assert BodyMutator.detect_content_type({"Content-Type": "application/json"}, "{}") == "json"
    assert BodyMutator.detect_content_type({"content-type": "application/x-www-form-urlencoded"}, "a=b") == "urlencoded"
    
    # 2. Heuristic based
    assert BodyMutator.detect_content_type({}, '{"test": 1}') == "json"
    assert BodyMutator.detect_content_type({}, '[1, 2, 3]') == "json"
    assert BodyMutator.detect_content_type({}, "user_id=123&name=test") == "urlencoded"
    assert BodyMutator.detect_content_type({}, "just a string") == "unknown"

def test_json_flow():
    body = '{"id": 123, "data": {"uuid": "550e8400-e29b-41d4-a716-446655440000", "items": [{"id": 456}]}}'
    ct = "json"
    
    # Extract IDs
    ids = BodyMutator.extract_ids(body, ct)
    values = [i[0] for i in ids]
    assert "123" in values
    assert "456" in values
    assert "550e8400-e29b-41d4-a716-446655440000" in values
    
    # Replace ID
    replaced = BodyMutator.replace_value(body, ct, "123", "999")
    data = json.loads(replaced)
    assert data["id"] == 999
    
    # Inject Properties (Mass Assignment)
    injected = BodyMutator.inject_properties(body, ct, {"role": "admin", "is_admin": True})
    data = json.loads(injected)
    assert data["role"] == "admin"
    assert data["is_admin"] is True
    assert data["id"] == 123 # Original remains

def test_urlencoded_flow():
    body = "user_id=123&name=test&token=abc"
    ct = "urlencoded"
    
    # Extract IDs
    ids = BodyMutator.extract_ids(body, ct)
    values = [i[0] for i in ids]
    assert "123" in values
    
    # Replace ID
    replaced = BodyMutator.replace_value(body, ct, "123", "456")
    assert "user_id=456" in replaced
    assert "name=test" in replaced
    
    # Inject
    injected = BodyMutator.inject_properties(body, ct, {"role": "admin"})
    assert "role=admin" in injected
    assert "user_id=123" in injected

def test_nested_json_replacement():
    body = '{"items": [{"user_id": 1}, {"user_id": 2}]}'
    replaced = BodyMutator.replace_value(body, "json", "1", "999")
    data = json.loads(replaced)
    assert data["items"][0]["user_id"] == 999
    assert data["items"][1]["user_id"] == 2
