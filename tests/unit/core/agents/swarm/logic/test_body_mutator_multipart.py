
import pytest
from src.core.agents.swarm.logic.body_mutator import BodyMutator

def test_multipart_parse_and_serialize():
    boundary = "----ShigokuBoundaryTest"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="user_id"\r\n'
        f"\r\n"
        f"123\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"file_content_here\r\n"
        f"--{boundary}--\r\n"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    
    # Parse
    parsed = BodyMutator.parse(body, content_type)
    assert parsed["user_id"]["value"] == "123"
    assert parsed["file"]["filename"] == "test.txt"
    assert parsed["file"]["content_type"] == "text/plain"
    assert parsed["file"]["value"] == "file_content_here"
    
    # Serialize
    serialized = BodyMutator.serialize(parsed, content_type)
    assert f"--{boundary}" in serialized
    assert 'name="user_id"' in serialized
    assert 'filename="test.txt"' in serialized
    assert "Content-Type: text/plain" in serialized
    assert "file_content_here" in serialized
    assert serialized.endswith(f"--{boundary}--\r\n")

def test_multipart_replace_value():
    boundary = "----ShigokuBoundaryTest"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="id"\r\n'
        f"\r\n"
        f"OLD_VALUE\r\n"
        f"--{boundary}--\r\n"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    
    new_body = BodyMutator.replace_value(body, content_type, "OLD_VALUE", "NEW_VALUE")
    assert "NEW_VALUE" in new_body
    assert "OLD_VALUE" not in new_body
    assert f"--{boundary}" in new_body

def test_multipart_duplicate_param():
    boundary = "----ShigokuBoundaryTest"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="target"\r\n'
        f"\r\n"
        f"orig_val\r\n"
        f"--{boundary}--\r\n"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    
    # HPP pattern
    new_body = BodyMutator.duplicate_param(body, content_type, "target", "injected_val")
    assert new_body.count('name="target"') == 2
    assert "orig_val" in new_body
    assert "injected_val" in new_body
    assert f"--{boundary}" in new_body
