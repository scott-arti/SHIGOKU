import pytest
from src.core.session.multi_session_manager import MultiSessionManager

def test_add_and_get_session():
    msm = MultiSessionManager()
    headers_admin = {"Authorization": "Bearer admin-token", "X-Custom": "val1"}
    msm.add_session("admin", headers_admin, {"user_id": 1})
    
    # 取得テスト
    retrieved = msm.get_session("admin")
    assert retrieved is not None
    assert retrieved["authorization"] == "Bearer admin-token" # 小文字化の確認
    
    # メタデータ取得テスト
    meta = msm.get_metadata("admin")
    assert meta["user_id"] == 1

def test_get_all_alternative_sessions():
    msm = MultiSessionManager()
    msm.add_session("admin", {"auth": "admin"})
    msm.add_session("user_a", {"auth": "user_a"})
    msm.add_session("user_b", {"auth": "user_b"})
    
    # user_a を除外して取得
    alts = msm.get_all_alternative_sessions(exclude_role="user_a")
    
    assert "admin" in alts
    assert "user_b" in alts
    assert "user_a" not in alts
    assert alts["admin"]["headers"]["auth"] == "admin"

def test_clear_sessions():
    msm = MultiSessionManager()
    msm.add_session("role1", {"h": "v"})
    msm.clear()
    assert len(msm.list_roles()) == 0

def test_list_roles():
    msm = MultiSessionManager()
    msm.add_session("a", {"h": "v"})
    msm.add_session("b", {"h": "v"})
    roles = msm.list_roles()
    assert "a" in roles
    assert "b" in roles
    assert len(roles) == 2
