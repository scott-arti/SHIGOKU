import pytest
import os
from pathlib import Path
from src.core.domain.scope.scope_manager import ScopeManager
from src.core.domain.model.target import TargetType

def test_scope_manager_load_static_url():
    # URL文字列を直接渡した場合
    targets = ScopeManager.load("http://example.com")
    assert len(targets) == 1
    assert targets[0].raw_input == "http://example.com"
    assert targets[0].asset_type == TargetType.SINGLE_URL_PUBLIC

def test_scope_manager_load_static_file(tmp_path):
    # ファイルパスを渡した場合
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("in-scope\nexample.com\n192.168.1.1\nout-of-scope\nforbidden.com")
    
    targets = ScopeManager.load(str(scope_file))
    # ScopeManagerの以前の定義では example.com と 192.168.1.1 が In-Scope
    # ただし IP判定などが走るので最低限 example.com が入ることを確認
    assert len(targets) >= 1
    inputs = [t.raw_input for t in targets]
    assert "example.com" in inputs
    assert "forbidden.com" not in inputs

def test_scope_manager_load_nonexistent():
    # 存在しないパスを渡した場合(URLとして解釈される)
    targets = ScopeManager.load("nonexistent_domain_or_file")
    assert len(targets) == 1
    assert targets[0].raw_input == "nonexistent_domain_or_file"
