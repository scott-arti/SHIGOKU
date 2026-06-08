"""
ConfigSchemaのテスト

Pydanticスキーマのバリデーション動作検証
"""

import tempfile
from pathlib import Path

import pytest
import yaml

from src.core.adapters.external.config_schema import (
    ExternalToolsConfig,
    ToolConfig,
    InstallMethod,
    load_config,
)


def test_tool_config_creation():
    """ToolConfigの作成テスト"""
    config = ToolConfig(
        name="dalfox",
        version="2.9.2",
        download_url="https://example.com/dalfox.tar.gz",
        checksum="abc123",
        install_method=InstallMethod.DIRECT_DOWNLOAD,
        timeout_seconds=120,
        max_concurrent=3
    )
    
    assert config.name == "dalfox"
    assert config.version == "2.9.2"
    assert config.executable_name == "dalfox"  # デフォルトでnameと同じ
    assert config.timeout_seconds == 120
    assert config.max_concurrent == 3


def test_tool_config_default_executable_name():
    """executable_nameのデフォルト値テスト"""
    config = ToolConfig(
        name="nuclei",
        version="3.1.0",
        install_method=InstallMethod.GO_INSTALL
    )
    
    # executable_nameが未指定時はnameが使用される
    assert config.executable_name == "nuclei"


def test_config_from_yaml():
    """YAMLファイルからの設定読み込みテスト"""
    # テスト用YAMLを作成
    yaml_content = {
        "tools": {
            "dalfox": {
                "name": "dalfox",
                "version": "2.9.2",
                "download_url": "https://github.com/hahwul/dalfox/releases/download/v2.9.2/dalfox_2.9.2_linux_amd64.tar.gz",
                "checksum": "sha256:abc123def456",
                "install_method": "direct_download",
                "timeout_seconds": 120,
                "max_concurrent": 3
            },
            "nuclei": {
                "name": "nuclei",
                "version": "3.1.0",
                "install_method": "go_install",
                "timeout_seconds": 300
            }
        },
        "global": {
            "security": {
                "prohibit_pre_verification_chmod": True
            }
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(yaml_content, f)
        temp_path = Path(f.name)
    
    try:
        config = ExternalToolsConfig.from_yaml(temp_path)
        
        # ツール設定が読み込まれていること
        assert "dalfox" in config.tools
        assert "nuclei" in config.tools
        
        dalfox = config.get_tool_config("dalfox")
        assert dalfox.version == "2.9.2"
        assert dalfox.install_method == InstallMethod.DIRECT_DOWNLOAD
        
        # グローバル設定
        assert config.global_.security.prohibit_pre_verification_chmod is True
        
    finally:
        temp_path.unlink()


def test_config_validation_success():
    """設定バリデーション成功テスト"""
    config = ExternalToolsConfig(
        tools={
            "dalfox": ToolConfig(
                name="dalfox",
                version="2.9.2",
                download_url="https://example.com/dalfox.tar.gz",
                install_method=InstallMethod.DIRECT_DOWNLOAD
            )
        }
    )
    
    errors = config.validate_all_tools()
    
    # エラーがないこと
    assert len(errors) == 0


def test_config_validation_missing_download_url():
    """ダウンロードURL不足時のバリデーションエラーテスト"""
    config = ExternalToolsConfig(
        tools={
            "dalfox": ToolConfig(
                name="dalfox",
                version="2.9.2",
                install_method=InstallMethod.DIRECT_DOWNLOAD
                # download_urlがない
            )
        }
    )
    
    errors = config.validate_all_tools()
    
    # direct_download時はdownload_urlが必須
    assert "dalfox" in errors
    assert any("download_url is required" in e for e in errors["dalfox"])


def test_config_validation_disallowed_method():
    """許可されていないインストール方法のテスト"""
    config = ExternalToolsConfig(
        tools={
            "test_tool": ToolConfig(
                name="test_tool",
                version="1.0.0",
                install_method=InstallMethod.PIP_INSTALL
            )
        },
        global_={
            "security": {
                "allowed_install_methods": [
                    InstallMethod.DIRECT_DOWNLOAD,
                    InstallMethod.GO_INSTALL
                ]
            }
        }
    )
    
    errors = config.validate_all_tools()
    
    # pip_installは許可されていない
    assert "test_tool" in errors


def test_load_config_default_path():
    """デフォルトパスでの設定読み込みテスト"""
    # 存在しないパスを指定してFileNotFoundErrorを確認
    with pytest.raises(FileNotFoundError):
        load_config(Path("/nonexistent/path/external_tools.yaml"))


def test_config_to_yaml():
    """設定のYAML書き出しテスト"""
    config = ExternalToolsConfig(
        tools={
            "test_tool": ToolConfig(
                name="test_tool",
                version="1.0.0",
                install_method=InstallMethod.DIRECT_DOWNLOAD,
                download_url="https://example.com/tool.tar.gz"
            )
        }
    )
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        temp_path = Path(f.name)
    
    try:
        # YAMLに書き出し
        config.to_yaml(temp_path)
        
        # 書き出したファイルを読み込み
        loaded = ExternalToolsConfig.from_yaml(temp_path)
        
        assert "test_tool" in loaded.tools
        assert loaded.tools["test_tool"].version == "1.0.0"
        
    finally:
        temp_path.unlink()
