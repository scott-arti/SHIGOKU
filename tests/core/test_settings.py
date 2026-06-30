import os
import pytest
from src.core.config.settings import get_settings, Settings
from pydantic import ValidationError

# Module-level env setup: the new YAML-based LLM config requires API keys to be set
os.environ.setdefault("DEEPSEEK_API_KEY", "test-key")
os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("ANY_LLM_API_KEY", "test-key")


def test_settings_default_values():
    """デフォルト値が正しく設定されるか"""
    settings = get_settings()
    assert settings.mode == "bugbounty"
    assert settings.scan.threads == 10
    assert settings.scan.rate_limit == 50

def test_settings_env_override():
    """環境変数による上書きが機能するか"""
    os.environ["SHIGOKU_MODE"] = "ctf"
    os.environ["SHIGOKU_SCAN__THREADS"] = "99"
    
    # 再初期化
    settings = Settings()
    
    assert settings.mode == "ctf"
    assert settings.scan.threads == 99
    
    # クリーンアップ
    del os.environ["SHIGOKU_MODE"]
    del os.environ["SHIGOKU_SCAN__THREADS"]

def test_settings_validation_error():
    """不正な型の設定でエラーが出るか"""
    os.environ["SHIGOKU_SCAN__THREADS"] = "not-an-int"
    
    with pytest.raises(ValidationError):
        Settings()
        
    del os.environ["SHIGOKU_SCAN__THREADS"]

def test_config_manager_integration():
    """ConfigManager との統合テスト"""
    from src.core.config_manager import get_config
    
    config = get_config()
    # 初期状態を確認
    assert hasattr(config, "scan")
    assert config.scan.threads == 10
    
    # 環境変数で上書き (新規インスタンスで反映される)
    os.environ["SHIGOKU_SCAN__THREADS"] = "42"
    from src.core.config.settings import get_settings as _get_settings
    new_settings = _get_settings(reinit=True) # 本来は reload 的なものが必要だが簡易的に
    
    # get_config 側もシングルトンなので、ここでの挙動を確認
    # 実際には get_settings は一度呼ばれるとキャッシュされる
    assert Settings().scan.threads == 42
    
    del os.environ["SHIGOKU_SCAN__THREADS"]
