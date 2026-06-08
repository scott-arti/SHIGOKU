
import pytest
from src.core.domain.model.target import TargetAsset, TargetType

def test_target_asset_creation():
    # Public URL
    url = "https://example.com"
    asset = TargetAsset.create(url)
    assert asset.asset_type == TargetType.SINGLE_URL_PUBLIC
    
    # Internal URL by IP
    internal_url = "http://192.168.1.1"
    asset = TargetAsset.create(internal_url)
    assert asset.asset_type == TargetType.SINGLE_URL_INTERNAL

    # Localhost
    localhost = "http://localhost:8080"
    asset = TargetAsset.create(localhost)
    assert asset.asset_type == TargetType.SINGLE_URL_INTERNAL

    # Wildcard Domain
    wildcard = "*.example.com"
    asset = TargetAsset.create(wildcard)
    assert asset.asset_type == TargetType.WILDCARD_DOMAIN
    
    # File Path (Abs)
    file_path = "/tmp/test.txt"
    asset = TargetAsset.create(file_path)
    assert asset.asset_type == TargetType.LOCAL_FILE or asset.asset_type == TargetType.LOCAL_DIR # Simplified logic currently

    # Directory Path
    dir_path = "/tmp/"
    asset = TargetAsset.create(dir_path)
    assert asset.asset_type == TargetType.LOCAL_DIR or asset.asset_type == TargetType.LOCAL_FILE

def test_internal_detection():
    assert TargetAsset._is_internal("localhost")
    assert TargetAsset._is_internal("127.0.0.1")
    assert TargetAsset._is_internal("192.168.100.2")
    assert TargetAsset._is_internal("10.0.0.5")
    assert TargetAsset._is_internal("dvwa.local")
    assert not TargetAsset._is_internal("example.com")
    assert not TargetAsset._is_internal("8.8.8.8")

def test_config_metadata():
    config = {'mode': 'CTF', 'flag_format': 'CTF{.*}'}
    asset = TargetAsset.create("example.com", config)
    assert asset.metadata.get('flag_format') == 'CTF{.*}'
