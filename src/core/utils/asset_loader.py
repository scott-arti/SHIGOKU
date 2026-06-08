import json
import yaml
from typing import Any, Dict, Union
from pathlib import Path
from functools import lru_cache

class AssetLoader:
    """
    AssetLoader is responsible for loading static assets (payloads, wordlists, configs)
    from the `src/assets` directory.
    
    It supports JSON and YAML formats and implements caching to minimize disk I/O.
    """
    
    _instance = None
    _assets_dir: Path
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AssetLoader, cls).__new__(cls)
            # Determine assets directory relative to project root or use config
            # Assuming src/main.py is entry point, assets is in src/assets
            # Or use settings if defined
            base_dir = Path(__file__).resolve().parent.parent.parent # src/core/utils -> src/core -> src -> PROJECT/src
            cls._instance._assets_dir = base_dir / "assets"
        return cls._instance

    @property
    def assets_dir(self) -> Path:
        return self._assets_dir

    def get_path(self, relative_path: str) -> Path:
        """Resolve absolute path for an asset."""
        return self._assets_dir / relative_path

    @lru_cache(maxsize=64)
    def load_yaml(self, filename: str) -> Union[Dict[str, Any], list]:
        """
        Load a YAML file from the assets directory.
        Cached to improve performance.
        """
        file_path = self.get_path(filename)
        if not file_path.exists():
            # Try finding it in payloads subdirectory if not found in root
            file_path_payloads = self.get_path(f"payloads/{filename}")
            if file_path_payloads.exists():
                file_path = file_path_payloads
            if file_path_payloads.exists():
                file_path = file_path_payloads
            else:
                raise FileNotFoundError(f"Asset file not found: {filename} (searched in {self._assets_dir})")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse YAML asset {filename}: {e}")

    @lru_cache(maxsize=32)
    def load_json(self, filename: str) -> Union[Dict[str, Any], list]:
        """
        Load a JSON file from the assets directory.
        Cached to improve performance.
        """
        file_path = self.get_path(filename)
        if not file_path.exists():
             # Try finding it in payloads subdirectory
            file_path_payloads = self.get_path(f"payloads/{filename}")
            if file_path_payloads.exists():
                file_path = file_path_payloads
            else:
                raise FileNotFoundError(f"Asset file not found: {filename}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON asset {filename}: {e}")

    def load_text_lines(self, filename: str) -> list[str]:
        """Load a text file as a list of lines, stripping whitespace."""
        file_path = self.get_path(filename)
        if not file_path.exists():
             # Try finding it in payloads subdirectory
            file_path_payloads = self.get_path(f"payloads/{filename}")
            if file_path_payloads.exists():
                file_path = file_path_payloads
            else:
                raise FileNotFoundError(f"Asset file not found: {filename}")
        
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

# Singleton instance access
asset_loader = AssetLoader()
