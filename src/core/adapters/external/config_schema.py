"""
External Tools Configuration Schema

external_tools.yamlのPydanticスキーマ定義。
型安全な設定管理とバリデーションを提供。
"""

from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, HttpUrl
import yaml


class InstallMethod(str, Enum):
    """インストール方法"""
    DIRECT_DOWNLOAD = "direct_download"
    GO_INSTALL = "go_install"
    SYSTEM_PACKAGE = "system_package"
    PIP_INSTALL = "pip_install"


class ToolConfig(BaseModel):
    """個別ツール設定スキーマ"""
    
    name: str = Field(..., description="ツール名")
    version: str = Field(..., description="ツールバージョン")
    download_url: Optional[str] = Field(
        default=None,
        description="ダウンロードURL（テンプレート可: {version}）"
    )
    checksum: Optional[str] = Field(
        default=None,
        description="SHA256チェックサム"
    )
    checksum_type: str = Field(
        default="sha256",
        description="チェックサムタイプ"
    )
    install_method: InstallMethod = Field(
        default=InstallMethod.DIRECT_DOWNLOAD,
        description="インストール方法"
    )
    executable_name: Optional[str] = Field(
        default=None,
        description="実行ファイル名（指定なしはnameと同じ）"
    )
    timeout_seconds: int = Field(
        default=60,
        ge=1,
        description="デフォルトタイムアウト秒数"
    )
    max_concurrent: int = Field(
        default=3,
        ge=1,
        le=20,
        description="最大同時実行数"
    )
    
    @field_validator('executable_name', mode='before')
    @classmethod
    def set_executable_name(cls, v, info):
        """executable_nameが未指定時はnameを使用"""
        if v is None:
            return info.data.get('name')
        return v


class DownloadConfig(BaseModel):
    """ダウンロード設定"""
    timeout_seconds: int = Field(default=60, ge=1)
    retry_count: int = Field(default=3, ge=0)
    verify_ssl: bool = Field(default=True)
    user_agent: str = Field(
        default="SHIGOKU-BinaryManager/1.0"
    )


class VerificationConfig(BaseModel):
    """検証設定"""
    enforce_checksum: bool = Field(
        default=True,
        description="チェックサム検証を強制"
    )
    gpg_verification: bool = Field(
        default=False,
        description="GPG署名検証（現在未対応）"
    )
    auto_update: bool = Field(
        default=False,
        description="自動アップデート確認"
    )


class SecurityConfig(BaseModel):
    """セキュリティ設定
    
    絶対禁止: 検証前のバイナリに実行権限付与
    """
    prohibit_pre_verification_chmod: bool = Field(
        default=True,
        description="検証前のchmod実行を禁止（絶対にTrueにすること）"
    )
    use_temp_directory_for_download: bool = Field(
        default=True,
        description="一時ディレクトリ使用を強制"
    )
    persist_verification_flags: bool = Field(
        default=True,
        description="検証済みフラグの永続化"
    )
    allowed_install_methods: List[InstallMethod] = Field(
        default=[
            InstallMethod.DIRECT_DOWNLOAD,
            InstallMethod.GO_INSTALL,
            InstallMethod.SYSTEM_PACKAGE,
            InstallMethod.PIP_INSTALL
        ],
        description="許可されたインストール方法"
    )


class GlobalConfig(BaseModel):
    """グローバル設定"""
    download: DownloadConfig = Field(default_factory=DownloadConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)


class ExternalToolsConfig(BaseModel):
    """external_tools.yamlのルートスキーマ"""
    
    tools: Dict[str, ToolConfig] = Field(
        default_factory=dict,
        description="ツール設定マップ（キー: ツール名）"
    )
    global_: GlobalConfig = Field(
        default_factory=GlobalConfig,
        alias="global",
        description="グローバル設定"
    )
    
    @classmethod
    def from_yaml(cls, path: Path) -> "ExternalToolsConfig":
        """YAMLファイルから設定を読み込み
        
        Args:
            path: YAMLファイルパス
            
        Returns:
            ExternalToolsConfig: パース済み設定
            
        Raises:
            FileNotFoundError: ファイルが存在しない場合
            ValueError: パース失敗時
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if data is None:
            data = {}
        
        return cls.model_validate(data)
    
    def to_yaml(self, path: Path) -> None:
        """設定をYAMLファイルに書き出し
        
        Args:
            path: 出力先ファイルパス
        """
        data = self.model_dump(by_alias=True, exclude_none=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    
    def get_tool_config(self, tool_name: str) -> Optional[ToolConfig]:
        """ツール設定を取得
        
        Args:
            tool_name: ツール名
            
        Returns:
            Optional[ToolConfig]: 設定が存在すればToolConfig、なければNone
        """
        return self.tools.get(tool_name)
    
    def validate_all_tools(self) -> Dict[str, List[str]]:
        """全ツール設定のバリデーション
        
        Returns:
            Dict[str, List[str]]: ツール名 → エラーメッセージリストのマップ
        """
        errors = {}
        
        for name, config in self.tools.items():
            tool_errors = []
            
            # インストール方法の検証
            if config.install_method not in self.global_.security.allowed_install_methods:
                tool_errors.append(
                    f"Install method '{config.install_method}' is not allowed"
                )
            
            # ダウンロードURLの検証（direct_download時）
            if config.install_method == InstallMethod.DIRECT_DOWNLOAD:
                if not config.download_url:
                    tool_errors.append(
                        "download_url is required for direct_download method"
                    )
            
            # チェックサム警告（推奨だが必須ではない）
            if self.global_.verification.enforce_checksum and not config.checksum:
                tool_errors.append(
                    "WARNING: checksum is empty but enforce_checksum is enabled"
                )
            
            if tool_errors:
                errors[name] = tool_errors
        
        return errors


def load_config(config_path: Optional[Path] = None) -> ExternalToolsConfig:
    """設定を読み込み
    
    Args:
        config_path: 設定ファイルパス。未指定時はデフォルトパス。
        
    Returns:
        ExternalToolsConfig: 設定オブジェクト
    """
    if config_path is None:
        # デフォルトパス: プロジェクトルート/config/external_tools.yaml
        config_path = Path(__file__).parent.parent.parent.parent.parent / "config" / "external_tools.yaml"
    
    try:
        return ExternalToolsConfig.from_yaml(config_path)
    except FileNotFoundError:
        # ファイルがない場合はデフォルト設定を返す
        return ExternalToolsConfig()


# グローバル設定（遅延初期化）
_config_cache: Optional[ExternalToolsConfig] = None


def get_config(force_reload: bool = False) -> ExternalToolsConfig:
    """グローバル設定を取得（キャッシュ付き）
    
    Args:
        force_reload: 強制的に再読み込みするか
        
    Returns:
        ExternalToolsConfig: 設定オブジェクト
    """
    global _config_cache
    
    if _config_cache is None or force_reload:
        _config_cache = load_config()
    
    return _config_cache


def reset_config():
    """設定キャッシュをリセット（テスト用）"""
    global _config_cache
    _config_cache = None
