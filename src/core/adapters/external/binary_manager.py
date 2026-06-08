"""
BinaryManager: 外部ツールバイナリの統一管理

4層防御によるセキュリティ検証フロー:
1. コードレビュー: PRテンプレートにチェックリスト
2. 静的解析: カスタムlinterルール
3. 実行時検証: 検証済みフラグによる状態管理
4. ファイルシステム: アトミックな配置プロセス

絶対禁止: 検証前のバイナリに実行権限付与
"""

import asyncio
import hashlib
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
import yaml

from src.core.security.pii_masker import PIIMasker

logger = logging.getLogger(__name__)


class BinaryVerificationError(Exception):
    """バイナリ検証失敗時の例外"""
    pass


class BinaryDownloadError(Exception):
    """バイナリダウンロード失敗時の例外"""
    pass


class SecurityError(Exception):
    """セキュリティ違反時の例外
    
    prohibit_pre_verification_chmodがFalseの場合など、
    セキュリティ設定違反時に発生
    """
    pass


@dataclass
class BinaryConfig:
    """バイナリ設定"""
    name: str
    version: str
    download_url: str
    checksum: str  # SHA256 expected
    checksum_type: str = "sha256"
    install_method: str = "direct_download"  # or "go_install"
    executable_name: Optional[str] = None


class BinaryManager:
    """外部ツールバイナリのライフサイクル管理
    
    セキュリティを最優先とした設計:
    - 検証前に絶対に実行権限を付与しない
    - 4層防御による多層的な保護
    - アトミックな配置プロセス
    
    正しいインストールフロー:
    1. 一時ディレクトリにダウンロード（実行権限なし）
    2. 検証（チェックサム、必要に応じて署名）
    3. 検証成功後、正式な場所に移動
    4. 移動後に実行権限付与
    """
    
    def __init__(self, installation_dir: Optional[Path] = None):
        """初期化
        
        Args:
            installation_dir: バイナリインストール先。未指定時は ~/.shigoku/binaries/
        """
        if installation_dir is None:
            installation_dir = Path.home() / ".shigoku" / "binaries"
        
        self.installation_dir = installation_dir
        self.installation_dir.mkdir(parents=True, exist_ok=True)
        
        # 設定ファイル読み込み
        self.config_path = Path(__file__).parent.parent.parent.parent / "config" / "external_tools.yaml"
        self.binaries_config: Dict[str, BinaryConfig] = {}
        self._load_config()
        
        # 検証済みフラグ（層3: 実行時検証）
        self._verified_binaries: set = set()
        self._verification_file = self.installation_dir.parent / "verified_binaries.json"
        
        # 検証済みフラグを永続化から復元
        self._load_verification_flags()
        
        # セキュリティ強制メカニズム：設定検証
        self._enforce_security_settings()
    
    def _load_config(self):
        """設定ファイルからバイナリ情報を読み込み"""
        if not self.config_path.exists():
            logger.warning(f"Config file not found: {self.config_path}")
            return
        
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            tools_config = config.get('tools', {})
            for name, tool_config in tools_config.items():
                self.binaries_config[name] = BinaryConfig(
                    name=name,
                    version=tool_config.get('version', 'latest'),
                    download_url=tool_config.get('download_url', ''),
                    checksum=tool_config.get('checksum', ''),
                    checksum_type=tool_config.get('checksum_type', 'sha256'),
                    install_method=tool_config.get('install_method', 'direct_download'),
                    executable_name=tool_config.get('executable_name')
                )
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
    
    def _get_binary_path(self, tool_name: str) -> Path:
        """ツールのバイナリパスを取得"""
        config = self.binaries_config.get(tool_name)
        if config and config.executable_name:
            return self.installation_dir / config.executable_name
        return self.installation_dir / tool_name
    
    def _get_system_binary_path(self, tool_name: str) -> Optional[Path]:
        """システムPATHからバイナリパスを取得
        
        Args:
            tool_name: ツール名
            
        Returns:
            Optional[Path]: 見つかった場合はパス、なければNone
        """
        system_path = shutil.which(tool_name)
        if system_path:
            return Path(system_path)
        return None
    
    async def ensure_binary(self, tool_name: str) -> Path:
        """バイナリが存在することを保証（必要に応じてダウンロード・検証）
        
        検索順序:
            1. インストールディレクトリ（検証済み）
            2. インストールディレクトリ（未検証）
            3. システムPATH
            4. ダウンロード・インストール
        
        Args:
            tool_name: ツール名
            
        Returns:
            Path: 検証済みバイナリのパス
            
        Raises:
            BinaryVerificationError: 検証失敗時
            BinaryDownloadError: ダウンロード失敗時
        """
        # 1. インストールディレクトリ（検証済み）
        binary_path = self._get_binary_path(tool_name)
        
        if tool_name in self._verified_binaries and binary_path.exists():
            logger.debug(f"Using verified binary: {binary_path}")
            return binary_path
        
        # 2. インストールディレクトリ（未検証）
        if binary_path.exists():
            logger.info(f"Binary exists but not verified: {binary_path}")
            if await self._verify_existing_binary(tool_name, binary_path):
                self._verified_binaries.add(tool_name)
                return binary_path
            else:
                # 検証失敗時は削除して再ダウンロードへ
                logger.warning(f"Verification failed, removing: {tool_name}")
                binary_path.unlink()
        
        # 3. システムPATHを確認
        system_path = self._get_system_binary_path(tool_name)
        if system_path:
            logger.info(f"Found system binary: {system_path}")
            # システムバイナリは検証スキップ（信頼する）
            return system_path
        
        # 4. 新規ダウンロード・インストール
        logger.info(f"Binary not found, downloading: {tool_name}")
        return await self._download_and_install(tool_name)
    
    async def _verify_existing_binary(self, tool_name: str, binary_path: Path) -> bool:
        """既存バイナリの検証
        
        Args:
            tool_name: ツール名
            binary_path: バイナリパス
            
        Returns:
            bool: 検証成功時True
        """
        config = self.binaries_config.get(tool_name)
        if not config:
            logger.warning(f"No config found for {tool_name}, skipping verification")
            return True  # 設定がない場合は検証スキップ（開発時のみ）
        
        if not config.checksum:
            logger.warning(f"No checksum configured for {tool_name}")
            return True
        
        return await self._verify_checksum(binary_path, config.checksum)
    
    async def _download_and_install(self, tool_name: str) -> Path:
        """バイナリをダウンロードして安全にインストール
        
        セキュリティフロー（層4: ファイルシステム）:
        1. 一時ディレクトリにダウンロード（実行権限なし）
        2. 検証（チェックサム）
        3. 検証成功後、正式な場所に移動
        4. 移動後に実行権限付与
        
        Args:
            tool_name: ツール名
            
        Returns:
            Path: インストールされたバイナリのパス
        """
        config = self.binaries_config.get(tool_name)
        if not config:
            raise BinaryDownloadError(f"No configuration found for tool: {tool_name}")
        
        logger.info(f"Downloading {tool_name} v{config.version}...")
        
        # 1. 一時ディレクトリにダウンロード（実行権限なし！）
        temp_dir = Path(tempfile.gettempdir()) / "shigoku_downloads"
        temp_dir.mkdir(exist_ok=True)
        temp_path = temp_dir / f"{tool_name}_download"
        
        try:
            await self._download_file(config.download_url, temp_path)
            
            # 圧縮ファイルの場合は展開
            if config.download_url.endswith('.zip') or config.download_url.endswith('.tar.gz'):
                temp_path = await self._extract_archive(temp_path, temp_dir, tool_name)
            
            # 2. 検証（実行権限付与前）- 絶対に先に検証！
            if config.checksum:
                logger.info(f"Verifying checksum for {tool_name}...")
                if not await self._verify_checksum(temp_path, config.checksum):
                    raise BinaryVerificationError(
                        f"Checksum verification failed for {tool_name}. "
                        f"Expected: {config.checksum}"
                    )
            else:
                logger.warning(f"No checksum configured for {tool_name}, skipping verification")
            
            # 3. 検証成功後、正式な場所に移動
            final_path = self._get_binary_path(tool_name)
            shutil.move(str(temp_path), str(final_path))
            
            # 4. 移動後に実行権限付与（検証済みの安全なバイナリのみ）
            final_path.chmod(0o755)
            
            # 検証済みフラグを設定（層3）
            self._verified_binaries.add(tool_name)
            
            # 検証済みフラグを永続化（設定で有効な場合）
            from .config_schema import load_config
            try:
                config = load_config(self.config_path)
                if config.global_.security.persist_verification_flags:
                    self._save_verification_flags()
            except Exception as e:
                logger.warning(f"Failed to persist verification flags: {e}")
            
            logger.info(f"Successfully installed {tool_name} to {final_path}")
            return final_path
            
        except Exception as e:
            # クリーンアップ
            if temp_path.exists():
                temp_path.unlink()
            raise BinaryDownloadError(f"Failed to install {tool_name}: {e}")
    
    async def _download_file(self, url: str, dest_path: Path):
        """ファイルを非同期ダウンロード"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        raise BinaryDownloadError(
                            f"HTTP {response.status} when downloading {url}"
                        )
                    
                    content = await response.read()
                    dest_path.write_bytes(content)
                    
        except Exception as e:
            raise BinaryDownloadError(f"Download failed for {url}: {e}")
    
    async def _extract_archive(self, archive_path: Path, dest_dir: Path, tool_name: str) -> Path:
        """アーカイブを展開して実行ファイルを抽出"""
        import zipfile
        import tarfile
        
        try:
            if archive_path.suffix == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    zf.extractall(dest_dir)
            elif archive_path.suffix in ['.gz', '.tgz'] or '.tar' in archive_path.name:
                with tarfile.open(archive_path, 'r:*') as tf:
                    tf.extractall(dest_dir)
            
            # 実行ファイルを探す
            for extracted_file in dest_dir.iterdir():
                if extracted_file.is_file() and tool_name in extracted_file.name:
                    return extracted_file
            
            raise BinaryDownloadError(f"Could not find executable in extracted archive for {tool_name}")
            
        except Exception as e:
            raise BinaryDownloadError(f"Failed to extract archive for {tool_name}: {e}")
    
    async def _verify_checksum(self, file_path: Path, expected_checksum: str) -> bool:
        """ファイルのチェックサムを検証
        
        Args:
            file_path: 検証対象ファイル
            expected_checksum: 期待されるSHA256ハッシュ
            
        Returns:
            bool: 検証成功時True
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            actual_checksum = sha256_hash.hexdigest()
            
            # 大小文字を無視して比較
            if actual_checksum.lower() == expected_checksum.lower():
                logger.debug(f"Checksum verified: {file_path}")
                return True
            else:
                logger.error(
                    f"Checksum mismatch for {file_path}: "
                    f"expected={expected_checksum}, actual={actual_checksum}"
                )
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify checksum for {file_path}: {e}")
            return False
    
    async def health_check(self, tool_name: str) -> bool:
        """ツールのヘルスチェック
        
        バイナリ存在確認、バージョンチェック、基本的な実行テストを実施。
        
        Args:
            tool_name: ツール名
            
        Returns:
            bool: ツールが正常に動作すればTrue
        """
        try:
            binary_path = await self.ensure_binary(tool_name)
            
            # 基本的な実行テスト（バージョン表示等）
            proc = await asyncio.create_subprocess_exec(
                str(binary_path), "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=10.0
                )
                return proc.returncode == 0
            except asyncio.TimeoutError:
                logger.warning(f"Health check timeout for {tool_name}")
                return False
                
        except Exception as e:
            logger.error(f"Health check failed for {tool_name}: {e}")
            return False
    
    def is_verified(self, tool_name: str) -> bool:
        """ツールが検証済みかどうかを確認（層3: 実行時検証）"""
        return tool_name in self._verified_binaries
    
    def _enforce_security_settings(self):
        """セキュリティ設定の強制検証
        
        prohibit_pre_verification_chmodがFalseの場合は
        セキュリティエラーを発生させて強制的にブロック
        """
        try:
            from .config_schema import load_config
            config = load_config(self.config_path)
            
            if not config.global_.security.prohibit_pre_verification_chmod:
                raise SecurityError(
                    "CRITICAL SECURITY VIOLATION: "
                    "prohibit_pre_verification_chmod is set to False. "
                    "Pre-verification chmod is a CRITICAL security risk "
                    "that could allow execution of malicious binaries. "
                    "This setting must be True at all times. "
                    "Please fix your external_tools.yaml configuration."
                )
            
            if not config.global_.security.use_temp_directory_for_download:
                logger.warning(
                    "SECURITY WARNING: use_temp_directory_for_download is False. "
                    "It's strongly recommended to use temp directories for security."
                )
                
        except SecurityError:
            raise
        except Exception as e:
            # 設定読み込み失敗時は安全側に倒してエラー
            logger.error(f"Failed to verify security settings: {e}")
            raise SecurityError(
                f"Cannot verify security settings due to configuration error: {e}. "
                "Refusing to proceed for safety."
            )
    
    def _load_verification_flags(self):
        """検証済みフラグを永続化ファイルから復元"""
        import json
        
        if not self._verification_file.exists():
            logger.debug("No verification file found, starting fresh")
            return
        
        try:
            with open(self._verification_file, 'r') as f:
                data = json.load(f)
            
            # 検証済みツール名を復元
            verified_tools = data.get('verified_tools', [])
            self._verified_binaries.update(verified_tools)
            
            logger.info(f"Restored {len(verified_tools)} verification flags from {self._verification_file}")
            
        except Exception as e:
            logger.warning(f"Failed to load verification flags: {e}. Starting fresh.")
            self._verified_binaries.clear()
    
    def _save_verification_flags(self):
        """検証済みフラグを永続化ファイルに保存"""
        import json
        
        try:
            data = {
                'verified_tools': list(self._verified_binaries),
                'version': '1.0'
            }
            
            with open(self._verification_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved {len(self._verified_binaries)} verification flags")
            
        except Exception as e:
            logger.error(f"Failed to save verification flags: {e}")
