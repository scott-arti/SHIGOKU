"""
Integration Tests for Caido Pipeline
caido_importer → tagging_filter のパイプラインテスト
"""

import pytest
import json
import base64
import tempfile
from pathlib import Path
from datetime import datetime

import sys
import importlib.util

# __init__.py のチェーン読み込みを回避するため直接モジュールをロード
def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

# tests/core/intel/ から 4 階層上がってプロジェクトルートへ
base_path = Path(__file__).resolve().parent.parent.parent.parent
caido_importer_module = load_module("caido_importer", base_path / "src" / "tools" / "custom" / "caido_importer.py")
tagging_filter_module = load_module("tagging_filter", base_path / "src" / "core" / "intel" / "tagging_filter.py")

CaidoImporter = caido_importer_module.CaidoImporter
TaggingFilter = tagging_filter_module.TaggingFilter


class TestCaidoPipeline:
    """Caido Importer → Tagging Filter の統合テスト"""

    @pytest.fixture
    def mock_caido_logs(self):
        """モック Caido ログ（複数エントリ）"""
        
        def make_entry(entry_id, host, path, method, query, status, req_body="", res_body=""):
            request_raw = f"{method} {path}{'?' + query if query else ''} HTTP/1.1\r\nHost: {host}\r\nCookie: session=test123\r\nAuthorization: Bearer token\r\n\r\n{req_body}"
            response_raw = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{res_body}"
            
            return {
                "id": entry_id,
                "host": host,
                "port": 443,
                "method": method,
                "path": path,
                "query": query,
                "is_tls": True,
                "raw": base64.b64encode(request_raw.encode()).decode(),
                "response": {
                    "status_code": status,
                    "raw": base64.b64encode(response_raw.encode()).decode()
                }
            }
        
        return [
            # auth タグ: login パス
            make_entry(1, "example.com", "/api/login", "POST", "", 200, req_body="username=test&password=secret"),
            # admin タグ: admin パス + 200
            make_entry(2, "example.com", "/admin/dashboard", "GET", "", 200),
            # id_param タグ: id パラメータ
            make_entry(3, "example.com", "/api/user", "GET", "id=123", 200),
            # redirect_param タグ: redirect パラメータ
            make_entry(4, "example.com", "/auth/callback", "GET", "redirect=https://evil.com", 302),
            # file_param タグ: file パラメータ
            make_entry(5, "example.com", "/download", "GET", "file=/etc/passwd", 200),
            # upload タグ: upload パス
            make_entry(6, "example.com", "/api/upload", "POST", "", 200),
            # debug_info タグ: エラーメッセージ
            make_entry(7, "example.com", "/api/error", "GET", "", 500, res_body="Error: stack trace at line 42"),
            # uncategorized: タグなし
            make_entry(8, "example.com", "/about", "GET", "", 200, res_body="About us page"),
            # 静的ファイル: スキップされる
            make_entry(9, "example.com", "/assets/style.css", "GET", "", 200),
            # 重複: id=3 と同じ（クエリ順序違い）
            make_entry(10, "example.com", "/api/user", "GET", "id=123", 200),
        ]

    def test_full_pipeline(self, mock_caido_logs):
        """フルパイプラインテスト"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Caido ログをファイルに書き込み
            caido_file = Path(tmpdir) / "caido_export.json"
            with open(caido_file, 'w') as f:
                json.dump(mock_caido_logs, f)
            
            # 2. Caido Importer で処理
            importer = CaidoImporter()
            imported = importer.import_file(str(caido_file))
            
            # 静的ファイル（id=9）がスキップされていることを確認
            assert len(imported) == 9  # 10 - 1 (静的ファイル)
            
            # 3. インポート結果をファイルに書き込み
            imported_file = Path(tmpdir) / "imported.json"
            with open(imported_file, 'w') as f:
                json.dump(imported, f)
            
            # 4. Tagging Filter で処理
            filter_instance = TaggingFilter(project_name="integration_test")
            output_dir = Path(tmpdir) / "output"
            stats = filter_instance.process_file(str(imported_file), str(output_dir))
            
            # 5. 統計確認
            assert stats["auth"] >= 1, "auth タグが付与されていない"
            assert stats["admin"] >= 1, "admin タグが付与されていない"
            assert stats["id_param"] >= 1, "id_param タグが付与されていない"
            assert stats["redirect_param"] >= 1, "redirect_param タグが付与されていない"
            assert stats["file_param"] >= 1, "file_param タグが付与されていない"
            assert stats["upload"] >= 1, "upload タグが付与されていない"
            assert stats["debug_info"] >= 1, "debug_info タグが付与されていない"
            assert stats["uncategorized"] >= 1, "uncategorized が空"
            
            # 6. 出力ファイル確認
            date_str = datetime.now().strftime("%Y%m%d")
            auth_file = output_dir / f"{date_str}_integration_test_tagged_auth.jsonl"
            assert auth_file.exists(), "auth ファイルが存在しない"
            
            # 7. 重複排除確認（id=3 と id=10 は同じ URL なので 1 件のみ）
            # id_param には 1 件のみ存在するはず
            id_param_file = output_dir / f"{date_str}_integration_test_tagged_id_param.jsonl"
            with open(id_param_file, 'r') as f:
                lines = f.readlines()
                # 重複が排除されているので 1 件
                assert len(lines) == 1, f"重複排除が機能していない: {len(lines)} 件"

    def test_auth_context_preserved(self, mock_caido_logs):
        """認証コンテキストが保持されることを確認"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # パイプライン実行
            caido_file = Path(tmpdir) / "caido_export.json"
            with open(caido_file, 'w') as f:
                json.dump(mock_caido_logs[:1], f)  # auth エントリのみ
            
            importer = CaidoImporter()
            imported = importer.import_file(str(caido_file))
            
            imported_file = Path(tmpdir) / "imported.json"
            with open(imported_file, 'w') as f:
                json.dump(imported, f)
            
            filter_instance = TaggingFilter(project_name="auth_test")
            output_dir = Path(tmpdir) / "output"
            filter_instance.process_file(str(imported_file), str(output_dir))
            
            # auth ファイルを読み込み
            date_str = datetime.now().strftime("%Y%m%d")
            auth_file = output_dir / f"{date_str}_auth_test_tagged_auth.jsonl"
            
            with open(auth_file, 'r') as f:
                entry = json.loads(f.readline())
            
            # auth_context に Cookie と Authorization が含まれている
            assert "auth_context" in entry
            # (PIIMasker によりマスクされている可能性があるため、キーの存在のみ確認)


class TestRealDataPipeline:
    """実際の Caido ログを使用したテスト（存在する場合）"""
    
    @pytest.fixture
    def real_caido_file(self):
        """実際の Caido ログファイルパス"""
        path = Path("/home/bbb/Documents/App/Shigoku/2026-01-17-011223_json_requests.json")
        if not path.exists():
            pytest.skip("実データファイルが存在しません")
        return path

    def test_real_data_import(self, real_caido_file):
        """実データのインポート"""
        importer = CaidoImporter()
        results = importer.import_file(str(real_caido_file))
        
        # 処理が完了すること
        assert isinstance(results, list)
        # 何らかのエントリが処理されること
        assert len(results) > 0

    def test_real_data_pipeline(self, real_caido_file):
        """実データのフルパイプライン"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # インポート
            importer = CaidoImporter()
            imported = importer.import_file(str(real_caido_file))
            
            imported_file = Path(tmpdir) / "imported.json"
            with open(imported_file, 'w') as f:
                json.dump(imported, f)
            
            # タグ付け
            filter_instance = TaggingFilter(project_name="real_data_test")
            output_dir = Path(tmpdir) / "output"
            stats = filter_instance.process_file(str(imported_file), str(output_dir))
            
            # 統計出力
            print(f"\n実データ処理結果:")
            print(f"  インポート件数: {len(imported)}")
            for tag, count in stats.items():
                if count > 0:
                    print(f"  {tag}: {count} 件")
