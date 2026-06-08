"""
Fingerprint 統合機能の簡易テスト
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def test_fingerprint_import():
    """ScopeParserAgent の import テスト"""
    print("🧪 Testing Fingerprint integration...")
    
    try:
        from src.core.agents.specialized.scope_parser import ScopeParserAgent
        print("✅ ScopeParserAgent imported successfully")
        
        # インスタンス化テスト
        agent = ScopeParserAgent()
        print("✅ ScopeParserAgent instantiated")
        
        # fingerprint メソッドが存在するか確認
        assert hasattr(agent, 'fingerprint'), "❌ fingerprint method not found"
        print("✅ fingerprint method exists")
        
        # メソッドシグネチャの確認
        import inspect
        sig = inspect.signature(agent.fingerprint)
        params = list(sig.parameters.keys())
        assert 'target_url' in params, "❌ target_url parameter not found"
        print(f"✅ fingerprint method signature: {sig}")
        
        print("\n✨ Fingerprint integration test passed!")
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_fingerprint_import()
    sys.exit(0 if success else 1)
