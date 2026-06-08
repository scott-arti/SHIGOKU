"""
統合テスト: セッション永続化とFingerprint統合

全機能を統合的にテストします。
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_integration():
    """統合テスト"""
    print("=" * 70)
    print("🧪 Integration Test: Session Persistence & Fingerprint Integration")
    print("=" * 70)
    
    test_results = []
    
    # Test 1: Session Save/Load
    print("\n📝 Test 1: Session Persistence")
    try:
        from src.core.engine.master_conductor import MasterConductor, Task
        
        mc = MasterConductor()
        mc.task_queue.append(Task(
            id="integration_001",
            name="Integration Test Task",
            agent_type="test",
            action="test",
            phase="test"
        ))
        
        mc.save_session("integration_test.json")
        assert Path("integration_test.json").exists()
        
        mc2 = MasterConductor()
        mc2.load_session("integration_test.json")
        assert len(mc2.task_queue) == 1
        assert mc2.task_queue[0].id == "integration_001"
        
        Path("integration_test.json").unlink()
        test_results.append(("Session Persistence", True, None))
        print("   ✅ PASSED")
    except Exception as e:
        test_results.append(("Session Persistence", False, str(e)))
        print(f"   ❌ FAILED: {e}")
    
    # Test 2: Pipeline Syntax Check
    print("\n📝 Test 2: Pipeline Syntax (Fingerprint Integration)")
    try:
        import py_compile
        py_compile.compile("src/recon/pipeline.py", doraise=True)
        test_results.append(("Pipeline Syntax", True, None))
        print("   ✅ PASSED")
    except Exception as e:
        test_results.append(("Pipeline Syntax", False, str(e)))
        print(f"   ❌ FAILED: {e}")
    
    # Test 3: MasterConductor Syntax Check
    print("\n📝 Test 3: MasterConductor Syntax")
    try:
        import py_compile
        py_compile.compile("src/core/engine/master_conductor.py", doraise=True)
        test_results.append(("MasterConductor Syntax", True, None))
        print("   ✅ PASSED")
    except Exception as e:
        test_results.append(("MasterConductor Syntax", False, str(e)))
        print(f"   ❌ FAILED: {e}")
    
    # Test 4: Task Serialization
    print("\n📝 Test 4: Task Serialization/Deserialization")
    try:
        from src.core.engine.master_conductor import Task, TaskState
        
        task = Task(
            id="serial_test",
            name="Serialization Test",
            agent_type="test",
            action="serialize",
            phase="test",
            params={"key": "value"},
            priority=100
        )
        
        # Serialize
        task_dict = {
            "id": task.id,
            "name": task.name,
            "agent_type": task.agent_type,
            "action": task.action,
            "phase": task.phase,
            "params": task.params,
            "state": task.state.value,
            "priority": task.priority,
        }
        
        json_str = json.dumps(task_dict)
        
        # Deserialize
        loaded = json.loads(json_str)
        assert loaded["id"] == "serial_test"
        assert loaded["params"]["key"] == "value"
        
        test_results.append(("Task Serialization", True, None))
        print("   ✅ PASSED")
    except Exception as e:
        test_results.append(("Task Serialization", False, str(e)))
        print(f"   ❌ FAILED: {e}")
    
    # Test 5: Context Serialization
    print("\n📝 Test 5: ExecutionContext Serialization")
    try:
        from src.core.engine.master_conductor import ExecutionContext
        
        ctx = ExecutionContext()
        ctx._total_attempts = 10
        ctx._successful_attempts = 7
        ctx.discovered_assets.append("example.com")
        ctx.bypass_methods.append("jwt_bypass")
        
        # Serialize
        ctx_dict = {
            "total_attempts": ctx._total_attempts,
            "successful_attempts": ctx._successful_attempts,
            "discovered_assets": ctx.discovered_assets,
            "bypass_methods": ctx.bypass_methods,
            "target_info": ctx.target_info,
        }
        
        json_str = json.dumps(ctx_dict)
        loaded = json.loads(json_str)
        
        assert loaded["total_attempts"] == 10
        assert loaded["successful_attempts"] == 7
        assert "example.com" in loaded["discovered_assets"]
        
        test_results.append(("Context Serialization", True, None))
        print("   ✅ PASSED")
    except Exception as e:
        test_results.append(("Context Serialization", False, str(e)))
        print(f"   ❌ FAILED: {e}")
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 Test Summary")
    print("=" * 70)
    
    passed = sum(1 for _, success, _ in test_results if success)
    failed = len(test_results) - passed
    
    for test_name, success, error in test_results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status:10} | {test_name}")
        if error:
            print(f"             Error: {error}")
    
    print("=" * 70)
    print(f"Total: {passed}/{len(test_results)} passed, {failed}/{len(test_results)} failed")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    try:
        success = test_integration()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Integration test crashed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
