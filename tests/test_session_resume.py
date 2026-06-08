#!/usr/bin/env python3
"""
SHIGOKU セッション再開機能テスト

Session Resume Mechanism の統合テスト
"""
import sys
import tempfile
import shutil
from pathlib import Path

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_session_manager_crud():
    """SessionManager CRUD操作テスト"""
    print("[Test] SessionManager CRUD...")
    
    from src.core.session import SessionManager, Session
    
    # テスト用一時ディレクトリ
    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)
        sm = SessionManager(project_dir)
        
        # 1. Create
        session = sm.create_session(
            project_name="test_project",
            mode="bugbounty",
            target_url="https://example.com"
        )
        assert session is not None
        assert session.project_name == "test_project"
        print("  ✅ create_session()")
        
        # 2. Read
        loaded = sm.load_session(session.session_id)
        assert loaded is not None
        assert loaded.session_id == session.session_id
        print("  ✅ load_session()")
        
        # 3. Update (via update_progress)
        sm.update_progress(session, completed=["task_1"], pending=["task_2", "task_3"])
        reloaded = sm.load_session(session.session_id)
        assert "task_1" in reloaded.completed_targets
        assert len(reloaded.pending_targets) == 2
        print("  ✅ update_progress()")
        
        # 4. List
        sessions = sm.list_sessions()
        assert len(sessions) >= 1
        print("  ✅ list_sessions()")
        
        # 5. Delete
        result = sm.delete_session(session.session_id)
        assert result is True
        assert sm.load_session(session.session_id) is None
        print("  ✅ delete_session()")
    
    print("  ✅ SessionManager CRUD: PASSED\n")


def test_master_conductor_checkpoint():
    """MasterConductor チェックポイント保存テスト"""
    print("[Test] MasterConductor Checkpoint...")
    
    from src.core.engine.master_conductor import MasterConductor, Task
    from src.core.domain.model.task import TaskState
    from src.core.engine.task_queue import DynamicTaskQueue
    from src.core.session import SessionManager
    
    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)
        sm = SessionManager(project_dir)
        
        # MasterConductor with SessionManager
        conductor = MasterConductor(session_manager=sm, auto_checkpoint=True)
        
        # セッション開始
        conductor.start_session("https://example.com", "bugbounty")
        assert conductor._current_session is not None
        print("  ✅ start_session()")
        
        # タスクキューを追加
        conductor.task_queue = DynamicTaskQueue()
        conductor.task_queue.add_batch(
            [
                Task(id="task_1", name="Test Task 1", agent_type="test", action="test"),
                Task(id="task_2", name="Test Task 2", agent_type="test", action="test"),
            ],
            source="test_master_conductor_checkpoint",
        )
        completed_task = Task(
            id="done_1",
            name="Done Task",
            agent_type="test",
            action="test",
            state=TaskState.SUCCESS,
        )
        conductor.completed_tasks = [completed_task]
        conductor.context.target_info = {"target": "https://example.com", "scan_mode": "bugbounty"}
        conductor.context._total_attempts = 4
        conductor.context._successful_attempts = 3
        conductor.context.discovered_assets = ["example.com", "api.example.com"]
        conductor.context.bypass_methods = ["jwt_bypass"]
        conductor.context.current_attack_chain = ["recon", "auth"]
        conductor.pending_hitl = [{"ticket_id": "ticket-1", "task": {"id": "task_1"}}]
        
        # チェックポイント保存
        conductor._checkpoint()
        
        # セッションがファイルに保存されたか確認
        sessions = sm.list_sessions()
        assert len(sessions) >= 1
        reloaded = sm.load_session(conductor._current_session.session_id)
        assert reloaded is not None
        assert len(reloaded.pending_targets) == 2
        assert reloaded.completed_targets == ["done_1"]
        assert reloaded.metadata["context"] == {"target": "https://example.com", "scan_mode": "bugbounty"}
        assert reloaded.metadata["total_attempts"] == 4
        assert reloaded.metadata["successful_attempts"] == 3
        assert reloaded.metadata["discovered_assets"] == ["example.com", "api.example.com"]
        assert reloaded.metadata["bypass_methods"] == ["jwt_bypass"]
        assert reloaded.metadata["attack_chain"] == ["recon", "auth"]
        assert reloaded.metadata["pending_hitl"] == [{"ticket_id": "ticket-1", "task": {"id": "task_1"}}]
        print("  ✅ _checkpoint()")
    
    print("  ✅ MasterConductor Checkpoint: PASSED\n")


def test_master_conductor_start_session_uses_sanitized_project_name_and_context():
    """MasterConductor セッション開始テスト"""
    print("[Test] MasterConductor Start Session...")

    from src.core.engine.master_conductor import MasterConductor
    from src.core.session import SessionManager

    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)
        sm = SessionManager(project_dir)

        conductor = MasterConductor(session_manager=sm, auto_checkpoint=True)
        conductor.context.target_info = {"target": "https://example.com", "program": "Example"}

        conductor.start_session("https://example.com/path/to/deeply/nested/resource", "bugbounty")

        assert conductor._current_session is not None
        assert conductor._current_session.project_name == "example.com_path_to_deeply_nested_resource"
        assert conductor._current_session.mode == "bugbounty"
        assert conductor._current_session.target_url == "https://example.com/path/to/deeply/nested/resource"
        assert conductor._current_session.metadata == {
            "context": {"target": "https://example.com", "program": "Example"},
        }
        print("  ✅ start_session()")

    print("  ✅ MasterConductor Start Session: PASSED\n")


def test_master_conductor_resume():
    """MasterConductor セッション復元テスト"""
    print("[Test] MasterConductor Resume...")
    
    from src.core.engine.master_conductor import MasterConductor, Task
    from src.core.engine.task_queue import DynamicTaskQueue
    from src.core.session import SessionManager
    
    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)
        sm = SessionManager(project_dir)
        
        # === 最初のConductor: タスクを途中まで実行してクラッシュをシミュレート ===
        conductor1 = MasterConductor(session_manager=sm, auto_checkpoint=True)
        conductor1.start_session("https://target.example.com", "ctf")
        
        # タスクキューを設定
        conductor1.task_queue = DynamicTaskQueue()
        conductor1.task_queue.add_batch(
            [
                Task(id="task_1", name="Recon", agent_type="cartographer", action="enumerate"),
                Task(id="task_2", name="Fingerprint", agent_type="fingerprinter", action="scan"),
                Task(id="task_3", name="Attack", agent_type="attacker", action="exploit"),
            ],
            source="test_master_conductor_resume",
        )
        conductor1.context.discovered_assets = ["asset1.example.com", "asset2.example.com"]
        conductor1.context.bypass_methods = ["encoding_bypass"]
        
        # チェックポイント保存（クラッシュ前の状態）
        conductor1._checkpoint()
        session_id = conductor1._current_session.session_id
        print("  ✅ Initial session saved")
        
        # === 新しいConductor: 復元 ===
        conductor2 = MasterConductor(session_manager=sm, auto_checkpoint=True)
        result = conductor2.resume_session(session_id)
        
        assert result is True
        restored_tasks = list(conductor2.task_queue)
        assert len(restored_tasks) == 3
        assert restored_tasks[0].id == "task_1"
        assert conductor2.context.target_info == conductor1.context.target_info
        assert conductor2.context.discovered_assets == ["asset1.example.com", "asset2.example.com"]
        assert conductor2.context.bypass_methods == ["encoding_bypass"]
        print("  ✅ resume_session() restored task queue and context")
    
    print("  ✅ MasterConductor Resume: PASSED\n")


def test_serialization_roundtrip():
    """タスクシリアライズ・デシリアライズの整合性テスト"""
    print("[Test] Task Serialization Roundtrip...")
    
    from src.core.engine.master_conductor import MasterConductor, Task
    from src.core.engine.task_queue import DynamicTaskQueue
    from src.core.session import SessionManager
    
    with tempfile.TemporaryDirectory() as tmpdir:
        sm = SessionManager(Path(tmpdir))
        conductor = MasterConductor(session_manager=sm)
        
        # 複雑なパラメータを持つタスク
        original_tasks = [
            Task(
                id="complex_1",
                name="Complex Task",
                agent_type="jwt_inspector",
                action="analyze",
                params={"token": "eyJ...", "verify": True, "options": {"strict": False}},
                priority=100,
                parent_id="parent_task"
            ),
            Task(
                id="simple_1",
                name="Simple Task",
                agent_type="universal",
                action="run",
                params={},
                priority=50,
            ),
        ]
        
        conductor.task_queue = DynamicTaskQueue()
        conductor.task_queue.add_batch(original_tasks, source="test_serialization_roundtrip")
        
        # シリアライズ
        serialized = conductor._serialize_task_queue()
        assert len(serialized) == 2
        assert all(isinstance(s, str) for s in serialized)
        print("  ✅ _serialize_task_queue()")
        
        # デシリアライズ
        restored, failed = conductor._deserialize_task_queue(serialized)
        assert failed == []
        assert len(restored) == 2
        assert restored[0].id == "complex_1"
        assert restored[0].params["verify"] is True
        assert restored[0].parent_id == "parent_task"
        assert restored[1].id == "simple_1"
        print("  ✅ _deserialize_task_queue()")
    
    print("  ✅ Task Serialization Roundtrip: PASSED\n")


def main():
    """全テスト実行"""
    print("=" * 70)
    print("SHIGOKU セッション再開機能テスト")
    print("=" * 70)
    print()
    
    tests = [
        test_session_manager_crud,
        test_master_conductor_checkpoint,
        test_master_conductor_resume,
        test_serialization_roundtrip,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            import traceback
            print(f"  ❌ {test.__name__} FAILED: {e}")
            traceback.print_exc()
            print()
    
    print("=" * 70)
    print(f"テスト結果: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    if failed == 0:
        print("\n✅ 全テスト合格！")
        return 0
    else:
        print(f"\n❌ {failed}件のテストが失敗しました")
        return 1


if __name__ == "__main__":
    sys.exit(main())
