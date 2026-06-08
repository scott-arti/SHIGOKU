
import sys
import os
import unittest
from unittest.mock import MagicMock

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..")))

from src.core.engine.error_replanner import ErrorReplanner
from src.core.engine.master_conductor import Task, ExecutionContext

class TestErrorReplanner(unittest.TestCase):
    def setUp(self):
        self.replanner = ErrorReplanner()
        self.context = ExecutionContext()
        self.task = Task(id="test_task", name="Test Task", agent_type="mock", action="run")
        
    def test_403_recovery(self):
        tasks = self.replanner.analyze_error_and_replan(self.task, "403 Forbidden", self.context)
        self.assertTrue(len(tasks) > 0)
        self.assertTrue(any("proxy" in t.name.lower() for t in tasks))
        print("403 Recovery Test Passed")

    def test_timeout_recovery(self):
        tasks = self.replanner.analyze_error_and_replan(self.task, "Connection timed out", self.context)
        self.assertTrue(len(tasks) > 0)
        self.assertTrue(any("delay" in t.name.lower() for t in tasks))
        print("Timeout Recovery Test Passed")

if __name__ == "__main__":
    unittest.main()
