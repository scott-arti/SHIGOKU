import unittest
from src.core.agent import Agent
from src.core.config_manager import get_config_manager
from src.cli.cli import Runner  # Checking import

class TestRefactor(unittest.TestCase):
    def test_agent_init(self):
        agent = Agent(name="Test", instructions="Test")
        self.assertEqual(agent.name, "Test")
        self.assertTrue(len(agent.messages) >= 1)

    def test_config_manager(self):
        cm = get_config_manager()
        self.assertIsNotNone(cm.config)
        self.assertEqual(cm.config.mode, "bugbounty") # Default

if __name__ == "__main__":
    unittest.main()
