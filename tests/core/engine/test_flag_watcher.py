import pytest
import re
from src.core.engine.flag_watcher import FlagWatcher

@pytest.fixture
def watcher():
    w = FlagWatcher.get_instance()
    w.clear()
    return w

def test_singleton():
    w1 = FlagWatcher.get_instance()
    w2 = FlagWatcher.get_instance()
    assert w1 is w2

def test_register_pattern(watcher):
    watcher.register_pattern(r"flag\{.*\}")
    assert len(watcher.patterns) == 1
    assert watcher.patterns[0].pattern == r"flag\{.*\}"

def test_check_flag_found(watcher):
    found_flags = []
    def callback(flag, source):
        found_flags.append((flag, source))
    
    watcher.register_pattern(r"flag\{[a-z0-9]+\}")
    watcher.register_callback(callback)
    
    content = "Hello, here is your flag{abc123} and some other text."
    watcher.check(content, source="test_source")
    
    assert len(found_flags) == 1
    assert found_flags[0] == ("flag{abc123}", "test_source")

def test_check_no_flag(watcher):
    found_flags = []
    def callback(flag, source):
        found_flags.append((flag, source))
    
    watcher.register_pattern(r"flag\{[a-z0-9]+\}")
    watcher.register_callback(callback)
    
    content = "No flag here."
    watcher.check(content, source="test_source")
    
    assert len(found_flags) == 0

def test_check_multiple_patterns(watcher):
    found_flags = []
    def callback(flag, source):
        found_flags.append(flag)
    
    watcher.register_pattern(r"flag\{.*?\}")
    watcher.register_pattern(r"SKG\{.*?\}")
    watcher.register_callback(callback)
    
    content = "flag{one} and SKG{two}"
    watcher.check(content)
    
    assert len(found_flags) == 2
    assert "flag{one}" in found_flags
    assert "SKG{two}" in found_flags
