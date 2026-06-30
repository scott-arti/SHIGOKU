import threading

import pytest

from src.core.intelligence.priority_booster import (
    BoostEvent,
    BoostTrigger,
    PriorityBooster,
)


def test_priority_booster_serializes_concurrent_mutations():
    """T-7.9: PriorityBooster protects shared boost state under concurrent callers."""
    booster = PriorityBooster()
    booster.register_task("auth-test", base_priority=0.1)

    def boost(i: int) -> None:
        booster.boost_on_discovery(BoostEvent(
            trigger=BoostTrigger.AUTH_BYPASS,
            target=f"https://example.com/{i}",
            boost_amount=0.01,
            reason=f"signal-{i}",
            related_tasks=["auth-test"],
        ))

    threads = [threading.Thread(target=boost, args=(i,)) for i in range(25)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1.0)

    assert hasattr(booster, "_lock")
    assert booster.get_stats()["active_boosts"] == 25
    assert booster.get_priority("auth-test") == pytest.approx(0.35)
