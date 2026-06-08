from __future__ import annotations

import pytest

from tests.scripts.verify_chaining_flow import verify_chaining_flow


@pytest.mark.asyncio
async def test_verify_chaining_flow_passes() -> None:
    await verify_chaining_flow()
