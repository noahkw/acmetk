import aiohttp

import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_metrics(service):
    m = service.directory / "../metrics"
    async with aiohttp.ClientSession() as c:
        r = await c.get(str(m))
        assert r.status == 200
