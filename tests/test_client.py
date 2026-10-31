import asyncio
import copy

import pytest
import pytest_asyncio
from aiohttp import web

import astrbot_plugin_cve_card.client as module
from astrbot_plugin_cve_card.client import CveClient, LookupFailure
from test_records import sample


@pytest_asyncio.fixture
async def server(monkeypatch):
    state = {"main": (200, sample()), "backup": (200, sample()), "calls": [], "delay": 0, "headers": {}}
    async def handler(request):
        key = request.match_info["source"]
        state["calls"].append(key)
        await asyncio.sleep(state["delay"])
        status, body = state[key]
        if isinstance(body, str):
            return web.Response(status=status, text=body, headers=state["headers"])
        return web.json_response(body, status=status, headers=state["headers"])
    app = web.Application()
    app.router.add_get('/{source}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    monkeypatch.setattr(module, 'source_urls', lambda cid: [(key, f'http://127.0.0.1:{port}/{key}') for key in ['main', 'backup']])
    yield state
    await runner.cleanup()


@pytest_asyncio.fixture
async def client():
    c = CveClient()
    yield c
    await c.close()


@pytest.mark.asyncio
async def test_fetch_cache_and_coalesce(server, client):
    server['delay'] = 0.03
    values = await asyncio.gather(*[client.get('CVE-2026-98432') for _ in range(8)])
    assert server['calls'] == ['main']
    cached = await client.get('CVE-2026-98432')
    assert cached.cached and not values[0].cached
    cached.raw['cveMetadata']['state'] = 'BROKEN'
    assert (await client.get('CVE-2026-98432')).raw['cveMetadata']['state'] == 'PUBLISHED'


@pytest.mark.parametrize('status,body', [(503, {}), (200, '<html>error</html>'), (200, {'cveMetadata': {'cveId': 'CVE-2024-3094'}}), (404, {}), (200, {'cveMetadata': None}), (200, [])])
@pytest.mark.asyncio
async def test_fallback(server, client, status, body):
    server['main'] = (status, body)
    value = await client.get('CVE-2026-98432')
    assert value.source == 'backup' and server['calls'] == ['main', 'backup']


@pytest.mark.asyncio
async def test_missing_is_not_reserved_and_negative_cache(server, client):
    server['main'] = server['backup'] = (404, {})
    for _ in range(2):
        with pytest.raises(LookupFailure, match='未找到公开记录') as exc:
            await client.get('CVE-2026-98432')
        assert exc.value.kind == 'not_found'
    assert len(server['calls']) == 2


@pytest.mark.asyncio
async def test_mixed_404_and_server_error_not_false_missing(server, client):
    server['main'], server['backup'] = (404, {}), (503, {})
    with pytest.raises(LookupFailure) as exc:
        await client.get('CVE-2026-98432')
    assert exc.value.kind == 'unavailable' and '503' in str(exc.value)


@pytest.mark.asyncio
async def test_limit_and_cooldown(server, client):
    client.fallback = False
    server['main'] = (429, {})
    with pytest.raises(LookupFailure, match='请求受限'):
        await client.get('CVE-2026-98432')
    with pytest.raises(LookupFailure, match='限流冷却'):
        await client.get('CVE-2024-3094')
    assert server['calls'] == ['main']


@pytest.mark.asyncio
async def test_timeout(server, client):
    client.timeout, client.fallback = 0.02, False
    server['delay'] = 0.08
    with pytest.raises(LookupFailure, match='超时'):
        await client.get('CVE-2026-98432')


@pytest.mark.asyncio
async def test_payload_limit(server, client):
    client.MAX_BYTES, client.fallback = 100, False
    with pytest.raises(LookupFailure, match='上限'):
        await client.get('CVE-2026-98432')


@pytest.mark.asyncio
async def test_rejected_valid_record(server, client):
    raw = sample(); raw['cveMetadata']['state'] = 'REJECTED'
    server['main'] = (200, raw)
    assert (await client.get('CVE-2026-98432')).raw['cveMetadata']['state'] == 'REJECTED'


def test_bad_proxy():
    with pytest.raises(ValueError, match='SOCKS'):
        CveClient(proxy='socks5://127.0.0.1:1080')
