import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from astrbot_plugin_cve_card.enrichment import KevCache, resolve_record
from astrbot_plugin_cve_card.client import CveClient, LookupFailure
from astrbot_plugin_cve_card.official import render_official

CID='CVE-2026-118527'
def feed():
    return {'catalogVersion':'v1','count':1,'vulnerabilities':[{'cveID':CID,'shortDescription':'Description','requiredAction':'Action'}]}

@pytest.mark.parametrize('state',['RESERVED','PUBLISHED','REJECTED'])
async def test_explicit_state(state):
    raw={'cveMetadata':{'cveId':CID,'state':state},'containers':{'cna':{}}}
    client=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(raw=raw)))
    cache=SimpleNamespace(get=AsyncMock(return_value=feed()['vulnerabilities'][0]))
    result=await resolve_record(client,cache,CID)
    assert result['cveMetadata']['state']==state
    if state=='RESERVED':assert result['_kev_fallback']
    else:cache.get.assert_not_called()

async def test_not_found_is_unknown_even_for_former_hardcoded_id():
    client=SimpleNamespace(get=AsyncMock(side_effect=LookupFailure('not_found','missing')))
    cache=SimpleNamespace(get=AsyncMock(return_value=feed()['vulnerabilities'][0]))
    raw=await resolve_record(client,cache,CID)
    assert raw['cveMetadata']['state']=='UNKNOWN'
    assert 'currently unavailable' in render_official(raw)

async def test_reserved_no_kev_minimal_card():
    raw={'cveMetadata':{'cveId':CID,'state':'RESERVED'}}
    client=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(raw=raw)))
    cache=SimpleNamespace(get=AsyncMock(return_value=None))
    result=await resolve_record(client,cache,CID)
    html=render_official(result)
    assert 'Details are not yet public.' in html
    assert 'Source: CISA KEV' not in html

async def test_no_sources_preserves_failure():
    client=SimpleNamespace(get=AsyncMock(side_effect=LookupFailure('not_found','missing')))
    cache=SimpleNamespace(get=AsyncMock(side_effect=LookupFailure('kev_unavailable','failed')))
    with pytest.raises(LookupFailure,match='missing'):await resolve_record(client,cache,CID)

async def test_cache_concurrent_negative_and_etag():
    cache=KevCache({})
    cache.source.fetch=AsyncMock(return_value=(feed(),'etag'))
    results=await asyncio.gather(*[cache.get(CID) for _ in range(5)])
    assert cache.source.fetch.await_count==1 and cache.source.etag=='etag'
    results[0]['shortDescription']='mutated'
    assert (await cache.get(CID))['shortDescription']=='Description'
    assert await cache.get('CVE-2026-0000') is None
    assert cache.source.fetch.await_count==1
    cache.expires=0;cache.source.fetch.return_value=(None,'etag')
    assert await cache.get(CID)
    assert cache.source.fetch.await_count==2
    await cache.close()

async def test_expired_cache_failure_cooldown_does_not_serve_stale():
    cache=KevCache({});cache.source.fetch=AsyncMock(return_value=(feed(),'etag'))
    await cache.get(CID)
    cache.expires=0;cache.source.fetch.side_effect=RuntimeError('failure')
    for _ in range(2):
        with pytest.raises(LookupFailure):await cache.get(CID)
    assert cache.source.fetch.await_count==2
    await cache.close()

async def test_client_accepts_reserved_metadata_only():
    client=CveClient()
    client._request=AsyncMock(return_value={'cveMetadata':{'cveId':CID,'state':'RESERVED'}})
    result=await client.get(CID)
    assert result.raw['containers']['cna']=={}
    await client.close()
