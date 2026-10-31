"""Cached KEV enrichment; never changes the push baseline or queue."""
import asyncio
import copy
import time
from pathlib import Path

from .client import LookupFailure
from .official import kev_record, reserved_record
from .push import KevPush, catalog


class KevCache:
    def __init__(self, config):
        self.source = KevPush(Path('unused-cache-state.json'), config, None)
        self.ttl = max(60, min(86400, int(config.get('kev_cache_ttl', 3600))))
        self.entries = {}
        self.expires = 0
        self.retry_after = 0
        self.lock = asyncio.Lock()

    async def get(self, cid):
        async with self.lock:
            now = time.monotonic()
            if now >= self.expires:
                if now < self.retry_after:
                    raise LookupFailure('kev_unavailable', 'KEV 数据暂不可用')
                try:
                    data, etag = await self.source.fetch()
                    if data is not None:
                        _, entries = catalog(data)
                        self.entries = entries
                    elif not self.entries:
                        raise ValueError('304 without cached catalog')
                    self.source.etag = etag
                    self.expires = time.monotonic() + self.ttl
                    self.retry_after = 0
                except Exception:
                    self.retry_after = time.monotonic() + 30
                    raise LookupFailure('kev_unavailable', 'KEV 数据暂不可用') from None
            return copy.deepcopy(self.entries.get(cid))

    async def close(self):
        await self.source.close()


async def resolve_record(client, cache, cid, entry=None):
    failure = None
    try:
        result = await client.get(cid)
        raw = result.raw
        state = raw['cveMetadata']['state']
        if state != 'RESERVED':
            return raw
    except LookupFailure as exc:
        failure = exc
        raw = None
        state = 'UNKNOWN'
    if entry is None:
        try:
            entry = await cache.get(cid)
        except LookupFailure:
            entry = None
    if entry is not None:
        return kev_record(entry, state)
    if raw is not None:
        return reserved_record(raw)
    raise failure
