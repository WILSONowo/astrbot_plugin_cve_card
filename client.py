import asyncio
import copy
import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from urllib.parse import urlsplit

import aiohttp

from .ids import source_urls, validate_id


class LookupFailure(Exception):
    def __init__(self, kind, message):
        self.kind = kind
        super().__init__(message)


@dataclass
class RecordResult:
    raw: dict
    source: str
    fetched_at: float
    cached: bool = False


class CveClient:
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, *, timeout=12, proxy="", trust_env=False, fallback=True, ttl=3600, cache_size=256, concurrency=2):
        if proxy:
            p = urlsplit(proxy)
            if p.scheme not in {"http", "https"} or not p.hostname:
                raise ValueError("代理地址需要使用 http:// 或 https://（不支持 SOCKS）")
        self.timeout, self.proxy, self.trust_env = timeout, proxy or None, trust_env
        self.fallback, self.ttl, self.cache_size = fallback, ttl, cache_size
        self.cache = OrderedDict()
        self.inflight = {}
        self.semaphore = asyncio.Semaphore(concurrency)
        self.session = None
        self.source_pause = {}

    async def close(self):
        tasks = list(self.inflight.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.session:
            await self.session.close()

    async def get(self, cve_id):
        cve_id = validate_id(cve_id)
        now = time.monotonic()
        entry = self.cache.get(cve_id)
        if entry and entry[0] > now:
            self.cache.move_to_end(cve_id)
            value = entry[1]
            if isinstance(value, LookupFailure):
                raise LookupFailure(value.kind, str(value))
            return RecordResult(copy.deepcopy(value.raw), value.source, value.fetched_at, True)
        self.cache.pop(cve_id, None)
        if cve_id not in self.inflight:
            self.inflight[cve_id] = asyncio.create_task(self._load(cve_id))
            self.inflight[cve_id].add_done_callback(lambda task, key=cve_id: self._finish(key, task))
        return await asyncio.shield(self.inflight[cve_id])

    def _finish(self, key, task):
        self.inflight.pop(key, None)
        if not task.cancelled():
            task.exception()  # Consume errors even if every waiting event was cancelled.

    def _remember(self, key, value, ttl):
        self.cache[key] = (time.monotonic() + ttl, value)
        self.cache.move_to_end(key)
        while len(self.cache) > self.cache_size:
            self.cache.popitem(last=False)

    async def _load(self, cve_id):
        async with self.semaphore:
            errors = []
            for source, url in source_urls(cve_id)[:2 if self.fallback else 1]:
                try:
                    raw = await self._request(url, source)
                    if not isinstance(raw, dict):
                        raise LookupFailure("invalid", "数据源返回的记录不是 JSON 对象")
                    meta = raw.get("cveMetadata")
                    if not isinstance(meta, dict) or meta.get("cveId") != cve_id :
                        raise LookupFailure("invalid", "数据源返回的记录格式或编号不正确")
                    if meta.get("state") not in {"PUBLISHED", "REJECTED", "RESERVED"}:
                        raise LookupFailure("invalid", "记录状态无法识别")
                    if meta.get("state") == "RESERVED":
                        raw = copy.deepcopy(raw)
                        raw.setdefault("containers", {})
                        if not isinstance(raw["containers"], dict):
                            raise LookupFailure("invalid", "记录容器格式错误")
                        raw["containers"].setdefault("cna", {})
                    if not isinstance(raw.get("containers"), dict):
                        raise LookupFailure("invalid", "记录缺少容器")
                    cna = raw["containers"].get("cna")
                    if not isinstance(cna, dict):
                        raise LookupFailure("invalid", "记录缺少 CNA 数据")
                    value = RecordResult(raw, source, time.time())
                    self._remember(cve_id, value, self.ttl)
                    return value
                except LookupFailure as exc:
                    errors.append(exc)
            if all(e.kind == "not_found" for e in errors):
                failure = LookupFailure("not_found", "未找到公开记录；不能据此判断编号是否已保留。")
                self._remember(cve_id, failure, 120)
            else:
                detail = "；".join(dict.fromkeys(str(e) for e in errors if e.kind != "not_found"))
                failure = LookupFailure("unavailable", detail)
                self._remember(cve_id, failure, 15)
            raise failure

    async def _request(self, url, source):
        if self.source_pause.get(source, 0) > time.monotonic():
            raise LookupFailure("rate_limit", f"{source} 限流冷却中，请稍后重试")
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout), trust_env=self.trust_env,
                headers={"Accept": "application/json", "User-Agent": "AstrBot-CVE-Card/0.2.0"},
            )
        try:
            async with self.session.get(url, proxy=self.proxy, allow_redirects=False) as response:
                if response.status == 404:
                    raise LookupFailure("not_found", "未找到公开记录")
                if response.status == 429:
                    try:
                        delay = max(30, min(600, int(response.headers.get("Retry-After", "60"))))
                    except ValueError:
                        delay = 60
                    self.source_pause[source] = time.monotonic() + delay
                    raise LookupFailure("rate_limit", f"{source} 请求受限，请稍后重试")
                if response.status != 200:
                    raise LookupFailure("http", f"{source} 返回 HTTP {response.status}")
                chunks, size = [], 0
                async for chunk in response.content.iter_chunked(65536):
                    size += len(chunk)
                    if size > self.MAX_BYTES:
                        raise LookupFailure("invalid", "记录超过 2 MB 上限")
                    chunks.append(chunk)
                try:
                    return json.loads(b"".join(chunks))
                except (ValueError, UnicodeError):
                    raise LookupFailure("invalid", f"{source} 返回了无效 JSON") from None
        except asyncio.TimeoutError:
            raise LookupFailure("timeout", f"{source} 请求超时") from None
        except (aiohttp.ClientProxyConnectionError, aiohttp.ClientHttpProxyError):
            raise LookupFailure("proxy", "代理连接失败，请检查插件代理设置") from None
        except aiohttp.ClientError:
            raise LookupFailure("network", f"{source} 网络连接失败，请检查网络或代理") from None
