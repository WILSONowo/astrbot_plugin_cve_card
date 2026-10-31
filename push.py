"""Independent KEV subscription engine: durable per-session queues, no historical flood."""
import asyncio
import copy
import json
import os
import re
import tempfile
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from .ids import validate_id, record_url

FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


def normalize_session(value):
    text = value.strip()
    match = re.fullmatch(r'UMO\s*[:：]\s*「([^「」]+)」', text, re.I)
    if match:
        text = match.group(1).strip()
    parts = text.split(':', 2)
    if len(parts) != 3 or not all(parts) or parts[1] not in {'GroupMessage', 'FriendMessage', 'OtherMessage'} or any(c.isspace() for c in text) or any(c in text for c in '「」'):
        raise ValueError('目标会话格式错误，请填写 /sid 返回的冒号分隔标识，不含 UMO 提示和括号')
    return text


def sessions(value):
    if not isinstance(value, list):
        raise ValueError('目标会话必须为列表')
    return list(dict.fromkeys(normalize_session(v) for v in value if isinstance(v, str) and v.strip()))


def catalog(data):
    if not isinstance(data, dict) or not data.get('catalogVersion') or not isinstance(data.get('vulnerabilities'), list) or not data['vulnerabilities']:
        raise ValueError('KEV 目录格式异常或目录为空，未更新基线')
    entries = {}
    for entry in data['vulnerabilities']:
        if not isinstance(entry, dict):
            raise ValueError('KEV 条目格式异常')
        cid = validate_id(entry.get('cveID', ''))
        if cid in entries:
            raise ValueError('KEV 目录存在重复编号')
        entries[cid] = {k:str(entry.get(k) or '')[:(12000 if k in {'shortDescription','requiredAction'} else 160)] for k in ('cveID','vendorProject','product','vulnerabilityName','shortDescription','dateAdded','requiredAction','dueDate')}
    if 'count' in data and data['count'] != len(entries):
        raise ValueError('KEV 目录条数不符，未更新基线')
    return str(data['catalogVersion']), entries


def digest(entries):
    lines = ['CISA KEV 漏洞记录（已确认在野利用）']
    for entry in entries:
        lines.append(f"\n{entry['cveID']} · {entry['vendorProject']} / {entry['product']}\n{entry['vulnerabilityName']}\n{entry['shortDescription'][:240]}\n加入日期：{entry['dateAdded']}\n{record_url(entry['cveID'])}")
    return '\n'.join(lines)


class KevPush:
    def __init__(self, path, config, deliver, notify=None):
        self.path = Path(path)
        self.config, self.deliver, self.notify = config, deliver, notify
        self.state = {'schema':1, 'seeded':False, 'version':'', 'seen':[], 'targets':[], 'pending':{}, 'last_success':''}
        self.lock = asyncio.Lock()
        self.task = None
        self.http = None
        self.failed = False
        self.last_error = ''
        self.etag = None

    async def load(self):
        if not self.path.exists():
            return
        data = json.loads(await asyncio.to_thread(self.path.read_text, encoding='utf-8'))
        if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('seeded'), bool):
            raise ValueError('推送状态文件损坏，未覆盖原文件')
        if not isinstance(data.get('seen'), list) or not isinstance(data.get('targets'), list) or not isinstance(data.get('pending'), dict):
            raise ValueError('推送状态结构异常，未覆盖原文件')
        for cid in data['seen']:
            validate_id(cid)
        for target, queue in data['pending'].items():
            if not sessions([target]) or not isinstance(queue, list):
                raise ValueError('推送队列异常')
            for entry in queue:
                if not isinstance(entry, dict):
                    raise ValueError('推送队列条目异常')
                validate_id(entry.get('cveID', ''))
        # Migrate copied /sid wrappers without losing queued records or the established baseline.
        data['targets'] = sessions(data['targets'])
        pending = {}
        for target, queue in data['pending'].items():
            merged = pending.setdefault(normalize_session(target), [])
            known = {e['cveID'] for e in merged}
            for entry in queue:
                if entry['cveID'] not in known:
                    merged.append(entry)
                    known.add(entry['cveID'])
        data['pending'] = pending
        self.state = data

    def _write(self, state):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = None
        try:
            with tempfile.NamedTemporaryFile('w',encoding='utf-8',dir=self.path.parent,delete=False) as f:
                temp = Path(f.name)
                json.dump(state, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            temp.replace(self.path)
        finally:
            if temp:
                temp.unlink(missing_ok=True)

    async def commit(self, state):
        # Complete the atomic write before propagating cancellation or sending messages.
        task = asyncio.create_task(asyncio.to_thread(self._write, state))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            self.state = state
            raise
        self.state = state

    async def fetch(self):
        if self.http is None:
            self.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30),trust_env=bool(self.config.get('trust_env',False)))
        url = str(self.config.get('kev_feed_url') or FEED)
        if not url.startswith(('https://','http://')):
            raise ValueError('KEV 数据源必须为 HTTP(S) 地址')
        headers = {'User-Agent':'AstrBot-CVE-Card/0.3.4'}
        if self.etag:
            headers['If-None-Match'] = self.etag
        async with self.http.get(url,headers=headers,proxy=self.config.get('proxy') or None) as response:
            if response.status == 304:
                return None, self.etag
            if response.status != 200:
                raise RuntimeError(f'KEV HTTP {response.status}')
            parts, size = [], 0
            async for part in response.content.iter_chunked(65536):
                size += len(part)
                if size > 16*1024*1024:
                    raise ValueError('KEV 目录超过 16 MB 上限')
                parts.append(part)
            return json.loads(b''.join(parts)), response.headers.get('ETag')

    async def refresh(self):
        async with self.lock:
            targets = sessions(self.config.get('target_sessions', []))
            data, etag = await self.fetch()
            state = copy.deepcopy(self.state)
            new_count = 0
            if data is not None:
                version, entries = catalog(data)
                seen = set(state['seen'])
                if state['seeded'] and not (seen & entries.keys()):
                    raise ValueError('KEV 目录与既有基线完全不相交，请检查数据源')
                fresh = [v for k,v in entries.items() if k not in seen] if state['seeded'] else []
                new_count = len(fresh)
                for target in targets:
                    if target in state['targets']:
                        state['pending'].setdefault(target, []).extend(fresh)
                state.update(seeded=True, version=version, seen=sorted(seen | entries.keys()))
            # Newly subscribed sessions start from now; removed targets lose their queues.
            state['pending'] = {t:state['pending'].get(t, []) if t in state['targets'] else [] for t in targets}
            state['targets'] = targets
            await self.commit(state)
            self.etag = etag
            batch_size = max(1, min(15, int(self.config.get('max_items_per_message', 5))))
            failures = 0
            # Bound each round; queues persist and drain on later checks/manual refreshes.
            for target in targets:
                for _ in range(5):
                    batch = self.state['pending'].get(target, [])[:batch_size]
                    if not batch:
                        break
                    while len(batch) > 1 and len(digest(batch)) > 3500:
                        batch = batch[:-1]
                    try:
                        if not await self.deliver(target, batch):
                            raise RuntimeError('adapter returned false')
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logging.getLogger(__name__).warning('CVE push delivery failed: %s', type(exc).__name__)
                        failures += 1
                        break
                    state = copy.deepcopy(self.state)
                    del state['pending'][target][:len(batch)]
                    await self.commit(state)
            state = copy.deepcopy(self.state)
            state['last_success'] = datetime.now(timezone.utc).isoformat()
            await self.commit(state)
            return {'new':new_count,'failed_sessions':failures,'pending':sum(map(len,self.state['pending'].values())),'version':self.state['version']}

    async def check(self):
        try:
            result = await self.refresh()
            if result['failed_sessions']:
                raise RuntimeError('部分会话发送失败，已保留待补发队列')
            if self.failed and self.notify:
                await self.notify('CVE 推送已恢复正常。')
            self.failed = False
            self.last_error = ''
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Never expose proxy credentials or raw HTTP exception strings.
            self.last_error = type(exc).__name__
            logging.getLogger(__name__).warning('CVE push check failed: %s', self.last_error)
            if not self.failed and self.notify:
                await self.notify('CVE 推送检查失败（'+self.last_error+'），队列保留，请检查日志、网络及目标会话。')
            self.failed = True
            return None

    async def run(self):
        while True:
            await self.check()
            try:
                hours = max(1, min(48, int(self.config.get('push_interval_hours', 6))))
            except (ValueError, TypeError):
                hours = 6
            await asyncio.sleep(hours*3600)

    async def close(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task,return_exceptions=True)
        if self.http:
            await self.http.close()
