import asyncio
import re
import time
from pathlib import Path
from collections import OrderedDict

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Image, Plain, Node, Nodes
from astrbot.api.star import Context, Star

from .cards import plain_summary
from .client import CveClient, LookupFailure
from .ids import extract_ids, record_url
from .records import normalize_record
from .official import render_official
from .enrichment import KevCache, resolve_record
from .push import KevPush, catalog, digest, sessions


def bounded(config, key, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(config.get(key, default))))
    except (TypeError, ValueError):
        return default


def group_ids(config, key):
    value = config.get(key, [])
    return {str(x).strip() for x in value if str(x).strip()} if isinstance(value, list) else set()


class CveCardPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.client = CveClient(
            timeout=bounded(config, "request_timeout", 12, 3, 60),
            proxy=str(config.get("proxy", "")).strip(), trust_env=bool(config.get("trust_env", False)),
            fallback=bool(config.get("github_fallback", True)),
            ttl=bounded(config, "cache_ttl", 3600, 60, 86400),
            cache_size=bounded(config, "cache_size", 256, 16, 2048),
            concurrency=bounded(config, "fetch_concurrency", 2, 1, 5),
        )
        self._render_gate = asyncio.Semaphore(1)
        self._active = set()
        self._recent = OrderedDict()
        self._cooldowns = OrderedDict()
        self.kev_cache = KevCache(config)
        self.push = None
        self.push_error = ''
        self._manual_lock = asyncio.Lock()

    async def initialize(self):
        if not self.config.get('push_enabled', False):
            return
        from astrbot.api.star import StarTools
        self.push = KevPush(StarTools.get_data_dir('astrbot_plugin_cve_card') / 'kev_state.json',
                            self.config, self._deliver_push, self._notify_push)
        try:
            await self.push.load()
        except Exception as exc:
            self.push_error = type(exc).__name__
            logger.error('[CVE Card] push state load failed: %s', self.push_error)
            return
        self.push.task = asyncio.create_task(self.push.run(), name='cve-card-kev')

    def _forward_platform(self, target):
        platform = self.context.get_platform_inst(target.split(':', 1)[0])
        return platform if platform and platform.meta().name == 'aiocqhttp' else None

    async def _render_raw(self, raw, umo):
        async with self._render_gate:
            path = await asyncio.wait_for(self.html_render(
                "{{ card_html | safe }}", {"card_html": render_official(raw)}, return_url=False,
                options={"type": "jpeg", "quality": 90, "full_page": True,
                         "viewport_width": 1500, "viewport_height": 1,
                         "device_scale_factor_level": "normal"}, umo=umo,
            ), timeout=bounded(self.config, "render_timeout", 40, 5, 120))
        if not path:
            raise RuntimeError("empty render result")
        return path

    @staticmethod
    def _bundle(chains, sender, title=None):
        nodes = [Node(uin=str(sender), name='CVE 漏洞卡片', content=[Plain(title)])] if title else []
        nodes.extend(Node(uin=str(sender), name='CVE 漏洞卡片', content=chain) for chain in chains)
        return Nodes(nodes)

    async def _lookup_raw(self, cid, entry=None):
        return await resolve_record(self.client, self.kev_cache, cid, entry)

    async def _push_chains(self, entries, target, paths):
        chains = []
        for entry in entries:
            cid = entry['cveID']
            heading = cid
            try:
                raw = await self._lookup_raw(cid, entry)
                record = normalize_record(raw)
                heading = f"{cid} · {record['state_label']}"
                path = await self._render_raw(raw, target)
                paths.append(path)
                chain = [Plain(f"{heading}\n{record_url(cid)}\n"), Image.fromFileSystem(path)]
            except Exception as exc:
                logger.warning('[CVE Card] push image unavailable: %s', type(exc).__name__)
                chain = [Plain(f"{heading}\n图片暂不可用，可通过编号重试查询。\n{record_url(cid)}\n")]
            chains.append(chain)
        return chains

    async def _deliver_push(self, target, entries):
        from astrbot.api.event import MessageChain
        platform = self._forward_platform(target)
        paths = []
        try:
            chains = await self._push_chains(entries, target, paths)
            if platform and len(entries) > 2 and self.config.get('push_forward', True):
                info = await platform.get_client().call_action('get_login_info')
                chains = [[self._bundle(chains, str(info['user_id']))]]
            # Send one ordinary message for <=2 entries, so retry does not duplicate a partial batch.
            return bool(await self.context.send_message(target, MessageChain([component for i, chain in enumerate(chains) for component in ([Plain('\n\n')] if i else []) + chain])))
        finally:
            for path in paths:
                try:
                    Path(path).unlink(missing_ok=True)
                except OSError:
                    logger.warning('[CVE Card] push temporary image cleanup failed')

    @filter.command('获取推送')
    async def fetch_push(self, event: AstrMessageEvent):
        """立即获取最新 KEV 记录，只回复当前会话，不改变定时推送基线。"""
        event.set_extra('cve_card_handled', True)
        if not self._push_admin(event):
            yield self._plain(event, '此指令仅限管理员使用。')
            return
        if self._manual_lock.locked():
            yield self._plain(event, '正在获取推送，请稍后重试。')
            return
        async with self._manual_lock:
            # Separate fetcher: no ETag/304, queue mutation, baseline update or scheduler dependency.
            source = KevPush(Path('unused-manual-state.json'), self.config, self._deliver_push)
            paths = []
            try:
                data, _ = await source.fetch()
                _, records = catalog(data)
                limit = bounded(self.config, 'max_items_per_message', 5, 1, 15)
                entries = sorted(records.values(), key=lambda e: (e['dateAdded'], e['cveID']), reverse=True)[:limit]
                chains = await self._push_chains(entries, event.unified_msg_origin, paths)
                for path in paths:
                    event.track_temporary_local_file(path)
                if len(entries) > 2 and self.config.get('push_forward', True) and event.get_platform_name() == 'aiocqhttp':
                    yield event.chain_result([self._bundle(chains, event.get_self_id())]).use_t2i(False)
                else:
                    for chain in chains:
                        yield event.chain_result(chain).use_t2i(False)
            except Exception as exc:
                logger.warning('[CVE Card] manual fetch failed: %s', type(exc).__name__)
                yield self._plain(event, '获取推送失败，请检查 KEV 数据源、代理设置和日志。')
            finally:
                await source.close()

    async def _notify_push(self, message):
        from astrbot.api.event import MessageChain
        for target in sessions(self.config.get('failure_notify_sessions', [])):
            try:
                await self.context.send_message(target, MessageChain([Plain(message)]))
            except Exception as exc:
                logger.warning('[CVE Card] notification failed: %s', type(exc).__name__)

    def _push_admin(self, event):
        return event.is_admin() or str(event.get_sender_id()) in group_ids(self.config, 'admin_users')

    @filter.command('cve推送状态')
    async def push_status(self, event: AstrMessageEvent):
        if not self._push_admin(event):
            yield self._plain(event, '此指令仅限管理员使用。')
            return
        if not self.push:
            yield self._plain(event, '推送未启用。请在插件设置中开启 push_enabled 并设置 target_sessions；修改后重载插件。')
            return
        state = self.push.state
        yield self._plain(event, f"CVE 推送状态\n启动错误：{self.push_error or '无'}\n最近错误：{self.push.last_error or '无'}\n已建立基线：{state['seeded']}\n目录版本：{state['version']}\n目标会话：{len(state['targets'])}\n待补发：{sum(map(len,state['pending'].values()))}\n最近完成检查（UTC）：{state['last_success'] or '尚无'}")

    @filter.command('cve推送刷新')
    async def push_refresh(self, event: AstrMessageEvent):
        if not self._push_admin(event):
            yield self._plain(event, '此指令仅限管理员使用。')
            return
        if not self.push or self.push_error:
            yield self._plain(event, '推送未启用或状态文件加载失败，请检查插件设置和日志。')
            return
        if self.push.lock.locked():
            yield self._plain(event, '推送检查正在进行，请稍后重试。')
            return
        result = await self.push.check()
        yield self._plain(event, f"检查完成：新增 {result['new']} 条，待补发 {result['pending']} 条。" if result else '推送检查失败，已有队列已保留。')

    async def terminate(self):
        if self.push:
            await self.push.close()
        await self.kev_cache.close()
        await self.client.close()

    @staticmethod
    def _plain(event, text):
        # A broken renderer must not be called again by AstrBot's automatic T2I.
        return event.plain_result(text).use_t2i(False)

    @filter.command("cve", alias={"CVE"})
    async def cve_command(self, event: AstrMessageEvent):
        """查询 CVE 编号或链接：/cve CVE-2026-98432"""
        event.set_extra("cve_card_handled", True)
        ids = extract_ids(event.get_message_str())
        if not ids:
            yield self._plain(event, "用法：/cve CVE-2026-98432\n也可发送 CVE 官方记录链接；多个编号用空格分隔。\n管理员：/获取推送、/cve推送状态、/cve推送刷新。推送目标会话可通过 /sid 获取。")
            return
        async for response in self._handle(event, ids, explicit=True):
            yield response

    @filter.event_message_type(filter.EventMessageType.ALL)
    async def auto_detect(self, event: AstrMessageEvent):
        if not self.config.get("auto_detect", True) or event.get_extra("cve_card_handled", False):
            return
        text = event.get_message_str().strip()
        # Command routing owns these inputs; do not send twice if handlers run in either order.
        if re.match(r"^/?cve(?:\s|$)", text, re.I):
            return
        if str(event.get_sender_id()) == str(event.get_self_id()):
            return
        group_id = str(event.get_group_id() or "")
        allowed = group_ids(self.config, "auto_groups")
        blocked = group_ids(self.config, "disabled_groups")
        if group_id:
            if group_id in blocked or (allowed and group_id not in allowed):
                return
        elif not self.config.get("auto_private", True):
            return
        ids = extract_ids(text)
        if ids:
            event.set_extra("cve_card_handled", True)
            async for response in self._handle(event, ids, explicit=False):
                yield response

    @staticmethod
    def _trim(mapping):
        while len(mapping) > 2048:
            mapping.popitem(last=False)

    async def _handle(self, event, ids, explicit):
        can_forward = self.config.get('query_forward', True) and event.get_platform_name() == 'aiocqhttp'
        if not can_forward:
            async for response in self._handle_individual(event, ids, explicit):
                yield response
            return
        responses = [response async for response in self._handle_individual(event, ids, explicit)]
        # Count actual CVE responses after limit/deduplication, not the overflow notice.
        records = [r for r in responses if not (r.chain and isinstance(r.chain[0], Plain) and r.chain[0].text.startswith('本条消息只解析前 '))]
        if len(records) > 2:
            for response in responses:
                if response not in records:
                    yield response
            yield event.chain_result([self._bundle([r.chain for r in records], event.get_self_id())]).use_t2i(False)
        else:
            for response in responses:
                yield response

    async def _handle_individual(self, event, ids, explicit):
        session = event.unified_msg_origin
        now = time.monotonic()
        if session in self._active or len(self._active) >= 8:
            if explicit:
                yield self._plain(event, "CVE 查询正在处理中，请稍后重试。")
            return
        if not explicit:
            cooldown = bounded(self.config, "cooldown_seconds", 15, 0, 3600)
            if now - self._cooldowns.get(session, float("-inf")) < cooldown:
                return
            repeat = bounded(self.config, "dedupe_seconds", 120, 0, 86400)
            ids = [cid for cid in ids if now - self._recent.get((session, cid), float("-inf")) >= repeat]
            if not ids:
                return
        limit = bounded(self.config, "max_ids", 3, 1, 5)
        overflow = len(ids) > limit
        ids = ids[:limit]
        self._active.add(session)
        self._cooldowns[session] = now
        self._cooldowns.move_to_end(session)
        self._trim(self._cooldowns)
        try:
            if overflow:
                yield self._plain(event, f"本条消息只解析前 {limit} 个 CVE 编号。")
            for cve_id in ids:
                try:
                    raw = await self._lookup_raw(cve_id)
                    record = normalize_record(raw)
                except LookupFailure as exc:
                    logger.warning("[CVE Card] %s: %s", cve_id, exc.kind)
                    yield self._plain(event, f"{cve_id} 查询失败：{exc}\n{record_url(cve_id)}")
                    continue
                except Exception as exc:
                    # Only log the error type; proxy URLs and raw records may contain sensitive data.
                    logger.warning("[CVE Card] record parse failed: %s", type(exc).__name__)
                    yield self._plain(event, f"{cve_id} 数据解析失败，请通过官方链接查看：\n{record_url(cve_id)}")
                    continue
                pages = [raw]
                rendered = 0
                for page in pages:
                    try:
                        path = await self._render_raw(page, event.unified_msg_origin)
                    except Exception as exc:
                        logger.warning("[CVE Card] render failed: %s", type(exc).__name__)
                        prefix = "图片渲染失败，以下为文字摘要：\n" if not rendered else "后续页面渲染失败，完整记录请查看原文：\n"
                        yield self._plain(event, prefix + plain_summary(record))
                        break
                    event.track_temporary_local_file(path)
                    chain = [Image.fromFileSystem(path)]
                    if rendered == 0:
                        chain.insert(0, Plain(f"{cve_id} · {record['state_label']}\n{record_url(cve_id)}"))
                    yield event.chain_result(chain).use_t2i(False)
                    rendered += 1
                self._recent[(session, cve_id)] = time.monotonic()
                self._recent.move_to_end((session, cve_id))
                self._trim(self._recent)
        finally:
            self._active.discard(session)
