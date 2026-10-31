"""Adapter contract tests with explicit AstrBot interface doubles; no QQ connection."""
import importlib
import logging
import sys
import time
import types
from unittest.mock import AsyncMock

import pytest

from astrbot_plugin_cve_card.client import RecordResult, LookupFailure
from test_records import sample


class Result:
    def __init__(self, chain):
        self.chain = chain
        self.use_t2i_ = None

    def use_t2i(self, flag):
        self.use_t2i_ = flag
        return self


class Plain:
    def __init__(self, text): self.text = text


class Image:
    @classmethod
    def fromFileSystem(cls, path):
        instance = cls(); instance.path = path; return instance


class Node:
    def __init__(self, **kwargs): self.__dict__.update(kwargs)

class Nodes:
    def __init__(self, nodes): self.nodes = nodes

class Event:
    def __init__(self, message='CVE-2026-98432', group='123', sender='user', session=None):
        self.message, self.group, self.sender = message, group, sender
        self.unified_msg_origin = session or 'test:GroupMessage:' + group
        self.extras = {}
        self.temporary = []

    def get_message_str(self): return self.message
    def get_group_id(self): return self.group
    def get_sender_id(self): return self.sender
    def get_platform_name(self): return 'test'
    def get_self_id(self): return 'bot'
    def is_admin(self): return False
    def get_extra(self, key, default=None): return self.extras.get(key, default)
    def set_extra(self, key, value): self.extras[key] = value
    def plain_result(self, text): return Result([Plain(text)])
    def chain_result(self, chain): return Result(chain)
    def track_temporary_local_file(self, path): self.temporary.append(path)


@pytest.fixture
def plugin_class(monkeypatch):
    class Star:
        def __init__(self, context): self.context = context
        async def html_render(self, *args, **kwargs): raise NotImplementedError

    def decorator(*args, **kwargs): return lambda fn: fn
    modules = {name: types.ModuleType(name) for name in ['astrbot', 'astrbot.api', 'astrbot.api.event', 'astrbot.api.star', 'astrbot.api.message_components']}
    modules['astrbot.api'].AstrBotConfig = dict
    modules['astrbot.api'].logger = logging.getLogger('test')
    modules['astrbot.api.event'].AstrMessageEvent = Event
    modules['astrbot.api.event'].filter = types.SimpleNamespace(command=decorator, event_message_type=decorator, EventMessageType=types.SimpleNamespace(ALL=7))
    modules['astrbot.api.star'].Star = Star
    modules['astrbot.api.star'].Context = object
    modules['astrbot.api.message_components'].Image = Image
    modules['astrbot.api.message_components'].Plain = Plain
    modules['astrbot.api.message_components'].Node = Node
    modules['astrbot.api.message_components'].Nodes = Nodes
    modules['astrbot.api.event'].MessageChain = Result
    for key, module in modules.items(): monkeypatch.setitem(sys.modules, key, module)
    sys.modules.pop('astrbot_plugin_cve_card.main', None)
    return importlib.import_module('astrbot_plugin_cve_card.main').CveCardPlugin


@pytest.fixture
async def plugin(plugin_class, monkeypatch):
    import astrbot_plugin_cve_card.main as main
    monkeypatch.setattr(main.KevPush, 'fetch', AsyncMock(side_effect=RuntimeError('unavailable test feed')))
    p = plugin_class(object(), {})
    p.client.get = AsyncMock(return_value=RecordResult(sample(), 'Test', time.time()))
    p.html_render = AsyncMock(return_value='test.jpg')
    yield p
    await p.terminate()


async def collect(iterator): return [x async for x in iterator]


async def test_command_and_auto_only_once(plugin):
    event = Event('/cve CVE-2026-98432')
    assert not await collect(plugin.auto_detect(event))
    values = await collect(plugin.cve_command(event))
    assert len(values) == 1 and isinstance(values[0].chain[1], Image)
    assert 'https://www.cve.org/' in values[0].chain[0].text
    assert not await collect(plugin.auto_detect(event))
    assert plugin.client.get.await_count == 1
    assert event.temporary == ['test.jpg']
    kwargs = plugin.html_render.await_args.kwargs
    assert kwargs['umo'] == event.unified_msg_origin and kwargs['return_url'] is False
    assert kwargs['options']['viewport_width'] == 1500


async def test_render_failure_fallback_disables_auto_t2i(plugin):
    plugin.html_render.side_effect = RuntimeError('failed')
    values = await collect(plugin.auto_detect(Event()))
    assert len(values) == 1 and '图片渲染失败' in values[0].chain[0].text
    assert values[0].use_t2i_ is False
    assert not plugin._active


async def test_failed_lookup_does_not_call_renderer(plugin):
    plugin.client.get.side_effect = LookupFailure('not_found', '未找到公开记录')
    values = await collect(plugin.cve_command(Event()))
    assert '未找到公开记录' in values[0].chain[0].text
    plugin.html_render.assert_not_called()
    assert not plugin._active


@pytest.mark.parametrize('config,group,sender', [
    ({'auto_detect':False}, '123','user'), ({'auto_groups':['999']}, '123','user'),
    ({'disabled_groups':['123']}, '123','user'), ({'auto_private':False}, '','user'),
    ({}, '123','bot'),
])
async def test_auto_switches(plugin, config, group, sender):
    plugin.config.update(config)
    assert not await collect(plugin.auto_detect(Event(group=group,sender=sender)))
    plugin.client.get.assert_not_called()


async def test_command_bypasses_auto_switch(plugin):
    plugin.config['auto_detect'] = False
    assert await collect(plugin.cve_command(Event()))


async def test_cooldown_and_explicit_bypass(plugin):
    assert await collect(plugin.auto_detect(Event()))
    assert not await collect(plugin.auto_detect(Event('CVE-2024-3094')))
    assert await collect(plugin.cve_command(Event('/cve CVE-2026-98432')))


async def test_dedupe_without_cooldown_and_session_isolation(plugin):
    plugin.config['cooldown_seconds'] = 0
    assert await collect(plugin.auto_detect(Event()))
    assert not await collect(plugin.auto_detect(Event()))
    assert await collect(plugin.auto_detect(Event(session='other:GroupMessage:123')))


async def test_command_empty(plugin):
    values = await collect(plugin.cve_command(Event('/cve')))
    assert '用法' in values[0].chain[0].text
    plugin.client.get.assert_not_called()


async def test_query_cap(plugin):
    plugin.config['max_ids'] = 1
    values = await collect(plugin.auto_detect(Event('CVE-2026-98432 CVE-2024-3094')))
    assert '只解析前 1 个' in values[0].chain[0].text
    assert plugin.client.get.await_count == 1


async def test_busy_command_explicit_error(plugin):
    event = Event()
    plugin._active.add(event.unified_msg_origin)
    values = await collect(plugin.cve_command(event))
    assert '正在处理中' in values[0].chain[0].text
    assert not await collect(plugin.auto_detect(Event()))


async def test_long_record_uses_approved_template(plugin):
    raw = sample(); raw['containers']['cna']['descriptions'][0]['value'] = 'Long description. ' * 150
    plugin.client.get.return_value = RecordResult(raw, 'Test', time.time())
    values = await collect(plugin.cve_command(Event()))
    assert isinstance(values[0].chain[1], Image)
    assert len(values) == 1
    assert 'Required CVE Record Information' in plugin.html_render.call_args.args[1]['card_html']
    assert not plugin._active


async def test_push_disabled_by_default(plugin):
    await plugin.initialize()
    assert plugin.push is None


async def test_push_admin_permissions(plugin):
    values=await collect(plugin.push_refresh(Event()))
    assert '仅限管理员' in values[0].chain[0].text
    plugin.config['admin_users']=['user']
    values=await collect(plugin.push_status(Event()))
    assert '推送未启用' in values[0].chain[0].text


async def test_url_triggers_same_renderer(plugin):
    await collect(plugin.auto_detect(Event('https://www.cve.org/CVERecord?id=CVE-2026-98432')))
    plugin.client.get.assert_awaited_once_with('CVE-2026-98432')

async def test_multi_query_forward(plugin):
    event=Event('/cve CVE-2026-98432 CVE-2024-3094 CVE-2024-6387')
    event.get_platform_name=lambda: 'aiocqhttp'
    values=await collect(plugin.cve_command(event))
    assert len(values)==1 and isinstance(values[0].chain[0], Nodes)
    nodes=values[0].chain[0].nodes
    assert len(nodes)==3 and all(n.uin=='bot' for n in nodes)
    assert all(isinstance(n.content[1], Image) for n in nodes)
    assert len(event.temporary)==3

async def test_forward_query_error_keeps_other_record(plugin):
    event=Event('CVE-2026-98432 CVE-2024-3094 CVE-2024-6387'); event.get_platform_name=lambda:'aiocqhttp'
    plugin.client.get.side_effect=[LookupFailure('not_found','未找到'), RecordResult(sample(),'Test',time.time()), RecordResult(sample(),'Test',time.time())]
    values=await collect(plugin.cve_command(event))
    nodes=values[0].chain[0].nodes
    assert '未找到' in nodes[0].content[0].text
    assert isinstance(nodes[2].content[1],Image)

async def test_forward_query_disabled(plugin):
    plugin.config['query_forward']=False
    event=Event('CVE-2026-98432 CVE-2024-3094 CVE-2024-6387'); event.get_platform_name=lambda:'aiocqhttp'
    values=await collect(plugin.cve_command(event))
    assert len(values)==3 and isinstance(values[0].chain[1],Image)


def push_context(plugin, name='aiocqhttp'):
    client=types.SimpleNamespace(call_action=AsyncMock(return_value={'user_id':12345}))
    platform=types.SimpleNamespace(meta=lambda:types.SimpleNamespace(name=name), get_client=lambda:client)
    plugin.context=types.SimpleNamespace(get_platform_inst=lambda _:platform,send_message=AsyncMock(return_value=True))
    return plugin.context


def entry():
    return dict(cveID='CVE-2026-98432',vendorProject='Linux',product='Linux',vulnerabilityName='test',shortDescription='desc',dateAdded='2026-10-30')

async def test_push_forward_images_cleanup(plugin,tmp_path):
    ctx=push_context(plugin); path=tmp_path/'image.jpg'; path.write_bytes(b'image'); plugin.html_render.return_value=str(path)
    assert await plugin._deliver_push('qq:GroupMessage:1',[entry()])
    chain=ctx.send_message.call_args.args[1].chain
    assert isinstance(chain[0],Plain) and isinstance(chain[1],Image)
    assert not path.exists()

async def test_push_send_failure_propagates_and_cleans(plugin,tmp_path):
    ctx=push_context(plugin); ctx.send_message.side_effect=RuntimeError('send failed')
    path=tmp_path/'image.jpg'; path.write_bytes(b'image'); plugin.html_render.return_value=str(path)
    with pytest.raises(RuntimeError): await plugin._deliver_push('qq:GroupMessage:1',[entry()])
    assert not path.exists() and ctx.send_message.await_count==1

async def test_push_render_failure_text_node(plugin):
    ctx=push_context(plugin); plugin.html_render.side_effect=RuntimeError('render failed')
    assert await plugin._deliver_push('qq:GroupMessage:1',[entry()])
    chain=ctx.send_message.call_args.args[1].chain
    assert '图片暂不可用' in chain[-1].text

@pytest.mark.parametrize('platform,enabled',[('telegram',True),('aiocqhttp',False)])
async def test_push_plain_platform_or_disabled(plugin,platform,enabled):
    ctx=push_context(plugin,platform); plugin.config['push_forward']=enabled
    assert await plugin._deliver_push('qq:GroupMessage:1',[entry()])
    assert isinstance(ctx.send_message.call_args.args[1].chain[0],Plain)
    assert plugin.client.get.await_count == 1

@pytest.mark.parametrize('count',[1,2,3])
async def test_forward_threshold_and_no_heading(plugin,count):
    ids=['CVE-2026-98432','CVE-2024-3094','CVE-2024-6387'][:count]
    event=Event(' '.join(ids));event.get_platform_name=lambda:'aiocqhttp'
    values=await collect(plugin.cve_command(event))
    if count>2:
        assert len(values)==1 and len(values[0].chain[0].nodes)==3
        chains=[n.content for n in values[0].chain[0].nodes]
    else:
        assert len(values)==count
        chains=[r.chain for r in values]
    assert all(isinstance(c[0],Plain) and isinstance(c[1],Image) for c in chains)
    assert all('展开查看' not in c[0].text for c in chains)

async def test_limit_to_two_not_forward(plugin):
    plugin.config['max_ids']=2
    event=Event('CVE-2026-98432 CVE-2024-3094 CVE-2024-6387');event.get_platform_name=lambda:'aiocqhttp'
    values=await collect(plugin.cve_command(event))
    assert len(values)==3 and not any(isinstance(r.chain[0],Nodes) for r in values)

@pytest.mark.parametrize('count',[2,3])
async def test_push_forward_threshold(plugin,tmp_path,count):
    ctx=push_context(plugin);path=tmp_path/'image.jpg';path.write_bytes(b'image');plugin.html_render.return_value=str(path)
    assert await plugin._deliver_push('qq:GroupMessage:1',[entry() for _ in range(count)])
    chain=ctx.send_message.call_args.args[1].chain
    assert isinstance(chain[0],Nodes)==(count>2)
    if count>2: assert len(chain[0].nodes)==3
    else: assert len(chain)==5 and isinstance(chain[0],Plain) and isinstance(chain[1],Image)

async def test_manual_fetch_disabled_scheduler_latest_and_no_state(plugin,monkeypatch):
    import astrbot_plugin_cve_card.main as main
    from test_push import feed
    data=feed(1000,1001,1002)
    for e,date in zip(data['vulnerabilities'],['2026-10-28','2026-10-30','2026-10-29']):e['dateAdded']=date
    fetch=AsyncMock(return_value=(data,None));close=AsyncMock()
    monkeypatch.setattr(main.KevPush,'fetch',fetch);monkeypatch.setattr(main.KevPush,'close',close)
    plugin.config.update(admin_users=['user'],max_items_per_message=2,push_enabled=False)
    event=Event('/获取推送');event.get_platform_name=lambda:'aiocqhttp'
    values=await collect(plugin.fetch_push(event))
    assert len(values)==2 and plugin.push is None
    assert 'CVE-2026-1001' in values[0].chain[0].text
    assert 'CVE-2026-1002' in values[1].chain[0].text
    assert len(event.temporary)==2
    close.assert_awaited_once()

async def test_manual_fetch_denied_and_busy(plugin):
    assert '仅限管理员' in (await collect(plugin.fetch_push(Event())))[0].chain[0].text
    plugin.config['admin_users']=['user']
    async with plugin._manual_lock:
        assert '正在获取' in (await collect(plugin.fetch_push(Event())))[0].chain[0].text

async def test_manual_fetch_failure_closes(plugin,monkeypatch):
    import astrbot_plugin_cve_card.main as main
    monkeypatch.setattr(main.KevPush,'fetch',AsyncMock(side_effect=RuntimeError('secret')))
    close=AsyncMock();monkeypatch.setattr(main.KevPush,'close',close)
    plugin.config['admin_users']=['user']
    values=await collect(plugin.fetch_push(Event()))
    assert '获取推送失败' in values[0].chain[0].text and 'secret' not in values[0].chain[0].text
    close.assert_awaited_once()

async def test_push_matches_query_no_kev_prose(plugin):
    paths=[]
    chains=await plugin._push_chains([entry()], 'qq:GroupMessage:1', paths)
    text=chains[0][0].text
    assert text.startswith('CVE-2026-98432 · ')
    assert text.endswith('https://www.cve.org/CVERecord?id=CVE-2026-98432\n')
    assert 'CISA' not in text and '加入日期' not in text and 'desc' not in text
    assert isinstance(chains[0][1],Image)

async def test_failed_push_link_separated_from_next_record(plugin):
    ctx=push_context(plugin);plugin.client.get.side_effect=LookupFailure('not_found','not found');plugin.html_render.side_effect=RuntimeError('render failed')
    assert await plugin._deliver_push('qq:GroupMessage:1',[entry(),entry()])
    text=''.join(c.text for c in ctx.send_message.call_args.args[1].chain if isinstance(c,Plain))
    assert '98432\n\n\nCVE-' in text
    assert '98432图片' not in text and 'KEV' not in text
