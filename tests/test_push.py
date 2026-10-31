import copy
from unittest.mock import AsyncMock
import pytest
from astrbot_plugin_cve_card.push import KevPush, catalog, digest

A='test:GroupMessage:1'
B='test:GroupMessage:2'

def feed(*ids):
    return {'catalogVersion':str(len(ids)), 'count':len(ids),'vulnerabilities':[{'cveID':f'CVE-2026-{i:04d}','vendorProject':'Vendor','product':'Product','shortDescription':'Description'} for i in ids]}

def engine(tmp_path, targets=None):
    service=KevPush(tmp_path/'state.json',{'target_sessions':targets or [A]},AsyncMock(return_value=True))
    service.fetch=AsyncMock(return_value=(feed(1000),None))
    return service

async def test_seed_no_history_and_new_entries(tmp_path):
    s=engine(tmp_path)
    await s.load();await s.refresh();s.deliver.assert_not_called()
    s.fetch.return_value=(feed(1000,1001),None)
    r=await s.refresh();assert r['new']==1
    assert s.deliver.call_args.args[1][0]['cveID']=='CVE-2026-1001'
    await s.refresh();assert s.deliver.call_count==1

async def test_failure_isolated_and_restart_retry(tmp_path):
    s=engine(tmp_path,[A,B]);await s.refresh()
    s.fetch.return_value=(feed(1000,1001),None)
    s.deliver.side_effect=[False,True]
    r=await s.refresh();assert r['failed_sessions']==1
    assert len(s.state['pending'][A])==1 and not s.state['pending'][B]
    other=engine(tmp_path,[A,B]);await other.load()
    other.fetch.return_value=(None,None)
    await other.refresh();assert other.deliver.call_count==1
    assert other.deliver.call_args.args[0]==A

async def test_new_target_no_history_and_removed_queue(tmp_path):
    s=engine(tmp_path);await s.refresh()
    s.config['target_sessions']=[A,B];s.fetch.return_value=(feed(1000,1001),None)
    await s.refresh();assert s.deliver.call_count==1 and s.deliver.call_args.args[0]==A
    s.deliver.return_value=False;s.fetch.return_value=(feed(1000,1001,1002),None)
    await s.refresh();s.config['target_sessions']=[B]
    await s.refresh();assert A not in s.state['pending']

@pytest.mark.parametrize('bad',[{}, {'catalogVersion':'1','vulnerabilities':[]}, {'catalogVersion':'2','count':2,'vulnerabilities':[{'cveID':'invalid'}]},feed(1000,1000)])
async def test_bad_feed_never_advances_state(tmp_path,bad):
    s=engine(tmp_path);await s.refresh();before=copy.deepcopy(s.state)
    s.fetch.return_value=(bad,None)
    with pytest.raises(ValueError):await s.refresh()
    assert s.state==before

async def test_corrupt_state_not_overwritten(tmp_path):
    p=tmp_path/'state.json';p.write_text('{bad')
    s=engine(tmp_path)
    with pytest.raises(ValueError):await s.load()
    assert p.read_text()=='{bad'

async def test_persistence_failure_prevents_send(tmp_path,monkeypatch):
    s=engine(tmp_path);await s.refresh();s.fetch.return_value=(feed(1000,1001),None)
    def fail(state):raise OSError('disk full')
    monkeypatch.setattr(s,'_write',fail)
    with pytest.raises(OSError):await s.refresh()
    s.deliver.assert_not_called()

async def test_notifications_only_once_then_recovery(tmp_path):
    s=engine(tmp_path);s.notify=AsyncMock();s.fetch.side_effect=TimeoutError()
    await s.check();await s.check();assert s.notify.call_count==1
    s.fetch.side_effect=None
    await s.check();assert s.notify.call_count==2

async def test_bounded_batches_no_loss(tmp_path):
    s=engine(tmp_path);s.config['max_items_per_message']=2;await s.refresh()
    s.fetch.return_value=(feed(*range(1000,1014)),None)
    r=await s.refresh();assert s.deliver.call_count==5 and r['pending']==3
    await s.refresh();assert not s.state['pending'][A]

async def test_disabled_empty_targets_still_safe(tmp_path):
    s=engine(tmp_path);s.config['target_sessions']=[];await s.refresh()
    s.fetch.return_value=(feed(1000,1001),None);await s.refresh()
    s.deliver.assert_not_called();assert not s.state['pending']

async def test_wrapped_target_migrates_pending_without_loss(tmp_path):
    import json
    wrapped='UMO: 「test:GroupMessage:1」'
    s=engine(tmp_path,[wrapped]);await s.refresh()
    s.fetch.return_value=(feed(1000,1001),None);s.deliver.return_value=False;await s.refresh()
    state=copy.deepcopy(s.state);state['targets']=[wrapped];state['pending']={wrapped:state['pending'][A]}
    s.path.write_text(json.dumps(state),encoding='utf-8')
    restored=engine(tmp_path,[A]);await restored.load()
    assert restored.state['seeded'] and len(restored.state['pending'][A])==1
    restored.fetch.return_value=(feed(1000,1001),None)
    result=await restored.refresh()
    assert result['new']==0 and result['pending']==0
    assert restored.deliver.call_args.args[0]==A

@pytest.mark.parametrize('value',['UMO: broken','wrong:Kind:123','test:GroupMessage:', 'UMO: 「bad」'])
def test_invalid_session_rejected(value):
    from astrbot_plugin_cve_card.push import sessions
    with pytest.raises(ValueError):sessions([value])
