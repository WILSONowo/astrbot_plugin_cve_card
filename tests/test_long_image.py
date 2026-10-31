import time

from astrbot_plugin_cve_card.cards import make_pages, render_html
from astrbot_plugin_cve_card.records import normalize_record
from astrbot_plugin_cve_card.client import RecordResult
from test_records import sample


def test_long_image_keeps_versions_and_last_reference():
    raw = sample()
    raw['containers']['cna']['descriptions'][0]['value'] = 'Long official description. ' * 120
    raw['containers']['cna']['affected'] = [{'product':'Test','defaultStatus':'unaffected','versions':[
        {'version':str(i),'status':'affected'} for i in range(20)]}]
    raw['containers']['cna']['references'] = [{'url':f'https://example.com/{i}'} for i in range(12)]
    r = normalize_record(raw)
    pages = make_pages(r, RecordResult(raw,'Test',time.time()), max_pages=1, mode='long')
    assert len(pages) == 1
    html = render_html(pages[0])
    assert 'https://example.com/11' in html and '受影响 · 19' in html
    assert not pages[0]['omitted'] and '仅发送前' not in html
    assert '版本条目预览' not in html


def test_extreme_record_splits_without_omitting_tail():
    raw = sample()
    raw['containers']['cna']['references'] = [{'url':f'https://example.com/{i}'} for i in range(200)]
    pages = make_pages(normalize_record(raw), RecordResult(raw,'Test',time.time()), max_pages=1, mode='long')
    assert len(pages) > 1 and not any(p['omitted'] for p in pages)
    assert 'https://example.com/199' in render_html(pages[-1])
