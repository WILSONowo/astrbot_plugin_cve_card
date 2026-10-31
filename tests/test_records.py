import copy
import time

import pytest
from jinja2 import Environment

from astrbot_plugin_cve_card.ids import extract_ids, source_urls, validate_id
from astrbot_plugin_cve_card.records import normalize_record, version_label
from astrbot_plugin_cve_card.cards import make_pages, render_html
from astrbot_plugin_cve_card.client import RecordResult


def sample():
    return {"dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {"cveId": "CVE-2026-98432", "state": "PUBLISHED"},
            "containers": {"cna": {"providerMetadata": {"shortName": "Test CNA"},
                                   "descriptions": [{"lang": "en", "value": "Official description"}]}}}


@pytest.mark.parametrize("value,expected", [
    ("cve-2026-98432 CVE-2026-98432", ["CVE-2026-98432"]),
    ("https://www.cve.org/CVERecord?id=CVE-2026-98432", ["CVE-2026-98432"]),
    ("https://example.test/?id=CVE%2D2024%2D3094", ["CVE-2024-3094"]),
    ("（CVE-2024-3094），CVE-2026-123456", ["CVE-2024-3094", "CVE-2026-123456"]),
    ("xCVE-2026-98432 CVE-2026-98432x CVE-2026-123 CVE-2026-１２３４", []),
    ("CVE-2026-12345678901234567890", []),
])
def test_extract(value, expected):
    assert extract_ids(value) == expected


@pytest.mark.parametrize("value,bucket", [("CVE-2024-3094", "3xxx"), ("CVE-2026-98432", "98xxx"), ("CVE-2026-123456", "123xxx"), ("CVE-1999-0001", "0xxx")])
def test_buckets(value, bucket):
    assert f"/{bucket}/" in source_urls(value)[1][1]


def test_reject_arbitrary_url():
    with pytest.raises(ValueError):
        validate_id("http://127.0.0.1/CVE-2026-98432")


def test_missing_score_is_not_zero():
    r = normalize_record(sample())
    assert r["scores"] == []
    assert r["title"] == "CVE 漏洞记录"


def test_null_provider_and_unknown_adp_not_attributed_to_cna():
    raw = sample()
    raw['containers']['cna']['providerMetadata'] = None
    raw['containers']['adp'] = [{'metrics': [{'cvssV3_1': {'baseScore': 0}}]}]
    r = normalize_record(raw)
    assert r['provider'] == 'CNA'
    assert r['scores'][0]['source'] == '未注明 ADP'
    assert r['scores'][0]['tone'] == 'neutral'


def test_adp_sources_scores_and_dedup_refs():
    raw = sample()
    raw["containers"]["cna"]["references"] = [{"url": "https://example.com/a"}]
    raw["containers"]["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": 5.5}}]
    raw["containers"]["adp"] = [{"providerMetadata": {"shortName": "CISA-ADP"},
        "metrics": [{"cvssV4_0": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
        "references": [{"url": "https://example.com/a"}, {"url": "https://example.com/b"}, {"url": "javascript:alert(1)"}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-416"}]}]}]
    r = normalize_record(raw)
    assert [s["score"] for s in r["scores"]] == ["5.5", "9.3"]
    assert r["scores"][1]["source"] == "CISA-ADP"
    assert len(r["references"]) == 2
    assert r["weaknesses"] == ["CWE-416"]


@pytest.mark.parametrize("score", [True, -1, 11, "9.8", None])
def test_invalid_scores_are_not_displayed(score):
    raw = sample()
    raw["containers"]["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": score}}]
    assert normalize_record(raw)["scores"] == []


def test_rejected_reason_and_no_critical_badge():
    raw = sample()
    raw["cveMetadata"]["state"] = "REJECTED"
    raw["containers"]["cna"]["rejectedReasons"] = [{"lang": "en", "value": "Duplicate record"}]
    r = normalize_record(raw)
    assert r["description"] == "Duplicate record"
    assert r["state_label"] == "已撤销"
    html = render_html(make_pages(r, RecordResult(raw, "Test", time.time()))[0])
    assert "已撤销" in html and "Duplicate record" in html


def test_range_changes_and_git_not_reinterpreted():
    v = {"version": "aabb", "lessThan": "ccdd", "versionType": "git", "status": "affected",
         "changes": [{"at": "bbcc", "status": "unaffected"}]}
    s = version_label(v)
    assert "≥ aabb 且 < ccdd" in s and "[git]" in s and "自 bbcc 起：不受影响" in s
    assert "≤ 5.10.*" in version_label({"version": "5.10.272", "lessThanOrEqual": "5.10.*", "status": "unaffected"})


def test_chinese_preferred_and_language_visible():
    raw = sample()
    raw["containers"]["cna"]["descriptions"].append({"lang": "zh-CN", "value": "中文描述"})
    r = normalize_record(raw)
    assert r["description"] == "中文描述" and r["language"] == "zh-CN"


def test_pagination_marks_omissions_and_preserves_text():
    raw = sample()
    raw["containers"]["cna"]["descriptions"] = [{"lang": "en", "value": "long sentence. " * 300}]
    r = normalize_record(raw)
    pages = make_pages(r, RecordResult(raw, "Test", time.time()), 2)
    assert len(pages) == 2 and all(p["omitted"] for p in pages)
    assert "仅发送前 2 页" in render_html(pages[0])
    full = make_pages(r, RecordResult(raw, "Test", time.time()), 50)
    joined = " ".join(b["body"] for p in full for b in p["blocks"])
    assert joined.count("long sentence.") == 300


def test_html_and_template_injection_are_literal():
    raw = sample()
    raw["containers"]["cna"]["title"] = '<img src="http://127.0.0.1/secret"> {{ 7*7 }}'
    r = normalize_record(raw)
    html = render_html(make_pages(r, RecordResult(raw, "Test", time.time()))[0])
    assert '<img src="http' not in html and "&lt;img" in html
    sent = Environment().from_string("{{ card_html | safe }}").render(card_html=html)
    assert "{{ 7*7 }}" in sent
    assert "default-src 'none'" in sent
