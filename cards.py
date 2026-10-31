import math
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, StrictUndefined

from .ids import record_url


def units(value):
    return sum(2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in value)


def lines(value, width=72):
    return sum(max(1, math.ceil(units(line) / width)) for line in value.split("\n"))


def chunks(value, budget=550):
    # Break on whitespace when practical, but also support long unbroken/CJK text.
    while value:
        count, end = 0, 0
        for char in value:
            cost = 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
            if count + cost > budget:
                break
            count += cost
            end += 1
        end = max(1, end)
        if end < len(value):
            boundary = max(value.rfind("\n\n", 0, end), value.rfind(". ", 0, end), value.rfind("。", 0, end))
            if boundary <= end * 0.6:
                boundary = max(value.rfind("\n", 0, end), value.rfind(" ", 0, end))
            if boundary > end * 0.6:
                end = boundary + 1
        yield value[:end].strip()
        value = value[end:]


def make_pages(record, result, max_pages=3, theme="light", mode="paged"):
    blocks = []
    long_image = mode == "long"
    budget = 2500 if long_image else 550

    def add(label, body, kind="text"):
        for part in chunks(body, budget):
            blocks.append({"label": label, "body": part, "kind": kind,
                           "cost": 72 + lines(part) * 32})

    # Prefer human-readable version entries for the overview only.
    semver = [v for v in record["versions"] if "[git]" not in v["value"]]
    desc_chunks = list(chunks(record["description"], budget))
    if desc_chunks:
        add("撤销原因" if record["state"] == "REJECTED" else f"官方描述 · {record['language']}", desc_chunks[0])
    # Show a small literal version excerpt on the overview, not an invented fix list.
    preview = [v for v in semver if not v["heading"]][:3]
    if preview and record["state"] != "REJECTED" and not long_image:
        add("版本条目预览 · 完整范围见后页 / 原文", "\n".join(f"{v['product']}：{v['value']}" for v in preview), "versions")
    overview_count = len(blocks)
    for part in desc_chunks[1:]:
        add("官方描述 · 续", part)
    if record["weaknesses"]:
        add("弱点分类 · 官方记录", "\n".join(record["weaknesses"]), "versions")
    for score in record["scores"]:
        add(f"评分明细 · {score['source']} · CVSS {score['version']}",
            f"{score['score']} / {score['severity']}\n{score['vector']}", "versions")
    if record["versions"]:
        add("版本范围阅读说明", "以下保留官方状态与边界，不自动推断所有分支的修复版本。通配符及 Git 范围按原文展示；各产品块的默认状态只适用于该块未覆盖的版本。", "note")
    # Keep each product block and its defaultStatus together; never move defaults across blocks.
    for version in record["versions"]:
        add(("产品块 · " if version["heading"] else "版本 · ") + version["product"], version["value"], "versions")
    for ref in record["references"]:
        add("参考 · " + ref["name"], ref["url"], "reference")

    pages, current, cost = [], [], 0
    for index, block in enumerate(blocks):
        capacity = 11000 if long_image else (900 if not pages else 1140)
        # The overview is intentionally a concise card, with a clean page break.
        if current and (cost + block["cost"] > capacity or (not long_image and index == overview_count)):
            pages.append(current)
            current, cost = [], 0
        current.append(block)
        cost += block["cost"]
    if current:
        pages.append(current)
    total_pages = len(pages)
    visible = pages if long_image else pages[:max_pages]
    omitted = not long_image and total_pages > max_pages
    fetched = datetime.fromtimestamp(result.fetched_at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    base = {
        "record": record, "source": result.source, "fetched": fetched, "cached": result.cached,
        "url": record_url(record["id"]), "theme": "dark" if theme == "dark" else "light",
        "omitted": omitted, "total_pages": total_pages, "page_count": len(visible),
        "tone": record["scores"][0]["tone"] if record["scores"] and record["state"] == "PUBLISHED" else "neutral",
    }
    return [{**base, "page": i + 1, "blocks": blocks} for i, blocks in enumerate(visible)]


ENV = Environment(autoescape=True, undefined=StrictUndefined)
TEMPLATE_PATH = Path(__file__).parent / "templates" / "card.html"


def render_html(page):
    # The remote renderer receives already escaped static HTML and no external assets.
    return ENV.from_string(TEMPLATE_PATH.read_text(encoding="utf-8")).render(**page)


def plain_summary(record):
    scores = "；".join(f"{s['score']}（CVSS {s['version']}，{s['source']}）" for s in record["scores"][:3]) or "未提供"
    desc = record["description"]
    if len(desc) > 800:
        desc = desc[:800] + "…（描述已截断，完整内容见原文）"
    return f"{record['id']} · {record['state_label']}\n{record['title']}\n评分：{scores}\n{desc}\n{record_url(record['id'])}"
