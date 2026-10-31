"""Normalize CVE 5.x without inferring scores or ordering vendor versions."""
from urllib.parse import urlsplit


def text(value, limit=12000):
    if value is None:
        return ""
    value = str(value).replace("\x00", "").strip()
    return value if len(value) <= limit else value[:limit] + " … [字段过长，已截断]"


def objects(value):
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def mapping(value):
    return value if isinstance(value, dict) else {}


def description(values):
    values = objects(values)
    for prefix in ("zh", "en", ""):
        selected = [v for v in values if str(v.get("lang", "")).lower().startswith(prefix) and v.get("value")]
        if selected:
            return "\n\n".join(text(v["value"]) for v in selected), text(selected[0].get("lang", "unknown"), 30)
    return "官方记录暂未提供描述。", "unknown"


def safe_url(value):
    value = text(value, 2500)
    try:
        p = urlsplit(value)
        if p.scheme in {"https", "http"} and p.hostname and not p.username and not p.password:
            return value
    except ValueError:
        pass
    return ""


STATUS = {"affected": "受影响", "unaffected": "不受影响", "unknown": "状态未知"}


def version_label(version):
    start = text(version.get("version", "未注明"), 160)
    if "lessThan" in version:
        span = f"≥ {start} 且 < {text(version['lessThan'], 160)}"
    elif "lessThanOrEqual" in version:
        span = f"≥ {start} 且 ≤ {text(version['lessThanOrEqual'], 160)}"
    else:
        span = start
    kind = text(version.get("versionType", ""), 70)
    result = f"{STATUS.get(version.get('status'), '状态未知')} · {span}"
    if kind:
        result += f" [{kind}]"
    for change in objects(version.get("changes")):
        result += f"；自 {text(change.get('at'), 100)} 起：{STATUS.get(change.get('status'), '状态未知')}"
    return result


def normalize_record(raw):
    meta = raw.get("cveMetadata", {})
    containers = raw.get("containers", {})
    cna = containers.get("cna", {})
    state = text(meta.get("state", "UNKNOWN"), 40)
    desc, language = description(cna.get("rejectedReasons") if state == "REJECTED" else cna.get("descriptions"))
    provider = text(mapping(cna.get("providerMetadata")).get("shortName") or meta.get("assignerShortName") or "CNA", 120)
    scores, references, weaknesses, products, versions = [], [], [], [], []
    seen_refs, seen_scores = set(), set()
    for container in [cna] + objects(containers.get("adp")):
        source = text(mapping(container.get("providerMetadata")).get("shortName") or (provider if container is cna else "未注明 ADP"), 120)
        for metric in objects(container.get("metrics")):
            for key, label in [("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0")]:
                data = metric.get(key)
                if not isinstance(data, dict):
                    continue
                score = data.get("baseScore")
                if isinstance(score, bool) or not isinstance(score, (float, int)) or not 0 <= score <= 10:
                    continue
                vector = text(data.get("vectorString"), 200)
                identity = (source, label, score, vector)
                if identity in seen_scores:
                    continue
                seen_scores.add(identity)
                # Only a display color is derived; never invent an official severity.
                tone = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "neutral"
                scores.append({"score": f"{score:.1f}", "version": label, "source": source,
                               "severity": text(data.get("baseSeverity") or "未提供等级", 40),
                               "vector": vector, "tone": tone})
        for ref in objects(container.get("references")):
            url = safe_url(ref.get("url"))
            if url and url not in seen_refs:
                seen_refs.add(url)
                references.append({"url": url, "name": text(ref.get("name") or urlsplit(url).hostname, 120)})
        for problem in objects(container.get("problemTypes")):
            for item in objects(problem.get("descriptions")):
                value = text(item.get("cweId") or item.get("description"), 200)
                if value and value not in weaknesses:
                    weaknesses.append(value)
    for affected in objects(cna.get("affected")):
        vendor, product = text(affected.get("vendor"), 120), text(affected.get("product") or "未注明产品", 160)
        name = product if vendor in {product, "", "n/a"} else f"{vendor} / {product}"
        if name not in products:
            products.append(name)
        default = STATUS.get(affected.get("defaultStatus"), "未注明")
        versions.append({"product": name, "value": f"未被以下条目覆盖的版本：{default}", "heading": True})
        for version in objects(affected.get("versions")):
            versions.append({"product": name, "value": version_label(version), "heading": False})
    return {
        "id": text(meta.get("cveId"), 50), "state": state,
        "state_label": {"PUBLISHED": "已发布", "REJECTED": "已撤销", "RESERVED": "已保留"}.get(state, state),
        "title": text(cna.get("title") or ("此 CVE 记录已撤销" if state == "REJECTED" else "CVE 漏洞记录"), 220),
        "description": desc, "language": language, "provider": provider,
        "published": text(meta.get("datePublished") or "N/A", 40),
        "updated": text(meta.get("dateUpdated") or "N/A", 40),
        "scores": scores, "references": references, "weaknesses": weaknesses,
        "products": products, "versions": versions, "format": text(raw.get("dataVersion"), 20),
    }
