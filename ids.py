import re
from urllib.parse import unquote

# CVE sequences have at least four digits; the practical input cap prevents abuse.
ID_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])CVE-[0-9]{4}-[0-9]{4,19}(?![A-Za-z0-9_-])", re.I)
FULL_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z", re.I)


def extract_ids(text: str) -> list[str]:
    return list(dict.fromkeys(m.group().upper() for m in ID_PATTERN.finditer(unquote(text[:16384]))))


def validate_id(value: str) -> str:
    if not FULL_ID.fullmatch(value):
        raise ValueError("无效的 CVE 编号")
    return value.upper()


def record_url(cve_id: str) -> str:
    return f"https://www.cve.org/CVERecord?id={validate_id(cve_id)}"


def source_urls(cve_id: str) -> list[tuple[str, str]]:
    cve_id = validate_id(cve_id)
    _, year, number = cve_id.split("-")
    bucket = number[:-3] + "xxx"
    return [
        ("CVE Services", f"https://cveawg.mitre.org/api/cve/{cve_id}"),
        ("CVE 官方 GitHub", f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve_id}.json"),
    ]
