"""JSON-based renderer matching the approved webpage layout; no browser scraping."""
from pathlib import Path
from jinja2 import Environment, StrictUndefined
from .records import normalize_record, objects, mapping, text, safe_url, description

ENV = Environment(autoescape=True, undefined=StrictUndefined)


def document(raw):
    record = normalize_record(raw)
    panels = []
    containers = raw['containers']
    for index, container in enumerate([containers['cna']] + objects(containers.get('adp'))):
        name = text(mapping(container.get('providerMetadata')).get('shortName') or record['provider'])
        # Display names for the verified sample CNAs; unknown providers keep their own name.
        display = {'Linux':'kernel.org','redhat':'Red Hat, Inc.'}.get(name, name)
        local = normalize_record({'cveMetadata': raw['cveMetadata'], 'containers': {'cna': container}})
        products = []
        for item in objects(container.get('affected')):
            groups = []
            for status in ('affected', 'unaffected', 'unknown'):
                versions = []
                for version in objects(item.get('versions')):
                    if version.get('status', 'unknown') != status:
                        continue
                    versions.append({
                        'start': text(version.get('version') or 'Not specified'),
                        'end': text(version.get('lessThan') or version.get('lessThanOrEqual')),
                        'relation': 'before' if 'lessThan' in version else 'through',
                        'kind': text(version.get('versionType')),
                        'changes': objects(version.get('changes')),
                    })
                if versions:
                    groups.append({'status':status, 'versions':versions})
            products.append({'vendor':text(item.get('vendor')), 'product':text(item.get('product')),
                             'package':text(item.get('packageName')), 'default':text(item.get('defaultStatus') or 'Not specified'),
                             'groups':groups, 'total':len(objects(item.get('versions'))),
                             'platforms':item.get('platforms') if isinstance(item.get('platforms'),list) else []})
        panels.append({'name':('CNA: '+display) if index == 0 else ('CVE Program' if name == 'CVE' else 'ADP: '+display),
                       'program':index > 0 and name == 'CVE', 'primary':index==0,
                       'description':local['description'] if container.get('descriptions') or container.get('rejectedReasons') else '',
                       'title':text(container.get('title')), 'updated':text(mapping(container.get('providerMetadata')).get('dateUpdated') or record['updated'])[:10],
                       'scores':local['scores'], 'weaknesses':local['weaknesses'], 'products':products,
                       'references':local['references'],
                       'credits':[text(x.get('value')) for x in objects(container.get('credits'))],
                       'solutions':[text(x.get('value')) for x in objects(container.get('solutions'))],
                       'workarounds':[text(x.get('value')) for x in objects(container.get('workarounds'))]})
    fallback = bool(raw.get('_kev_fallback'))
    if fallback:
        panels[0]['name'] = 'Source: CISA KEV'
    return {'record':record, 'panels':panels, 'kev_fallback':fallback}


def render_official(raw):
    template = Path(__file__).parent / 'templates' / 'official.html'
    return ENV.from_string(template.read_text(encoding='utf-8')).render(**document(raw))

def kev_record(entry, state="UNKNOWN"):
    cid = entry['cveID']
    if state not in {'RESERVED', 'UNKNOWN'}:
        raise ValueError('KEV fallback requires RESERVED or UNKNOWN state')
    return {'_kev_fallback': True, 'cveMetadata': {'cveId': cid, 'state': state},
            'containers': {'cna': {'providerMetadata': {'shortName': 'CISA KEV'},
                'title': entry.get('vulnerabilityName', ''),
                'descriptions': [{'lang': 'en', 'value': entry.get('shortDescription', '')}],
                'solutions': [{'lang': 'en', 'value': entry.get('requiredAction', '')}]}}}

def reserved_record(raw):
    import copy
    result = copy.deepcopy(raw)
    result['containers'] = {'cna': {
        'providerMetadata': {'shortName': result['cveMetadata'].get('assignerShortName') or 'N/A'},
        'title': 'CVE record reserved',
        'descriptions': [{'lang': 'en', 'value': 'This ID has been reserved by a CVE Numbering Authority (CNA). Details are not yet public.'}]
    }}
    return result
