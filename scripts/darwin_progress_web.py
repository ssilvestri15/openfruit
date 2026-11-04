"""Render the reviewed Darwin diagnostic projection; never infer runtime correctness."""
from __future__ import annotations

import argparse
from collections import Counter
from html import escape
import json
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

STATES = ("implemented", "partial", "missing", "unreviewed")
COLORS = dict(zip(STATES, ("#39b980", "#dfac42", "#d96973", "#65758d")))


def safe_url(value):
    if not isinstance(value, str) or any(ord(c) < 33 for c in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        parsed.port
    except ValueError:
        return None
    return value


def validate(progress):
    """Reject inconsistent denominators before writing any output."""
    if progress.get("schema_version") != 1:
        raise ValueError("Unsupported progress schema")
    catalogs = {c["id"]: c for c in progress["catalogs"]}
    if len(catalogs) != len(progress["catalogs"]):
        raise ValueError("Duplicate catalog IDs")
    rows = progress["contracts"]
    if len({r["id"] for r in rows}) != len(rows):
        raise ValueError("Duplicate contract IDs")
    grouped = {}
    for row in rows:
        if row["catalog_id"] not in catalogs or row["implementation"] not in STATES:
            raise ValueError("Unknown catalog or implementation state")
        if type(row["verified_scope"]) is not bool or type(row["dispatch_registered"]) not in (bool, type(None)):
            raise ValueError("Invalid independent coverage dimensions")
        if row["requirement"] not in ("observed", "potential", "unknown"):
            raise ValueError("Unknown requirement status")
        grouped.setdefault((row["catalog_id"], row["family"]), []).append(row)
    counts = Counter(r["catalog_id"] for r in rows)
    for cid, catalog in catalogs.items():
        if type(catalog["denominator"]) is not int or catalog["denominator"] != counts[cid]:
            raise ValueError(f"Catalog denominator mismatch: {cid}")
    supplied = {(f["catalog_id"], f["family"]): f for f in progress["families"]}
    if len(supplied) != len(progress["families"]) or set(supplied) != set(grouped):
        raise ValueError("Family membership mismatch")
    for key, members in grouped.items():
        expected = Counter(r["implementation"] for r in members)
        expected.update(Counter(r["requirement"] for r in members))
        expected["denominator"] = len(members)
        expected["verified_scopes"] = sum(r["verified_scope"] for r in members)
        expected["dispatch_registered"] = sum(r["dispatch_registered"] is True for r in members)
        for field in (*STATES, "observed", "potential", "unknown", "denominator", "verified_scopes", "dispatch_registered"):
            if type(supplied[key].get(field)) is not int or supplied[key][field] != expected[field]:
                raise ValueError(f"Family count mismatch: {key}/{field}")
    return grouped


def percent(count, denominator):
    return f"{100 * count / denominator:.1f}%" if denominator else "n/a"


def metric(count, denominator):
    return f"{count}/{denominator} ({percent(count, denominator)})"


def treemap(groups, x, y, width, height):
    """Balanced slice-and-dice layout; rectangle area equals family denominator."""
    if not groups:
        return []
    if len(groups) == 1:
        return [(groups[0], x, y, width, height)]
    total = sum(len(rows) for _, rows in groups)
    split, subtotal = 1, len(groups[0][1])
    while split < len(groups) - 1 and subtotal < total / 2:
        subtotal += len(groups[split][1])
        split += 1
    ratio = subtotal / total
    if width >= height:
        return treemap(groups[:split], x, y, width * ratio, height) + treemap(groups[split:], x + width * ratio, y, width * (1-ratio), height)
    return treemap(groups[:split], x, y, width, height * ratio) + treemap(groups[split:], x, y + height * ratio, width, height * (1-ratio))


def svg_map(progress, grouped):
    panel_height = 340
    height = 90 + max(1, len(progress["catalogs"])) * panel_height
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 {height}" role="img" aria-labelledby="title desc">',
             '<title id="title">Darwin bounded catalog coverage</title><desc id="desc">Each tile is one contract. Color describes implementation review; a white dot marks verification within the exact ledger scope.</desc>', '<g font-family="sans-serif">',
             f'<rect width="1000" height="{height}" fill="#101827"/>']
    for i, (state, color) in enumerate(COLORS.items()):
        parts.append(f'<rect x="{16+i*240}" y="15" width="12" height="12" fill="{color}"/><text x="{34+i*240}" y="26" fill="#fff" font-size="14">{state}</text>')
    parts.append('<text x="16" y="52" fill="#ced8e7" font-size="13">White dot: verified scope. Family area: bounded contract count. No overall Darwin completion percentage.</text>')
    for index, catalog in enumerate(progress["catalogs"]):
        top = 75 + index * panel_height
        parts.append(f'<text x="16" y="{top+18}" fill="#fff" font-size="16">{escape(str(catalog["title"]))}: {catalog["denominator"]} cataloged contracts</text>')
        groups = sorted(((key, rows) for key, rows in grouped.items() if key[0] == catalog["id"]), key=lambda pair: (-len(pair[1]), pair[0][1]))
        for (key, rows), x, y, w, h in treemap(groups, 16, top + 28, 968, 290):
            parts.append(f'<g><title>{escape(str(key[1]))}: {len(rows)} contracts</title>')
            columns = max(1, math.ceil(math.sqrt(len(rows)*w/max(h-20, 1))))
            gridrows = math.ceil(len(rows)/columns)
            cw, ch = w/columns, max(h-20, 1)/gridrows
            for n, row in enumerate(rows):
                cx, cy = x + (n % columns)*cw, y + 20 + (n//columns)*ch
                title = f'{row["name"]}: {row["implementation"]}; verified scope={row["verified_scope"]}; target={row["requirement"]}'
                parts.append(f'<rect x="{cx:.2f}" y="{cy:.2f}" width="{max(cw-.6, .1):.2f}" height="{max(ch-.6, .1):.2f}" fill="{COLORS[row["implementation"]]}"><title>{escape(title)}</title></rect>')
                if row["verified_scope"]:
                    parts.append(f'<circle cx="{cx+cw/2:.2f}" cy="{cy+ch/2:.2f}" r="{min(cw, ch)*.16:.2f}" fill="#fff"/>')
            parts.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" fill="none" stroke="#101827" stroke-width="2"/>')
            if w > 50 and h > 30:
                label = str(key[1])[:max(3, int(w/7)-1)]
                parts.append(f'<text x="{x+3:.2f}" y="{y+14:.2f}" fill="#fff" font-size="11">{escape(label)}</text>')
            parts.append('</g>')
    return '\n'.join(parts + ['</g></svg>'])


def badge(label, count, denominator):
    value = metric(count, denominator)
    left, right = max(90, 7*len(label)+12), 7*len(value)+12
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{left+right}" height="24" role="img" aria-label="{escape(label)}: {escape(value)}">'
            f'<rect width="{left}" height="24" fill="#354256"/><rect x="{left}" width="{right}" height="24" fill="#246956"/>'
            f'<g fill="white" font-family="sans-serif" font-size="11" text-anchor="middle"><text x="{left/2}" y="16">{escape(label)}</text><text x="{left+right/2}" y="16">{escape(value)}</text></g></svg>')


def links(items):
    result = []
    for item in items or []:
        if isinstance(item, dict):
            label = str(item.get("label", item.get("name", "source")))
            url = safe_url(item.get("url"))
            result.append(f'<a href="{escape(url)}" rel="noopener noreferrer">{escape(label)}</a>' if url else escape(label))
        else:
            result.append(escape(str(item)))
    return '<br>'.join(result)


def detail(value):
    return escape(json.dumps(value, ensure_ascii=False, indent=2))


def html_page(progress):
    family_rows = []
    for f in progress["families"]:
        d = f["denominator"]
        members = [r for r in progress["contracts"] if r["catalog_id"] == f["catalog_id"] and r["family"] == f["family"]]
        dispatch_metric = metric(f["dispatch_registered"], d) if any(r["dispatch_registered"] is not None for r in members) else "unknown / not applicable"
        cells = [escape(str(f["catalog_id"])), escape(str(f["family"])), str(d), metric(f["implemented"], d), str(f["partial"]), str(f["missing"]), str(f["unreviewed"]), metric(f["verified_scopes"], d), dispatch_metric, str(f["observed"]), str(f["potential"]), str(f["unknown"])]
        family_rows.append('<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>')
    contract_rows = []
    for row in progress["contracts"]:
        scope = escape(str(row.get("scope", "")))
        remaining = row.get("remaining", "")
        if remaining:
            scope += '<br><small>Remaining: ' + escape(str(remaining)) + '</small>'
        tests = row.get("tests", [])
        if isinstance(tests, str):
            tests = [tests]
        test_content = links(tests)
        if row.get("test_links"):
            test_content += '<br>' + links(row['test_links'])
        name = escape(str(row['name'])) + '<br><small>' + escape(str(row['id'])) + '</small>'
        cells = [name, escape(str(row["catalog_id"])), escape(str(row["family"])), escape(str(row["kind"])), row["implementation"], "yes" if row["verified_scope"] else "no", escape(', '.join(row.get("verification_levels", []))), "unknown / not applicable" if row["dispatch_registered"] is None else ("yes" if row["dispatch_registered"] else "no"), row["requirement"], scope, links(row.get("source_links", [])), test_content]
        cells.append(escape(str(row.get('owner', 'main'))))
        contract_rows.append(f'<tr data-state="{row["implementation"]}" data-requirement="{row["requirement"]}">' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>')
    catalogs = ''.join(f'<li><strong>{escape(str(c["title"]))}</strong>: {c["denominator"]} rows; revision <code>{escape(str(c["revision"]))}</code>; {escape(str(c["completeness"]))}. {links(c.get("sources", []))}</li>' for c in progress["catalogs"])
    sections = ''.join(f'<section><h2>{title}</h2><pre>{detail(progress.get(key))}</pre></section>' for title, key in [("Native diagnostic inventory", "native_overview"), ("Current blocker", "current_blocker"), ("Subsystem responsibility", "subsystem_ownership"), ("Error routing (not causal proof)", "error_attribution"), ("Next priorities", "priorities"), ("Target requirements: swift-plugin-server", "target_requirements"), ("Checkpoint identity", "checkpoint"), ("Checkpoint comparison", "comparison"), ("Measurement limits", "measurement_limits")])
    mode = escape(str(progress.get('checkpoint', {}).get('mode', 'unspecified')))
    summaries = []
    for catalog in progress['catalogs']:
        members = [r for r in progress['contracts'] if r['catalog_id'] == catalog['id']]
        if members and all(r['kind'] == 'scoped' for r in members):
            d = catalog['denominator']
            summaries.append(f'<div class="card"><h2>{escape(str(catalog["title"]))}</h2><p>Implemented within scope: <strong>{metric(sum(r["implementation"] == "implemented" for r in members), d)}</strong></p><p>Verified scopes: <strong>{metric(sum(r["verified_scope"] for r in members), d)}</strong></p><small>This denominator contains reviewed ledger scopes, not all Darwin APIs.</small></div>')
    overview = progress.get('native_overview', {})
    inventory_counts = [("static_selector_candidates", "Static selector candidates"), ("unresolved_selector_sites", "Unresolved selector sites"), ("registered_candidate_dispatches", "Registered dispatches")]
    count_text = ' · '.join(f'{label}: <strong>{escape(str(overview[key]))}</strong>' for key, label in inventory_counts if key in overview)
    top_overview = '<div class="cards">' + ''.join(summaries) + '</div>'
    if count_text:
        top_overview += '<p>' + count_text + '. These are inventory counts, not semantic verification.</p>'
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OPENFRUIT Darwin progress</title><style>
body{font:15px system-ui,sans-serif;background:#101827;color:#e2e8f0;margin:0;padding:24px}main{max-width:1400px;margin:auto}a{color:#80caff}h1,h2{color:white}img{width:100%;height:auto}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:8px;border-bottom:1px solid #354256;text-align:left;vertical-align:top}th{background:#1c293d}.scroll{overflow:auto}.map-scroll{max-height:700px;overflow:auto}.cards{display:flex;gap:16px;flex-wrap:wrap}.card{background:#1c293d;padding:16px;border-radius:8px}.card h2{margin-top:0}summary{cursor:pointer;padding:12px;background:#1c293d}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1c293d;padding:16px;border-radius:8px}input,select{margin:6px;padding:8px;background:#1c293d;color:white;border:1px solid #65758d}small{color:#b8c6da}li{margin:10px 0}.notice{border-left:4px solid #dfac42;padding:12px;background:#1c293d}</style></head><body><main>
<h1>OPENFRUIT Darwin progress</h1><p class="notice">This page measures bounded catalogs and reviewed contract scopes. Dispatcher registration, implementation review and verified semantics are independent. A verified scope does not prove the entire API or the original plugin works. Unreviewed entries are not known missing. The full Darwin denominator and undiscovered target requirements remain unknown.</p>
<p><strong>Checkpoint mode: ''' + mode + '''</strong>. Evidence applies only to its recorded candidate and exact scope.</p>
''' + top_overview + '''<p><a href="progress.json">Download exact progress data</a> · <a href="progress.svg">Standalone SVG</a></p><details><summary>Explore contract heatmap (implementation colors and verified scope markers)</summary><div class="map-scroll"><img src="progress.svg" alt="Contract heatmap grouped by catalog and family"></div></details>
<h2>Catalog denominators</h2><details><summary>Inspect bounded sources and catalog revisions</summary><ul>''' + catalogs + '''</ul></details><h2>Coverage by family</h2><div class="scroll"><table><thead><tr><th>Catalog</th><th>Family</th><th>Denominator</th><th>Implemented within scope</th><th>Partial</th><th>Missing</th><th>Unreviewed</th><th>Verified scopes</th><th>Dispatch registered</th><th>Observed</th><th>Potential</th><th>Unknown</th></tr></thead><tbody>''' + ''.join(family_rows) + '''</tbody></table></div>''' + sections + '''<h2>Contract inventory</h2><label>Search <input id="search" type="search" placeholder="Name, family, scope, source…"></label><label>Implementation <select id="state"><option value="">All</option><option>implemented</option><option>partial</option><option>missing</option><option>unreviewed</option></select></label><label>Target requirement <select id="requirement"><option value="">All</option><option>observed</option><option>potential</option><option>unknown</option></select></label><p id="result" aria-live="polite"></p><div class="scroll"><table id="contracts"><thead><tr><th>Contract</th><th>Catalog</th><th>Family</th><th>Kind</th><th>Implementation</th><th>Verified scope</th><th>Proof levels</th><th>Dispatch</th><th>Target requirement</th><th>Exact scope / remaining</th><th>Sources</th><th>Tests</th><th>Owner</th></tr></thead><tbody>''' + ''.join(contract_rows) + '''</tbody></table></div></main><script>
const rows=[...document.querySelectorAll('#contracts tbody tr')];function filter(){const query=document.getElementById('search').value.toLowerCase(),state=document.getElementById('state').value,requirement=document.getElementById('requirement').value;let count=0;for(const row of rows){row.hidden=!(row.textContent.toLowerCase().includes(query)&&(!state||row.dataset.state===state)&&(!requirement||row.dataset.requirement===requirement));if(!row.hidden)count++;}document.getElementById('result').textContent=count+' / '+rows.length+' cataloged contracts shown';}for(const id of ['search','state','requirement'])document.getElementById(id).addEventListener('input',filter);filter();
</script></body></html>\n'''


def render(progress, output_directory):
    grouped = validate(progress)
    outputs = {"progress.json": json.dumps(progress, ensure_ascii=False, indent=2) + '\n', "progress.svg": svg_map(progress, grouped), "index.html": html_page(progress)}
    slugs = set()
    for catalog in progress["catalogs"]:
        slug = re.sub(r"[^a-z0-9-]+", "-", catalog["id"].lower()).strip('-') or 'catalog'
        if slug in slugs:
            raise ValueError("Catalog badge filename collision")
        slugs.add(slug)
        rows = [r for r in progress["contracts"] if r["catalog_id"] == catalog["id"]]
        for dimension, count in [("implemented", sum(r["implementation"] == "implemented" for r in rows)), ("verified-scopes", sum(r["verified_scope"] for r in rows))]:
            outputs[f"badge-{slug}-{dimension}.svg"] = badge(f'{catalog["title"]} {dimension}', count, catalog["denominator"])
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    for name, contents in outputs.items():
        (output/name).write_text(contents, encoding="utf-8")
    return sorted(outputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        files = render(json.loads(args.input.read_text(encoding='utf-8')), args.output)
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(f'Generated {len(files)} static files in {args.output}')


if __name__ == '__main__':
    main()
