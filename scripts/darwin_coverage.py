"""Public, bounded coverage projection of the native Darwin diagnostic report.

This module never scans C++ or accepts new proof attestations. Native report-progress
owns evidence eligibility; this adapter checks consistency and preserves its scopes.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from urllib.parse import quote, urlsplit

STATES = ('implemented', 'partial', 'missing', 'unreviewed')
ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://github.com/ssilvestri15/openfruit'
SOURCE_REVISION = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()


def _text(value):
    if not isinstance(value, str):
        return ''
    # Report paths are never useful public prose. Drop strings containing private
    # absolute paths instead of attempting incomplete username redaction.
    if re.search(r'[A-Za-z]:[\\/]|\\\\|/Users/|/home/', value):
        return '[private path omitted]'
    return value


def _hash(value):
    return value if isinstance(value, str) and re.fullmatch(r'[a-fA-F0-9]{64}', value) else None


def _name(value):
    return _text(str(value).replace('\\', '/').rsplit('/', 1)[-1])


def _link(source):
    if not isinstance(source, str):
        return None
    url = urlsplit(source)
    if url.scheme == 'https' and url.netloc and not url.username and not url.password:
        return source if not url.query and not url.fragment else None
    path = PurePosixPath(source.replace('\\', '/'))
    if path.is_absolute() or '..' in path.parts or ':' in source:
        return None
    if not (ROOT / path).is_file():
        return None
    return REPOSITORY + '/blob/' + quote(SOURCE_REVISION, safe='') + '/' + quote(str(path), safe='/')


def _selector_key(number):
    domain = 'platform' if number == -2147483648 else 'arm-trap' if number in (-3, -4) else 'mach' if number < 0 else 'bsd'
    return f'{domain}:{number}'


def validate_catalog(catalog):
    if catalog.get('schema_version') != 1:
        raise ValueError('Unsupported catalog schema')
    catalogs = {c['id']: c for c in catalog['catalogs']}
    if len(catalogs) != len(catalog['catalogs']):
        raise ValueError('Duplicate catalog ID')
    seen, counts = set(), Counter()
    for row in catalog['contracts']:
        if not row.get('id') or row['id'] in seen or row['catalog_id'] not in catalogs:
            raise ValueError('Duplicate contract or unknown catalog')
        if not row.get('family') or row.get('kind') not in ('syscall', 'mach-trap', 'mig', 'scoped'):
            raise ValueError('Invalid contract family/kind')
        if 'selector_id' in row and (type(row['selector_id']) is not int or not -2147483648 <= row['selector_id'] <= 2147483647):
            raise ValueError('Selector must be a signed integer')
        seen.add(row['id']); counts[row['catalog_id']] += 1
    for key, item in catalogs.items():
        if type(item.get('denominator')) is not int or item['denominator'] != counts[key]:
            raise ValueError('Catalog denominator differs from rows')


def validate_native(report):
    if report.get('schema_version') != 1:
        raise ValueError('Unsupported native report schema')
    rows, selectors, summary = report['contracts'], report['selector_candidates'], report['summary']
    if type(summary.get('manifest_present')) is not bool:
        raise ValueError('Invalid native manifest presence')
    if type(summary.get('unresolved_selector_sites')) is not int or summary['unresolved_selector_sites'] < 0:
        raise ValueError('Invalid unresolved selector count')
    ledger = {}
    for row in rows:
        if not row.get('id') or row['id'] in ledger or row.get('implementation') not in STATES:
            raise ValueError('Invalid native scoped contract')
        proofs = []
        for proof in row.get('evidence', []):
            if proof.get('accepted') is not True:
                continue
            if (not _hash(report.get('candidate_sha256')) or not _hash(proof.get('candidate_sha256')) or
                    row['implementation'] in ('missing', 'unreviewed') or
                    proof.get('scope') != row.get('scope') or
                    proof.get('candidate_sha256') != report.get('candidate_sha256') or
                    proof.get('level') not in ('contract', 'propagation', 'original-path') or
                    proof.get('result') != 'pass' or not _hash(proof.get('sha256')) or
                    (proof['level'] == 'original-path' and (not _hash(report.get('probe_sha256')) or proof.get('probe_sha256') != report.get('probe_sha256')))):
                raise ValueError('Inconsistent native accepted proof')
            proofs.append(proof)
        if type(row.get('verified_scope')) is not bool or row['verified_scope'] != bool(proofs):
            raise ValueError('Native verification differs from accepted scopes')
        ledger[row['id']] = row
    counts = Counter(r['implementation'] for r in rows)
    expected = {'identified_scoped_contracts': len(rows), 'verified_scopes': sum(r['verified_scope'] for r in rows),
                'static_selector_candidates': len(selectors)}
    expected.update({state + '_scoped_contracts': counts[state] for state in STATES})
    for key, count in expected.items():
        if type(summary.get(key)) is not int or summary[key] != count:
            raise ValueError('Native aggregate differs from rows: ' + key)
    registry = {}
    for row in selectors:
        if row['id'] in registry or not re.fullmatch(r'(bsd|mach|platform|arm-trap):-?\d+', row['id']):
            raise ValueError('Invalid/duplicate selector key')
        if row['id'] != _selector_key(int(row['id'].split(':')[1])):
            raise ValueError('Selector domain differs from signed Darwin ID')
        if row.get('dispatch_registered') is not None and type(row.get('dispatch_registered')) is not bool:
            raise ValueError('Invalid dispatcher state')
        registry[row['id']] = row
    registered = sum(r.get('dispatch_registered') is True for r in selectors)
    if summary.get('registered_candidate_dispatches') != (registered if summary.get('manifest_present') else None):
        raise ValueError('Native dispatcher aggregate differs from rows')
    if not summary.get('manifest_present') and any(r.get('dispatch_registered') is not None for r in selectors):
        raise ValueError('Dispatcher rows require manifest')
    return ledger, registry


def _target_projection(report):
    requirements, targets = {}, []
    for target in report.get('target_requirements', []):
        if _name(target.get('target', '')) != 'swift-plugin-server':
            continue
        bound = (bool(_hash(report.get('candidate_sha256'))) and bool(_hash(report.get('probe_sha256'))) and report.get('command_probe_hash_bound') is True and
                 target.get('command_probe_hash_bound') is True and target.get('probe_target_identity_bound') is True)
        projected = {'target': 'swift-plugin-server', 'command_probe_hash_bound': bound,
                     'all_required_contracts_discovered': False, 'execution_verified': target.get('execution_verified') is True}
        for key in ('structural_required_images', 'potential_dependency_images', 'import_references', 'matched_observed_sites',
                    'unjoined_observed_sites', 'weak_symbol_references', 'nonweak_symbol_references', 'unknown_symbol_references', 'unparsed_trace_records'):
            if type(target.get(key)) is int and target[key] >= 0:
                projected[key] = target[key]
        components = []
        for component in target.get('components', []):
            sites = component.get('selector_sites', [])
            components.append({'component': _name(component.get('image', '')), 'dependency_requirement': _text(component.get('dependency_requirement')),
                               'static_selector_sites': len(sites), 'unknown_selector_sites': sum(type(s.get('selector_id')) is not int for s in sites),
                               'execution_verified': component.get('execution_verified') is True})
            for site in sites:
                number = site.get('selector_id')
                if type(number) is not int:
                    continue
                state = 'observed' if (bound and site.get('requirement') == 'observed-required' and site.get('observed_at_exact_static_pc') is True) else 'potential'
                if requirements.get(number) != 'observed':
                    requirements[number] = state
        projected['components'] = components
        targets.append(projected)
    return requirements, targets


def _compare(result, previous):
    if previous is None:
        return {'available': False, 'percentages_comparable': False}
    validate_catalog(previous)
    old = {r['id']: r for r in previous['contracts']}
    new = {r['id']: r for r in result['contracts']}
    old_catalogs = {c['id']: (c['revision'], c['denominator']) for c in previous['catalogs']}
    new_catalogs = {c['id']: (c['revision'], c['denominator']) for c in result['catalogs']}
    fields = ('implementation', 'verified_scope', 'verification_levels', 'requirement', 'dispatch_registered', 'scope', 'catalog_id', 'family')
    changed, regressions = [], []
    for key in sorted(old.keys() & new.keys()):
        def safe(value):
            if isinstance(value, str):
                return _text(value)
            if isinstance(value, list):
                return [safe(item) for item in value]
            if type(value) in (bool, int) or value is None:
                return value
            raise ValueError('Invalid previous state dimension')
        delta = {field: {'before': safe(old[key].get(field)), 'after': safe(new[key].get(field))} for field in fields if old[key].get(field) != new[key].get(field)}
        if delta:
            changed.append({'id': key, 'changes': delta})
        if old[key].get('verified_scope') and not new[key].get('verified_scope'):
            regressions.append({'id': key, 'reason': 'lost-verification'})
        if set(old[key].get('verification_levels', [])) - set(new[key].get('verification_levels', [])):
            regressions.append({'id': key, 'reason': 'lost-verification-level'})
        if old[key].get('implementation') == 'implemented' and new[key].get('implementation') != 'implemented':
            regressions.append({'id': key, 'reason': 'implementation-state-regressed'})
        if old[key].get('scope') != new[key].get('scope'):
            regressions.append({'id': key, 'reason': 'scope-changed-requires-review'})
    for key in sorted(old.keys() - new.keys()):
        if old[key].get('verified_scope'):
            regressions.append({'id': key, 'reason': 'verified-contract-removed'})
    catalog_changes = [{'catalog_id': key, 'before': old_catalogs.get(key), 'after': new_catalogs.get(key)}
                       for key in sorted(old_catalogs.keys() | new_catalogs.keys()) if old_catalogs.get(key) != new_catalogs.get(key)]
    return {'available': True, 'added_contracts': sorted(new.keys() - old.keys()), 'removed_contracts': sorted(old.keys() - new.keys()),
            'changed_contracts': changed, 'regressions': regressions, 'catalog_changes': catalog_changes,
            'percentages_comparable': not catalog_changes and not any(set(r['changes']) & {'scope', 'family', 'catalog_id'} for r in changed),
            'previous_candidate_sha256': previous['checkpoint'].get('candidate_sha256')}


def build_progress(catalog, native_report, previous=None):
    validate_catalog(catalog)
    ledger, registry = validate_native(native_report)
    required, targets = _target_projection(native_report)
    contracts, families = [], defaultdict(Counter)
    for item in catalog['contracts']:
        row = {key: _text(item[key]) for key in ('id', 'catalog_id', 'name', 'family', 'kind', 'scope') if key in item}
        for key in ('selector_id', 'ledger_id'):
            if key in item:
                row[key] = item[key]
        semantic = ledger.get(item.get('ledger_id'))
        if semantic and item.get('scope') != semantic.get('scope'):
            semantic = None  # historical catalog scope cannot inherit changed proof
        number = item.get('selector_id')
        dispatch = registry.get(_selector_key(number), {}) if type(number) is int else {}
        row.update(dispatch_registered=dispatch.get('dispatch_registered'), implementation=semantic['implementation'] if semantic else 'unreviewed',
                   verified_scope=semantic['verified_scope'] if semantic else False,
                   verification_levels=sorted({p['level'] for p in semantic.get('evidence', []) if p.get('accepted')}) if semantic else [],
                   requirement=required.get(number, 'unknown'))
        if semantic:
            for key in ('remaining', 'tests'):
                row[key] = _text(semantic.get(key))
        links = []
        sources = [item.get('source')]
        if semantic:
            for filename in re.findall(r'\b[a-zA-Z_0-9]+\.cpp\b', semantic.get('source', '')):
                sources.append('openfruit/windows/src/' + filename)
        for source in sources:
            link = _link(source)
            if link and link not in [v['url'] for v in links]:
                links.append({'label': _name(source), 'url': link})
        row['source_links'] = links
        row['test_links'] = []
        if semantic:
            for test_name in sorted(set(re.findall(r'\b[a-zA-Z_0-9]+_tests\b', semantic.get('tests', '')))):
                link = _link('openfruit/windows/tests/' + test_name + '.cpp')
                if link:
                    row['test_links'].append({'label': test_name, 'url': link})
        contracts.append(row)
        group = families[(row['catalog_id'], row['family'])]
        group['denominator'] += 1; group[row['implementation']] += 1; group[row['requirement']] += 1
        group['verified_scopes'] += int(row['verified_scope']); group['dispatch_registered'] += int(row['dispatch_registered'] is True)
    public_catalogs = []
    for item in catalog['catalogs']:
        record = {k: _text(item[k]) for k in ('id', 'title', 'revision', 'completeness')}
        record['denominator'] = item['denominator']
        record['sources'] = [{k: value for k, value in (('url', _link(s.get('url') or s.get('path'))), ('sha256', _hash(s.get('sha256'))), ('hash_encoding', _text(s.get('hash_encoding')))) if value}
                             for s in item.get('sources', [])]
        public_catalogs.append(record)
    checkpoint = {key: _hash(native_report.get(key)) for key in ('candidate_sha256', 'probe_sha256')}
    checkpoint['mode'] = 'historical-native-report' if checkpoint['candidate_sha256'] else 'seed-only'
    checkpoint['source_revision'] = SOURCE_REVISION
    checkpoint['scope'] = _text(native_report.get('scope'))
    checkpoint['input_hashes'] = [{'role': ('inventory', 'probe', 'command', 'ledger')[index] if len(native_report.get('inputs', [])) == 4 else 'ledger' if checkpoint['mode'] == 'seed-only' and len(native_report.get('inputs', [])) == 1 else 'unknown-input', 'sha256': _hash(source.get('sha256'))}
                                for index, source in enumerate(native_report.get('inputs', []))]
    blocker = {key: value for key, value in native_report.get('current_blocker', {}).items()
               if key in ('stop_reason', 'selector', 'interrupt', 'opcode', 'localization') and (value is None or type(value) in (str, int, bool))}
    blocker = {key: _text(value) if isinstance(value, str) else value for key, value in blocker.items()}
    result = {'schema_version': 1, 'catalogs': public_catalogs, 'contracts': contracts,
              'families': [{'catalog_id': key[0], 'family': key[1], **{field: counts[field] for field in ('denominator', *STATES, 'verified_scopes', 'dispatch_registered', 'observed', 'potential', 'unknown')}} for key, counts in sorted(families.items())],
              'checkpoint': checkpoint, 'target_requirements': targets, 'current_blocker': blocker,
              'native_overview': {key: native_report['summary'][key] for key in ('identified_scoped_contracts', 'implemented_scoped_contracts', 'partial_scoped_contracts', 'missing_scoped_contracts', 'unreviewed_scoped_contracts', 'verified_scopes', 'static_selector_candidates', 'unresolved_selector_sites', 'registered_candidate_dispatches', 'manifest_present') if key in native_report['summary']},
              'priorities': [{key: _text(p[key]) if isinstance(p[key], str) else p[key] for key in ('priority', 'contract', 'action') if key in p and type(p[key]) in (str, int)} for p in native_report.get('priorities', [])],
              'measurement_limits': [_text(s) for s in catalog.get('measurement_limits', []) + native_report.get('measurement_limits', [])]}
    result['measurement_limits'].append('Source links browse the specified repository revision; they are not source provenance proof for the historical native candidate.')
    from darwin_subsystems import project
    ownership = project(catalog, native_report)
    owner_by_id = {r['contract_id']: r['owner'] for r in ownership['contracts']}
    for row in result['contracts']:
        row['owner'] = owner_by_id[row['id']]
    result['subsystem_ownership'] = ownership['counts_by_owner']
    result['error_attribution'] = ownership['attribution']
    if previous is not None and 'checkpoint' not in previous:
        import copy
        previous_catalog = copy.deepcopy(catalog)
        previous_ledger = {r['id']: r for r in previous['contracts']}
        # New scopes must not enter the historical denominator retroactively.
        previous_catalog['contracts'] = [item for item in previous_catalog['contracts']
                                         if not item.get('ledger_id') or item['ledger_id'] in previous_ledger]
        for item in previous_catalog['contracts']:
            if item.get('ledger_id') in previous_ledger:
                item['scope'] = previous_ledger[item['ledger_id']]['scope']
        scoped_catalog = next((c for c in previous_catalog['catalogs']
                               if c['id'] == 'openfruit-reviewed-scopes'), None)
        if scoped_catalog:
            retained = {item.get('ledger_id') for item in previous_catalog['contracts']}
            for identifier, row in previous_ledger.items():
                if identifier not in retained:
                    previous_catalog['contracts'].append({
                        'id': 'scope.' + identifier, 'catalog_id': scoped_catalog['id'],
                        'ledger_id': identifier, 'name': identifier, 'kind': 'scoped',
                        'family': row.get('workgroup', row['family']), 'scope': row['scope']})
        for definition in previous_catalog['catalogs']:
            rows = [item for item in previous_catalog['contracts'] if item['catalog_id'] == definition['id']]
            definition['denominator'] = len(rows)
            if any(item.get('ledger_id') for item in rows):
                definition['revision'] = 'unknown-historical-catalog-revision'
                definition['sources'] = []
        previous = build_progress(previous_catalog, previous)
        result['measurement_limits'].append('Previous native report projected using current catalog; historical catalog revisions are unavailable.')
    result['comparison'] = _compare(result, previous)
    if previous and any('historical catalog revisions' in s for s in result['measurement_limits']):
        result['comparison']['percentages_comparable'] = False
    return result


def main():
    global SOURCE_REVISION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', required=True); parser.add_argument('--report', required=True)
    parser.add_argument('--previous'); parser.add_argument('--output', required=True)
    parser.add_argument('--source-revision', default=SOURCE_REVISION)
    args = parser.parse_args()
    SOURCE_REVISION = args.source_revision
    def read(path):
        return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    data = build_progress(read(args.catalog), read(args.report), read(args.previous) if args.previous else None)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
