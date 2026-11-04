"""Owner projection and diagnostic routing; never starts or simulates agents."""
import argparse
from collections import Counter
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_ownership():
    return json.loads((ROOT / 'docs/DARWIN_SUBSYSTEM_OWNERS.json').read_text(encoding='utf-8'))


def owner_for(contract, ownership):
    if contract.get('ledger_id'):
        return ownership['ledger_owners'].get(contract['ledger_id'], 'main')
    rules = ownership['catalog_rules']
    family = contract.get('family', '')
    if contract['kind'] == 'mig':
        return rules['mig_vm_subsystem'] if contract['catalog_id'] == 'xnu-mig-mach_vm' else rules['other_mig_wire_contracts']
    if contract['kind'] == 'syscall':
        names = [contract['name']] + [v.get('name', '') for v in contract.get('variants', [])]
        if any(any(token in name for token in rules['bsd_pthread_tokens']) for name in names):
            return 'darwin_pthread'
        if any(name in rules['bsd_vm_names'] for name in names):
            return 'darwin_mach_vm'
        return rules['bsd_default']
    if family == 'Mach VM':
        return rules['mach_vm']
    if family == 'Mach scheduling':
        return rules['mach_scheduling']
    if family == 'Mach clocks':
        return rules['mach_clock']
    return 'darwin_mach_ipc' if contract['kind'] == 'mach-trap' else 'main'


def project(catalog, native_report=None, ownership=None):
    ownership = ownership or load_ownership()
    allowed = {'main'} | {s['id'] for s in ownership['subsystems']}
    seen, rows = set(), []
    for contract in catalog['contracts']:
        if contract['id'] in seen:
            raise ValueError('Duplicate contract attribution')
        seen.add(contract['id'])
        owner = owner_for(contract, ownership)
        if owner not in allowed:
            raise ValueError('Unknown subsystem owner')
        rows.append({'contract_id': contract['id'], 'catalog_id': contract['catalog_id'],
                     'owner': owner, 'unit': contract['kind']})
    blocker = (native_report or {}).get('current_blocker', {})
    selector = blocker.get('selector')
    matches = [c for c in catalog['contracts'] if type(selector) is int and c.get('selector_id') == selector]
    owners = sorted({owner_for(c, ownership) for c in matches})
    attribution = {'reason': blocker.get('stop_reason', 'no-native-report'),
                   'selector_id': selector, 'owner_candidates': owners or ['main'],
                   'confidence': 'static-routing' if owners else 'unknown',
                   'contract_ids': [c['id'] for c in matches],
                   'root_cause_verified': False}
    return {'schema_version': 1, 'contracts': rows,
            'counts_by_owner': dict(sorted(Counter(r['owner'] for r in rows).items())),
            'attribution': attribution,
            'candidate_sha256': (native_report or {}).get('candidate_sha256'),
            'probe_sha256': (native_report or {}).get('probe_sha256'),
            'limits': ['Owner routing is not a causal finding or semantic verification.',
                       'ABI/clock/shared loader and unresolved faults remain assigned to Main.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=ROOT/'docs/DARWIN_CONTRACT_CATALOG.json')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    read = lambda p: json.loads(p.read_text(encoding='utf-8-sig'))
    result = project(read(args.catalog), read(args.report) if args.report else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result['counts_by_owner']))
    print(json.dumps(result['attribution']))


if __name__ == '__main__':
    main()
