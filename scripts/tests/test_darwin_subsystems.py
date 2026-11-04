import copy
import json
from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from darwin_subsystems import load_ownership, project


class SubsystemTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads((ROOT/'docs/DARWIN_CONTRACT_CATALOG.json').read_text())
        self.ownership = load_ownership()

    def test_every_catalog_contract_has_exactly_one_owner(self):
        result = project(self.catalog, ownership=self.ownership)
        self.assertEqual(len(result['contracts']), len(self.catalog['contracts']))
        self.assertEqual(sum(result['counts_by_owner'].values()), len(self.catalog['contracts']))
        ledger = json.loads((ROOT/'docs/DARWIN_CONTRACT_LEDGER.json').read_text())
        self.assertEqual(set(self.ownership['ledger_owners']), {c['id'] for c in ledger['contracts']})

    def test_files_and_roles_have_no_conflicting_writers(self):
        files = {}
        for subsystem in self.ownership['subsystems']:
            role = ROOT/'.codex/agents'/f"{subsystem['id']}.toml"
            config = tomllib.loads(role.read_text())
            self.assertEqual(config['name'], subsystem['id'])
            self.assertTrue(config['description'] and config['developer_instructions'])
            for filename in subsystem['owned_files']:
                self.assertNotIn(filename, files)
                self.assertNotIn(filename, self.ownership['shared_files'])
                files[filename] = subsystem['id']
        mandatory = {'darwin_bsd_vfs', 'darwin_mach_vm', 'darwin_mach_ipc',
                     'darwin_pthread', 'darwin_objc', 'darwin_swift_transport'}
        configured = {role['id'] for role in self.ownership['subsystems']}
        self.assertTrue(mandatory <= configured)
        schema = json.loads((ROOT/'docs/DARWIN_AGENT_RESULT.schema.json').read_text())
        self.assertTrue(configured <= set(schema['properties']['subsystem']['enum']))

    def test_exact_selector_routes_without_causal_promotion(self):
        report = {'current_blocker': {'selector': 366, 'stop_reason': 'unsupported_pthread_capabilities'}}
        route = project(self.catalog, report)['attribution']
        self.assertEqual(route['owner_candidates'], ['darwin_pthread'])
        self.assertEqual(route['confidence'], 'static-routing')
        self.assertFalse(route['root_cause_verified'])
        self.assertIn('xnu.bsd.366', route['contract_ids'])
        report['current_blocker']['selector'] = None
        self.assertEqual(project(self.catalog, report)['attribution']['confidence'], 'unknown')

    def test_duplicate_and_invalid_owner_fail(self):
        bad = copy.deepcopy(self.catalog)
        bad['contracts'].append(copy.deepcopy(bad['contracts'][0]))
        with self.assertRaises(ValueError):
            project(bad)
        bad_ownership = copy.deepcopy(self.ownership)
        bad_ownership['catalog_rules']['bsd_default'] = 'nonexistent'
        with self.assertRaises(ValueError):
            project(self.catalog, ownership=bad_ownership)


if __name__ == '__main__':
    unittest.main()
