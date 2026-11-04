import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from darwin_coverage import build_progress


def inputs():
    scope = 'Task-owned bounded semantics'
    catalog = {'schema_version': 1, 'catalogs': [{'id': 'owned', 'title': 'Owned scopes', 'revision': 'abc', 'denominator': 2,
                'completeness': 'bounded', 'sources': [{'url': 'https://github.com/apple-oss-distributions/xnu', 'sha256': 'f' * 64, 'path': 'C:/private/input'}]}],
               'contracts': [{'id': 'scoped:one', 'catalog_id': 'owned', 'name': 'scope', 'family': 'Mach IPC', 'kind': 'scoped',
                              'ledger_id': 'one', 'scope': scope, 'source': 'openfruit/windows/src/darwin_progress.cpp'},
                             {'id': 'trap:-28', 'catalog_id': 'owned', 'name': 'task_self', 'family': 'Mach IPC', 'kind': 'mach-trap',
                              'selector_id': -28, 'source': 'https://github.com/apple-oss-distributions/xnu'}], 'measurement_limits': []}
    proof = {'accepted': True, 'candidate_sha256': 'a' * 64, 'probe_sha256': 'b' * 64, 'sha256': 'c' * 64, 'scope': scope,
             'level': 'contract', 'result': 'pass', 'artifact': 'C:/Users/private/secret.log'}
    report = {'schema_version': 1, 'candidate_sha256': 'a' * 64, 'probe_sha256': 'b' * 64, 'scope': 'bounded', 'command_probe_hash_bound': True,
              'inputs': [{'path': 'C:/Users/private/inventory', 'sha256': 'd' * 64}],
              'contracts': [{'id': 'one', 'scope': scope, 'implementation': 'partial', 'verified_scope': True, 'evidence': [proof],
                             'remaining': 'Additional APIs missing', 'source': 'darwin_progress.cpp', 'tests': 'owned tests', 'observed': {'private': 'secret'}}],
              'selector_candidates': [{'id': 'mach:-28', 'dispatch_registered': True}],
              'summary': {'identified_scoped_contracts': 1, 'partial_scoped_contracts': 1, 'implemented_scoped_contracts': 0,
                          'missing_scoped_contracts': 0, 'unreviewed_scoped_contracts': 0, 'verified_scopes': 1,
                          'static_selector_candidates': 1, 'registered_candidate_dispatches': 1, 'manifest_present': True},
              'target_requirements': [{'target': '/Xcode/usr/bin/swift-plugin-server', 'command_probe_hash_bound': True, 'probe_target_identity_bound': True,
                    'components': [{'image': '/Xcode/lib.dylib', 'dependency_requirement': 'structural-required', 'selector_sites': [
                        {'selector_id': -28, 'requirement': 'observed-required', 'observed_at_exact_static_pc': True, 'pc': 1234}]}]}],
              'priorities': [], 'current_blocker': {'pc': 1234, 'stop_reason': 'unsupported', 'selector': -28}, 'measurement_limits': []}
    report['summary']['unresolved_selector_sites'] = 0
    return catalog, report


class CoverageTests(unittest.TestCase):
    def test_dimensions_independent_and_public_projection(self):
        catalog, report = inputs()
        result = build_progress(catalog, report)
        semantic, trap = result['contracts']
        self.assertEqual(semantic['implementation'], 'partial')
        self.assertTrue(semantic['verified_scope'])
        self.assertIsNone(semantic['dispatch_registered'])
        self.assertEqual(trap['implementation'], 'unreviewed')
        self.assertFalse(trap['verified_scope'])
        self.assertTrue(trap['dispatch_registered'])
        self.assertEqual(trap['requirement'], 'observed')
        self.assertEqual(result['families'][0]['denominator'], 2)
        import json
        serialized = json.dumps(result)
        for private in ('C:/', 'secret', 'artifact', '"pc"', '/Xcode/'):
            self.assertNotIn(private, serialized)

    def test_target_identity_and_exact_site_required(self):
        for mutate in (
            lambda r: r.update(command_probe_hash_bound=False),
            lambda r: r['target_requirements'][0].update(probe_target_identity_bound=False),
            lambda r: r['target_requirements'][0]['components'][0]['selector_sites'][0].update(observed_at_exact_static_pc=False)):
            catalog, report = inputs(); mutate(report)
            self.assertEqual(build_progress(catalog, report)['contracts'][1]['requirement'], 'potential')
        catalog, report = inputs(); report['target_requirements'][0]['target'] = '/different/tool'
        self.assertEqual(build_progress(catalog, report)['contracts'][1]['requirement'], 'unknown')

    def test_malformed_counts_and_proofs_fail_closed(self):
        mutations = [lambda c, r: c['catalogs'][0].update(denominator=3),
                     lambda c, r: c['contracts'].append(copy.deepcopy(c['contracts'][0])),
                     lambda c, r: r['summary'].update(verified_scopes=0),
                     lambda c, r: r['summary'].update(registered_candidate_dispatches=0),
                     lambda c, r: r['contracts'][0]['evidence'][0].update(candidate_sha256='f' * 64),
                     lambda c, r: r['contracts'][0]['evidence'][0].update(scope='different'),
                     lambda c, r: r['contracts'][0].update(verified_scope=False)]
        for mutate in mutations:
            catalog, report = inputs(); mutate(catalog, report)
            with self.assertRaises(ValueError):
                build_progress(catalog, report)

    def test_catalog_scope_cannot_inherit_verification(self):
        catalog, report = inputs(); catalog['contracts'][0]['scope'] = 'new broader scope'
        row = build_progress(catalog, report)['contracts'][0]
        self.assertFalse(row['verified_scope']); self.assertEqual(row['implementation'], 'unreviewed')

    def test_checkpoint_losses_and_denominator_change(self):
        catalog, report = inputs(); previous = build_progress(catalog, report)
        report['contracts'][0]['evidence'] = []; report['contracts'][0]['verified_scope'] = False
        report['summary']['verified_scopes'] = 0
        catalog['catalogs'][0]['revision'] = 'new'
        result = build_progress(catalog, report, previous)
        self.assertFalse(result['comparison']['percentages_comparable'])
        self.assertIn({'id': 'scoped:one', 'reason': 'lost-verification'}, result['comparison']['regressions'])

    def test_seed_has_no_eligible_evidence(self):
        catalog, report = inputs(); report['candidate_sha256'] = ''; report['probe_sha256'] = ''
        report['contracts'][0]['evidence'] = []; report['contracts'][0]['verified_scope'] = False; report['summary']['verified_scopes'] = 0
        result = build_progress(catalog, report)
        self.assertIsNone(result['checkpoint']['candidate_sha256'])
        self.assertFalse(result['contracts'][0]['verified_scope'])

    def test_native_previous_not_claimed_catalog_comparable(self):
        catalog, report = inputs()
        result = build_progress(catalog, report, copy.deepcopy(report))
        self.assertTrue(result['comparison']['available'])
        self.assertFalse(result['comparison']['percentages_comparable'])

    def test_new_scope_does_not_enter_historical_denominator(self):
        catalog, report = inputs(); previous = copy.deepcopy(report)
        new = copy.deepcopy(catalog['contracts'][0])
        new.update(id='scoped:two', ledger_id='two')
        catalog['contracts'].append(new)
        catalog['catalogs'][0]['denominator'] += 1
        row = copy.deepcopy(report['contracts'][0]); row['id'] = 'two'
        report['contracts'].append(row)
        report['summary']['identified_scoped_contracts'] += 1
        report['summary']['partial_scoped_contracts'] += 1
        report['summary']['verified_scopes'] += 1
        result = build_progress(catalog, report, previous)
        self.assertEqual(result['comparison']['added_contracts'], ['scoped:two'])
        change = result['comparison']['catalog_changes'][0]
        self.assertEqual(change['before'][1], 2)
        self.assertEqual(change['after'][1], 3)
        self.assertFalse(result['comparison']['percentages_comparable'])

    def test_prior_scope_change_is_retained_in_native_comparison(self):
        catalog, report = inputs(); previous = copy.deepcopy(report)
        previous['contracts'][0]['scope'] = 'Prior narrower scope'
        previous['contracts'][0]['evidence'][0]['scope'] = 'Prior narrower scope'
        result = build_progress(catalog, report, previous)
        change = result['comparison']['changed_contracts'][0]['changes']['scope']
        self.assertEqual(change['before'], 'Prior narrower scope')
        self.assertEqual(change['after'], catalog['contracts'][0]['scope'])

    def test_partition_change_disables_percent_comparison(self):
        catalog, report = inputs(); previous = build_progress(catalog, report)
        catalog['contracts'][0]['family'] = 'new family'
        self.assertFalse(build_progress(catalog, report, previous)['comparison']['percentages_comparable'])

    def test_invalid_candidate_hash_cannot_grant_verification(self):
        for value in ('', 'a' * 63, 'z' * 64):
            catalog, report = inputs()
            report['candidate_sha256'] = value
            report['contracts'][0]['evidence'][0]['candidate_sha256'] = value
            with self.assertRaises(ValueError):
                build_progress(catalog, report)
        catalog, report = inputs()
        proof = report['contracts'][0]['evidence'][0]
        proof.update(level='original-path', probe_sha256='z' * 64)
        report['probe_sha256'] = 'z' * 64
        with self.assertRaises(ValueError):
            build_progress(catalog, report)

    def test_catalog_source_hash_encoding_and_repo_path_survive(self):
        catalog, report = inputs()
        catalog['catalogs'][0]['sources'] = [{'path': 'docs/DARWIN_CONTRACT_LEDGER.json', 'sha256': 'a' * 64,
                                             'hash_encoding': 'canonical sorted compact UTF-8 JSON'}]
        source = build_progress(catalog, report)['catalogs'][0]['sources'][0]
        self.assertTrue(source['url'].endswith('/docs/DARWIN_CONTRACT_LEDGER.json'))
        self.assertEqual(source['hash_encoding'], 'canonical sorted compact UTF-8 JSON')
        self.assertEqual(source['sha256'], 'a' * 64)

    def test_selector_range_is_signed_darwin_32_bit(self):
        for selector in (-2147483649, 2147483648):
            catalog, report = inputs(); catalog['contracts'][1]['selector_id'] = selector
            with self.assertRaises(ValueError):
                build_progress(catalog, report)

    def test_sources_reject_credentials_and_local_paths(self):
        for source in ('https://user:secret@example.com/code', 'https://example.com/code?token=secret', '../secret', 'C:/secret'):
            catalog, report = inputs(); catalog['contracts'][1]['source'] = source
            self.assertEqual(build_progress(catalog, report)['contracts'][1]['source_links'], [])


if __name__ == '__main__':
    unittest.main()
