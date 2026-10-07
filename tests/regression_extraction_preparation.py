"""Bounded public extraction fixtures; independent literal outputs and replay."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import compiler_checker as checker
from compiler_replay import replay
from compiler_cases import fixture, FAULTS


def refresh(env):
    for snap in env['closures'].values():
        snap['records'] = sorted(name for name, row in env['records'].items()
                                 if row.get('context') == env['context']['id']
                                 and type(row.get('time')) is int
                                 and row['time'] <= snap['cutoff'])


def certificate(env, kind, **refs):
    return dict(kind=kind, context=env['context']['id'], actor=2, **refs)


def fixtures():
    rows = []
    # Literal rule expectations, not computed by the candidate or historical code.
    for fault in FAULTS:
        env = fixture(5, 2, 3, fault)['public']
        expected = {'malformed_entry': [certificate(env, 'bad_entry', envelope='envelope')],
                    'invalid_message': [certificate(env, 'bad_message', envelope='envelope', complaint='complaint')],
                    'missing_bounded': [certificate(env, 'nonopening', accept='accept', ready='ready', closure='final')]}.get(fault, [])
        rows.append((fault, env, expected))

    for label in ('late', 'late-censorable', 'late-ready', 'late-malformed',
                  'duplicate-accept', 'truncated', 'multiple-ready-closure',
                  'multiple-complaints', 'foreign-complaint', 'unsigned-complaint',
                  'wrong-statement', 'complaint-before-envelope', 'complaint-at-D',
                  'complaint-at-D-plus-1', 'irrelevant-records', 'renamed-envelope'):
        missing = label in ('duplicate-accept', 'truncated', 'multiple-ready-closure')
        env = fixture(5, 2, 3, 'missing_bounded' if missing else 'invalid_message')['public']
        expected = [certificate(env, 'nonopening', accept='accept', ready='ready', closure='final')] if missing else [certificate(env, 'bad_message', envelope='envelope', complaint='complaint')]
        if label.startswith('late'):
            env = fixture(5, 2, 3, 'malformed_entry' if label == 'late-malformed' else 'honest_valid')['public']
            env['records']['envelope']['time'] = 13
            expected = [certificate(env, 'nonopening', accept='accept', ready='ready', closure='final')]
            if label == 'late-censorable':
                env['context']['service'] = 'censorable'; expected = []
            elif label == 'late-ready':
                env['records']['ready']['time'] = 7; expected = []
            elif label == 'late-malformed':
                expected.insert(0, certificate(env, 'bad_entry', envelope='envelope'))
        elif label == 'duplicate-accept':
            env['records']['accept2'] = deepcopy(env['records']['accept']); expected = []
        elif label == 'multiple-ready-closure':
            env['records']['A-ready'] = deepcopy(env['records']['ready'])
            env['closures']['A-close'] = deepcopy(env['closures']['final'])
            expected = [certificate(env, 'nonopening', accept='accept', ready='A-ready', closure='A-close')]
        elif label == 'multiple-complaints':
            env['records']['A-complaint'] = deepcopy(env['records']['complaint'])
            expected[0]['complaint'] = 'A-complaint'
        elif label in ('foreign-complaint', 'unsigned-complaint', 'wrong-statement', 'complaint-before-envelope'):
            complaint = env['records']['complaint']
            if label == 'foreign-complaint': complaint['context'] = 'foreign'
            if label == 'unsigned-complaint': complaint['signature_valid'] = False
            if label == 'wrong-statement': complaint['body']['complaint_statement'] = '0'*64
            if label == 'complaint-before-envelope': complaint['time'] = 3
            expected = []
        elif label.startswith('complaint-at-D'):
            env['records']['complaint']['time'] = 12 if label == 'complaint-at-D' else 13
            if label.endswith('plus-1'): expected = []
        elif label == 'irrelevant-records':
            for i in range(12):
                env['records'][f'A-noise-{i:02}'] = dict(context='foreign', kind='complaint', actor=2,
                                                       time=0, signature_valid=False, body={})
        elif label == 'renamed-envelope':
            env['records']['X-envelope'] = env['records'].pop('envelope')
            body = env['records']['complaint']['body']
            body['envelope'] = 'X-envelope'
            # Test-local canonical digest from the public statement specification.
            import hashlib, json
            body['complaint_statement'] = hashlib.sha256(json.dumps(
                [env['context']['id'], 'X-envelope', 2, 3, 3],
                sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
            expected[0]['envelope'] = 'X-envelope'
        refresh(env)
        if label == 'truncated':
            env['closures']['final']['records'].remove('ready'); expected = []
        rows.append((label, env, expected))
    return rows


def snapshot():
    rows = []
    for label, env, expected in fixtures():
        actual = checker.extract(env)
        if actual != expected:
            raise AssertionError('literal extraction mismatch: '+label)
        checked = [[checker.verify(env, c), replay(env, c)] for c in actual]
        if any(pair != [True, True] for pair in checked):
            raise AssertionError('certificate rejected: '+label)
        rows.append(dict(label=label, environment=env, certificates=actual, checked=checked))
    return {'fixtures': rows}


class ExtractionTests(unittest.TestCase):
    def test_literal_full_certificates_and_independent_replay(self):
        self.assertEqual(len(snapshot()['fixtures']), 24)
        for label, env, expected in fixtures():
            self.assertEqual(checker.extract(env), checker.extract(deepcopy(env)))
            for cert in expected:
                for field in cert:
                    bad = deepcopy(cert)
                    bad[field] = 'changed' if field != 'actor' else True
                    with self.subTest(label=label, field=field):
                        self.assertFalse(checker.verify(env, bad))
                        self.assertFalse(replay(env, bad))
        self.assertEqual(checker.extract(None), [])
        env = fixtures()[0][1]; env['context']['group']['q'] = 4
        self.assertEqual(checker.extract(env), [])

    def test_selected_certificate_still_uses_standalone_judge(self):
        env = next(env for label, env, _ in fixtures() if label == 'irrelevant-records')
        with patch.object(checker, 'verify', wraps=checker.verify) as judge:
            result = checker.extract(env)
        self.assertEqual(len(result), 1)
        # One positive-content check and the retained, rejected omission probe.
        self.assertEqual(judge.call_count, 2)
        self.assertEqual(judge.call_args_list[0].args, (env, result[0]))
        self.assertEqual(judge.call_args_list[1].args[1]['kind'], 'nonopening')
        # Call-local state: editing a subsequent public complaint invalidates it.
        env['records']['complaint']['body']['complaint_proof_valid'] = False
        self.assertEqual(checker.extract(env), [])


if __name__ == '__main__':
    unittest.main()
