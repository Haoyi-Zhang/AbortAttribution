"""Typed metadata conformance for locally constructed ideal-model records."""
from copy import deepcopy
import unittest

from compiler_checker import _digest, verify
from compiler_replay import replay


def fixture():
    ctx = dict(id='local-type-test', roster=[1, 2], round=1, sender=1, recipient=2,
               group=dict(p=23, q=11, g=2), accept_by=0, deadline=1,
               read_bound=0, compute_bound=0, delivery_bound=0, service='bounded_delivery')
    def record(kind, actor, body):
        return dict(context=ctx['id'], kind=kind, actor=actor, signature_valid=True, time=0, body=body)
    return dict(context=ctx, records={
        'accept': record('accept', 1, dict(round=1, recipient=2, deadline=1)),
        'ready': record('ready', 0, dict(round=1))},
        closures={'final': dict(context=ctx['id'], cutoff=1, complete=True, records=['accept', 'ready'])})


NONOPENING = dict(kind='nonopening', context='local-type-test', actor=1,
                  accept='accept', ready='ready', closure='final')


def envelope(env):
    statement = dict(sender=1, recipient=2, round=1, tag=1, ciphertext='local-model-token')
    env['records']['envelope'] = dict(context=env['context']['id'], kind='envelope',
        actor=1, signature_valid=True, time=0,
        body=dict(statement=statement, entry_proof_valid=True, entry_proof_statement=_digest(statement)))


class TypedBodies(unittest.TestCase):
    def judges(self, env, cert, expected):
        self.assertEqual(verify(env, cert), expected)
        self.assertEqual(replay(env, cert), expected)

    def test_valid_integer_duty_and_readiness(self):
        self.judges(fixture(), NONOPENING, True)

    def test_wrong_types_do_not_activate_duty_or_readiness(self):
        for token, field, value in (('accept', 'round', True), ('accept', 'deadline', True),
                                    ('accept', 'recipient', 2.0), ('ready', 'round', True)):
            with self.subTest(token=token, field=field):
                env = fixture()
                env['records'][token]['body'][field] = value
                self.judges(env, NONOPENING, False)
        for token, value in (('accept', True), ('ready', False)):
            env = fixture()
            env['records'][token]['actor'] = value
            self.judges(env, NONOPENING, False)
        env = fixture()
        env['closures']['final']['cutoff'] = True
        self.judges(env, NONOPENING, False)

    def test_malformed_integer_metadata_retains_attribution(self):
        good = fixture()
        envelope(good)
        cert = dict(kind='bad_entry', context=good['context']['id'], actor=1, envelope='envelope')
        self.judges(good, cert, False)
        for field, value in (('sender', True), ('recipient', 2.0), ('round', True)):
            env = deepcopy(good)
            env['records']['envelope']['body']['statement'][field] = value
            env['records']['envelope']['body']['entry_proof_statement'] = _digest(
                env['records']['envelope']['body']['statement'])
            self.judges(env, cert, True)

    def test_complaint_accused_has_exact_integer_type(self):
        env = fixture()
        envelope(env)
        env['records']['complaint'] = dict(context=env['context']['id'], kind='complaint',
            actor=2, signature_valid=True, time=0, body=dict(envelope='envelope', accused=1,
            claim='base_relation_false', complaint_proof_valid=True,
            complaint_statement=_digest([env['context']['id'], 'envelope', 1, 2, 1])))
        cert = dict(kind='bad_message', context=env['context']['id'], actor=1,
                    envelope='envelope', complaint='complaint')
        self.judges(env, cert, True)
        env['records']['complaint']['body']['accused'] = True
        self.judges(env, cert, False)


if __name__ == '__main__':
    unittest.main()
