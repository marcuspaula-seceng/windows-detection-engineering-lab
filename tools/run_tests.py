#!/usr/bin/env python3
"""Run the fixtures against every Sigma rule in the project.

Each fixture declares:

    _expected    the expected verdict PER RULE -- what the rule was designed to do
    _malicious   ground truth -- whether the behaviour is what we want to catch
    _behaviour   behaviour identifier; several fixtures can describe the
                 same behaviour seen through different telemetry sources

The distinction between _expected and _malicious is deliberate. A rule can fail to catch
a malicious behaviour and still behave as declared -- that is a KNOWN false
negative, and it counts as one in the matrix.

Exits with code 1 if any verdict diverges from the declared one.

    python tools/run_tests.py
"""

import importlib.util
import io
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / 'sigma'
FIXTURES = ROOT / 'tests' / 'fixtures-synthetic.json'


def load_evaluator():
    spec = importlib.util.spec_from_file_location('sigma_eval', ROOT / 'tools' / 'sigma_eval.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rule_fields(blocks):
    """Telemetry fields the rule references.

    EventID is left out on purpose: it is a selector present in every Windows event,
    not telemetry that distinguishes one logsource from another.
    """
    fields = set()
    for block in blocks.values():
        items = block if isinstance(block, list) else [block]
        for item in items:
            for spec in item:
                name = spec.split('|')[0]
                if name != 'EventID':
                    fields.add(name)
    return fields


def in_scope(fixture, fields):
    """Does the fixture belong to this rule's telemetry?

    A process_creation rule does not "fail" by missing a 4698 event: it never sees it.
    Counting that as a false negative would make the metric meaningless.
    """
    return any(fixture.get(name) is not None for name in fields)


def classify(malicious, matched):
    if malicious and matched:
        return 'TP'
    if malicious and not matched:
        return 'FN'
    if not malicious and matched:
        return 'FP'
    return 'TN'


def main():
    evaluator = load_evaluator()
    fixtures = json.load(io.open(FIXTURES, encoding='utf-8'))
    rule_paths = sorted(RULES_DIR.glob('*.yml'))

    if not rule_paths:
        print('no rules found in', RULES_DIR)
        return 1

    rules = {}
    for path in rule_paths:
        rule = yaml.safe_load(io.open(path, encoding='utf-8'))
        detection = dict(rule['detection'])
        condition = detection.pop('condition')
        rules[path.stem] = {
            'meta': rule,
            'condition': condition,
            'blocks': detection,
            'fields': rule_fields(detection),
        }

    print('RULES')
    for stem, rule in rules.items():
        meta = rule['meta']
        print(f"  {stem}")
        print(f"      {meta['title']}")
        print(f"      logsource={meta['logsource']}  level={meta.get('level')}  "
              f"status={meta.get('status')}")

    failures = 0
    results = {stem: [] for stem in rules}
    per_behaviour = {}

    print('\nMATRIX')
    header = f"  {'fixture':<44} {'truth':<7} " + ' '.join(f'{s[:26]:<26}' for s in rules)
    print(header)
    print('  ' + '-' * (len(header) - 2))

    for fixture in fixtures:
        truth = 'malicious' if fixture['_malicious'] else 'benign'
        cells = []
        behaviour = per_behaviour.setdefault(
            fixture['_behaviour'], {'malicious': fixture['_malicious'], 'detected': False})

        for stem, rule in rules.items():
            matched = evaluator.resolve_condition(rule['condition'], rule['blocks'], fixture)
            got = 'MATCH' if matched else 'NO MATCH'
            expected = fixture['_expected'][stem]
            verdict = 'PASS' if got == expected else 'FAIL'
            failures += verdict == 'FAIL'
            outcome = classify(fixture['_malicious'], matched)
            results[stem].append((outcome, in_scope(fixture, rule['fields'])))
            behaviour['detected'] = behaviour['detected'] or matched
            cells.append(f'{verdict} {outcome:<3} exp={expected:<9}')

        print(f"  {fixture['_fixture'][:43]:<44} {truth:<7} " + ' '.join(cells))

    print('\nPER-RULE SCORE')
    for stem, outcomes in results.items():
        scoped = [outcome for outcome, scope in outcomes if scope]
        counts = {key: scoped.count(key) for key in ('TP', 'TN', 'FP', 'FN')}
        skipped = len(outcomes) - len(scoped)
        print(f"  {stem}")
        print(f"      in scope for its telemetry: {len(scoped)} of {len(outcomes)} fixtures")
        print(f"      TP={counts['TP']}  TN={counts['TN']}  "
              f"FP={counts['FP']}  FN={counts['FN']}")
        if skipped:
            print(f"      {skipped} fixtures from another telemetry source, not counted")

    malicious_behaviours = {b: v for b, v in per_behaviour.items() if v['malicious']}
    covered = sum(1 for v in malicious_behaviours.values() if v['detected'])
    print('\nCOMBINED COVERAGE (by behaviour, not by event)')
    print(f"  malicious behaviours       : {len(malicious_behaviours)}")
    print(f"  detected by some rule      : {covered}")
    for name, value in sorted(malicious_behaviours.items()):
        if not value['detected']:
            print(f"      NOT DETECTED: {name}")

    benign_behaviours = {b: v for b, v in per_behaviour.items() if not v['malicious']}
    noisy = [b for b, v in benign_behaviours.items() if v['detected']]
    print(f"  benign behaviours          : {len(benign_behaviours)}   "
          f"alerting: {len(noisy)}")
    for name in noisy:
        print(f"      FALSE POSITIVE: {name}")

    total = len(fixtures) * len(rules)
    print(f"\n{total - failures}/{total} verdicts as declared")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
