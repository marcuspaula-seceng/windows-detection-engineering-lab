#!/usr/bin/env python3
"""Corre as fixtures contra todas as regras Sigma do projecto.

Cada fixture declara:

    _expected    o veredito esperado POR REGRA -- o que a regra foi desenhada para fazer
    _malicious   ground truth -- se o comportamento e o que queremos apanhar
    _behaviour   identificador do comportamento; varias fixtures podem descrever o
                 mesmo comportamento visto por telemetrias diferentes

A distincao entre _expected e _malicious e deliberada. Uma regra pode NAO apanhar um
comportamento malicioso e ainda assim comportar-se como declarado -- isso e um falso
negativo CONHECIDO, e conta como tal na matriz.

Sai com codigo 1 se qualquer veredito divergir do declarado.

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
    """Campos de telemetria que a regra referencia.

    EventID fica de fora de proposito: e um selector presente em todo o evento Windows,
    nao telemetria que distinga uma logsource da outra.
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
    """A fixture pertence a telemetria desta regra?

    Uma regra de process_creation nao "falha" ao nao apanhar um evento 4698: nao o ve.
    Contar isso como falso negativo tornaria a metrica sem sentido.
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
        print(f"      no ambito da sua telemetria: {len(scoped)} de {len(outcomes)} fixtures")
        print(f"      TP={counts['TP']}  TN={counts['TN']}  "
              f"FP={counts['FP']}  FN={counts['FN']}")
        if skipped:
            print(f"      {skipped} fixtures de outra fonte de telemetria, nao contadas")

    malicious_behaviours = {b: v for b, v in per_behaviour.items() if v['malicious']}
    covered = sum(1 for v in malicious_behaviours.values() if v['detected'])
    print('\nCOMBINED COVERAGE (por comportamento, nao por evento)')
    print(f"  comportamentos maliciosos : {len(malicious_behaviours)}")
    print(f"  detectados por alguma regra: {covered}")
    for name, value in sorted(malicious_behaviours.items()):
        if not value['detected']:
            print(f"      NAO DETECTADO: {name}")

    benign_behaviours = {b: v for b, v in per_behaviour.items() if not v['malicious']}
    noisy = [b for b, v in benign_behaviours.items() if v['detected']]
    print(f"  comportamentos benignos    : {len(benign_behaviours)}   "
          f"com alerta: {len(noisy)}")
    for name in noisy:
        print(f"      FALSO POSITIVO: {name}")

    total = len(fixtures) * len(rules)
    print(f"\n{total - failures}/{total} vereditos conforme declarado")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
