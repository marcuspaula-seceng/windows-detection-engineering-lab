#!/usr/bin/env python3
"""Corre as fixtures contra as regras Sigma proprias.

Sai com codigo 1 se qualquer fixture nao produzir o resultado declarado em "_expected".
Feito para correr em CI sem instalar nada alem de PyYAML.

    python tools/run_tests.py
"""

import importlib.util
import io
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / 'sigma'
FIXTURES = ROOT / 'tests' / 'fixtures-synthetic.json'


def load_evaluator():
    spec = importlib.util.spec_from_file_location('sigma_eval', ROOT / 'tools' / 'sigma_eval.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    evaluator = load_evaluator()
    fixtures = json.load(io.open(FIXTURES, encoding='utf-8'))
    rules = sorted(RULES.glob('*.yml'))

    if not rules:
        print('nenhuma regra encontrada em', RULES)
        return 1

    failures = 0
    for rule_path in rules:
        rule = yaml.safe_load(io.open(rule_path, encoding='utf-8'))
        detection = dict(rule['detection'])
        condition = detection.pop('condition')

        print(f"\n=== {rule_path.name}")
        print(f"    {rule['title']}")
        print(f"    level={rule.get('level')}  status={rule.get('status')}")
        print()

        for fixture in fixtures:
            got = 'MATCH' if evaluator.resolve_condition(condition, detection, fixture) else 'NO MATCH'
            expected = fixture['_expected']
            verdict = 'PASS' if got == expected else 'FAIL'
            failures += verdict == 'FAIL'
            print(f"    {verdict}  esperado={expected:<9} obtido={got:<9} {fixture['_fixture'][:70]}")

    total = len(fixtures) * len(rules)
    print(f"\n{total - failures}/{total} fixtures PASS")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
