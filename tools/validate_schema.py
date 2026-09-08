#!/usr/bin/env python3
"""Valida as regras contra o JSON Schema OFICIAL do Sigma.

O schema vem de SigmaHQ/sigma-specification, `json-schema/sigma-detection-rule-schema.json`,
e esta versionado em tools/schema/ com a origem registada em tools/schema/PROVENANCE.md.

Isto e validacao independente: o schema nao e meu. Nao substitui `sigma check` do sigma-cli
-- verifica a FORMA da regra, nao se o pySigma a consegue compilar para um backend.

    python tools/validate_schema.py
"""

import datetime
import io
import json
import pathlib
import sys

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / 'tools' / 'schema' / 'sigma-detection-rule-schema.json'
RULES_DIR = ROOT / 'sigma'


def to_jsonable(value):
    """Converte tipos que o YAML produz e o JSON nao tem.

    O YAML resolve `date: 2026-09-07` sem aspas para datetime.date. O JSON Schema espera
    uma string no formato YYYY-MM-DD. Sem esta conversao, uma regra perfeitamente valida --
    escrita exactamente como as regras da SigmaHQ -- reprova por um defeito do validador,
    nao da regra. Foi o que aconteceu na primeira execucao.
    """
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    return value


def main():
    if not SCHEMA.exists():
        print(f'schema nao encontrado: {SCHEMA}')
        return 1

    schema = json.load(io.open(SCHEMA, encoding='utf-8'))
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema)

    print(f"schema      : {SCHEMA.relative_to(ROOT)}")
    print(f"draft       : {schema.get('$schema')}")
    print(f"validator   : {validator_class.__name__}  (jsonschema)")
    print()

    rules = sorted(RULES_DIR.glob('*.yml'))
    if not rules:
        print('nenhuma regra encontrada em', RULES_DIR)
        return 1

    failed = 0
    for path in rules:
        rule = to_jsonable(yaml.safe_load(io.open(path, encoding='utf-8')))
        errors = sorted(validator.iter_errors(rule), key=lambda e: list(e.path))
        if errors:
            failed += 1
            print(f'{path.name}: {len(errors)} erro(s)')
            for error in errors:
                location = '/'.join(str(part) for part in error.path) or '(raiz)'
                print(f'    {location}: {error.message[:200]}')
        else:
            print(f'{path.name}: VALIDO')

    print()
    print(f"{len(rules) - failed}/{len(rules)} regras validam contra o schema oficial")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
