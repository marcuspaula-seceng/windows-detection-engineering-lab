#!/usr/bin/env python3
"""Validate the rules against the OFFICIAL Sigma JSON Schema.

O schema vem de SigmaHQ/sigma-specification, `json-schema/sigma-detection-rule-schema.json`,
and is pinned under tools/schema/ with its origin recorded in tools/schema/PROVENANCE.md.

This is independent validation: the schema is not mine. It does not replace sigma-cli's
`sigma check` -- it checks the SHAPE of a rule, not whether pySigma can compile it.

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
    """Convert types that YAML produces and JSON does not have.

    YAML resolves an unquoted `date: 2026-09-07` to datetime.date. The JSON Schema expects
    a YYYY-MM-DD string. Without this conversion a perfectly valid rule -- written exactly
    as SigmaHQ writes its own rules -- fails because of a validator defect, not a rule
    defect. That is what happened on the first run.
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
        print(f'schema not found: {SCHEMA}')
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
        print('no rules found in', RULES_DIR)
        return 1

    failed = 0
    for path in rules:
        rule = to_jsonable(yaml.safe_load(io.open(path, encoding='utf-8')))
        errors = sorted(validator.iter_errors(rule), key=lambda e: list(e.path))
        if errors:
            failed += 1
            print(f'{path.name}: {len(errors)} error(s)')
            for error in errors:
                location = '/'.join(str(part) for part in error.path) or '(raiz)'
                print(f'    {location}: {error.message[:200]}')
        else:
            print(f'{path.name}: VALIDO')

    print()
    print(f"{len(rules) - failed}/{len(rules)} rules validate against the official schema")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
