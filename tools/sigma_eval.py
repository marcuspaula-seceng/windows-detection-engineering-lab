#!/usr/bin/env python3
"""Minimal Sigma rule evaluator for already-normalised events.

This is NOT pySigma. It is a deliberately small subset, written to show that the rule
logic is understood -- not to replace the official tool.

SUPPORTED
    modifiers          contains, contains|all, startswith, endswith, exact equality
    values             scalar or list (a list means OR within the same field)
    within one block   several fields mean AND
    condition          "all of <prefix>_*", "1 of <prefix>_*", "and", "or", "not",
                       bare block names
    comparison         case-insensitive (Sigma's default behaviour)

NOT SUPPORTED -- a rule using any of these is REJECTED rather than silently mis-evaluated
    |re  |base64  |base64offset  |cidr  |lt  |lte  |gt  |gte  |fieldref  |expand
    null / absent fields used as a value
    aggregations (| count() ...)
    correlations across events

Usage:
    python sigma_eval.py <rule.yml> <events.json>
"""

import json
import re
import sys

import yaml

SUPPORTED_MODIFIER_SEQUENCES = {
    (), ('contains',), ('contains', 'all'), ('startswith',), ('endswith',),
}


class UnsupportedRule(Exception):
    """The rule uses something this evaluator does not implement."""


def match_value(actual, expected, modifiers):
    """Compare ONE observed value with ONE expected value, applying the modifiers."""
    if actual is None:
        # An absent field never matches. That is correct behaviour -- and the source of many
        # a silent false negative when the log schema does not carry the field.
        return False

    a = str(actual).lower()
    e = str(expected).lower()

    if 'contains' in modifiers:
        return e in a
    if 'startswith' in modifiers:
        return a.startswith(e)
    if 'endswith' in modifiers:
        return a.endswith(e)
    return a == e


def match_field(event, field_spec, expected):
    """Evaluate 'Field|modifiers: value(s)' against one event."""
    if not isinstance(field_spec, str) or not field_spec.split('|')[0]:
        raise UnsupportedRule('invalid field name')
    parts = field_spec.split('|')
    field = parts[0]
    modifiers = [p.lower() for p in parts[1:]]

    if tuple(modifiers) not in SUPPORTED_MODIFIER_SEQUENCES:
        raise UnsupportedRule(f'unsupported modifiers in {field_spec!r}')

    actual = event.get(field)
    values = expected if isinstance(expected, list) else [expected]
    if not values or any(v is None or not isinstance(v, (str, int, float, bool)) for v in values):
        raise UnsupportedRule(f'unsupported value in {field_spec!r}')

    if 'all' in modifiers:
        # every value must match -- AND within the field
        return all(match_value(actual, v, modifiers) for v in values)
    # default: OR within the field
    return any(match_value(actual, v, modifiers) for v in values)


def match_block(event, block):
    """One detection block. Several fields mean AND. A list of maps means OR."""
    if isinstance(block, list):
        if not block:
            raise UnsupportedRule('empty block')
        # Evaluate every alternative: unsupported syntax must not be hidden by a match.
        return any([match_block(event, item) for item in block])
    if not isinstance(block, dict) or not block:
        raise UnsupportedRule(f'unsupported block form: {type(block).__name__}')
    return all([match_field(event, spec, value) for spec, value in block.items()])


def resolve_condition(condition, blocks, event):
    """Evaluate the condition. Subset: 'all of X_*', '1 of X_*', and/or/not, names."""
    text = condition.strip()

    if '|' in text:
        raise UnsupportedRule('aggregation in a condition is not supported')

    def expand(match):
        quantifier, prefix = match.group(1).lower(), match.group(2)
        if prefix == 'them':
            names = list(blocks)
        else:
            pattern = '^' + re.escape(prefix).replace(r'\*', '.*') + '$'
            names = [n for n in blocks if re.match(pattern, n)]
        if not names:
            raise UnsupportedRule(f'no block matches {prefix!r}')
        joiner = ' and ' if quantifier == 'all' else ' or '
        return '(' + joiner.join(f'BLOCK_{n}' for n in names) + ')'

    text = re.sub(r'\b(all|any|1)\s+of\s+([A-Za-z0-9_*]+)', expand, text)

    for name in sorted(blocks, key=len, reverse=True):
        text = re.sub(rf'(?<!BLOCK_)\b{re.escape(name)}\b', f'BLOCK_{name}', text)

    values = {f'BLOCK_{n}': match_block(event, b) for n, b in blocks.items()}
    expression = text.replace(' AND ', ' and ').replace(' OR ', ' or ').replace(' NOT ', ' not ')

    if not re.fullmatch(r'[\w\s()]*', expression):
        raise UnsupportedRule(f'unsupported condition syntax: {condition!r}')

    try:
        return bool(eval(expression, {'__builtins__': {}}, values))  # noqa: S307 - expressao validada acima
    except (NameError, SyntaxError, TypeError) as error:
        raise UnsupportedRule(f'unsupported condition: {condition!r}') from error


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    rule_path, events_path = sys.argv[1], sys.argv[2]

    with open(rule_path, encoding='utf-8') as handle:
        rule = yaml.safe_load(handle)
    with open(events_path, encoding='utf-8-sig') as handle:
        events = json.load(handle)
    if isinstance(events, dict):
        events = [events]

    detection = dict(rule['detection'])
    condition = detection.pop('condition')

    # Validate the rule even when the event file is empty.
    try:
        resolve_condition(condition, detection, {})
    except UnsupportedRule as error:
        print(f'RULE REJECTED: {error}')
        return 3

    print(f"rule       : {rule['title']}")
    print(f"nivel      : {rule.get('level', '-')}   status: {rule.get('status', '-')}")
    print(f"logsource  : {rule['logsource']}")
    print(f"condition  : {condition}")
    print(f"eventos    : {len(events)}")
    print()

    hits, misses = [], []
    for event in events:
        try:
            (hits if resolve_condition(condition, detection, event) else misses).append(event)
        except UnsupportedRule as error:
            print(f'RULE REJECTED: {error}')
            return 3

    print(f'MATCH     : {len(hits)}')
    for event in hits:
        print(f"  [{event.get('SourceFile')}] {event.get('Image')}")
        print(f"      user: {event.get('User')}")
        print(f"      cmd : {str(event.get('CommandLine'))[:160]}")
    print()
    print(f'NO MATCH  : {len(misses)}')
    for event in misses:
        parent = event.get('ParentImage') or '(sem ParentImage neste schema)'
        print(f"  [{event.get('SourceFile')}] {event.get('Image')}   pai: {parent}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
