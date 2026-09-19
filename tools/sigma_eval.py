#!/usr/bin/env python3
"""Avaliador minimo de regras Sigma contra eventos ja normalizados.

Isto NAO e o pySigma. E um subconjunto escrito de proposito, para provar que a logica da
regra e compreendida -- nao para substituir a ferramenta oficial.

SUPORTADO
    modificadores      contains, contains|all, startswith, endswith, igualdade exacta
    valores            escalar ou lista (lista = OR dentro do mesmo campo)
    dentro de um bloco varios campos = AND
    condition          "all of <prefixo>_*", "1 of <prefixo>_*", "and", "or", "not",
                       nomes de bloco isolados
    comparacao         insensivel a maiusculas (o comportamento por omissao do Sigma)

NAO SUPORTADO -- e a regra e RECUSADA se os usar, em vez de dar resultado errado em silencio
    |re  |base64  |base64offset  |cidr  |lt  |lte  |gt  |gte  |fieldref  |expand
    null / campos ausentes como valor
    aggregations (| count() ...)
    correlacoes entre eventos

Uso:
    python sigma_eval.py <regra.yml> <eventos.json>
"""

import json
import re
import sys

import yaml

SUPPORTED_MODIFIER_SEQUENCES = {
    (), ('contains',), ('contains', 'all'), ('startswith',), ('endswith',),
}


class UnsupportedRule(Exception):
    """A regra usa algo que este avaliador nao implementa."""


def match_value(actual, expected, modifiers):
    """Compara UM valor observado com UM valor esperado, aplicando os modificadores."""
    if actual is None:
        # Campo ausente nunca casa. E o comportamento correcto -- e a origem de muito
        # falso negativo silencioso quando o schema do log nao tem o campo.
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
    """Avalia 'Campo|modificadores: valor(es)' contra um evento."""
    if not isinstance(field_spec, str) or not field_spec.split('|')[0]:
        raise UnsupportedRule('nome de campo invalido')
    parts = field_spec.split('|')
    field = parts[0]
    modifiers = [p.lower() for p in parts[1:]]

    if tuple(modifiers) not in SUPPORTED_MODIFIER_SEQUENCES:
        raise UnsupportedRule(f'modificadores nao suportados em {field_spec!r}')

    actual = event.get(field)
    values = expected if isinstance(expected, list) else [expected]
    if not values or any(v is None or not isinstance(v, (str, int, float, bool)) for v in values):
        raise UnsupportedRule(f'valor nao suportado em {field_spec!r}')

    if 'all' in modifiers:
        # todos os valores tem de casar -- AND dentro do campo
        return all(match_value(actual, v, modifiers) for v in values)
    # por omissao: OR dentro do campo
    return any(match_value(actual, v, modifiers) for v in values)


def match_block(event, block):
    """Um bloco de detection. Varios campos = AND. Lista de mapas = OR."""
    if isinstance(block, list):
        if not block:
            raise UnsupportedRule('bloco vazio')
        # Evaluate every alternative: unsupported syntax must not be hidden by a match.
        return any([match_block(event, item) for item in block])
    if not isinstance(block, dict) or not block:
        raise UnsupportedRule(f'forma de bloco nao suportada: {type(block).__name__}')
    return all([match_field(event, spec, value) for spec, value in block.items()])


def resolve_condition(condition, blocks, event):
    """Avalia a condition. Subconjunto: 'all of X_*', '1 of X_*', and/or/not, nomes."""
    text = condition.strip()

    if '|' in text:
        raise UnsupportedRule('aggregation na condition nao e suportada')

    def expand(match):
        quantifier, prefix = match.group(1).lower(), match.group(2)
        if prefix == 'them':
            names = list(blocks)
        else:
            pattern = '^' + re.escape(prefix).replace(r'\*', '.*') + '$'
            names = [n for n in blocks if re.match(pattern, n)]
        if not names:
            raise UnsupportedRule(f'nenhum bloco casa com {prefix!r}')
        joiner = ' and ' if quantifier == 'all' else ' or '
        return '(' + joiner.join(f'BLOCK_{n}' for n in names) + ')'

    text = re.sub(r'\b(all|any|1)\s+of\s+([A-Za-z0-9_*]+)', expand, text)

    for name in sorted(blocks, key=len, reverse=True):
        text = re.sub(rf'(?<!BLOCK_)\b{re.escape(name)}\b', f'BLOCK_{name}', text)

    values = {f'BLOCK_{n}': match_block(event, b) for n, b in blocks.items()}
    expression = text.replace(' AND ', ' and ').replace(' OR ', ' or ').replace(' NOT ', ' not ')

    if not re.fullmatch(r'[\w\s()]*', expression):
        raise UnsupportedRule(f'condition com sintaxe nao suportada: {condition!r}')

    try:
        return bool(eval(expression, {'__builtins__': {}}, values))  # noqa: S307 - expressao validada acima
    except (NameError, SyntaxError, TypeError) as error:
        raise UnsupportedRule(f'condition nao suportada: {condition!r}') from error


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
        print(f'REGRA RECUSADA: {error}')
        return 3

    print(f"regra      : {rule['title']}")
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
            print(f'REGRA RECUSADA: {error}')
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
