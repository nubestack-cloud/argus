#!/usr/bin/env python3
"""Generate a chart's values.schema.json from its values.yaml.

Helm validates every install and upgrade against the schema, so a misspelled
key or a value of the wrong type fails before anything reaches the cluster,
with the key named. Run after changing a chart's values.yaml:

    scripts/gen-values-schema.py deploy/helm/argus-hub
    scripts/gen-values-schema.py deploy/helm/argus-agent

Every key in values.yaml is described by the type of its default. Objects
with keys are closed (an unknown key is an error); an object whose default is
empty ({}) is a free-form map such as annotations or resources. A string
default also accepts a number, because `--set port=30443` arrives as one.
ENUMS and EXTRA below hold what a default cannot say.
"""
import json
import re
import sys
from pathlib import Path

import yaml

ENUMS = {
    'argus-hub': {
        'postgres.mode': ['bundled', 'external'],
        'tunnel.service.type': ['ClusterIP', 'NodePort', 'LoadBalancer'],
        'api.service.type': ['ClusterIP', 'NodePort', 'LoadBalancer'],
        'image.pullPolicy': ['Always', 'IfNotPresent', 'Never'],
        'cliRunner.image.pullPolicy': ['Always', 'IfNotPresent', 'Never'],
        'cliRunner.authMode': ['', 'subscription'],
    },
    'argus-agent': {
        'image.pullPolicy': ['Always', 'IfNotPresent', 'Never'],
        'identity.mode': ['secret', 'ephemeral'],
    },
}

# Keys whose value may take more than one shape.
EXTRA = {
    'argus-hub': {
        'cliRunner.enabled': {'enum': ['auto', True, False, 'true', 'false']},
        # The agent chart's values; its own schema validates them.
        'localAgent': {'type': 'object'},
        # Older charts had a nightly backup and then a pre-upgrade dump here
        # (enabled, schedule, beforeUpgrade, keep, ...). Neither exists now;
        # the keys are accepted and ignored so a values file written for them
        # still upgrades.
        'postgres.bundled.backup': {'type': 'object'},
    },
    'argus-agent': {},
}

FREE_FORM = {'annotations', 'labels', 'nodeSelector', 'podAnnotations', 'podLabels', 'resources', 'securityContext', 'podSecurityContext', 'affinity'}


def describe(value, path, enums, extra):
    if path in extra:
        return dict(extra[path])
    if path in enums:
        return {'enum': enums[path]}
    if isinstance(value, bool):
        return {'type': 'boolean'}
    if isinstance(value, int):
        return {'type': ['integer', 'string']}
    if isinstance(value, float):
        return {'type': ['number', 'string']}
    if isinstance(value, str):
        return {'type': ['string', 'number']}
    if isinstance(value, list):
        return {'type': 'array'}
    if isinstance(value, dict):
        leaf = path.rsplit('.', 1)[-1]
        if not value or leaf in FREE_FORM:
            return {'type': 'object'}
        return {
            'type': 'object',
            'additionalProperties': False,
            'properties': {k: describe(v, f'{path}.{k}' if path else k, enums, extra) for k, v in value.items()},
        }
    return {}  # null: anything


def referenced_paths(chart):
    paths = set()
    for f in (chart / 'templates').rglob('*'):
        if f.is_file():
            paths |= set(re.findall(r'\.Values((?:\.[A-Za-z0-9_]+)+)', f.read_text()))
    return {p.lstrip('.') for p in paths}


def allows(schema, path):
    node = schema
    for part in path.split('.'):
        if node.get('type') == 'object' and 'properties' not in node:
            return True
        props = node.get('properties')
        if props is None:
            return True
        if part not in props:
            return not node.get('additionalProperties', True) is False
        node = props[part]
    return True


def main(chart_dir):
    chart = Path(chart_dir)
    name = chart.name
    values = yaml.safe_load((chart / 'values.yaml').read_text())
    schema = describe(values, '', ENUMS.get(name, {}), EXTRA.get(name, {}))
    schema = {'$schema': 'https://json-schema.org/draft-07/schema#', 'title': f'{name} values', **schema}
    # Global keys Helm itself passes to every chart.
    schema['properties'].setdefault('global', {'type': 'object'})
    missing = sorted(p for p in referenced_paths(chart) if not allows(schema, p))
    if missing:
        sys.exit(f'{name}: templates read values the schema would refuse; add them to values.yaml: {", ".join(missing)}')
    (chart / 'values.schema.json').write_text(json.dumps(schema, indent=2) + '\n')
    print(f'wrote {chart}/values.schema.json')


if __name__ == '__main__':
    for d in sys.argv[1:]:
        main(d)
