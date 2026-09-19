"""Regression tests for unsupported rule rejection; no Windows or SIEM required."""

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sigma_eval', ROOT / 'tools' / 'sigma_eval.py')
evaluator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluator)


class EvaluatorContractTests(unittest.TestCase):
    def test_supported_comparisons(self):
        for field, expected in [
            ('Image', 'POWERSHELL.EXE'),
            ('Image|contains', 'shell'),
            ('Image|contains|all', ['power', '.exe']),
            ('Image|startswith', 'power'),
            ('Image|endswith', '.exe'),
            ('Image', ['cmd.exe', 'powershell.exe']),
        ]:
            with self.subTest(field=field):
                self.assertTrue(evaluator.match_field({'Image': 'powershell.exe'}, field, expected))

    def test_missing_observed_field_does_not_match(self):
        self.assertFalse(evaluator.match_field({}, 'Image|contains', 'power'))

    def test_unknown_or_ambiguous_modifiers_are_rejected(self):
        for field in ['Image|unknown', 'Image|re', 'Image|all',
                      'Image|contains|startswith', 'Image|contains|contains', 'Image|']:
            with self.subTest(field=field), self.assertRaises(evaluator.UnsupportedRule):
                evaluator.match_field({}, field, 'power')

    def test_null_and_non_scalar_values_are_rejected(self):
        for value in [None, ['power', None], [], {'nested': 'power'}, [['power']]]:
            with self.subTest(value=value), self.assertRaises(evaluator.UnsupportedRule):
                evaluator.match_field({}, 'Image', value)

    def test_invalid_field_is_not_hidden_by_an_earlier_mismatch(self):
        with self.assertRaises(evaluator.UnsupportedRule):
            evaluator.match_block({'Image': 'cmd.exe'},
                                  {'Image': 'powershell.exe', 'CommandLine|unknown': 'x'})

    def test_invalid_alternative_is_not_hidden_by_an_earlier_match(self):
        with self.assertRaises(evaluator.UnsupportedRule):
            evaluator.match_block({'Image': 'cmd.exe'},
                                  [{'Image': 'cmd.exe'}, {'CommandLine': None}])

    def test_unsupported_condition_is_reported_as_rule_rejection(self):
        with self.assertRaises(evaluator.UnsupportedRule):
            evaluator.resolve_condition('missing', {'selection': {'Image': 'cmd.exe'}}, {})

    def test_cli_rejects_unsupported_rule_with_no_events(self):
        with tempfile.TemporaryDirectory() as folder:
            rule = pathlib.Path(folder) / 'rule.yml'
            events = pathlib.Path(folder) / 'events.json'
            rule.write_text('title: test\nlogsource: {product: windows}\ndetection:\n'
                            '  selection:\n    Image|unknown: cmd.exe\n  condition: selection\n')
            events.write_text(json.dumps([]))
            result = subprocess.run([sys.executable, str(ROOT / 'tools' / 'sigma_eval.py'),
                                     str(rule), str(events)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
            self.assertIn('REGRA RECUSADA', result.stdout)


if __name__ == '__main__':
    unittest.main()
