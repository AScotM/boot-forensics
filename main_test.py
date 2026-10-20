import argparse
import json
import tempfile
import unittest
from pathlib import Path
import main

class BootForensicsTests(unittest.TestCase):
    def test_boot_list(self):
        value = ' -1 abcdef0123456789abcdef0123456789 Mon 2026-10-19\n 0 1234567890abcdef1234567890abcdef Tue 2026-10-20'
        self.assertEqual(len(main.parse_boot_list(value)), 2)
        self.assertEqual(main.parse_boot_list(value)[0]['index'], -1)

    def test_blame(self):
        result = main.parse_blame('1min 2.4s example.service\n500ms second.service\n')
        self.assertEqual(result[0]['seconds'], 60)
        self.assertEqual(result[1]['seconds'], .5)

    def test_time(self):
        result = main.parse_systemd_time('Startup finished in 1.2s (kernel) + 5.4s (userspace) = 6.6s.')
        self.assertEqual(result['total'], 6.6)

    def test_journal(self):
        records = main.parse_journal_json('{"MESSAGE":"ok","PRIORITY":"6"}\ninvalid\n{"MESSAGE":"bad","PRIORITY":"3"}')
        self.assertEqual(len(records), 2)
        self.assertEqual(main.summarize_journal(records)['priorities']['error'], 1)

    def test_rules(self):
        self.assertGreaterEqual(len(main.RULES), 400)
        self.assertTrue(next(rule for rule in main.RULES if rule.code == 'KERNEL_PANIC_01').matches('Kernel panic - not syncing'))

    def test_baseline(self):
        args = argparse.Namespace(regression_seconds=10)
        ctx = main.Context(args, results={'identity': {'kernel': 'new'}, 'timing': {'stages': {'total': 30}}, 'units': {'failed': []}})
        main.apply_baseline(ctx, {'results': {'identity': {'kernel': 'old'}, 'timing': {'stages': {'total': 10}}, 'units': {'failed': []}}})
        self.assertTrue(any(item.code == 'BOOT_REGRESSION' for item in ctx.findings))

    def test_json_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nested' / 'test.json'
            main.atomic_json(path, {'a': 1})
            self.assertEqual(main.load_json(path), {'a': 1})

    def test_render(self):
        report = {'results': {}, 'generated': 'now', 'summary': {'findings': 0, 'errors': 0, 'sections': 0, 'severities': {}}, 'findings': [], 'errors': []}
        self.assertIn('BOOT FORENSICS', main.render_text(report))
        self.assertIn('severity,code', main.render_csv(report))
        self.assertIn('metadata', main.render_ndjson(report))

if __name__ == '__main__':
    unittest.main()
