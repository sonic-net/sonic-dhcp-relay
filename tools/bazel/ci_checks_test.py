import copy
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from defusedxml.ElementTree import parse

from ci_checks import MINIMUM_CASES, audit_actions, audit_tests, main


class CIGatesTest(unittest.TestCase):
    def test_action_graph(self):
        graph = {'actions': [{'mnemonic': 'CppLink', 'outputIds': [1]}],
                 'artifacts': [{'id': 1, 'pathFragmentId': 1}],
                 'pathFragments': [{'id': 1, 'label': 'relay'}]}
        self.assertEqual(audit_actions(graph), 1)
        forbidden = copy.deepcopy(graph)
        forbidden['pathFragments'][0]['label'] = 'fixture.deb'
        with self.assertRaises(ValueError):
            audit_actions(forbidden)
        # Shared Infra's debug manifest is a TAR input, never a DEB producer.
        debug = copy.deepcopy(graph)
        debug['actions'][0]['mnemonic'] = 'DebugSymbolsManifest'
        self.assertEqual(audit_actions(debug), 1)
        debug['pathFragments'][0]['label'] = 'unexpected.deb'
        with self.assertRaises(ValueError):
            audit_actions(debug)
        with self.assertRaises(ValueError):
            audit_actions({'actions': []})

    def test_complete_and_empty_or_skipped_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, count in MINIMUM_CASES.items():
                path = root / 'tests/runtime' / name / 'test.xml'
                path.parent.mkdir(parents=True)
                suite = ET.Element('testsuite')
                for i in range(count):
                    ET.SubElement(suite, 'testcase', name=str(i), status='run', result='completed')
                ET.ElementTree(suite).write(path)
            self.assertEqual(audit_tests(root), MINIMUM_CASES)
            receipt = root / 'test-audit.json'
            with contextlib.redirect_stdout(io.StringIO()):
                main(['tests', str(root), '--receipt', str(receipt)])
            self.assertEqual(json.loads(receipt.read_text()), {
                'schema': 1, 'status': 'passed', 'cases': MINIMUM_CASES,
                'total': 114, 'skipped': 0,
            })
            path = root / 'tests/runtime/sender_test/test.xml'
            tree = parse(path)
            ET.SubElement(tree.getroot()[0], 'skipped')
            tree.write(path)
            with self.assertRaises(ValueError):
                audit_tests(root)
            path.write_text('<testsuite/>')
            with self.assertRaises(ValueError):
                audit_tests(root)

    def test_public_artifacts_exclude_raw_diagnostics_and_project_audited_counts(self):
        # Read the actual workflow selection; do not duplicate it in this test.
        repo = Path(__file__).resolve().parents[2]
        workflow = (repo / '.github/workflows/bazel.yml').read_text()
        block = re.search(r'^          path: \|\n((?:            .+\n)+)', workflow, re.MULTILINE)
        self.assertIsNotNone(block)
        patterns = [line.strip() for line in block[1].splitlines()]
        sentinel = 'SYNTHETIC_PRIVATE_ENV_NEVER_UPLOAD'
        raw_events = json.dumps({
            'id': {'unstructuredCommandLine': {}},
            'unstructuredCommandLine': {'args': ['--client_env=FIXTURE_TOKEN=' + sentinel]},
        }) + '\n'
        graph = {
            'actions': [{'mnemonic': 'CppLink', 'outputIds': [1],
                         'arguments': [sentinel], 'environmentVariables': [{'name': 'FIXTURE', 'value': sentinel}]}],
            'artifacts': [{'id': 1, 'pathFragmentId': 1}],
            'pathFragments': [{'id': 1, 'label': 'relay'}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = root / 'ci-state', root / 'ci-evidence'
            private.mkdir()
            public.mkdir()
            for directory in (private, public):
                # Even an accidentally misplaced raw file must not be selected.
                (directory / 'build.bep.json').write_text(raw_events)
                (directory / 'test.bep.json').write_text(raw_events)
                (directory / 'configured-actions.json').write_text(json.dumps(graph))
                (directory / 'unexpected.json').write_text(raw_events)
            receipt = public / 'action-audit.json'
            with contextlib.redirect_stdout(io.StringIO()):
                main(['actions', str(private / 'configured-actions.json'), '--receipt', str(receipt)])
            self.assertEqual(json.loads(receipt.read_text()), {
                'schema': 1, 'status': 'passed', 'configured_actions': 1, 'deb_outputs': 0,
            })
            selected = {path for pattern in patterns for path in root.glob(pattern) if path.is_file()}
            self.assertEqual(selected, {receipt})
            self.assertNotIn(sentinel, b''.join(path.read_bytes() for path in selected).decode())
            # Preserve all six production output paths in the same allowlist.
            artifact_patterns = [pattern for pattern in patterns
                                 if pattern.startswith('ci-evidence/artifacts/') and '*' not in pattern]
            self.assertEqual(len(artifact_patterns), 6)
            for name in artifact_patterns:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'synthetic output')
            selected = {path for pattern in patterns for path in root.glob(pattern) if path.is_file()}
            self.assertEqual(selected, {receipt, *(root / name for name in artifact_patterns)})
            # A rejected configured action cannot produce a success receipt.
            receipt.unlink()
            graph['pathFragments'][0]['label'] = 'forbidden.deb'
            (private / 'configured-actions.json').write_text(json.dumps(graph))
            with self.assertRaises(ValueError):
                main(['actions', str(private / 'configured-actions.json'), '--receipt', str(receipt)])
            self.assertFalse(receipt.exists())

    def test_private_state_cannot_be_inside_uploaded_evidence(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / 'public'
            result = subprocess.run(['/bin/bash', str(repo / 'tools/bazel/ci.sh')], env={
                'PATH': '/usr/bin:/bin', 'BAZEL': '/unused', 'CI_SOURCE_SHA': 'unused',
                'CI_STATE': str(evidence / 'private'), 'CI_EVIDENCE': str(evidence),
            }, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('CI_STATE must be outside uploaded evidence', result.stdout)
            self.assertFalse(evidence.exists())


if __name__ == '__main__':
    unittest.main()
