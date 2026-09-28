"""Exactly 21 offline tests. Runtime/firewall calls are mocked, never dispatched."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('dig_controller', Path(__file__).with_name('orchestration.py'))
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
CID = 'a' * 64
FOREIGN = 'f' * 64


def result(code=0, output=''):
    return subprocess.CompletedProcess([], code, output, '')


class MockRuntime(c.Runtime):
    def __init__(self, mode='ok'):
        super().__init__(call=self.command_call)
        self.mode, self.calls, self.objects = mode, [], {}

    def command_call(self, argv, **kwargs):
        args = argv[1:]
        self.calls.append(args)
        if args[:2] == ['container', 'exists']:
            if args[2] in self.objects:
                return result(0)
            if not c.canonical_id(args[2]):
                return result({'collision': 0, 'unknown': 125}.get(self.mode, 1))
            return result(1)
        if args[0] == 'create':
            labels = dict(args[index + 1].split('=', 1) for index, word in enumerate(args) if word == '--label')
            self.objects[CID] = {'Id': CID, 'Name': args[2], 'Config.Labels': labels}
            if self.mode == 'wrong-label':
                labels[c.LABEL + 'run'] = 'foreign'
            if self.mode == 'ambiguous':
                self.objects[FOREIGN] = copy.deepcopy(self.objects[CID])
            return result(125 if self.mode in ('partial', 'ambiguous') else 0,
                          'not-a-receipt' if self.mode == 'bad-id' else CID + '\n')
        if args[0] == 'rm':
            del self.objects[args[-1]]
            return result()
        if args[0] == 'start':
            return result()
        raise AssertionError('unmocked runtime operation')

    def inspect(self, cid):
        self.calls.append(['inspect', cid])
        return self.objects[cid]


def policy_fixture():
    return {
        'State.Status': 'created', 'Image': CID, 'Config.User': '1000:1000',
        'Config.WorkingDir': '/workspace', 'Config.Entrypoint': c.FETCH_ARGV[:1],
        'Config.Cmd': c.FETCH_ARGV[1:], 'Config.Secrets': [], 'Config.Volumes': {},
        'EffectiveCaps': [], 'BoundingCaps': [], 'env_keys': list(c.GO_ENV),
        'Mounts': [{'Type': 'bind', 'Source': '/fixture', 'Destination': '/workspace',
                    'RW': False, 'Options': ['nosuid', 'nodev', 'noexec'], 'Propagation': 'rprivate'}],
        'HostConfig': {'Privileged': False, 'ReadonlyRootfs': True,
                       'SecurityOpt': ['no-new-privileges'], 'NetworkMode': 'none',
                       'IpcMode': 'private', 'PidMode': 'private', 'UTSMode': 'private',
                       'IDMappings': {'UidMap': ['0:1:1000', '1000:0:1', '1001:1001:64536'],
                                      'GidMap': ['0:1:1000', '1000:0:1', '1001:1001:64536']},
                       'Binds': ['/fixture:/workspace:ro,nosuid,nodev,noexec'],
                       'Devices': [], 'DeviceRequests': [], 'PortBindings': {}, 'VolumesFrom': [],
                       'GroupAdd': [], 'Links': [], 'ExtraHosts': [], 'Dns': [], 'DnsOptions': [], 'DnsSearch': [],
                       'Memory': 4 * 1024**3, 'PidsLimit': 256, 'NanoCpus': 2 * 10**9,
                       'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=3g,mode=1777'}},
        'parent_mappings': {'uidmap': [{'container_id': 0, 'host_id': 1000, 'size': 1}],
                            'gidmap': [{'container_id': 0, 'host_id': 1000, 'size': 1}]}}


def verify(data):
    c.verify_policy(data, CID, 1000, 1000, c.FETCH_ARGV,
                    [(Path('/fixture'), '/workspace', False)], c.GO_ENV)


class ContractTests(unittest.TestCase):
    def job(self):
        text = (ROOT / '.github/workflows/integration-services.yml').read_text()
        return text.split('  dig-contract:', 1)[1].split('\n  postgres-live:', 1)[0]

    def test_01_main_only(self):
        job = self.job()
        self.assertIn("if: ${{ (github.event_name == 'push' || github.event_name == 'workflow_dispatch' || github.event_name == 'schedule') && github.ref == 'refs/heads/main' }}", job)
        self.assertIn('runs-on: ubuntu-24.04', job)
        self.assertNotIn('pull_request_target', job)

    def test_02_permissions_and_checkout(self):
        job = self.job()
        self.assertIn('permissions:\n      contents: read', job)
        self.assertIn('persist-credentials: false', job)
        refs = re.findall(r'uses: (\S+)', job)
        self.assertEqual(refs, ['actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09'])
        for forbidden in ('secrets.', 'id-token:', ': write', 'upload-artifact', 'inputs:', 'go test', 'go build'):
            self.assertNotIn(forbidden, job)

    def test_03_images_and_no_builds(self):
        self.assertNotIn('GO_TOOLCHAIN_IMAGE:', self.job())
        self.assertNotIn('PYTHON_CHECK_IMAGE:', self.job())
        self.assertIn('bash tests/live/postgres/ci.sh --dig-contract-only', self.job())
        shared = (ROOT / 'tests/live/postgres/ci.sh').read_text()
        self.assertIn('rootfs_profile_args=(--profile dig-contract)', shared)
        self.assertLess(shared.index("'dig-contract-offline-passed'"), shared.index('cluster_state="$(bounded_timeout 60 python3'))
        rootfs = (ROOT / 'tests/live/postgres/rootfs.py').read_text()
        self.assertIn('"dig-contract"', rootfs)
        self.assertFalse(list(Path(__file__).parent.glob('Containerfile*')))
        source = Path(c.__file__).read_text()
        self.assertNotRegex(source, r"podman\(['\"](?:build|run|pull)['\"]")
        self.assertIn('--pull=never', source)
        main = source.split('def main():', 1)[1]
        for forbidden in ('fetch=True', 'firewall.install', 'resolve_fetch_policy', "'mod', 'download'"):
            self.assertNotIn(forbidden, main)
        self.assertNotIn('getaddrinfo', source)
        with c.tempfile.TemporaryDirectory() as directory, patch.dict(c.os.environ, {'RUNNER_TEMP': directory}):
            with self.assertRaisesRegex(c.Rejected, 'offline-module-cache-unavailable'):
                c.existing_module_cache()
            cache = Path(directory) / 'statekit-r102dig-modcache'
            cache.mkdir(mode=0o700)
            self.assertEqual(c.existing_module_cache(), cache)
            (cache / 'link').symlink_to('/nonexistent')
            with self.assertRaisesRegex(c.Rejected, 'offline-cache-special-file'):
                c.existing_module_cache()
            (cache / 'link').unlink()
            cache.chmod(0o777)
            with self.assertRaisesRegex(c.Rejected, 'offline-cache-ownership-or-mode'):
                c.existing_module_cache()
            cache.chmod(0o700)

    def test_04_shell_syntax_and_entrypoint(self):
        for name in ('run.sh', 'payload.sh'):
            completed = subprocess.run(['bash', '-n', str(Path(__file__).with_name(name))], capture_output=True)
            self.assertEqual(completed.returncode, 0)
        self.assertIn('bash tests/live/dig/run.sh --preflight-only', self.job())
        self.assertIn('bash tests/live/dig/run.sh', self.job())
        with patch.dict(c.os.environ, {'DOCKER_HOST': 'synthetic-forbidden'}, clear=True), \
                patch.object(c.os, 'getuid', return_value=1000):
            runtime = MockRuntime()
            with self.assertRaisesRegex(c.Rejected, 'runtime-host-credential-or-remote-environment'):
                c.preflight(runtime)
            self.assertFalse(runtime.calls)
        with patch.dict(c.os.environ, {}, clear=True), patch.object(c.os, 'getuid', return_value=1000), \
                patch.object(c.Runtime, 'podman', side_effect=[result(output='true'), result(output='false'), result(output='true')]):
            with self.assertRaisesRegex(c.Rejected, 'runner-context-unverified'):
                c.preflight(c.Runtime())

    def test_05_receipt_cleanup_by_id(self):
        runtime = MockRuntime()
        cid = runtime.create('contract', [])
        self.assertEqual(cid, CID)
        self.assertIn(CID, runtime.receipts)
        runtime.cleanup()
        runtime.cleanup()
        self.assertEqual([call for call in runtime.calls if call[0] == 'rm'], [['rm', '--force', CID]])

    def test_06_collisions_and_unknown(self):
        for mode in ('collision', 'unknown'):
            runtime = MockRuntime(mode)
            with self.assertRaises(c.Rejected):
                runtime.create('python', [])
            runtime.cleanup()
            self.assertFalse(runtime.receipts)
            self.assertFalse(any(call[0] in ('create', 'rm') for call in runtime.calls))

    def test_07_failed_partial_create_preserved(self):
        runtime = MockRuntime('partial')
        with self.assertRaises(c.Rejected):
            runtime.create('fetch', [])
        runtime.cleanup()
        self.assertIn(CID, runtime.objects)
        self.assertTrue(runtime.ambiguous)
        self.assertFalse(runtime.receipts)

    def test_08_bad_receipts_and_labels_preserved(self):
        for mode in ('bad-id', 'wrong-label', 'ambiguous'):
            runtime = MockRuntime(mode)
            with self.assertRaises(c.Rejected):
                runtime.create('contract', [])
            runtime.cleanup()
            self.assertIn(CID, runtime.objects)
            self.assertFalse(any(call[0] in ('rm', 'start', 'ps') for call in runtime.calls))

    def test_09_cleanup_reverifies_identity(self):
        runtime = MockRuntime()
        runtime.create('contract', [])
        runtime.objects[CID]['Config.Labels'][c.LABEL + 'phase'] = 'foreign'
        with self.assertRaises(c.Rejected):
            runtime.cleanup()
        self.assertIn(CID, runtime.objects)

    def test_10_unowned_reconciliation_never_deletes(self):
        runtime = MockRuntime('ambiguous')
        with self.assertRaises(c.Rejected):
            runtime.create('fetch', [])
        runtime.cleanup()
        self.assertEqual(set(runtime.objects), {CID, FOREIGN})
        with self.assertRaises(c.Rejected):
            runtime.remove(FOREIGN)

    def test_11_firewall_exact_destinations_both_families(self):
        for family in (4, 6):
            rules, jump = c.firewall_rules('CHAIN', 1000, ['192.0.2.1', '2001:db8::1'], '127.0.0.53', family)
            self.assertEqual(rules[-1], ['-A', 'CHAIN', '-j', 'DROP'])
            self.assertEqual(jump, ['-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '1000', '-j', 'CHAIN'])
            for row in rules[1:-1]:
                self.assertIn(row[row.index('--dport') + 1], ('443', '53'))
        v6, _ = c.firewall_rules('CHAIN', 1000, ['192.0.2.1'], '127.0.0.53', 6)
        self.assertEqual(v6, [['-N', 'CHAIN'], ['-A', 'CHAIN', '-j', 'DROP']])

    def test_12_firewall_canonicalization(self):
        row = '-A CHAIN -d 192.0.2.1/32 -p tcp -m tcp --dport 443 -j ACCEPT'
        self.assertEqual(c.canonical_rule(row), ['-A', 'CHAIN', '-d', '192.0.2.1', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'])
        with self.assertRaises(c.Rejected):
            c.canonical_rule('-A CHAIN -d 192.0.2.0/24 -j ACCEPT')

    def test_13_firewall_rejects_mutations(self):
        firewall = c.Firewall(1000, 'nonce')
        rows = {}
        for family, tool in ((4, 'iptables'), (6, 'ip6tables')):
            rules, jump = c.firewall_rules(firewall.chain, 1000, ['192.0.2.1'], '127.0.0.53', family)
            firewall.expected[tool] = (rules, jump)
            rows[tool] = {firewall.chain: [' '.join(row) for row in rules], 'OUTPUT': ['-P OUTPUT ACCEPT', ' '.join(jump)]}
        def mocked(tool, *args):
            return result(output='\n'.join(rows[tool][args[1]]))
        with patch.object(firewall, 'run', side_effect=mocked):
            firewall.verify()
            baseline = copy.deepcopy(rows)
            for tool in rows:
                for mutation in ('port', 'destination', 'extra', 'order', 'jump'):
                    rows = copy.deepcopy(baseline)
                    if mutation == 'jump':
                        rows[tool]['OUTPUT'].insert(1, '-A OUTPUT -j ACCEPT')
                    elif mutation == 'order':
                        rows[tool][firewall.chain] = list(reversed(rows[tool][firewall.chain]))
                    elif mutation == 'extra':
                        rows[tool][firewall.chain].insert(1, '-A ' + firewall.chain + ' -j RETURN')
                    else:
                        rows[tool][firewall.chain].insert(1, '-A ' + firewall.chain + ' -d 192.0.2.2 -p tcp --dport 80 -j ACCEPT')
                    with self.assertRaises(c.Rejected):
                        firewall.verify()

    def test_14_firewall_requires_both_families(self):
        firewall = c.Firewall(1000, 'nonce')
        with self.assertRaises(c.Rejected):
            firewall.verify()
        states = {tool: {'OUTPUT': []} for tool in ('iptables', 'ip6tables')}

        def mocked(tool, *args):
            state = states[tool]
            op, chain = args[:2] if len(args) >= 2 else (args[0], '')
            if op == '-N':
                self.assertNotIn(chain, state)
                state[chain] = []
            elif op == '-A':
                state[chain].append(list(args))
            elif op == '-I':
                state[chain].insert(int(args[2]) - 1, ['-A', chain, *args[3:]])
            elif op == '-D':
                state[chain].remove(['-A', *args[1:]])
                if chain == firewall.chain:
                    # Transition to deny must never temporarily allow traffic.
                    self.assertEqual(state[chain][0][-2:], ['-j', 'DROP'])
            elif op == '-F':
                self.assertFalse(state['OUTPUT'])
                state[chain] = []
            elif op == '-X':
                del state[chain]
            elif op == '-S':
                names = [chain] if chain else list(state)
                lines = []
                for name in names:
                    lines.append('-P OUTPUT ACCEPT' if name == 'OUTPUT' else '-N ' + name)
                    lines.extend(' '.join(row) for row in state[name])
                return result(output='\n'.join(lines))
            else:
                raise AssertionError('unexpected firewall operation')
            return result()

        with patch.object(firewall, 'run', side_effect=mocked):
            firewall.install(['192.0.2.1'], '127.0.0.53')
            firewall.deny()
            firewall.cleanup()
            firewall.cleanup()
        self.assertEqual(states, {tool: {'OUTPUT': []} for tool in ('iptables', 'ip6tables')})

    def test_15_effective_policy_valid_fixture(self):
        verify(policy_fixture())

    def test_16_policy_rejects_privilege_network_and_environment(self):
        for key, value in [('Privileged', True), ('ReadonlyRootfs', False), ('NetworkMode', 'host'),
                           ('SecurityOpt', []), ('Devices', ['/dev/sda']), ('PidMode', 'host')]:
            data = policy_fixture()
            data['HostConfig'][key] = value
            with self.assertRaises(c.Rejected):
                verify(data)
        for key, value in [('env_keys', ['AWS_SECRET_ACCESS_KEY']), ('EffectiveCaps', ['CAP_SYS_ADMIN']),
                           ('Config.Cmd', ['mod', 'tidy']), ('Config.Secrets', ['unexpected'])]:
            data = policy_fixture()
            data[key] = value
            with self.assertRaises(c.Rejected):
                verify(data)

    def test_17_policy_rejects_mount_and_uid_mapping(self):
        for mutation in ('rw', 'socket', 'uid', 'tmpfs-dev', 'mount-exec'):
            data = policy_fixture()
            if mutation == 'rw':
                data['Mounts'][0]['RW'] = True
            elif mutation == 'socket':
                data['Mounts'][0]['Source'] = '/run/podman/podman.sock'
            elif mutation == 'tmpfs-dev':
                data['HostConfig']['Tmpfs']['/tmp'] += ',dev'
            elif mutation == 'mount-exec':
                data['Mounts'][0]['Options'].append('exec')
            else:
                data['parent_mappings']['uidmap'][0]['host_id'] = 0
            with self.assertRaises(c.Rejected):
                verify(data)

    def test_18_inspection_before_start(self):
        runtime = MockRuntime()
        with patch.object(c, 'verify_policy', side_effect=c.Rejected('test-policy-rejected')):
            with self.assertRaises(c.Rejected):
                c.run_stage(runtime, 'contract', c.GO_IMAGE, CID, c.CONTRACT_ARGV, [], c.GO_ENV)
        self.assertFalse(any(call[0] == 'start' for call in runtime.calls))
        runtime.cleanup()
        events = []
        runtime = MockRuntime()
        original = runtime.podman

        def record(*args, **kwargs):
            if args[0] in ('start', 'rm'):
                events.append(args[0])
            return original(*args, **kwargs)

        firewall = c.Firewall(1000, 'nonce')
        with patch.object(runtime, 'podman', side_effect=record), \
                patch.object(c, 'verify_policy', side_effect=lambda *a, **k: events.append('policy')), \
                patch.object(firewall, 'verify', side_effect=lambda: events.append('firewall')), \
                patch('builtins.print'):
            c.run_stage(runtime, 'fetch', c.GO_IMAGE, CID, c.FETCH_ARGV, [], c.GO_ENV,
                        fetch=True, firewall=firewall)
        self.assertEqual(events, ['policy', 'firewall', 'start', 'firewall', 'rm'])

    def test_19_fixed_fetch_and_offline_contract(self):
        self.assertEqual(c.FETCH_ARGV, ['/usr/local/go/bin/go', 'mod', 'download'])
        argv = c.sandbox_args(c.GO_IMAGE, 1000, 1000, c.FETCH_ARGV,
                              [(Path('/manifests'), '/workspace', False), (Path('/cache'), '/cache', True)],
                              {**c.GO_ENV, 'GOPROXY': 'https://proxy.golang.org'}, fetch=True)
        self.assertIn('--userns=keep-id', argv)
        self.assertIn('GOTOOLCHAIN=local', argv)
        self.assertIn('GOWORK=off', argv)
        self.assertIn('GOPROXY=https://proxy.golang.org', argv)
        self.assertIn('GOSUMDB=sum.golang.org', argv)
        self.assertNotIn('bash', ' '.join(argv))
        payload = Path(__file__).with_name('payload.sh').read_text()
        self.assertIn(' '.join(c.CONTRACT_ARGV), payload)
        self.assertIn(' '.join(c.CONTRACT_ARGV[1:]), (ROOT / 'tests/live/postgres/ci.sh').read_text())
        self.assertIn('/usr/local/go/bin/go mod verify', payload)
        for field in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'mountinfo'):
            self.assertIn(field, payload)

    def test_20_backend_build_tags(self):
        for path in ('internal/cli/dig_cli_test.go', 'modules/exec/dig/dig_test.go',
                     'tests/differential/r10_dig_contract_test.go'):
            self.assertEqual((ROOT / path).read_text().splitlines()[0], '//go:build dns_contract')
        self.assertNotRegex((ROOT / 'tests/differential/r10_test.go').read_text(), r'func TestR10Dig\w*\(')
        self.assertIn('./tests/differential', c.CONTRACT_ARGV)

    def test_21_exact_inventory_zero_skips(self):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)
        self.assertEqual(suite.countTestCases(), 21)
        source = Path(__file__).read_text()
        for forbidden in ('skip' + 'Test', 'skip' + 'If', 'skip' + 'Unless', 'expected' + 'Failure'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
