"""R10.2 controller: no project/dependency payload runs on the host.

Unknown inspect/firewall schemas fail closed. Firewall privilege stays on the
controller, never on Podman. Failed creates never confer cleanup ownership.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
GO_IMAGE = 'docker.io/library/golang:1.26.6@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6'
PYTHON_IMAGE = 'docker.io/library/python:3.14.7@sha256:be8ccd085666c34273c9dc5607c9842f8b2e3116128aae45148ce164c07ce09d'
PACKAGES = ['./modules/exec/dig', './internal/cli', './tests/differential']
FETCH_ARGV = ['/usr/local/go/bin/go', 'mod', 'download']
CONTRACT_ARGV = ['/usr/local/go/bin/go', 'test', '-tags=dns_contract', '-count=1', *PACKAGES]
DOMAINS = ('proxy.golang.org', 'sum.golang.org', 'storage.googleapis.com')
LABEL = 'statekit.r102dig.'
FETCH_NETWORK = 'slirp4netns:allow_host_loopback=false,enable_ipv6=true'
BASE_ENV = {'PATH': '/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp/home', 'TMPDIR': '/tmp'}
GO_ENV = {**BASE_ENV, 'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'local', 'GOWORK': 'off',
          'GOENV': 'off', 'GOPROXY': 'off', 'GOSUMDB': 'sum.golang.org',
          'GOPRIVATE': '', 'GONOPROXY': '', 'GONOSUMDB': '',
          'GOMODCACHE': '/cache', 'GOCACHE': '/tmp/go-cache', 'GOPATH': '/tmp/go'}
PY_ENV = {**BASE_ENV, 'PYTHONDONTWRITEBYTECODE': '1'}


class Rejected(RuntimeError):
    """Only fixed, value-free categories are emitted by the controller."""


def require(condition, category):
    if not condition:
        raise Rejected(category)


def execute(argv, *, check=True, timeout=30, quiet=False):
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C'}
    for key in ('HOME', 'XDG_RUNTIME_DIR'):
        if key in os.environ:
            environment[key] = os.environ[key]
    try:
        result = subprocess.run(argv, env=environment, text=True,
                                stdout=subprocess.DEVNULL if quiet else subprocess.PIPE,
                                stderr=subprocess.DEVNULL if quiet else subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Rejected('controller-command-unavailable-or-timeout') from error
    require(not check or result.returncode == 0, 'controller-command-failed')
    return result


def canonical_id(value):
    return bool(re.fullmatch('[0-9a-f]{64}', value))


class Runtime:
    def __init__(self, command=None, call=execute):
        self.command = command or ['/usr/bin/podman']
        self.call = call
        self.nonce = secrets.token_hex(12)
        self.receipts = {}
        self.ambiguous = False

    def podman(self, *args, **kwargs):
        return self.call([*self.command, *args], **kwargs)

    def inspect(self, cid):
        # Do not collect full inspect objects or environment values.
        fields = ('Id', 'Name', 'Image', 'State.Status', 'Config.User',
                  'Config.WorkingDir', 'Config.Entrypoint', 'Config.Cmd',
                  'Config.Labels', 'Config.Secrets', 'Config.Volumes',
                  'HostConfig', 'Mounts', 'EffectiveCaps', 'BoundingCaps')
        result = {}
        for field in fields:
            raw = self.podman('container', 'inspect', '--format', '{{json .' + field + '}}', cid).stdout
            try:
                result[field] = json.loads(raw)
            except ValueError as error:
                raise Rejected('inspect-policy-schema-unverifiable') from error
        keys = self.podman('container', 'inspect', '--format',
                           '{{range .Config.Env}}{{println (index (split . "=") 0)}}{{end}}', cid)
        result['env_keys'] = keys.stdout.split()
        result['parent_mappings'] = json.loads(self.podman('info', '--format', '{{json .Host.IDMappings}}').stdout)
        return result

    def identity(self, data, cid, name, phase):
        labels = data.get('Config.Labels') or {}
        return (data.get('Id') == cid and data.get('Name', '').lstrip('/') == name
                and all(labels.get(LABEL + key) == value for key, value in
                        [('run', self.nonce), ('gate', 'dns_contract'), ('phase', phase)]))

    def create(self, phase, args):
        name = 'statekit-r102dig-' + self.nonce + '-' + phase
        absent = self.podman('container', 'exists', name, check=False)
        require(absent.returncode == 1, 'container-name-present-or-unknown')
        labels = [item for key, value in [('run', self.nonce), ('gate', 'dns_contract'), ('phase', phase)]
                  for item in ('--label', LABEL + key + '=' + value)]
        # Set before invocation: timeout/signals can hide a partial create.
        self.ambiguous = True
        result = self.podman('create', '--name', name, *labels, *args, check=False)
        cid = result.stdout.strip()
        require(result.returncode == 0 and canonical_id(cid), 'create-unowned-preserved')
        data = self.inspect(cid)
        require(self.identity(data, cid, name, phase), 'create-identity-unverified-preserved')
        require(cid not in self.receipts, 'duplicate-create-receipt')
        self.receipts[cid] = (name, phase)
        self.ambiguous = False
        return cid

    def remove(self, cid):
        require(cid in self.receipts and canonical_id(cid), 'cleanup-without-receipt')
        name, phase = self.receipts[cid]
        state = self.podman('container', 'exists', cid, check=False).returncode
        require(state in (0, 1), 'cleanup-existence-unknown')
        if state == 0:
            require(self.identity(self.inspect(cid), cid, name, phase), 'cleanup-identity-changed')
            self.podman('rm', '--force', cid)
        require(self.podman('container', 'exists', cid, check=False).returncode == 1,
                'cleanup-absence-unverified')
        del self.receipts[cid]

    def cleanup(self):
        failed = False
        for cid in list(self.receipts):
            try:
                self.remove(cid)
            except Rejected:
                failed = True
        require(not failed, 'owned-container-cleanup-failed')


def firewall_rules(chain, uid, addresses, resolver, version):
    rules = [['-N', chain]]
    for address in sorted(set(addresses)):
        if ipaddress.ip_address(address).version == version:
            rules.append(['-A', chain, '-d', address, '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'])
    if ipaddress.ip_address(resolver).version == version:
        for protocol in ('tcp', 'udp'):
            rules.append(['-A', chain, '-d', resolver, '-p', protocol, '--dport', '53', '-j', 'ACCEPT'])
    rules.append(['-A', chain, '-j', 'DROP'])
    jump = ['-A', 'OUTPUT', '-m', 'owner', '--uid-owner', str(uid), '-j', chain]
    return rules, jump


def canonical_rule(line):
    tokens = shlex.split(line)
    result = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == '-m' and index + 1 < len(tokens) and tokens[index + 1] in ('tcp', 'udp'):
            index += 2
            continue
        if token == '-d' and index + 1 < len(tokens):
            network = ipaddress.ip_network(tokens[index + 1], strict=True)
            require(network.prefixlen == network.max_prefixlen, 'firewall-non-host-destination')
            result.extend(['-d', str(network.network_address)])
            index += 2
            continue
        result.append(token)
        index += 1
    return result


class Firewall:
    def __init__(self, uid, nonce, call=execute):
        self.uid, self.call = uid, call
        self.chain = 'SKD' + nonce[:16]
        self.owned = []
        self.jumped = []
        self.expected = {}

    def run(self, tool, *args, **kwargs):
        return self.call(['/usr/bin/sudo', '-n', '/usr/sbin/' + tool, '-w', '5', *args], **kwargs)

    def install(self, addresses, resolver):
        require(bool(addresses), 'fetch-destinations-empty')
        for version, tool in ((4, 'iptables'), (6, 'ip6tables')):
            rules, jump = firewall_rules(self.chain, self.uid, addresses, resolver, version)
            self.run(tool, '-N', self.chain)
            self.owned.append(tool)
            self.expected[tool] = (rules, jump)
            for rule in rules[1:]:
                self.run(tool, *rule)
            self.run(tool, '-I', 'OUTPUT', '1', *jump[2:])
            self.jumped.append(tool)
        self.verify()

    def verify(self):
        require(set(self.expected) == {'iptables', 'ip6tables'}, 'firewall-family-missing')
        for tool, (expected, jump) in self.expected.items():
            rules = [canonical_rule(line) for line in self.run(tool, '-S', self.chain).stdout.splitlines()]
            output = [canonical_rule(line) for line in self.run(tool, '-S', 'OUTPUT').stdout.splitlines()]
            rules_out = [rule for rule in output if rule[:2] == ['-A', 'OUTPUT']]
            require(rules == expected and bool(rules_out) and rules_out[0] == jump
                    and sum(self.chain in rule for rule in rules_out) == 1,
                    'firewall-effective-policy-mismatch')

    def deny(self):
        # Fetch is already absent; retain default-deny throughout offline tests.
        for tool in self.owned:
            old_rules, jump = self.expected[tool]
            self.run(tool, '-I', self.chain, '1', '-j', 'DROP')
            for rule in old_rules[1:]:
                self.run(tool, '-D', *rule[1:])
            self.expected[tool] = ([['-N', self.chain], ['-A', self.chain, '-j', 'DROP']], jump)
        self.verify()

    def cleanup(self):
        for tool in reversed(self.owned[:]):
            if tool in self.jumped:
                self.run(tool, '-D', 'OUTPUT', *self.expected[tool][1][2:])
                self.jumped.remove(tool)
            self.run(tool, '-F', self.chain)
            self.run(tool, '-X', self.chain)
            rows = [shlex.split(line) for line in self.run(tool, '-S').stdout.splitlines()]
            require(not any(self.chain in row for row in rows), 'firewall-cleanup-unverified')
            self.owned.remove(tool)


def sandbox_args(image, uid, gid, argv, mounts, env, *, fetch=False):
    tmpfs = '/tmp:rw,nosuid,nodev,size=3g,mode=1777' + (',noexec' if env == PY_ENV else '')
    args = ['--pull=never', '--read-only', '--read-only-tmpfs=false',
            '--userns=keep-id', '--user', f'{uid}:{gid}', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--ipc=private', '--pid=private',
            '--uts=private', '--network=' + (FETCH_NETWORK if fetch else 'none'),
            '--memory=4g', '--cpus=2', '--pids-limit=256', '--timeout=900',
            '--tmpfs=' + tmpfs,
            '--http-proxy=false', '--unsetenv-all', '--image-volume=ignore',
            '--no-healthcheck', '--log-driver=none', '--workdir=/workspace',
            '--entrypoint=' + argv[0]]
    for source, destination, writable in mounts:
        args.extend(['--mount', f'type=bind,src={source},dst={destination},'
                     + ('rw' if writable else 'ro') + ',nosuid,nodev,noexec'])
    for key, value in env.items():
        args.extend(['--env', key + '=' + value])
    return [*args, image, *argv[1:]]


def verify_policy(data, image_id, uid, gid, argv, mounts, env, *, fetch=False):
    host = data['HostConfig']
    require(data['State.Status'] == 'created' and data['Image'].removeprefix('sha256:') == image_id.removeprefix('sha256:'),
            'sandbox-image-or-state-mismatch')
    require(data['Config.User'] == f'{uid}:{gid}' and data['Config.WorkingDir'] == '/workspace', 'sandbox-user-or-workdir-mismatch')
    require(data['Config.Entrypoint'] in (argv[0], [argv[0]]) and data['Config.Cmd'] == argv[1:], 'sandbox-argv-mismatch')
    require(host['Privileged'] is False and host['ReadonlyRootfs'] is True
            and not data['EffectiveCaps'] and not data['BoundingCaps'], 'sandbox-privilege-mismatch')
    require('no-new-privileges' in host['SecurityOpt'] or 'no-new-privileges=true' in host['SecurityOpt'], 'sandbox-nnp-missing')
    require(not any('unconfined' in option for option in host['SecurityOpt']), 'sandbox-unconfined')
    require(host['NetworkMode'] == ('slirp4netns' if fetch else 'none'), 'sandbox-network-mismatch')
    require(all(host[key] == 'private' for key in ('IpcMode', 'PidMode', 'UTSMode')), 'sandbox-namespace-mismatch')
    mappings = host.get('IDMappings')
    require(isinstance(mappings, dict), 'sandbox-user-mapping-unverifiable')
    for key, parent_key, identity in (('UidMap', 'uidmap', uid), ('GidMap', 'gidmap', gid)):
        # Inspect maps into Podman's rootless parent user namespace, where
        # ID 0 must map to this exact filtered host UID/GID, not host root.
        require(f'{identity}:0:1' in mappings.get(key, []), 'sandbox-user-mapping-mismatch')
        require({'container_id': 0, 'host_id': identity, 'size': 1}
                in data['parent_mappings'][parent_key], 'sandbox-parent-mapping-mismatch')
    for key in ('Devices', 'PortBindings', 'VolumesFrom', 'GroupAdd', 'Links', 'ExtraHosts', 'Dns', 'DnsOptions', 'DnsSearch'):
        require(key in host and not host[key], 'sandbox-extra-host-access')
    require(not host.get('DeviceRequests'), 'sandbox-extra-device-request')
    require(not data['Config.Secrets'] and not data['Config.Volumes'], 'sandbox-secret-or-volume')
    require(sorted(data['env_keys']) == sorted(env), 'sandbox-environment-mismatch')
    actual = data['Mounts']
    require(len(actual) == len(mounts), 'sandbox-extra-mount')
    require(len(host['Binds'] or []) == len(mounts), 'sandbox-extra-bind')
    for source, destination, writable in mounts:
        matches = [m for m in actual if m.get('Destination') == destination]
        require(len(matches) == 1, 'sandbox-mount-missing')
        mount = matches[0]
        require(mount.get('Type') == 'bind' and mount.get('Source') == str(source)
                and mount.get('RW') is writable
                and {'nosuid', 'nodev', 'noexec'} <= set(mount.get('Options', []))
                <= {'nosuid', 'nodev', 'noexec', 'rbind', 'bind'}
                and mount.get('Propagation') == 'rprivate', 'sandbox-mount-mismatch')
    tmpfs = host['Tmpfs']
    required_tmpfs = {'rw', 'nosuid', 'nodev', 'size=3g', 'mode=1777'}
    if env == PY_ENV:
        required_tmpfs.add('noexec')
    require(set(tmpfs) == {'/tmp'} and required_tmpfs <= set(tmpfs['/tmp'].split(','))
            <= required_tmpfs | {'rprivate', 'tmpcopyup'}, 'sandbox-tmpfs-mismatch')
    require(host['Memory'] == 4 * 1024 ** 3 and host['PidsLimit'] == 256
            and host['NanoCpus'] == 2 * 10**9, 'sandbox-resource-policy-mismatch')


def preflight(runtime):
    require(os.getuid() != 0, 'runtime-is-not-non-root')
    for key in ('CONTAINER_HOST', 'DOCKER_HOST', 'PODMAN_HOST', 'CONTAINER_CONNECTION',
                'DOCKER_CONFIG', 'DOCKER_AUTH_CONFIG', 'REGISTRY_AUTH_FILE', 'CONTAINERS_AUTH_FILE', 'SSH_AUTH_SOCK'):
        require(key not in os.environ, 'runtime-host-credential-or-remote-environment')
    require(os.environ.get('CONTAINER_RUNTIME', 'podman') == 'podman', 'runtime-not-podman')
    require(runtime.podman('info', '--format', '{{.Host.Security.Rootless}}').stdout.strip() == 'true', 'runtime-not-rootless')
    require(runtime.podman('info', '--format', '{{.Host.ServiceIsRemote}}').stdout.strip() == 'false', 'runtime-remote')
    require(runtime.podman('info', '--format', '{{.Host.Security.SeccompEnabled}}').stdout.strip() == 'true', 'runtime-seccomp-unavailable')
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Linux'
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_EVENT_NAME') in ('push', 'workflow_dispatch', 'schedule'), 'runner-context-unverified')
    release = Path('/etc/os-release').read_text()
    require('ID=ubuntu\n' in release and 'VERSION_ID="24.04"' in release, 'runner-os-unverified')
    for name, image in (('GO_TOOLCHAIN_IMAGE', GO_IMAGE), ('PYTHON_CHECK_IMAGE', PYTHON_IMAGE)):
        require(os.environ.get(name, image) == image, 'image-override-rejected')
    for path in ('internal/cli/dig_cli_test.go', 'modules/exec/dig/dig_test.go'):
        require((ROOT / path).read_text().splitlines()[0] == '//go:build dns_contract', 'contract-build-tag-missing')
    require(re.search(r'^go 1\.26\.6$', (ROOT / 'go.mod').read_text(), re.M), 'go-version-unlocked')
    require(not re.search(r'^\s*(replace|toolchain)\b', (ROOT / 'go.mod').read_text(), re.M), 'go-manifest-override')


def image_identity(runtime, image):
    # No mutable tags or new identities are accepted.
    digest = image.split('@')[1]
    refs = json.loads(runtime.podman('image', 'inspect', '--format', '{{json .RepoDigests}}', image).stdout)
    require(any(ref.endswith('@' + digest) for ref in refs), 'image-digest-unverified')
    identity = runtime.podman('image', 'inspect', '--format', '{{.Id}}', image).stdout.strip()
    require(canonical_id(identity.removeprefix('sha256:')), 'image-id-unverified')
    return identity


def stage_source(destination):
    # Explicit source roots; never mount checkout metadata or host config.
    roots = ('cmd', 'internal', 'modules', 'providers', 'tests', 'tools', 'docs', 'references', 'saltstack')
    blocked = {'.git', '.gotmp', '.ssh', '.aws', '.azure', '.config', '.docker',
               '.env', '.netrc', '.git-credentials', '__pycache__'}

    def copy(source, target):
        if source.name in blocked or source.name.startswith('.env.'):
            return
        require(not source.is_symlink(), 'source-symlink-rejected')
        mode = source.stat().st_mode
        if stat.S_ISDIR(mode):
            target.mkdir()
            for child in source.iterdir():
                copy(child, target / child.name)
        else:
            require(stat.S_ISREG(mode) and source.stat().st_nlink == 1, 'source-special-file-rejected')
            shutil.copyfile(source, target)
            target.chmod(0o444)

    destination.mkdir()
    for name in roots:
        if (ROOT / name).exists():
            copy(ROOT / name, destination / name)
    for name in ('go.mod', 'go.sum'):
        copy(ROOT / name, destination / name)
    workflow = destination / '.github/workflows'
    workflow.mkdir(parents=True)
    copy(ROOT / '.github/workflows/integration-services.yml', workflow / 'integration-services.yml')


def existing_module_cache():
    # Latest authorization is cache-only. Never install, fetch, or guess an
    # alternate cache when this exact pre-provisioned directory is unavailable.
    base = Path(os.environ.get('RUNNER_TEMP', ''))
    require(base.is_absolute() and base.resolve() == base, 'runner-temp-unverified')
    cache = base / 'statekit-r102dig-modcache'
    require(cache.is_dir() and not cache.is_symlink(), 'offline-module-cache-unavailable')
    for directory, dirs, files in os.walk(cache, followlinks=False):
        for path in [Path(directory), *(Path(directory) / name for name in dirs + files)]:
            metadata = path.lstat()
            require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode), 'offline-cache-special-file')
            require(metadata.st_uid == os.getuid() and not metadata.st_mode & 0o022,
                    'offline-cache-ownership-or-mode')
    return cache


def run_stage(runtime, phase, image, image_id, argv, mounts, env, *, fetch=False, firewall=None):
    uid, gid = os.getuid(), os.getgid()
    cid = runtime.create(phase, sandbox_args(image, uid, gid, argv, mounts, env, fetch=fetch))
    verify_policy(runtime.inspect(cid), image_id, uid, gid, argv, mounts, env, fetch=fetch)
    if fetch:
        require(firewall is not None, 'fetch-firewall-missing')
    if firewall is not None:
        firewall.verify()
    result = runtime.podman('start', '--attach', cid, check=False, timeout=910, quiet=True)
    if firewall is not None:
        firewall.verify()
    runtime.remove(cid)
    require(result.returncode == 0, 'sandbox-stage-failed')
    print('r10.2-dig-contract: ' + phase + ' passed', flush=True)


def main():
    runtime = Runtime()
    work = None
    try:
        preflight(runtime)
        images = {image: image_identity(runtime, image) for image in (GO_IMAGE, PYTHON_IMAGE)}
        cache = existing_module_cache()
        if sys.argv[1:] == ['--preflight-only']:
            print('r10.2-dig-contract: preflight passed')
            return
        require(sys.argv[1:] == ['--ci'], 'invalid-controller-mode')
        work = Path(tempfile.mkdtemp(prefix='statekit-r102dig-'))
        source = work / 'source'
        stage_source(source)
        payload = ['/bin/bash', '/workspace/tests/live/dig/payload.sh']
        run_stage(runtime, 'python', PYTHON_IMAGE, images[PYTHON_IMAGE], [*payload, 'python'],
                  [(source, '/workspace', False)], PY_ENV)
        run_stage(runtime, 'go-preflight', GO_IMAGE, images[GO_IMAGE], [*payload, 'go-preflight'],
                  [(source, '/workspace', False), (cache, '/cache', False)], GO_ENV)
        run_stage(runtime, 'verify', GO_IMAGE, images[GO_IMAGE], [*payload, 'verify'],
                  [(source, '/workspace', False), (cache, '/cache', False)], GO_ENV)
        run_stage(runtime, 'contract', GO_IMAGE, images[GO_IMAGE], [*payload, 'contract'],
                  [(source, '/workspace', False), (cache, '/cache', False)], GO_ENV)
    finally:
        runtime.cleanup()
        # Preserve workspace if partial-create ownership is unknown.
        require(not runtime.ambiguous, 'unowned-partial-create-preserved')
        if work is not None:
            shutil.rmtree(work)


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise Rejected('controller-interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        require(sys.argv[1:] == ['--runner-preflight'], 'legacy-image-controller-disabled')
        preflight(Runtime())
    except (Rejected, KeyError, ValueError, OSError) as error:
        print('r10.2-dig-contract: ' + (str(error) if isinstance(error, Rejected) else 'policy-unverifiable'), file=sys.stderr)
        sys.exit(1)
