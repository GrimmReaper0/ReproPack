"""Inspectable bug reports with verified inputs and explicit replay consent."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tempfile
import zipfile
from . import __version__
from ._runtime import child_env, command, dump, relative, run, sha

MAX_ARCHIVE = 25 * 1024 * 1024
MAX_INPUT = 20 * 1024 * 1024
SECRET = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})|(?:password|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*[\"\']?[^\s\"\']{8,}', re.I)


def redact(text):
    text = SECRET.sub('[REDACTED]', text)
    for name, value in os.environ.items():
        if re.search(r'TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY', name, re.I) and len(value) >= 8:
            text = text.replace(value, '[REDACTED]')
    return text


def safe_name(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name or '\x00' in name:
        raise ValueError('Invalid archive member name.')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != name or name.endswith('/'):
        raise ValueError(f'Unsafe archive path: {name!r}')
    return name


def collect(root, includes):
    root = Path(root).resolve()
    if not root.is_dir() or not includes:
        raise ValueError('Provide a project directory and at least one --include file or glob.')
    inputs, total = {}, 0
    for pattern in includes:
        relative(root, pattern)
        matches = sorted(root.glob(pattern))
        if not matches:
            raise ValueError(f'Include matched nothing: {pattern}')
        for path in matches:
            name = path.relative_to(root).as_posix()
            relative(root, name)
            safe_name(name)
            if not path.is_file():
                raise ValueError(f'Include only ordinary files: {name}')
            if any(part.startswith('.') for part in path.relative_to(root).parts) or path.suffix.lower() in {'.pem', '.key', '.p12'}:
                raise ValueError(f'Potential credential file excluded: {name}')
            if name in inputs:
                continue
            total += path.stat().st_size
            if total > MAX_INPUT or len(inputs) >= 1000:
                raise ValueError('Selected inputs exceed 20 MiB or 1,000 files.')
            data = path.read_bytes()
            text = data.decode('utf-8', errors='replace')
            if redact(text) != text:
                raise ValueError(f'Potential secret in {name}. Sanitize before capture.')
            inputs[name] = data
    return inputs


def canonical_command(argv):
    command(argv)
    if any(redact(arg) != arg for arg in argv) or any(re.fullmatch(r'--?(?:password|token|api-key|secret)(?:=.*)?', arg, re.I) for arg in argv):
        raise ValueError('Potential secret in command arguments. Use a sanitized reproduction.')
    return ['{python}' if i == 0 and arg in {'python', 'python3', sys.executable, '{python}'} else arg for i, arg in enumerate(argv)]


def resolved_command(argv):
    return [sys.executable if arg == '{python}' else arg for arg in command(argv)]


def normalize(text, work, home):
    for original, replacement in ((work.resolve(), '$WORKSPACE'), (work, '$WORKSPACE'), (home.resolve(), '$HOME'), (home, '$HOME')):
        text = text.replace(str(original), replacement)
    return redact(text.replace('\r\n', '\n'))


def capture(root, includes, argv, output, *, timeout=30):
    output = Path(output)
    if output.exists():
        raise ValueError('Output already exists. Captures are not silently overwritten.')
    inputs = collect(root, includes)
    argv = canonical_command(argv)
    modes = {name: (0o755 if (Path(root)/name).stat().st_mode & 0o111 else 0o644) for name in inputs}
    with tempfile.TemporaryDirectory(prefix='repropack-') as temporary:
        base = Path(temporary)
        work, home = base/'workspace', base/'home'
        work.mkdir()
        for name, data in inputs.items():
            path = relative(work, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(modes[name])
        result = run(resolved_command(argv), work, timeout=timeout, env=child_env(home))
        result['stdout'] = normalize(result['stdout'], work, home)
        result['stderr'] = normalize(result['stderr'], work, home)
        payloads = {'files/' + name: data for name, data in inputs.items()}
        payloads.update({'stdout.txt': result.pop('stdout').encode(), 'stderr.txt': result.pop('stderr').encode()})
        manifest = {'schema': 1, 'tool': 'repropack', 'version': __version__,
                    'created_at': datetime.now(timezone.utc).isoformat(), 'command': argv,
                    'runtime': {'python': platform.python_version(), 'system': platform.system(), 'machine': platform.machine()},
                    'capture': result, 'timeout': timeout,
                    'members': {name: {'sha256': sha(data), 'bytes': len(data),
                                      'mode': modes.get(name[6:], 0o644) if name.startswith('files/') else 0o644}
                                for name, data in payloads.items()}}
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as handle:
            temporary_zip = Path(handle.name)
        try:
            with zipfile.ZipFile(temporary_zip, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('manifest.json', json.dumps(manifest, indent=2, sort_keys=True) + '\n')
                for name, data in sorted(payloads.items()):
                    archive.writestr(name, data)
            with output.open('xb') as target:
                target.write(temporary_zip.read_bytes())
        finally:
            temporary_zip.unlink(missing_ok=True)
    return manifest


def inspect(path):
    """Validate names, types, expansion limits and hashes without extraction."""
    path = Path(path)
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError('Archive exceeds the 25 MiB limit.')
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > 1003 or sum(i.file_size for i in infos) > MAX_ARCHIVE:
            raise ValueError('Archive expands beyond the file count or size limit.')
        names = [safe_name(i.filename) for i in infos]
        if len(names) != len(set(n.casefold() for n in names)) or names.count('manifest.json') != 1:
            raise ValueError('Archive has duplicate/ambiguous names or no unique manifest.')
        for info in infos:
            kind = stat.S_IFMT(info.external_attr >> 16)
            if kind not in (0, stat.S_IFREG) or info.flag_bits & 1:
                raise ValueError('Links, directories, special and encrypted members are refused.')
        if archive.getinfo('manifest.json').file_size > 1024 * 1024:
            raise ValueError('Manifest is too large.')
        manifest = json.loads(archive.read('manifest.json'))
        if not isinstance(manifest, dict) or manifest.get('schema') != 1 or manifest.get('tool') != 'repropack':
            raise ValueError('Unsupported ReproPack archive schema.')
        command(manifest['command'])
        if not 0 < manifest['timeout'] <= 3600 or not isinstance(manifest['members'], dict):
            raise ValueError('Invalid manifest.')
        if set(names) != {'manifest.json'} | set(manifest['members']):
            raise ValueError('Archive members do not match the manifest.')
        payloads = {}
        for name, metadata in manifest['members'].items():
            if name not in {'stdout.txt', 'stderr.txt'} and not name.startswith('files/'):
                raise ValueError(f'Unexpected member: {name}')
            if not isinstance(metadata, dict) or metadata.get('mode', 0o644) not in {0o644, 0o755}:
                raise ValueError('Unsupported metadata or file mode.')
            data = archive.read(name)
            if len(data) != metadata['bytes'] or sha(data) != metadata['sha256']:
                raise ValueError(f'Integrity check failed: {name}')
            payloads[name] = data
        if not {'stdout.txt', 'stderr.txt'} <= set(payloads):
            raise ValueError('Capture logs are missing.')
        return manifest, payloads


def replay(path, *, timeout=None):
    manifest, payloads = inspect(path)
    with tempfile.TemporaryDirectory(prefix='repropack-') as temporary:
        base = Path(temporary)
        work, home = base/'workspace', base/'home'
        work.mkdir()
        for name, data in payloads.items():
            if name.startswith('files/'):
                target = relative(work, name[6:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(manifest['members'][name].get('mode', 0o644))
        result = run(resolved_command(manifest['command']), work,
                     timeout=manifest['timeout'] if timeout is None else timeout, env=child_env(home))
        result['stdout'] = normalize(result['stdout'], work, home)
        result['stderr'] = normalize(result['stderr'], work, home)
        expected = manifest['capture']
        matches = (result['status'] == expected['status'] == 'completed'
                   and result['exit_code'] == expected['exit_code']
                   and result['stderr'] == payloads['stderr.txt'].decode('utf-8')
                   and result['stdout'] == payloads['stdout.txt'].decode('utf-8'))
        return {'schema': 1, 'tool': 'repropack', 'reproduced': matches,
                'match_rule': 'completed + same exit code + normalized stdout and stderr',
                'expected_exit': expected['exit_code'], 'actual': result,
                'captured_runtime': manifest['runtime'], 'replay_python': platform.python_version()}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Stop describing bugs. Send inspectable reproductions.')
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('capture')
    p.add_argument('--root', type=Path, default=Path('.'))
    p.add_argument('--include', action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--timeout', type=float, default=30)
    p.add_argument('--trust', action='store_true', required=True, help='Authorize local execution. NOT a sandbox.')
    p.add_argument('command', nargs=argparse.REMAINDER)
    for name in ('inspect', 'run'):
        p = sub.add_parser(name)
        p.add_argument('archive', type=Path)
        p.add_argument('--json', type=Path, dest='report')
        if name == 'run':
            p.add_argument('--trust', action='store_true', required=True, help='Authorize the archive command to execute locally.')
            p.add_argument('--timeout', type=float)
    args = parser.parse_args(argv)
    try:
        if args.action == 'capture':
            cmd = args.command[1:] if args.command[:1] == ['--'] else args.command
            report = capture(args.root, args.include, cmd, args.output, timeout=args.timeout)
            print(f'Created {args.output}: {len(report["members"])-2} inputs; captured exit {report["capture"]["exit_code"]}.')
            print('Inspect before sharing. Secret scanning is best effort, not a guarantee.')
            return 0
        if args.action == 'inspect':
            manifest, _ = inspect(args.archive)
            if args.report:
                dump(args.report, manifest)
            print(json.dumps(manifest, indent=2))
            print('Integrity verified. Nothing executed. Checksums do not authenticate the author.')
            return 0
        report = replay(args.archive, timeout=args.timeout)
        if args.report:
            dump(args.report, report)
        print('REPRODUCED' if report['reproduced'] else 'NOT REPRODUCED')
        print(report['match_rule'])
        return 0 if report['reproduced'] else 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f'repropack: {exc}', file=sys.stderr)
        return 2


def entrypoint():
    raise SystemExit(main())
