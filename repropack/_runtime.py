"""Dependency-free execution helpers. Temporary workspaces are NOT sandboxes."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

MAX_BYTES = 2 * 1024 * 1024
MAX_PROJECT = 50 * 1024 * 1024
SKIP = {'.git', '.venv', 'venv', '__pycache__', 'node_modules', '.pytest_cache', '.mypy_cache'}


def dump(path, value):
    """Atomically publish UTF-8 JSON with owner-only temporary permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as f:
        temporary = Path(f.name)
        json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write('\n')
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def child_env(home, extra=None):
    """Do not implicitly inherit credentials, proxies, PYTHONPATH or user HOME."""
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    env = {k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'PATHEXT') if k in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), TMPDIR=str(home), TEMP=str(home),
               TMP=str(home), LANG='C.UTF-8', PYTHONIOENCODING='utf-8',
               PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1')
    env.update(extra or {})
    return env


def command(value):
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x and '\x00' not in x for x in value):
        raise ValueError('Command must be a non-empty argument array, not shell text.')
    return value


def run(argv, cwd, *, timeout=30, env=None, stdin='', limit=MAX_BYTES):
    """Bound captured output and elapsed time; terminate the POSIX process group."""
    command(argv)
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600:
        raise ValueError('Timeout must be between 0 and 3600 seconds.')
    started = time.monotonic()
    status, process = 'completed', None
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as inp:
        inp.write(stdin.encode('utf-8'))
        inp.seek(0)
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=inp, stdout=out,
                                       stderr=err, start_new_session=(os.name == 'posix'))
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    status = 'timeout'
                    break
                if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > limit:
                    status = 'output_limit'
                    break
                time.sleep(0.01)
        except OSError as exc:
            return {'status': 'unavailable', 'exit_code': None, 'stdout': '', 'stderr': str(exc),
                    'seconds': round(time.monotonic() - started, 3)}
        finally:
            if process is not None:
                try:
                    if os.name == 'posix':
                        os.killpg(process.pid, signal.SIGKILL)
                    elif process.poll() is None:
                        process.kill()
                except ProcessLookupError:
                    pass
                process.wait()
        total = os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size
        if status == 'completed' and total > limit:
            status = 'output_limit'
        out.seek(0)
        err.seek(0)
        return {'status': status, 'exit_code': process.returncode,
                'stdout': out.read(limit).decode('utf-8', errors='replace'),
                'stderr': err.read(limit).decode('utf-8', errors='replace'),
                'seconds': round(time.monotonic() - started, 3)}


def relative(root, name):
    """Reject lexical traversal and symlink paths before resolving."""
    root = Path(root).resolve()
    name = str(name)
    if not name or '\\' in name or '\x00' in name:
        raise ValueError(f'Invalid relative path: {name!r}')
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or ':' in name:
        raise ValueError(f'Path must stay inside the project: {name!r}')
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f'Symlinks are not supported: {name}')
    if not current.resolve().is_relative_to(root):
        raise ValueError(f'Path escapes the project: {name!r}')
    return current


def copy_project(source, destination):
    """Copy ordinary project files, excluding hidden files and common secrets."""
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not source.is_dir() or destination.is_relative_to(source):
        raise ValueError('Source must be a directory; destination must be outside it.')
    destination.mkdir(parents=True, exist_ok=True)
    size = 0
    for base, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith('.'))
        for name in dirs + files:
            if (Path(base) / name).is_symlink():
                raise ValueError(f'Symlink refused: {(Path(base) / name).relative_to(source)}')
        for name in sorted(files):
            if name.startswith('.') or Path(name).suffix.lower() in {'.pem', '.key', '.p12'}:
                continue
            path = Path(base) / name
            if not path.is_file():
                raise ValueError(f'Not an ordinary file: {path}')
            size += path.stat().st_size
            if size > MAX_PROJECT:
                raise ValueError('Project exceeds the 50 MiB copy limit.')
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    return size


def snapshot(root):
    root, result = Path(root), {}
    count = total = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        for name in dirs + files:
            if (Path(base) / name).is_symlink():
                raise ValueError('Workspace contains a symlink; refusing to follow it.')
        for name in sorted(files):
            path = Path(base) / name
            if not path.is_file():
                raise ValueError('Workspace contains a special file.')
            size = path.stat().st_size
            count += 1
            total += size
            if count > 10000 or size > MAX_BYTES or total > MAX_PROJECT:
                raise ValueError('Evidence exceeds 10,000 files, 2 MiB per file or 50 MiB total.')
            result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    return result
