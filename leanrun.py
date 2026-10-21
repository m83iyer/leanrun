#!/usr/bin/env python3
"""Opt-in local evidence reuse. Python 3.9+, macOS/Linux, no dependencies."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = 1


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def safe_file(root, name):
    p = Path(name)
    if p.is_absolute() or '..' in p.parts:
        raise ValueError('Inputs must be relative paths without ..')
    cur = root
    for part in p.parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError('Symlink inputs are not supported')
    if not cur.is_file():
        raise ValueError('Each declared input must be a regular file')
    return cur


def fingerprint(args):
    root = Path(args.root).resolve(strict=True)
    names = sorted(set(args.file + [args.input, args.env]))
    files = {name: digest(safe_file(root, name).read_bytes()) for name in names}
    # Environment descriptors must be explicit JSON, not guessed from process globals.
    for name in (args.input, args.env):
        json.loads(safe_file(root, name).read_text())
    material = dict(version=VERSION, root=str(root), scope=args.scope,
                    command=args.command, files=files,
                    python=sys.version, platform=platform.platform(),
                    wrapper=digest(Path(__file__).read_bytes()))
    return digest(encoded(material))


def atomic_json(path, value):
    fd, temp = tempfile.mkstemp(prefix='.record-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(encoded(value)); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def private_dir(path):
    path = Path(path).absolute()
    # Reject symlink state components instead of following them.
    for p in [path] + list(path.parents):
        if p.is_symlink():
            raise ValueError('State path may not contain symlinks')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('State directory must be owned by you with mode 0700')
    return path


@contextlib.contextmanager
def claim(state, task):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', task):
        raise ValueError('Task must contain 1-64 letters, numbers, _ or -')
    task_dir = private_dir(state / task)
    fd = os.open(task_dir / 'owner.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Task already owned; no duplicate command started')
        yield task_dir
    finally:
        os.close(fd)


def read_record(path):
    if path.is_symlink():
        raise ValueError('Symlink records are not supported')
    if not path.exists():
        return None
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get('state') not in ('running', 'passed', 'failed', 'released'):
        raise ValueError('Invalid evidence record')
    if value['state'] == 'released':
        if not isinstance(value.get('released_at'), (int, float)):
            raise ValueError('Invalid released evidence')
        return value
    if not re.fullmatch(r'[0-9a-f]{64}', str(value.get('fingerprint', ''))) or not re.fullmatch(r'[0-9a-f]{32}\.log', str(value.get('log', ''))):
        raise ValueError('Invalid evidence identity')
    if value['state'] == 'passed':
        if type(value.get('exit_code')) is not int or value['exit_code'] != 0 or value.get('inputs_unchanged') is not True or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('log_sha256', ''))):
            raise ValueError('Inconsistent passed evidence')
    return value


def log_file(task_dir, record):
    name = record.get('log', '')
    if not re.fullmatch(r'[0-9a-f]{32}\.log', name):
        raise ValueError('Invalid log identity')
    return safe_file(task_dir, name)


def log_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def report(task_dir, record, reused=False):
    log = log_file(task_dir, record)
    with log.open('rb') as f:
        f.seek(0, 2); size = f.tell(); f.seek(max(0, size - 4096))
        tail = f.read(4096).decode('utf-8', errors='replace')
    print(json.dumps(dict(state=record['state'], reused=reused,
                         exit_code=record.get('exit_code'), log=str(log),
                         log_bytes=size, tail_source_max_bytes=4096, tail=tail)))


def run(args):
    if not args.command:
        raise ValueError('A command is required after --')
    state = private_dir(args.state)
    with claim(state, args.task) as task_dir:
        path = task_dir / 'evidence.json'
        old = read_record(path)
        if old and old.get('state') == 'running':
            raise ValueError('Interrupted run: inspect it and explicitly release before retry')
        before = fingerprint(args)
        if old and old.get('state') == 'passed' and old.get('fingerprint') == before:
            log = log_file(task_dir, old)
            if log_hash(log) != old.get('log_sha256'):
                raise ValueError('Evidence log integrity mismatch; inspect and release')
            report(task_dir, old, True)
            return 0
        if old:
            atomic_json(task_dir / ('history-'+uuid.uuid4().hex+'.json'), old)
        record = dict(state='running', fingerprint=before, log=uuid.uuid4().hex+'.log',
                      started_at=time.time())
        atomic_json(path, record)
        logfile = task_dir / record['log']
        try:
            fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                # No shell; do not store argv or environment in evidence or print them.
                result = subprocess.run(args.command, cwd=Path(args.root).resolve(),
                                        stdin=subprocess.DEVNULL, stdout=out,
                                        stderr=subprocess.STDOUT, timeout=args.timeout)
            record['exit_code'] = result.returncode
            after = fingerprint(args)
            record['state'] = 'passed' if result.returncode == 0 and after == before else 'failed'
            record['inputs_unchanged'] = after == before
        except (Exception, KeyboardInterrupt) as exc:
            record['state'] = 'failed'
            record['error_type'] = type(exc).__name__
        record['finished_at'] = time.time()
        if logfile.is_file():
            record['log_sha256'] = log_hash(logfile)
        atomic_json(path, record)
        if logfile.is_file():
            report(task_dir, record)
        else:
            print(json.dumps({'state':'failed', 'error_type':record.get('error_type')}))
        return 0 if record['state'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('run')
    p.add_argument('--state', default='.leanrun')
    p.add_argument('--task', required=True)
    p.add_argument('--root', required=True)
    p.add_argument('--scope', required=True)
    p.add_argument('--input', required=True, help='Relative JSON input descriptor')
    p.add_argument('--env', required=True, help='Relative JSON environment descriptor')
    p.add_argument('--file', action='append', default=[], help='Repeat for EVERY dependency')
    p.add_argument('--timeout', type=float, default=300)
    p.add_argument('command', nargs=argparse.REMAINDER)
    p = sub.add_parser('release', help='Explicitly invalidate evidence after inspecting a stopped run')
    p.add_argument('--state', default='.leanrun'); p.add_argument('--task', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'run':
            if args.command[:1] == ['--']:
                args.command = args.command[1:]
            if not 0 < args.timeout <= 86400:
                raise ValueError('Timeout must be > 0 and <= 86400 seconds')
            return run(args)
        with claim(private_dir(args.state), args.task) as task_dir:
            path = task_dir / 'evidence.json'
            old = read_record(path)
            # Keep full log and prior evidence, rather than deleting originals.
            if old:
                atomic_json(task_dir / ('history-'+uuid.uuid4().hex+'.json'), old)
            atomic_json(path, dict(state='released', released_at=time.time()))
            print(json.dumps({'state':'released'}))
        return 0
    except (ValueError, OSError) as exc:
        print(json.dumps({'state':'blocked', 'reason':str(exc)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
