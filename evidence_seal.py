"""Content-addressed evidence manifests. Python 3.11+, standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys


def digest_file(path):
    # Reject symlinks at open time where the platform supports O_NOFOLLOW.
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f'Not a regular file: {path}')
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError(f'File changed while hashing: {path}')
        return {'size': after.st_size, 'sha256': digest.hexdigest()}


def inventory(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Evidence root must be a directory')
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
                raise ValueError(f'Linked evidence is forbidden: {path}')
        for name in files:
            path = Path(directory) / name
            result[path.relative_to(root).as_posix()] = digest_file(path)
    return dict(sorted(result.items()))


def seal(root, case_id):
    return {'schema': 'evidence-seal/v1', 'case_id': case_id, 'files': inventory(root)}


def validate_manifest(manifest):
    if manifest.get('schema') != 'evidence-seal/v1' or not isinstance(manifest.get('files'), dict):
        raise ValueError('Unsupported manifest schema')
    for name, entry in manifest['files'].items():
        path = PurePosixPath(name)
        if not name or '\\' in name or ':' in name or path.is_absolute() or '..' in path.parts or str(path) != name:
            raise ValueError(f'Unsafe manifest path: {name}')
        if not isinstance(entry, dict) or type(entry.get('size')) is not int or entry['size'] < 0:
            raise ValueError(f'Invalid file size: {name}')
        value = entry.get('sha256', '')
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError(f'Invalid SHA-256: {name}')


def verify(root, manifest):
    validate_manifest(manifest)
    current = inventory(root)
    expected = manifest['files']
    return {
        'case_id': manifest.get('case_id'),
        'added': sorted(current.keys() - expected.keys()),
        'missing': sorted(expected.keys() - current.keys()),
        'modified': sorted(name for name in current.keys() & expected.keys() if current[name] != expected[name]),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('seal')
    create.add_argument('root', type=Path)
    create.add_argument('--case-id', required=True)
    create.add_argument('--output', required=True, type=Path)
    check = commands.add_parser('verify')
    check.add_argument('root', type=Path)
    check.add_argument('manifest', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'seal':
            if args.output.resolve().is_relative_to(args.root.resolve()):
                raise ValueError('Store the manifest outside the evidence root')
            data = seal(args.root, args.case_id)
            with args.output.open('x', encoding='utf-8') as output:
                json.dump(data, output, indent=2, sort_keys=True)
                output.write('\n')
            return 0
        report = verify(args.root, json.loads(args.manifest.read_text(encoding='utf-8')))
        print(json.dumps(report, indent=2))
        return int(any(report[key] for key in ('added', 'missing', 'modified')))
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
