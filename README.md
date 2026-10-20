# Evidence Seal

Detect changes to engagement evidence using deterministic SHA-256 manifests. Keep a baseline outside the evidence directory and compare it before report delivery or handover.

## Run

Requires Python 3.12 or later. No runtime dependencies or network access.

```sh
python evidence_seal.py seal ./evidence --case-id ENG-001 --output manifest.json
python evidence_seal.py verify ./evidence manifest.json
python -m unittest discover -v
```

Create `evidence/` and place copied engagement artifacts inside it first. `seal` refuses to overwrite an existing manifest. `verify` returns JSON lists of added, missing, and modified paths. Empty evidence sets are permitted and should be assessed by the reviewer.

## Design

Files are read in 1 MiB blocks. File size and modification time are checked around hashing to catch ordinary concurrent modifications. Paths are relative and sorted, giving stable output for identical content. Symlinks and Windows junctions are rejected. Manifest paths and digests are validated before comparison. The manifest must be written outside the evidence root to avoid self-inclusion.

## Trust boundary

A checksum baseline detects changes only while the baseline itself remains trusted. It does not authenticate a collector, prove collection time, establish legal chain of custody, or prevent a privileged adversary from replacing both evidence and manifest. Sign or independently timestamp the baseline using your organization's approved process. Work from a read-only snapshot; this implementation is not race-proof against an attacker modifying the directory tree during collection. On platforms without `O_NOFOLLOW`, open-time link rejection is weaker. File metadata, ACLs, alternate data streams, and empty directories are outside the manifest.

## Review scenario

Seal a copied capture directory, modify one capture, delete another, and add an analyst note. Verification identifies each change class separately without changing any evidence files.
