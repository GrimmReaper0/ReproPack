# ReproPack

**Stop describing bugs. Send inspectable reproductions.**

ReproPack captures selected inputs, a sanitized command, normalized output, runtime metadata and checksums into a portable `.repro` ZIP. Recipients can inspect integrity without execution, then explicitly opt in to replay it.

## Install

```sh
git clone https://github.com/GrimmReaper0/ReproPack.git
cd ReproPack
python3 -m venv .venv && . .venv/bin/activate
python -m pip install .
repropack --help
```

## Quick start

```sh
repropack capture --trust --root examples/bug --include bug.py --include input.txt --output bug.repro -- python bug.py
repropack inspect bug.repro
repropack run --trust bug.repro
```

`inspect` never executes archive code. `run` requires explicit `--trust`. Captures are limited in size, reject unsafe archive paths and common credential files, and verify SHA-256 integrity before replay. Secret detection is best-effort, not a guarantee. ReproPack is an early source release, not a sandbox and not an environment/OS virtualizer.

Requires Python 3.11+ on Linux or macOS. MIT licensed.
