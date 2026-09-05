"""Intentionally failing, deterministic reproduction demo."""
from pathlib import Path
import sys

value = Path('input.txt').read_text().strip()
if value == 'trigger':
    print('ParserError: expected a number, received trigger', file=sys.stderr)
    raise SystemExit(7)
print(int(value))
