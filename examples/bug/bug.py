from pathlib import Path
text=Path('input.txt').read_text().strip()
print('input:',text)
if text=='trigger':
    raise TypeError('intentional parser failure')
