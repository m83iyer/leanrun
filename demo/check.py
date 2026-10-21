import json
from pathlib import Path
assert json.loads(Path('inputs.json').read_text())['case'] == 'safe-demo'
print('PASS: safe local demo')
