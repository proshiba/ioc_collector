"""conftest.py

Add the `app/` and `app/bin/` directories to sys.path so that `module.*`,
`collect_iocs`, and other bin scripts are importable from every test file in
this package.
"""

import os
import sys

_APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
_BIN_DIR = os.path.join(_APP_DIR, "bin")

for _dir in (_APP_DIR, _BIN_DIR):
    _abs = os.path.abspath(_dir)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)
