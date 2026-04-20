"""conftest.py

Add the `app/` directory to sys.path so that `module.*` and `collect_iocs`
are importable from every test file in this package.
"""

import os
import sys

_APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
if _APP_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_APP_DIR))
