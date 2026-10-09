# -*- coding: utf-8 -*-
"""Les suites historiques `_test_*.py` (scripts à check()) sont exécutées en sous-processus,
chacune dans un dossier temporaire (config, sauvegardes, audit : jamais dans le dépôt)."""
import glob
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITES = sorted(os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "_test_*.py"))
                if not p.endswith("_test_all.py"))


@pytest.mark.parametrize("suite", SUITES)
def test_legacy_suite(suite, tmp_path):
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=ROOT)
    for e in ("HYCU_HOST", "HYCU_PORT", "HYCU_OPEN_BROWSER", "HYCU_BACKUP_ROOT", "HYCU_KUBECTL_PATH"):
        env.pop(e, None)
    r = subprocess.run([sys.executable, os.path.join(ROOT, suite)], cwd=str(tmp_path), env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    assert r.returncode == 0, "%s\n--- stdout ---\n%s\n--- stderr ---\n%s" % (suite, r.stdout[-3000:], r.stderr[-3000:])
