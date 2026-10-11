#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Assemble l'interface (ui/) dans le fichier unique hycu_k8s_nutanix.py.

Sources :  ui/index.html   (squelette, marqueurs /* @@STYLES@@ */ et // @@SCRIPT@@)
           ui/styles.css   (feuille de style)
           ui/app.js       (script)
Sortie :   dans hycu_k8s_nutanix.py, entre les marqueurs UI-BEGIN/UI-END : HTML (page).

Usage :  python build.py            # régénère hycu_k8s_nutanix.py
         python build.py --check    # échoue si le .py n'est pas à jour (CI)
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(HERE, "hycu_k8s_nutanix.py")
UI = os.path.join(HERE, "ui")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()



def assemble(ui_dir=UI):
    """Renvoie la page HTML assemblée."""
    index = _read(os.path.join(ui_dir, "index.html"))
    css = _read(os.path.join(ui_dir, "styles.css")).rstrip("\n")
    js = _read(os.path.join(ui_dir, "app.js")).rstrip("\n")
    assert "/* @@STYLES@@ */" in index and "// @@SCRIPT@@" in index, "@@STYLES@@/@@SCRIPT@@ markers missing"
    html = index.replace("/* @@STYLES@@ */", css).replace("// @@SCRIPT@@", js)
    if html.endswith("\n"):
        html = html[:-1]
    return html



def render(src, ui_dir=UI):
    html = assemble(ui_dir)
    if '"""' in html:
        raise SystemExit("the UI contains a triple quote (\"\"\"): cannot embed it")
    ui_block = ('# >>> UI-BEGIN — région GÉNÉRÉE par build.py depuis ui/ (ne pas éditer à la main)\n'
                'HTML = r"""%s"""\n'
                '# <<< UI-END' % html)
    return re.sub(r"# >>> UI-BEGIN.*?# <<< UI-END", lambda m: ui_block, src, count=1, flags=re.S)



def main(argv):
    try:                                   # Windows : console cp1252 -> forcer l'UTF-8
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    src = _read(PY)
    out = render(src)
    if "--check" in argv:
        if out != src:
            print("hycu_k8s_nutanix.py is NOT up to date with ui/: run `python build.py`.")
            return 1
        print("hycu_k8s_nutanix.py is up to date.")
        return 0
    if out != src:
        with open(PY, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
        print("hycu_k8s_nutanix.py regenerated (%d KB)." % (len(out.encode("utf-8")) // 1024))
    else:
        print("hycu_k8s_nutanix.py already up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
