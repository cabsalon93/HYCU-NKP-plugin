#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Assemble l'interface (ui/) dans le fichier unique hycu_k8s_nutanix.py.

Sources :  ui/index.html   (squelette, marqueurs /* @@STYLES@@ */ et // @@SCRIPT@@)
           ui/styles.css   (feuille de style)
           ui/app.js       (script)
           ui/i18n/en.json (paires [français, anglais] : fragments EXACTS du source,
                            les plus longs sont appliqués d'abord)
Sorties :  dans hycu_k8s_nutanix.py, entre les marqueurs UI-BEGIN/UI-END :
             HTML    = page française (canonique)
             HTML_EN = page anglaise PRÉ-RENDUE (aucune traduction à l'exécution)
           et entre I18N-BEGIN/I18N-END : I18N_EN (pour les messages JSON du serveur).

Usage :  python build.py            # régénère hycu_k8s_nutanix.py
         python build.py --check    # échoue si le .py n'est pas à jour (CI)
         python build.py --lint     # contrôles i18n (fragments orphelins, identités, minuscules)
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(HERE, "hycu_k8s_nutanix.py")
UI = os.path.join(HERE, "ui")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def load_i18n(ui_dir=UI):
    pairs = json.load(open(os.path.join(ui_dir, "i18n", "en.json"), encoding="utf-8"))
    return [(fr, en) for fr, en in pairs]


def translate(text, pairs):
    """Traduction FR -> EN par fragments, les plus longs d'abord (même règle que le serveur)."""
    for fr, en in sorted(pairs, key=lambda p: len(p[0]), reverse=True):
        if fr in text:
            text = text.replace(fr, en)
    return text


def assemble(ui_dir=UI):
    """Renvoie (HTML, HTML_EN, I18N_EN)."""
    index = _read(os.path.join(ui_dir, "index.html"))
    css = _read(os.path.join(ui_dir, "styles.css")).rstrip("\n")
    js = _read(os.path.join(ui_dir, "app.js")).rstrip("\n")
    assert "/* @@STYLES@@ */" in index and "// @@SCRIPT@@" in index, "marqueurs @@STYLES@@/@@SCRIPT@@ absents"
    html = index.replace("/* @@STYLES@@ */", css).replace("// @@SCRIPT@@", js)
    if html.endswith("\n"):
        html = html[:-1]
    pairs = load_i18n(ui_dir)
    html_en = translate(html, pairs)
    return html, html_en, pairs


def _py_literal_pairs(pairs):
    out = ["["]
    for fr, en in pairs:
        out.append("    (%r, %r)," % (fr, en))
    out.append("]")
    return "\n".join(out)


def render(src, ui_dir=UI):
    html, html_en, pairs = assemble(ui_dir)
    for s in (html, html_en):
        if '"""' in s:
            raise SystemExit("l'interface contient une triple guillemet (\"\"\") : impossible à embarquer")
    ui_block = ('# >>> UI-BEGIN — région GÉNÉRÉE par build.py depuis ui/ (ne pas éditer à la main)\n'
                'HTML = r"""%s"""\n'
                'HTML_EN = r"""%s"""\n'
                '# <<< UI-END' % (html, html_en))
    i18n_block = ('# >>> I18N-BEGIN — région GÉNÉRÉE par build.py depuis ui/i18n/en.json (ne pas éditer à la main)\n'
                  'I18N_EN = %s\n'
                  '# <<< I18N-END' % _py_literal_pairs(pairs))
    src = re.sub(r"# >>> UI-BEGIN.*?# <<< UI-END", lambda m: ui_block, src, count=1, flags=re.S)
    src = re.sub(r"# >>> I18N-BEGIN.*?# <<< I18N-END", lambda m: i18n_block, src, count=1, flags=re.S)
    return src


def lint(ui_dir=UI):
    """Contrôles i18n : chaque fragment FR doit exister dans l'interface ou dans le code
    serveur (messages JSON) ; pas d'identité FR == EN ; pas de fragment 100 % minuscule
    sans délimiteur (il altérerait des données : noms d'hôte, sorties kubectl)."""
    html, _, pairs = assemble(ui_dir)
    src = _read(PY)
    # Le code serveur hors régions générées : les littéraux adjacents ("a" "b" sur deux
    # lignes) sont fusionnés par l'AST, comme à l'exécution.
    import ast
    server_src = re.sub(r"# >>> UI-BEGIN.*?# <<< UI-END", "", src, flags=re.S)
    server_src = re.sub(r"# >>> I18N-BEGIN.*?# <<< I18N-END", "I18N_EN = []", server_src, flags=re.S)
    consts = []
    for node in ast.walk(ast.parse(server_src)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            consts.append(node.value)
    server = "\n".join(consts)
    # Messages COMPOSÉS à l'exécution ("Stockage objet S3 : %s.") : un fragment qui
    # correspond au gabarit (les %s / {} valant « n'importe quoi ») n'est pas orphelin.
    templates = []
    for c in consts:
        if len(c) >= 8 and re.search(r"%[sdr]|%\(\w+\)[sdr]|\{[^}]*\}", c):
            pat = re.sub(r"%[sdr]|%\\\(\w+\\\)[sdr]|\\\{[^}]*\\\}", ".*?", re.escape(c))
            try:
                templates.append(re.compile(pat, re.S))
            except re.error:
                pass

    def _composed(fr):
        return any(t.search(fr) for t in templates)

    problems = []
    seen = set()
    for fr, en in pairs:
        if fr in seen:
            problems.append(("doublon", fr))
        seen.add(fr)
        if fr == en:
            problems.append(("identité FR == EN", fr))
        if fr not in html and fr not in server and not _composed(fr):
            problems.append(("orphelin (absent de l'UI et du serveur)", fr))
        bare = re.sub(r"[^A-Za-zÀ-ÿ]", "", fr)
        # Un fragment en minuscules sans AUCUN délimiteur (balise, ponctuation, guillemet,
        # espace) pourrait coïncider avec une donnée (nom d'hôte, de namespace…).
        if bare and re.fullmatch(r"[a-zà-ÿ.]+", fr):
            problems.append(("fragment minuscule sans délimiteur (risque sur les données)", fr))
    return problems


def main(argv):
    try:                                   # Windows : console cp1252 -> forcer l'UTF-8
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    src = _read(PY)
    if "--lint" in argv:
        probs = lint()
        for kind, fr in probs:
            print("i18n: %s : %r" % (kind, fr))
        print("%d problème(s) i18n" % len(probs))
        return 1 if probs else 0
    out = render(src)
    if "--check" in argv:
        if out != src:
            print("hycu_k8s_nutanix.py n'est PAS à jour par rapport à ui/ : lancez `python build.py`.")
            return 1
        print("hycu_k8s_nutanix.py est à jour.")
        return 0
    if out != src:
        with open(PY, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
        print("hycu_k8s_nutanix.py régénéré (%d Ko)." % (len(out.encode("utf-8")) // 1024))
    else:
        print("hycu_k8s_nutanix.py déjà à jour.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
