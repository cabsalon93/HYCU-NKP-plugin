# -*- coding: utf-8 -*-
"""Test du verrouillage des identifiants par session de navigateur (check_ui_session) :
une nouvelle session (pas de cookie / cookie inconnu) efface SESSION_CREDS et pose un
nouveau cookie ; la session courante (F5) ne change rien.
"""
import re
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


def _connected():
    return [k for k, v in H.SESSION_CREDS.items() if v]


# État propre.
H.UI_SESSION["id"] = None
for k in H.SESSION_CREDS:
    H.SESSION_CREDS[k] = None

# 1) Premier chargement (aucun cookie) : nouvelle session, cookie posé.
sc = H.check_ui_session(None)
check(sc is not None and "hycu_sess=" in sc, "premier chargement : Set-Cookie posé")
check("HttpOnly" in sc and "SameSite=Strict" in sc, "cookie HttpOnly + SameSite=Strict")
check("Expires" not in sc and "Max-Age" not in sc, "cookie de session (meurt avec le navigateur)")
tok = re.search(r"hycu_sess=([A-Za-z0-9_-]+)", sc).group(1)

# 2) Connexion simulée puis rechargement F5 (même cookie) : rien ne change.
H.SESSION_CREDS["hycu"] = {"mode": "basic", "user": "u", "password": "p"}
sc2 = H.check_ui_session("hycu_lang=fr; hycu_sess=" + tok)
check(sc2 is None, "même session (F5) : pas de nouveau cookie")
check(_connected() == ["hycu"], "même session (F5) : identifiants conservés")

# 3) Navigateur relancé (pas de cookie) : identifiants effacés, nouveau cookie.
sc3 = H.check_ui_session("hycu_lang=fr")
check(sc3 is not None and tok not in sc3, "navigateur relancé : nouvelle session, id différent")
check(_connected() == [], "navigateur relancé : identifiants effacés")

# 4) Ancien cookie devenu invalide : re-verrouillage aussi.
H.SESSION_CREDS["nutanix"] = {"mode": "basic", "user": "u", "password": "p"}
sc4 = H.check_ui_session("hycu_sess=" + tok)
check(sc4 is not None, "cookie périmé : nouvelle session")
check(_connected() == [], "cookie périmé : identifiants effacés")

# 5) Cookie forgé / malformé : traité comme absent, sans erreur.
sc5 = H.check_ui_session("hycu_sess=;;;garbage")
check(sc5 is not None, "cookie malformé : nouvelle session sans exception")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
