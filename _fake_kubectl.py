# -*- coding: utf-8 -*-
"""Faux kubectl pour les tests multi-cluster (aucun cluster réel requis).

Données : fichier JSON désigné par FAKE_KUBE_DATA, indexé par NOM DE CONTEXTE :
  { "<contexte>": { "namespaces": [...], "pvcs": {ns: [pvc…]}, "pvs": {name: pv},
                    "unreachable": false, "forbidden_ns": false,
                    "workspaces": [...], "kommanderclusters": [...],
                    "secrets": {"<ns>/<name>": secret} } }
Le contexte du cluster « local » (sans --kubeconfig) est FAKE_LOCAL_CTX (vide = non configuré).
Chaque appel est journalisé (une ligne JSON) dans FAKE_KUBE_LOG si défini.
Kubeconfigs acceptés : JSON uniquement (kubectl accepte aussi le JSON).
"""
import json
import os
import sys


def main(argv):
    kc = ctx = None
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--kubeconfig":
            kc = argv[i + 1]; i += 2; continue
        if a == "--context":
            ctx = argv[i + 1]; i += 2; continue
        if a.startswith("--request-timeout"):
            i += 1; continue
        args.append(a); i += 1
    log = os.environ.get("FAKE_KUBE_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"kc": bool(kc), "ctx": ctx, "args": args}) + "\n")

    cfg = None
    if kc:
        try:
            with open(kc, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            print("error: error loading config file \"%s\": %s" % (kc, e), file=sys.stderr)
            return 1
    if args[:2] == ["config", "view"]:
        print(json.dumps(cfg or {}))
        return 0
    if args[:2] == ["config", "current-context"]:
        cur = (cfg or {}).get("current-context") if kc else os.environ.get("FAKE_LOCAL_CTX", "")
        if not cur:
            print("error: current-context is not set", file=sys.stderr)
            return 1
        print(cur)
        return 0
    if args[:2] == ["config", "get-contexts"]:
        names = [c["name"] for c in (cfg or {}).get("contexts", [])] if kc else \
            [os.environ.get("FAKE_LOCAL_CTX")] if os.environ.get("FAKE_LOCAL_CTX") else []
        print("\n".join(names))
        return 0

    ctx = ctx or ((cfg or {}).get("current-context") if kc else os.environ.get("FAKE_LOCAL_CTX", ""))
    with open(os.environ["FAKE_KUBE_DATA"], encoding="utf-8") as f:
        data = json.load(f).get(ctx or "")
    if data is None:
        print("error: context \"%s\" does not exist" % ctx, file=sys.stderr)
        return 1
    if data.get("unreachable"):
        print("Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout", file=sys.stderr)
        return 1
    if not args or args[0] != "get":
        print("fake kubectl: unsupported %s" % args, file=sys.stderr)
        return 1
    ns = None
    if "-n" in args:
        ns = args[args.index("-n") + 1]
    all_ns = "-A" in args or "--all-namespaces" in args
    as_name = "name" in args and "-o" in args and args[args.index("-o") + 1] == "name"
    kind = args[1]
    target = args[2] if len(args) > 2 and not args[2].startswith("-") else None

    jsonpath = None
    if "-o" in args and args[args.index("-o") + 1].startswith("jsonpath="):
        jsonpath = args[args.index("-o") + 1][len("jsonpath="):]

    def light_line(o):
        """Émule les DEUX gabarits jsonpath de l'outil (workloads / PVC)."""
        m, s = o.get("metadata") or {}, o.get("spec") or {}
        if "volumeClaimTemplates" not in jsonpath:
            return "%s\t%s" % (m.get("namespace", ""), m.get("name", ""))
        lb = m.get("labels") or {}
        tpl = ((s.get("template") or {}).get("spec") or {})
        ctpl = ((((s.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {})
        claims = lambda ps: " ".join((v.get("persistentVolumeClaim") or {}).get("claimName", "") for v in (ps.get("volumes") or []) if v.get("persistentVolumeClaim"))
        return "\t".join([m.get("namespace", ""), o.get("kind", ""), m.get("name", ""),
                          lb.get("app.kubernetes.io/instance", ""), lb.get("app.kubernetes.io/name", ""), lb.get("app", ""),
                          str(s.get("replicas", "")) if s.get("replicas") is not None else "",
                          " ".join(x.get("kind", "") for x in (m.get("ownerReferences") or [])),
                          claims(tpl), claims(ctpl),
                          " ".join((t.get("metadata") or {}).get("name", "") for t in (s.get("volumeClaimTemplates") or []))])

    def out(items):
        if as_name:
            print("\n".join("%s/%s" % (kind, i["metadata"]["name"]) for i in items))
        elif jsonpath is not None:
            # comme kubectl : un objet UNIQUE n'est pas enveloppé dans une liste (.items absent -> vide)
            print("\n".join(light_line(i) for i in items) if len(items) != 1 else "")
        else:
            print(json.dumps({"items": items}))
        return 0

    def by_ns(table):
        """Objets d'un namespace, ou de TOUS (-A) avec metadata.namespace renseigné."""
        table = table or {}
        if all_ns:
            res = []
            for n, lst in table.items():
                for o in lst:
                    o = json.loads(json.dumps(o))
                    o.setdefault("metadata", {}).setdefault("namespace", n)
                    res.append(o)
            return res
        return list(table.get(ns, []))

    if kind in ("ns", "namespace", "namespaces"):
        if data.get("forbidden_ns"):
            print('Error from server (Forbidden): namespaces is forbidden', file=sys.stderr)
            return 1
        return out([{"metadata": {"name": n}} for n in data.get("namespaces", [])])
    if kind == "pvc":
        return out(by_ns(data.get("pvcs")))
    if "," in kind or kind in ("deployments", "statefulsets", "daemonsets", "cronjobs"):
        # workloads : { "<ns>": [objets avec kind] } — vide si absent des données
        return out(by_ns(data.get("workloads")))
    if kind == "pv" and target:
        pv = (data.get("pvs") or {}).get(target)
        if not pv:
            print('Error from server (NotFound): persistentvolumes "%s" not found' % target, file=sys.stderr)
            return 1
        print(json.dumps(pv))
        return 0
    if kind == "workspaces.kommander.mesosphere.io":
        if "workspaces" not in data:
            print('error: the server doesn\'t have a resource type "workspaces"', file=sys.stderr)
            return 1
        return out(data["workspaces"])
    if kind == "kommanderclusters.kommander.mesosphere.io":
        return out(data.get("kommanderclusters", []))
    if kind == "secret" and target:
        sec = (data.get("secrets") or {}).get("%s/%s" % (ns, target))
        if not sec:
            print('Error from server (NotFound): secrets "%s" not found' % target, file=sys.stderr)
            return 1
        print(json.dumps(sec))
        return 0
    return out([])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
