# -*- coding: utf-8 -*-
"""Faux kubectl À ÉTAT pour les tests de restauration (aucun cluster réel).

État : fichier JSON désigné par FAKE_STATE :
  { "namespaces": [...], "pvcs": {ns: {name: obj}}, "pvs": {name: obj}, "pods": {ns: [obj]},
    "deployments": {ns: {name: obj}}, "statefulsets": {ns: {name: obj}},
    "volumeattachments": [obj], "storageclasses": [name] }
Verbes : get / delete / patch / apply / wait / scale / auth can-i / version / config.
Injection de panne : FAKE_FAIL_AT = "verbe:kind[:nom]" (plusieurs séparés par « ; »),
ex. "apply:pv:pvc-new-2" ou "scale:deployment". Toutes les commandes sont journalisées
(une ligne JSON) dans FAKE_KUBE_LOG si défini.
"""
import json
import os
import sys

KIND_ALIASES = {"pvc": "pvc", "persistentvolumeclaim": "pvc", "persistentvolumeclaims": "pvc",
                "pv": "pv", "persistentvolume": "pv", "persistentvolumes": "pv",
                "pod": "pods", "pods": "pods", "po": "pods",
                "deployment": "deployments", "deployments": "deployments", "deploy": "deployments",
                "statefulset": "statefulsets", "statefulsets": "statefulsets", "sts": "statefulsets",
                "ns": "namespaces", "namespace": "namespaces", "namespaces": "namespaces",
                "volumeattachment": "volumeattachments", "volumeattachments": "volumeattachments",
                "storageclass": "storageclasses", "storageclasses": "storageclasses", "sc": "storageclasses"}


def load():
    with open(os.environ["FAKE_STATE"], encoding="utf-8") as f:
        return json.load(f)


def save(st):
    with open(os.environ["FAKE_STATE"], "w", encoding="utf-8") as f:
        json.dump(st, f, indent=1)


def fail_requested(verb, kind, name):
    spec = os.environ.get("FAKE_FAIL_AT", "")
    for rule in [r.strip() for r in spec.split(";") if r.strip()]:
        parts = rule.split(":")
        if parts[0] != verb:
            continue
        if len(parts) > 1 and parts[1] and parts[1] != kind:
            continue
        if len(parts) > 2 and parts[2] and parts[2] != name:
            continue
        return True
    return False


def main(argv):
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--kubeconfig", "--context", "-n", "--namespace", "-p", "--type", "-f", "-o", "--timeout",
                 "--replicas", "--for"):
            args.append(a); args.append(argv[i + 1] if i + 1 < len(argv) else ""); i += 2; continue
        args.append(a); i += 1
    if os.environ.get("FAKE_KUBE_LOG"):
        with open(os.environ["FAKE_KUBE_LOG"], "a", encoding="utf-8") as f:
            f.write(json.dumps(args) + "\n")
    # options
    opts = {}
    pos = []
    j = 0
    while j < len(args):
        a = args[j]
        if a in ("--kubeconfig", "--context", "-n", "--namespace", "-p", "--type", "-f", "-o", "--timeout",
                 "--replicas", "--for"):
            opts[a] = args[j + 1]; j += 2; continue
        if a.startswith("--replicas="):
            opts["--replicas"] = a.split("=", 1)[1]; j += 1; continue
        if a.startswith("--timeout=") or a.startswith("--request-timeout"):
            j += 1; continue
        if a.startswith("--for="):
            opts["--for"] = a.split("=", 1)[1]; j += 1; continue
        if a.startswith("--type="):
            opts["--type"] = a.split("=", 1)[1]; j += 1; continue
        if a.startswith("--"):
            opts[a] = True; j += 1; continue
        pos.append(a); j += 1
    ns = opts.get("-n") or opts.get("--namespace")
    out_json = opts.get("-o") == "json"
    out_name = opts.get("-o") == "name"
    if not pos:
        return 1
    verb = pos[0]

    if verb == "config":
        if pos[1:3] == ["current-context"]:
            print(os.environ.get("FAKE_LOCAL_CTX", "test-ctx")); return 0
        if pos[1:3] == ["get-contexts"]:
            print(os.environ.get("FAKE_LOCAL_CTX", "test-ctx")); return 0
        if pos[1:3] == ["view"]:
            print(json.dumps({"current-context": os.environ.get("FAKE_LOCAL_CTX", "test-ctx"), "contexts": []})); return 0
        return 1
    if verb == "version":
        print(json.dumps({"clientVersion": {"major": "1", "minor": "33"}})); return 0
    if verb == "auth":
        if fail_requested("auth", pos[3] if len(pos) > 3 else "", ""):
            print("no"); return 1
        print("yes"); return 0

    st = load()

    def kind_of(k):
        if "/" in k:
            k = k.split("/", 1)[0]
        return KIND_ALIASES.get(k.lower(), k.lower())

    def coll(kind):
        if kind in ("pvc", "pods", "deployments", "statefulsets"):
            key = "pvcs" if kind == "pvc" else kind
            return st.setdefault(key, {}).setdefault(ns or "default", {} if kind != "pods" else [])
        if kind == "pv":
            return st.setdefault("pvs", {})
        if kind == "namespaces":
            return st.setdefault("namespaces", [])
        if kind == "volumeattachments":
            return st.setdefault("volumeattachments", [])
        if kind == "storageclasses":
            return st.setdefault("storageclasses", [])
        return st.setdefault(kind, {}).setdefault(ns or "default", {})

    if verb == "get":
        kind = kind_of(pos[1]) if len(pos) > 1 else ""
        name = None
        if len(pos) > 2 and not pos[2].startswith("-"):
            name = pos[2]
        elif "/" in (pos[1] if len(pos) > 1 else ""):
            name = pos[1].split("/", 1)[1]
        if fail_requested("get", kind, name or ""):
            print("Error from server (Forbidden): %s is forbidden" % kind, file=sys.stderr); return 1
        c = coll(kind)
        if kind == "namespaces":
            items = [{"metadata": {"name": n}} for n in c]
        elif kind == "storageclasses":
            items = [{"metadata": {"name": n}} for n in c]
        elif isinstance(c, list):
            items = c
        else:
            items = list(c.values())
        if name:
            found = [it for it in items if it["metadata"]["name"] == name]
            if not found:
                if "--ignore-not-found" in opts:
                    print(""); return 0
                print('Error from server (NotFound): %s "%s" not found' % (kind, name), file=sys.stderr); return 1
            if out_name:
                print("%s/%s" % (kind, name)); return 0
            print(json.dumps(found[0])); return 0
        if out_name:
            print("\n".join("%s/%s" % (kind, it["metadata"]["name"]) for it in items)); return 0
        print(json.dumps({"items": items})); return 0

    if verb == "delete":
        kind = kind_of(pos[1]); name = pos[2]
        if fail_requested("delete", kind, name):
            print("Error from server (Forbidden): cannot delete %s %s" % (kind, name), file=sys.stderr); return 1
        c = coll(kind)
        if isinstance(c, dict):
            c.pop(name, None)
        elif isinstance(c, list):
            c[:] = [it for it in c if it["metadata"]["name"] != name]
        save(st)
        print('%s "%s" deleted' % (kind, name)); return 0

    if verb == "patch":
        kind = kind_of(pos[1]); name = pos[2]
        if fail_requested("patch", kind, name):
            print("Error from server (Forbidden): cannot patch", file=sys.stderr); return 1
        c = coll(kind)
        obj = c.get(name) if isinstance(c, dict) else None
        if obj is None:
            print('Error from server (NotFound): %s "%s" not found' % (kind, name), file=sys.stderr); return 1
        patch = json.loads(opts.get("-p") or "{}")

        def merge(dst, src):
            for k, v in src.items():
                if v is None:
                    dst.pop(k, None)
                elif isinstance(v, dict) and isinstance(dst.get(k), dict):
                    merge(dst[k], v)
                else:
                    dst[k] = v
        merge(obj, patch)
        save(st)
        print('%s/%s patched' % (kind, name)); return 0

    if verb == "apply":
        with open(opts.get("-f"), encoding="utf-8") as f:
            obj = json.load(f)
        kind = kind_of(obj.get("kind", ""))
        name = obj["metadata"]["name"]
        if fail_requested("apply", kind, name):
            print("Error from server: admission webhook denied the request", file=sys.stderr); return 1
        meta = obj.setdefault("metadata", {})
        if kind in ("pvc", "pods", "deployments", "statefulsets"):
            ns_obj = meta.get("namespace") or ns or "default"
            c = st.setdefault("pvcs" if kind == "pvc" else kind, {}).setdefault(ns_obj, {})
            if kind == "pvc":
                obj.setdefault("status", {})["phase"] = "Bound" if (obj.get("spec") or {}).get("volumeName") else "Pending"
            c[name] = obj
        elif kind == "pv":
            obj.setdefault("status", {})["phase"] = "Bound" if (obj.get("spec") or {}).get("claimRef") else "Available"
            st.setdefault("pvs", {})[name] = obj
        elif kind == "namespaces":
            if name not in st.setdefault("namespaces", []):
                st["namespaces"].append(name)
        else:
            st.setdefault(kind, {}).setdefault(meta.get("namespace") or ns or "default", {})[name] = obj
        save(st)
        print("%s/%s created" % (kind, name)); return 0

    if verb == "wait":
        # attente : l'état est synchrone dans le faux -> immédiat
        return 0

    if verb == "scale":
        kind = kind_of(pos[1]); name = pos[2]
        if fail_requested("scale", kind, name):
            print("Error from server (Forbidden): cannot scale", file=sys.stderr); return 1
        c = coll(kind)
        obj = c.get(name)
        if obj is None:
            print('Error from server (NotFound)', file=sys.stderr); return 1
        n = int(opts.get("--replicas", "0"))
        obj.setdefault("spec", {})["replicas"] = n
        # les pods suivent les réplicas
        pods = st.setdefault("pods", {}).setdefault(ns or "default", [])
        pods[:] = [p for p in pods if (p.get("metadata") or {}).get("labels", {}).get("app") != name]
        pvcs = [v.get("persistentVolumeClaim", {}).get("claimName")
                for v in ((obj.get("spec") or {}).get("template", {}).get("spec", {}).get("volumes") or [])]
        for k in range(n):
            pods.append({"metadata": {"name": "%s-%d" % (name, k), "namespace": ns, "labels": {"app": name},
                                      "ownerReferences": [{"kind": "ReplicaSet", "name": name, "controller": True}]},
                         "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": c2}} for c2 in pvcs if c2]},
                         "status": {"phase": "Running", "containerStatuses": [{"ready": True}]}})
        save(st)
        print("%s/%s scaled" % (kind, name)); return 0

    print("fake kubectl: unsupported %s" % args, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
