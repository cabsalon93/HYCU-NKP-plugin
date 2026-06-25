# Image « mode conteneur » de l'outil HYCU / Kubernetes / Nutanix.
# Empaquette EXACTEMENT le même hycu_k8s_nutanix.py que le mode « python » (source
# unique). Le comportement est piloté par variables d'environnement (mode-agnostique).
#
# Build (le contexte DOIT être la racine du dépôt) :
#   docker build -f deploy/Dockerfile -t hycu-nkp:local .
FROM python:3.12-slim

# kubectl épinglé (>= 1.23 requis par l'outil). TARGETARCH est fourni par buildx
# (amd64 / arm64) ; checksum vérifié depuis le .sha256 officiel.
ARG KUBECTL_VERSION=v1.30.0
ARG TARGETARCH=amd64
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates tzdata; \
    curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"; \
    curl -fsSLo /tmp/kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256"; \
    echo "$(cat /tmp/kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum -c -; \
    chmod +x /usr/local/bin/kubectl; \
    apt-get purge -y curl; apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /tmp/kubectl.sha256

# Utilisateur non-root + répertoire de données (volume monté au runtime).
RUN useradd -u 10001 -m -d /home/app app \
 && mkdir -p /data /home/app/.kube \
 && chown -R 10001:10001 /data /home/app

# Le code + le logo (le logo est auto-détecté par l'app : HYCU…logo….svg).
COPY hycu_k8s_nutanix.py HYCU_Logomark_White_RGB.svg /app/

# Mode conteneur : bind toutes interfaces (publié sur la loopback de l'HÔTE au runtime),
# pas d'ouverture de navigateur, données persistées sous /data.
ENV HYCU_HOST=0.0.0.0 \
    HYCU_OPEN_BROWSER=0 \
    HYCU_BACKUP_ROOT=/data/hycu-backups \
    TZ=Europe/Paris \
    KUBECONFIG=/home/app/.kube/config

WORKDIR /data
USER 10001
EXPOSE 8765

# Healthcheck : page d'accueil en loopback interne (Host=127.0.0.1 -> accepté par _origin_ok).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8765/', timeout=2)" || exit 1

CMD ["python", "/app/hycu_k8s_nutanix.py"]
