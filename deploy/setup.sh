#!/usr/bin/env bash
# One-shot setup for a fresh Ubuntu 22.04/24.04 Vultr Cloud Compute VM.
# Usage (as root, from the repo checkout):  DOMAIN=vulnigo.example.com bash deploy/setup.sh
#   DOMAIN   optional - if set, Caddy serves HTTPS for it; otherwise plain HTTP on :80 by IP.
#   GVISOR=0 optional - skip installing gVisor (runsc). Default installs it and uses it for sandboxes.
set -euo pipefail

APP_DIR=/opt/vulnigo
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
GVISOR="${GVISOR:-1}"

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg git python3 python3-venv debian-keyring debian-archive-keyring apt-transport-https ufw

echo "==> docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

if [ "$GVISOR" = "1" ] && ! command -v runsc >/dev/null; then
  echo "==> gVisor (runsc)"
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -y && apt-get install -y runsc
  runsc install
  systemctl restart docker
fi

echo "==> app user and files"
id vulnigo >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin vulnigo
usermod -aG docker vulnigo
mkdir -p "$APP_DIR"
rsync -a --delete --exclude .git --exclude .env --exclude data --exclude .venv "$SRC_DIR"/ "$APP_DIR"/ 2>/dev/null \
  || (apt-get install -y rsync && rsync -a --delete --exclude .git --exclude .env --exclude data --exclude .venv "$SRC_DIR"/ "$APP_DIR"/)
if [ ! -f "$APP_DIR/.env" ]; then
  cp "$APP_DIR/.env.example" "$APP_DIR/.env"
  echo "!! Edit $APP_DIR/.env and set VULTR_INFERENCE_API_KEY, then: systemctl restart vulnigo"
fi
set_env() {  # set_env KEY VALUE - replace or append in .env
  if grep -q "^$1=" "$APP_DIR/.env"; then sed -i "s|^$1=.*|$1=$2|" "$APP_DIR/.env"; else echo "$1=$2" >> "$APP_DIR/.env"; fi
}
[ "$GVISOR" = "1" ] && set_env SANDBOX_RUNTIME runsc
set_env VULNIGO_DATA_DIR "$APP_DIR/data"
mkdir -p "$APP_DIR/data"
chown -R vulnigo:vulnigo "$APP_DIR"
chmod 600 "$APP_DIR/.env"

echo "==> python venv"
sudo -u vulnigo python3 -m venv "$APP_DIR/.venv"
sudo -u vulnigo "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> sandbox image"
docker build -t vulnigo-sandbox:latest -f "$APP_DIR/deploy/sandbox.Dockerfile" "$APP_DIR/deploy"

echo "==> service"
cp "$APP_DIR/deploy/vulnigo.service" /etc/systemd/system/vulnigo.service
systemctl daemon-reload
systemctl enable --now vulnigo
systemctl restart vulnigo

echo "==> caddy (reverse proxy)"
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi
SITE="${DOMAIN:-:80}"
cat > /etc/caddy/Caddyfile <<EOF
$SITE {
  encode gzip
  reverse_proxy 127.0.0.1:8000 {
    flush_interval -1
  }
}
EOF
systemctl reload caddy || systemctl restart caddy

echo "==> firewall"
ufw allow OpenSSH >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw --force enable >/dev/null

sleep 2
curl -fsS http://127.0.0.1:8000/health && echo
echo "Done. Open http://$(curl -fsS -4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')/ ${DOMAIN:+or https://$DOMAIN/}"
