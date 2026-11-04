#!/usr/bin/env bash
# Deploy / update. Run as the admin user:  bash deploy/deploy.sh
# Re-runnable. Checks before it restarts anything that already works.

set -euo pipefail

APP_DIR="/opt/vulnigo"
cd "${APP_DIR}"

echo "==> fetch"
sudo chown -R "$(id -un):$(id -gn)" "${APP_DIR}"
git pull --ff-only

echo "==> python environment (built here, on the VM)"
[[ -d .venv ]] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r backend/requirements.txt
(cd backend && ../.venv/bin/python -c "import app.main")

echo "==> tests (agents/ and backend/ suites from the repo root)"
.venv/bin/python -m pytest -q

echo "==> units and the sandbox wrapper"
sudo cp deploy/vulnigo.service /etc/systemd/system/vulnigo.service
sudo install -o root -g root -m 755 sandbox/vulnigo-sandbox /usr/local/bin/vulnigo-sandbox
printf '%s\n' "vulnigo ALL=(root) NOPASSWD: /usr/local/bin/vulnigo-sandbox" \
  | sudo tee /etc/sudoers.d/vulnigo-sandbox >/dev/null
sudo chmod 440 /etc/sudoers.d/vulnigo-sandbox
sudo visudo -cf /etc/sudoers.d/vulnigo-sandbox

echo "==> sandbox image"
sudo docker image inspect vulnigo-sandbox:latest >/dev/null 2>&1 \
  || sudo docker build -t vulnigo-sandbox:latest sandbox

echo "==> restart"
sudo systemctl daemon-reload
sudo systemctl enable vulnigo >/dev/null 2>&1 || true
sudo systemctl restart vulnigo
sleep 2

echo "==> verify"
curl -fsS http://127.0.0.1:8000/health
echo
echo "-- limits as seen through the service user's one allowed sudo --"
sudo -u vulnigo sudo -n /usr/local/bin/vulnigo-sandbox --print-config
echo "-- effective ssh settings --"
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication' || true
sudo ufw status verbose | head -8

if ! sudo systemctl is-active --quiet vulnigo; then
  echo "vulnigo is not active -- journalctl -u vulnigo -n 40" >&2
  exit 1
fi
