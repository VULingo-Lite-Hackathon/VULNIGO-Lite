#!/usr/bin/env bash
# One-time VM setup. Run as root over SSH:  sudo bash provision.sh "<your ssh public key>"
#
# Deliberately does NOT disable root login. Do that by hand only after you have
# confirmed a second terminal can log in as the new user -- see the last lines.

set -euo pipefail

ADMIN_USER="ishaan"
APP_DIR="/opt/vulnigo"
SERVICE_USER="vulnigo"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run me as root:  sudo bash provision.sh \"ssh-ed25519 AAAA...\"" >&2
  exit 1
fi

KEY="${1:-}"
if [[ ! "${KEY}" =~ ^(ssh-(ed25519|rsa|dss|ecdsa)|sk-(ssh-)?ecdsa|ecdsa-sha2)- ]]; then
  echo "first argument does not look like a public key: ${KEY:-<empty>}" >&2
  echo "paste the FULL line from ~/.ssh/vulnigo.pub" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "==> system packages"
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq git docker.io python3-venv python3-pip ufw tmux curl ca-certificates

systemctl enable --now docker

echo "==> admin user ${ADMIN_USER}"
if ! id -u "${ADMIN_USER}" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "${ADMIN_USER}"
fi
usermod -aG sudo,docker "${ADMIN_USER}"
install -d -m 700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
printf '%s\n' "${KEY}" > "/home/${ADMIN_USER}/.ssh/authorized_keys"
chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"
chown "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh/authorized_keys"

echo "==> unprivileged service user ${SERVICE_USER} (no docker group, by design)"
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -m 755 -o root -g root "${APP_DIR}"
install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" /var/lib/vulnigo

echo "==> firewall: 22, 80, 443 only"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "==> ssh: key auth only"
# Ubuntu ships "Include /etc/ssh/sshd_config.d/*.conf" at the TOP of sshd_config and
# OpenSSH keeps the FIRST value for each keyword. Editing the main file therefore
# changes nothing: every override has to live in a drop-in, and any drop-in that
# sorts before ours (cloud-init writes 50-cloud-init.conf) would beat it too.
for f in /etc/ssh/sshd_config.d/*.conf; do
  [[ -e "${f}" ]] || continue
  sed -ri '/^(#)?(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitRootLogin)/d' "${f}"
done
cat > /etc/ssh/sshd_config.d/99-vulnigo.conf <<'SSH'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
SSH
chmod 600 /etc/ssh/sshd_config.d/99-vulnigo.conf
systemctl restart ssh

echo "==> effective ssh settings (this is the truth, not the files)"
sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauthentication' | tee /dev/stderr || true

cat <<DONE

Provisioned. Next, from a SECOND terminal:

    ssh -i ~/.ssh/vulnigo ${ADMIN_USER}@$(hostname -I | awk '{print $1}')

If that login works, close it and lock the door for good:

    sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo systemctl restart ssh

Never lose the first terminal until that test passes. Recovery is Vultr's web console.
DONE
