#!/usr/bin/env bash
# bootstrap.sh — Setup d'une VM Ubuntu 24.04 LTS neuve pour héberger le relais
# Frappuccino. Idempotent : ré-exécutable sans casser un état existant, et
# rejouable tel quel chez un autre hébergeur (Greenhost, 1984, ...). Il codifie
# le setup fait à la main sur le premier Vultr, le 2026-04-21.
#
# Connecte-toi en utilisateur non-root avec sudo (NOPASSWD ou mot de passe
# disponible) et vérifie que ta clé publique est dans le ~/.ssh/authorized_keys
# de cet utilisateur-là : le step 2 passe PermitRootLogin et
# PasswordAuthentication à no, puis redémarre sshd. Une VM livrée root-only, où
# la clé n'est que dans /root/.ssh, se verrouille toute seule au login suivant :
# crée l'utilisateur sudoer et installe-lui sa clé avant de lancer le script. Si
# c'est trop tard, il reste la console du panel de l'hébergeur, et la copie
# /etc/ssh/sshd_config.bak que le step 2 dépose avant de toucher à quoi que ce
# soit.
#
# Le sudo NOPASSWD n'est là que pour la durée du bootstrap : retire-le ensuite.
#
# Usage :
#   scp -r server/ relay@<IP>:/tmp/
#   ssh relay@<IP> 'cd /tmp/server/deploy && bash bootstrap.sh'

set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/frappuccino}"
RELAY_USER="${RELAY_USER:-relay}"
RELAY_PORT="${RELAY_PORT:-8443}"

log() { echo "[bootstrap] $*"; }
require_root() {
  [[ $EUID -eq 0 ]] || { log "ERROR: rerun with sudo"; exit 1; }
}
require_ubuntu_2404() {
  . /etc/os-release
  [[ "${VERSION_ID:-}" == "24.04" ]] || {
    log "WARN: this script targets Ubuntu 24.04 LTS, found ${VERSION_ID:-unknown}"
    log "      proceed at your own risk"
    sleep 3
  }
}

# 1. System update
step_system_update() {
  log "Step 1/8 — apt update + full-upgrade"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -qq
  DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq
}

# 2. Harden sshd
step_harden_sshd() {
  log "Step 2/8 — harden sshd (disable root login + password auth)"
  cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  sed -i \
    -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' \
    -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
    -e 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' \
    /etc/ssh/sshd_config
  # Ubuntu 24.04 cloud-init drops 50-cloud-init.conf with PasswordAuthentication yes
  if [[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]]; then
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' \
      /etc/ssh/sshd_config.d/50-cloud-init.conf
  fi
  sshd -t
  systemctl restart ssh
}

# 3. UFW firewall
step_ufw() {
  log "Step 3/8 — UFW firewall (22, 80, 443, ${RELAY_PORT})"
  apt-get install -y -qq ufw
  ufw default deny incoming  >/dev/null
  ufw default allow outgoing >/dev/null
  ufw allow 22/tcp           comment 'SSH'                  >/dev/null
  ufw allow 80/tcp           comment 'HTTP - Lets Encrypt'  >/dev/null
  ufw allow 443/tcp          comment 'HTTPS standard'       >/dev/null
  ufw allow "${RELAY_PORT}/tcp" comment 'HTTPS relay'       >/dev/null
  ufw --force enable >/dev/null
  ufw status verbose
}

# 4. Swap (vm.swappiness=10)
step_swap() {
  log "Step 4/8 — swap + swappiness tuning"
  # Vultr Ubuntu 24.04 ships with /swapfile already; only create if missing.
  if ! swapon --show | grep -q '/swapfile'; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-frappuccino-swappiness.conf
  sysctl -p /etc/sysctl.d/99-frappuccino-swappiness.conf
}

# 5. Docker official repo + engine + Compose plugin
step_docker() {
  log "Step 5/8 — Docker engine + Compose plugin (official repo)"
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
  fi
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu noble stable" \
    > /etc/apt/sources.list.d/docker.list
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  if id "${RELAY_USER}" &>/dev/null; then
    usermod -aG docker "${RELAY_USER}"
  fi
}

# 6. nginx + certbot + fail2ban
step_nginx_certbot() {
  log "Step 6/8 — nginx + certbot + fail2ban"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    nginx certbot python3-certbot-nginx \
    fail2ban htop unattended-upgrades
  systemctl enable --now nginx fail2ban
}

# 7. Deploy directory
step_deploy_dir() {
  log "Step 7/8 — provisioning ${DEPLOY_DIR}"
  install -d -m 0755 -o "${RELAY_USER}" -g "${RELAY_USER}" "${DEPLOY_DIR}"
  install -d -m 0750 -o "${RELAY_USER}" -g "${RELAY_USER}" "${DEPLOY_DIR}/state"
  install -d -m 0750 -o "${RELAY_USER}" -g "${RELAY_USER}" "${DEPLOY_DIR}/tls"
  if [[ ! -f "${DEPLOY_DIR}/.env" ]] && [[ -f "$(dirname "$0")/../.env.example" ]]; then
    cp "$(dirname "$0")/../.env.example" "${DEPLOY_DIR}/.env"
    chown "${RELAY_USER}:${RELAY_USER}" "${DEPLOY_DIR}/.env"
    chmod 600 "${DEPLOY_DIR}/.env"
    log "  → ${DEPLOY_DIR}/.env créé depuis .env.example. Édite-le AVANT le step suivant."
  fi
}

# 8. Reboot if kernel updated
step_reboot_check() {
  log "Step 8/8 — reboot check"
  if [[ -f /var/run/reboot-required ]]; then
    log "REBOOT REQUIRED — packages :"
    cat /var/run/reboot-required.pkgs 2>/dev/null || true
    log "Re-run with REBOOT=1 to trigger automatic reboot, or reboot manually."
    if [[ "${REBOOT:-0}" == "1" ]]; then
      log "Rebooting in 5s..."
      systemd-run --on-active=5 systemctl reboot
    fi
  else
    log "No reboot required."
  fi
}

# Main
require_root
require_ubuntu_2404
step_system_update
step_harden_sshd
step_ufw
step_swap
step_docker
step_nginx_certbot
step_deploy_dir
step_reboot_check

log "DONE. Next steps:"
log "  1. Edit ${DEPLOY_DIR}/.env (JWT_SECRET, MINIO_ROOT_PASSWORD, ...)"
log "  2. Generate TLS cert: bash $(dirname "$0")/tls/gen-self-signed.sh"
log "  3. Configure nginx: see $(dirname "$0")/nginx/relay.conf.template"
log "  4. Deploy: cd ${DEPLOY_DIR} && docker compose up -d"
log "  5. Update SPKI pin in client: bash $(dirname "$0")/tls/update-spki-pin.sh"
