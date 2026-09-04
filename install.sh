#!/bin/bash
# Deploys ssh-session-recorder for one shared account, per the steps in
# README.md. Idempotent — safe to re-run.
#
# Usage: sudo ./install.sh <account>
#   e.g. sudo ./install.sh ubuntu
set -euo pipefail

ACCOUNT="${1:-}"
if [ -z "$ACCOUNT" ]; then
    echo "Usage: sudo $0 <account>" >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root (sudo $0 $ACCOUNT)" >&2
    exit 1
fi
if ! getent passwd "$ACCOUNT" >/dev/null; then
    echo "No such account: $ACCOUNT" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="$(getent passwd "$ACCOUNT" | cut -d: -f6)"

echo "==> Creating /opt/audit/bin and /opt/audit/log"
mkdir -p /opt/audit/bin /opt/audit/log
chown root:root /opt/audit/log
chmod 0701 /opt/audit/log

echo "==> Installing scripts"
install -m 0755 -o root -g root "$SCRIPT_DIR/bin/create_session_log.sh" /opt/audit/bin/create_session_log.sh
install -m 0755 -o root -g root "$SCRIPT_DIR/bin/session-shell"        /opt/audit/bin/session-shell

echo "==> Installing sudoers rule for $ACCOUNT (fixed user, not a group — see README)"
sed "s/^ubuntu /${ACCOUNT} /" "$SCRIPT_DIR/sudoers.d/audit-session-log" > "/etc/sudoers.d/audit-session-log-${ACCOUNT}"
chown root:root "/etc/sudoers.d/audit-session-log-${ACCOUNT}"
chmod 0440 "/etc/sudoers.d/audit-session-log-${ACCOUNT}"
visudo -cf "/etc/sudoers.d/audit-session-log-${ACCOUNT}"

echo "==> Registering /opt/audit/bin/session-shell in /etc/shells"
grep -qxF "/opt/audit/bin/session-shell" /etc/shells || echo "/opt/audit/bin/session-shell" >> /etc/shells

echo "==> Locking down ${HOME_DIR}/.ssh/authorized_keys and .../environment"
if [ -f "${HOME_DIR}/.ssh/authorized_keys" ]; then
    chattr -i "${HOME_DIR}/.ssh/authorized_keys" 2>/dev/null || true
    chown root:root "${HOME_DIR}/.ssh/authorized_keys"
    chmod 0644 "${HOME_DIR}/.ssh/authorized_keys"
    chattr +i "${HOME_DIR}/.ssh/authorized_keys"
else
    echo "    WARNING: ${HOME_DIR}/.ssh/authorized_keys does not exist, skipping — set it up and re-run this script" >&2
fi
chattr -i "${HOME_DIR}/.ssh/environment" 2>/dev/null || true
touch "${HOME_DIR}/.ssh/environment"
chown root:root "${HOME_DIR}/.ssh/environment"
chmod 0444 "${HOME_DIR}/.ssh/environment"
chattr +i "${HOME_DIR}/.ssh/environment"

echo "==> Setting $ACCOUNT's login shell to session-shell"
usermod -s /opt/audit/bin/session-shell "$ACCOUNT"

cat <<EOF

Done. Remaining manual steps (see README.md):
  - Make sure sshd has "PermitUserEnvironment yes" if you want per-key
    REMOTEUSER attribution (add environment="REMOTEUSER=<name>" entries to
    ${HOME_DIR}/.ssh/authorized_keys — the file is now root-owned+immutable,
    so use "chattr -i" to edit it, then "chattr +i" again when done).
  - Verify OTHER accounts on this box can still log in normally before
    closing this session — this script only touches $ACCOUNT.
EOF
