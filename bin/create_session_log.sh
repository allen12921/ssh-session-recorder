#!/bin/bash
set -euo pipefail

# Invoked as: sudo -u root /opt/audit/bin/create_session_log.sh [remote_user_label]
# SUDO_USER is set by sudo to the real invoking user (ubuntu), not trusted CLI input.
if [ -z "${SUDO_USER:-}" ]; then
    echo "SUDO_USER not set, refusing" >&2
    exit 1
fi

# Optional label identifying which SSH key/person logged in (from the
# per-key `environment="REMOTEUSER=..."` entries in authorized_keys).
# Sanitized defensively even though authorized_keys is a root-only,
# high-trust file: only allow alnum/dash/underscore, capped length.
RAW_LABEL="${1:-unknown}"
LABEL="$(printf '%s' "$RAW_LABEL" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-32)"
[ -n "$LABEL" ] || LABEL="unknown"

LOGDIR="/opt/audit/log"
TS="$(date +%Y%m%d-%H%M%S)"
FILE="${LOGDIR}/${SUDO_USER}-${LABEL}-${TS}-$$.log"
TIMING="${FILE}.timing"
STDERR="${FILE}.stderr"

# Pre-create all three companion files up front: the caller (session-shell,
# running as the unprivileged real user) has no write access to LOGDIR itself
# (other than execute, to reach a file it already knows the name of), so it
# cannot create new files there later — e.g. the .stderr file used by the
# non-pty `ssh host "cmd"` path. Whichever files end up unused for a given
# session (e.g. .stderr for an interactive login) just stay empty.
#
# Owner-only (600): everyone sharing this account is the same uid, so group
# membership doesn't distinguish anyone — group/other access isn't needed.
#
# script(1) always O_TRUNC-opens the timing file regardless of -a/--append
# (see script.c: append only applies to SCRIPT_FMT_RAW), so it cannot be
# append-only. Tamper-resistance for it and for .stderr relies on the
# directory permissions alone; the main content log keeps the stronger
# chattr +a protection.
touch "$FILE" "$TIMING" "$STDERR"
chown "$SUDO_USER" "$FILE" "$TIMING" "$STDERR"
chmod 600 "$FILE" "$TIMING" "$STDERR"
chattr +a "$FILE"

echo "$FILE"
echo "$TIMING"
echo "$STDERR"
