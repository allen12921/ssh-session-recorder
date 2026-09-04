# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A deployable SSH login-shell wrapper that force-records every session on a *shared* account (multiple real people logging in as the same Linux user via different SSH keys), designed to survive abrupt disconnects and resist tampering by the person being recorded. See README.md for the full design rationale (including why `tlog` was evaluated and rejected) and the security model. There is no application code to build — this is three shell scripts plus a sudoers rule, deployed onto a target Linux host.

## Commands

There is no build step and no automated test suite — this is bash deployed onto a real sshd/PAM/filesystem stack, so "testing" means deploying to an actual host and exercising real SSH sessions.

- Syntax-check a script before deploying: `bash -n bin/session-shell` / `bash -n bin/create_session_log.sh` / `bash -n install.sh`
- Validate the sudoers template: `visudo -cf sudoers.d/audit-session-log`
- Deploy/redeploy (idempotent): `sudo ./install.sh <account>`
- The manual verification loop used throughout this repo's history (repeat all of these after any change to `bin/` or `install.sh`):
  1. `ssh -tt <account>@host "echo x; exit"` — interactive path still records
  2. `ssh <account>@host "exit 42"` then check `$?` client-side — exit code propagation still works
  3. `ssh <account>@host "echo out; echo err >&2" 1>out.log 2>err.log` — stdout/stderr still separated
  4. `scp somefile <account>@host:/tmp/` both directions — SFTP passthrough still works
  5. `ssh <other-admin-account>@host true` — confirm you have NOT broken any other account's access (see Gotchas below)
  6. Inspect `/opt/audit/log/` on the host: correct owner, `lsattr` shows `chattr +a` on the `.log` file only (not `.timing`/`.stderr`)

## Architecture

```
sshd → (per-key environment="REMOTEUSER=<name>" from authorized_keys, needs PermitUserEnvironment)
     → exec's the shared account's login shell = bin/session-shell
         → sudo -u root bin/create_session_log.sh "$REMOTEUSER"   (sudoers: fixed account, NOPASSWD)
             → pre-creates .log / .log.timing / .log.stderr, chown'd to the real user, chattr +a on .log only
         → real pty (interactive, or `ssh -tt host "cmd"`): exec script -f -a -q -e --timing=... <log>
         → no pty (`ssh host "cmd"`, the automation case): bypass script (it would force a pty and
           merge stdout/stderr) — use tee into .log/.log.stderr instead, exit code via PIPESTATUS
         → exception: if the -c command is actually sshd's external sftp subsystem invocation
           (`<shell> -c "/path/to/sftp-server"`), exec it directly with zero wrapping — SFTP needs
           a raw bidirectional channel and would break inside tee/script
```

The three files created per session (`.log`, `.log.timing`, `.log.stderr`) are **all pre-created up front** by `create_session_log.sh`, regardless of which code path ends up using them — the login shell process has no write access to the log directory itself (only execute), so it cannot create new files mid-session.

`.log.timing` cannot get the same `chattr +a` protection as `.log`: `script(1)`'s own source always `O_TRUNC`-opens the timing file regardless of `-a`, so append-only would make `script` fail to start. Its tamper-resistance is directory-permissions-only. Same reasoning applies to `.log.stderr`.

## Gotchas (both happened during this repo's development — read before touching sshd/PAM config)

- **Never make an `AuthorizedKeysFile`-style change global.** An earlier attempt relocated `AuthorizedKeysFile` to a per-`%u` path to make `REMOTEUSER` tamper-proof, but only created the new file for one account — every other account on the box (including the one being used for admin access) instantly lost SSH access. The correct fix is always to `chown root:root` + `chattr +i` the *existing* per-account `~/.ssh/authorized_keys` in place; never touch the global `AuthorizedKeysFile` directive for this.
- **`chattr +a` does not stop deletion.** `rm` checks the containing directory's write permission, not the file's own attributes — the account's own `~/.ssh` is (normally) still writable by that account. Use `chattr +i` (immutable) for anything that must survive `rm`, not just edits.
- **`usermod -s` swaps are easy to apply to the wrong account under pressure** (this happened once, swapping the recorded account's shell with the admin account's shell while restoring SSH access after the incident above). Always `getent passwd <account>` to confirm the actual state before and after touching login shells, for every account you might have affected — not just the one you meant to change.
- **`PermitUserEnvironment`'s value-list form (`PermitUserEnvironment REMOTEUSER`) is a newer OpenSSH feature** — OpenSSH 7.4p1 (the version this repo was built and tested against) only accepts bare `yes`/`no` and fails `sshd -t` on the list form. Always validate against `sshd -t -f <config-copy>` using the actual installed `sshd` binary before trusting any sshd_config syntax from documentation, since the docs describe the latest version, not necessarily the one in front of you.
