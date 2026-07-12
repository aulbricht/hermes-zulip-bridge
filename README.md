# hermes-zulip-bridge

A reusable Zulip bridge for Hermes.

`hermes-zulip-bridge` lets a Hermes instance participate in Zulip streams. It polls Zulip for new messages, sends them to Hermes, and posts the reply back into the same Zulip topic.

## Features

- Zulip stream/topic polling with fail-closed sender and numeric stream authorization
- Mention-gated Hermes command dispatch and Zulip reply posting
- Stable Zulip topic/session mapping across channel renames
- Same-sender mid-turn steering and interruption through same-topic Zulip messages
- Authenticated Zulip upload downloads with temporary local attachment context for Hermes
- Read-only chat slash commands with an explicit privileged-command policy
- `/goal` status/control support through Hermes goal state
- Optional Kanban terminal-status notifications back to Zulip
- YAML/JSON config with credentials from Zulip rc files or environment variables
- macOS LaunchAgent and Linux systemd user-service templates
- Smoke-test command for live bridge checks

## Install

```bash
python3 -m pip install -e .
```

The package uses the official Zulip Python client:

```bash
python3 -m pip install 'zulip>=0.9.1,<1'
```

## Quick Start

Create an owner-only config file at `~/.config/hermes-zulip-bridge/service.yaml` and run `chmod 600` on it before validation or startup. The bridge rejects configs and `zuliprc` files that are symlinks, multiply linked, non-private, foreign-owned, or below group/world-writable directories.

```yaml
instance_name: hermes
hermes:
  command: hermes
  # Use a dedicated profile with the minimum tools and workspaces required by chat.
  profile: restricted-chat
  # Required. `all` and command-line overrides are rejected.
  toolsets: [coding]
  working_directory: .
  # Optional names needed by a custom Hermes runtime; Zulip variables are always excluded.
  env_allowlist: [CUSTOM_RUNTIME_SETTING]
zulip:
  site: https://zulip.example.com
  bot_email_env: ZULIP_BOT_EMAIL
  bot_api_key_env: ZULIP_BOT_API_KEY
  stream: hermes
  stream_id: 12345
  allowed_senders: [id:42]
  # Use `any` for dynamic per-session topics, or `allowlist` with topic_allowlist.
  topic_policy: any
bridge:
  state_directory: ~/.hermes/state
  # Exit after this many consecutive poll failures so the service manager can restart the bridge.
  poll_failure_limit: 10
  require_mention: true
  # Optional operator-only state-changing commands. Both lists are required together.
  privileged_senders: [id:42]
  privileged_slash_commands: [goal, stop]
```

Set credentials:

```bash
export ZULIP_BOT_EMAIL='hermes-bot@example.com'
export ZULIP_BOT_API_KEY='...'
```

Validate and run:

```bash
hermes-zulip-bridge --config ~/.config/hermes-zulip-bridge/service.yaml validate-config
hermes-zulip-bridge --config ~/.config/hermes-zulip-bridge/service.yaml bridge
```

For direct source checkout testing:

```bash
PYTHONPATH=src python3 -m hermes_zulip_bridge --config ~/.config/hermes-zulip-bridge/service.yaml validate-config
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
```

CI and reproducible deployments use the committed `uv.lock`:

```bash
uv sync --frozen
uv run python -m unittest discover -s tests -p 'test_*.py'
```

`hermes.command` must resolve to an executable Python console script whose absolute shebang names Python inside a private virtual-environment `bin`. The bridge sends private prompt bytes through an inherited pipe and runs that script in-process so Zulip content never appears in process arguments. Launcher files and every executed path component must be owned by root or the bridge user and must not be group/world-writable. Immediately before launch, verified interpreter bytes are copied to a mode-`0500` private executable in that trusted `bin`; only the private copy is executed, so a package-manager source interpreter may live below a group-writable tree without becoming an executable pathname.

## Security Policy

The bridge fails closed unless `zulip.allowed_senders`, a positive numeric `zulip.stream_id`/`stream_ids`, and an explicit `zulip.topic_policy` are configured. Sender entries must use `id:<user-id>` or `email:<address>`; numeric user IDs are preferred. Environment-only installations can set the equivalent comma-separated `HERMES_ZULIP_ALLOWED_SENDERS` and `HERMES_ZULIP_STREAM_IDS` variables plus `HERMES_ZULIP_TOPIC_POLICY=any|allowlist`.

Run the bridge only in a private, operator-only Zulip channel. New turns and slash commands require a direct `@` mention of the bot by default. While a turn is active, only the same authorized sender can steer or interrupt it without repeating the mention.

Only exact `/status` and `/goal status` messages are chat-safe by default. State-changing slash commands are refused unless both the sender and command are explicitly listed under `bridge.privileged_senders` and `bridge.privileged_slash_commands`; `*` permits every known command for those privileged senders.

The bridge fences chat, attachment, route, history, and steering text as untrusted prompt data and excludes non-allowlisted human messages from topic history. Fencing does not make a tool-capable model immune to prompt injection. Every config must declare a restricted `hermes.toolsets` list; `all`, `--toolsets` overrides, and `--yolo` are rejected. A toolset is still not an OS sandbox, so use a dedicated Hermes profile, OS account, container, or equivalent execution boundary when chat-originated work must not inherit the bridge account's filesystem, process, or network access.

Notifier callbacks accept targets only from structured task metadata. Stream targets must match the configured numeric stream and sender policies. Direct messages are disabled by default; enable them with `notifier.allow_direct_messages: true` and a nonempty `notifier.allowed_dm_recipients` list of `id:`/`email:` identities.

Version `0.2.0` is a breaking security release. Before restarting an existing service, add the sender, stream ID, topic, mention, slash-command, and notifier policies shown above and run `validate-config`. Legacy notifier tasks that carry callback targets only in free-text bodies are intentionally ignored; recreate them with structured `metadata.notification_target` or `source_detail.notification_target` fields.

## Commands

Run the bridge:

```bash
hermes-zulip-bridge --config ~/.config/hermes-zulip-bridge/service.yaml bridge
```

Run the notifier once without posting:

```bash
hermes-zulip-bridge --config ~/.config/hermes-zulip-bridge/service.yaml notifier --once --dry-run
```

Run a live smoke test:

Stop the bridge service first. The standalone smoke test takes the same process lock as the daemon and will refuse to run concurrently.
The packaged `bridge`, `notifier`, and `smoke-test` commands securely parse and validate the selected complete Zulip credential source before installing credential environment variables, creating or acquiring locks, reading or migrating state, creating signing keys, calling Zulip, or starting Hermes. The validated in-memory credential value is passed forward instead of rereading the source. Inline YAML/environment credentials stay in memory; an explicitly configured user-supplied `zuliprc` remains supported.
`--run-hermes` requires `--post-probe` and `--human-origin-message-id`. Supply the ID of an existing allowed human-authored message in the requested stream and topic; Hermes refetches and authorizes that message as its origin. The bot-authored probe checks connectivity and destination routing only. Keep the daemon stopped for the whole smoke test.

```bash
hermes-zulip-bridge --config ~/.config/hermes-zulip-bridge/service.yaml smoke-test \
  --topic "Bridge smoke test" \
  --post-probe \
  --run-hermes \
  --human-origin-message-id <ID> \
  --post-reply
```

For live deployed validation, send a message to the running daemon in its configured Zulip stream and topic and verify its reply instead of running the standalone smoke test.

## Deploy

macOS LaunchAgent:

```bash
deploy/macos/install-launch-agent.sh ~/.config/hermes-zulip-bridge/service.yaml --no-start
```

Linux user systemd service:

```bash
cp deploy/env/hermes-zulip-bridge.env.example ~/.config/hermes-zulip-bridge.env
deploy/linux/install-systemd-user-service.sh ~/.config/hermes-zulip-bridge/service.yaml --no-start
systemctl --user status hermes-zulip-bridge
journalctl --user -u hermes-zulip-bridge -f
```

## Notes

Zulip upload links are private. The bridge rejects redirects, downloads attachments itself, inlines bounded text, and gives Hermes temporary owner-only local paths for image and other binary data. Zulip credentials and `zuliprc` paths are not included in prompts.

Hermes children receive a small operational environment allowlist instead of the bridge process environment. Extra variable names can be listed in `hermes.env_allowlist`; Zulip credential and path variables remain blocked even when listed. This is secret minimization, not OS isolation: Hermes running as the same UID can access files available to that account unless the configured Hermes profile or deployment supplies a separate sandbox.

For channel-name resilience, prefer `zulip.stream_id` when configuring a bridge. Zulip channel names can change; stream IDs are stable.

Bridge state is bound to the Zulip realm hostname stored in its top-level `realm` field. Older state is migrated automatically only when its thread/alias records provide one consistent matching realm; legacy ownership without realm evidence stops with a migration-required error instead of being reused across realms.

New origins are durably admitted before executor submission. A restart retries work that was definitely still before Hermes, but once Hermes may have started the bridge conservatively records the origin as terminal/seen to avoid duplicate Hermes turns or duplicate Zulip replies. A process can fail between starting Hermes or committing a Zulip POST and recording proof, so that interval is intentionally at-most-once and may require operator review. Persisted reconciliation jobs are authenticated with an HMAC from a separate owner-only 32-byte state signing key and verify the exact bot-authored reply content and route before moving it or publishing ownership. The sibling `*.signing-key` file must be backed up and restored together with the bridge state file; losing or corrupting it while reconciliation jobs are pending stops the bridge without PATCHing or dead-lettering those jobs. Rotating the Zulip API key does not invalidate queued jobs.

Notifier stream targets require the exact positive numeric origin message ID and stream ID. Before each delivery or reconciliation, the notifier refetches that exact human-authored stream message, verifies its identity and unchanged stream confidentiality scope, and uses only its current topic; stored stream names and topics are never delivery fallbacks. Notifications are admitted to a bounded durable outbox before POST and marked `post_started` before the write. A lost response or crash is reconciled by an authenticated stable marker plus exact bot author, content digest, numeric stream ID, and current verified topic. It is never blindly resent; unresolved uncertainty receives bounded backoff and ends in an operator-review dead letter.

Notifier state is a bounded signed schema stored as owner-only `0600` with a separate owner-only sibling signing key, unpredictable atomic temporary files, and file and directory fsync. Corruption, oversize data, unsafe ancestry, symlinks, hard links, foreign ownership, group/world-writable files, bad authentication, or signing-key loss fails closed. On first notifier startup, an existing owner-controlled regular single-link `0644` legacy state is migrated under the process lock to signed `0600` state without dropping its `notified` entries. Back up and restore the state and signing key together. Test migration only on copies of production state.

Smoke-test and notifier dry-run output is deliberately metadata-only: booleans, counts, necessary numeric message IDs, and opaque references. It does not print sites, email addresses, stream or topic names, launcher or session values, sidecar paths, task content, recipients, or local paths.

Origin retries, reply reconciliations, in-flight work, and dead letters are bounded. Reaching a durable queue limit stops polling and fails the daemon loudly; terminal work is retained for diagnosis and is never silently evicted or retried forever.

The initial Zulip message poll is required for startup. After startup, successful polls reset the failure counter; the bridge exits after `bridge.poll_failure_limit` consecutive failures (default `10`) so LaunchAgent or systemd can observe and restart an unhealthy daemon.

State and alias-manifest corruption is fatal at startup; existing bytes are never replaced with an empty default. External alias sessions must already be owned by the active realm-bound state, including legacy manifests without a realm field. Origin reservations are saved before Hermes starts. Bounded origin-retry and coordinator-only post-reconciliation queues use persisted capped backoff, so transient route failures survive the newest-message window and successful or uncertain answer posts are not repeated after restart.

Each normal state file has an independent owner-only process-lock anchor. Existing owner-controlled state directories are upgraded to mode `0700`; parent-path aliases share one canonical anchor, while state-file symlinks, non-regular files, foreign owners, and multiply linked files are rejected. Accepted state files are repaired to mode `0600`, and replacement writes fsync both the private temporary file and containing directory. State, signing-key, steering, derived smoke-steering, alias-manifest, lock, Zulip credential, and Hermes SQLite paths must be canonically disjoint. Steering sidecars are scoped to one active turn, securely appended, file-locked, deduplicated by Zulip message ID, and fsynced as owner-only `0600` files in a `0700` directory. They are removed and the directory is fsynced when the turn ends. An existing alias manifest must also be a regular, owner-only, single-link `0600` file. Replacing the compatibility `.lock` pathname does not bypass a running bridge, and handed-off locks must nonblockingly re-establish their authoritative exclusive lock before bridge or smoke-test side effects begin.

Hermes subprocess cleanup snapshots recursive same-UID descendants while the registered leader is alive and best-effort terminates detached descendant process groups and PIDs as well as the leader group. This is containment for accidental background children, not an OS sandbox: a trusted same-UID Hermes process can deliberately double-fork quickly enough to escape ancestry tracking and remains inside the trusted-Hermes limitation described above.
