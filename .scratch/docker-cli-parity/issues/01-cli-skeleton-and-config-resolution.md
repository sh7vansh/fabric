# 01 — Cobra CLI Skeleton & 4-Tier Host/Config Resolution

**What to build:** A modern, Cobra-based CLI root application for `fabric` supporting global flags (`-H`/`--host`, `--token`, `--context`), multi-context configuration files (`~/.fabric/config.json`), environment variables (`FABRIC_HOST`, `FABRIC_TOKEN`), and a `fabric version` command. Users can connect to the Socket mesh seamlessly from local or remote contexts.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] CLI runs with `spf13/cobra` routing and displays helpful help/usage messages for subcommands.
- [ ] Global flags `-H`/`--host` and `--token` override all other configuration sources.
- [ ] Environment variables `FABRIC_HOST` and `FABRIC_TOKEN` are read if flags are not provided.
- [ ] Multi-context configuration file at `~/.fabric/config.json` is read if flags/env are absent.
- [ ] Defaults to `ws://localhost:8080/ws` and `default-secret` if no configuration is provided.
- [ ] `fabric version` displays client version and attempts to display connected Socket version.
- [ ] End-to-end integration tests verify config loading precedence.
