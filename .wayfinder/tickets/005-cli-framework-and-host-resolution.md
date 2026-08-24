---
label: wayfinder:prototype
status: closed
---
## Question

How should the Fabric CLI be structured to support Docker-style top-level commands (`fabric exec`, `fabric ps`), grouped management subcommands (`fabric node ls`), unified flag parsing, and multi-source configuration resolution (`~/.fabric/config.json`, `FABRIC_HOST`, `FABRIC_TOKEN`, and `-H`/`--host`)?

## Resolution

- **Framework:** Selected `github.com/spf13/cobra` for command routing, persistent flags, and subcommands.
- **Hierarchy:** Implemented a hybrid structure featuring top-level convenience verbs (`exec`, `ps`, `cp`, `port`) and grouped management commands (`node ls`, `node inspect`).
- **Configuration Precedence:** 4-tier resolution hierarchy:
  1. CLI Flags (`-H` / `--host`, `--token`)
  2. Environment Variables (`FABRIC_HOST`, `FABRIC_TOKEN`)
  3. Config File (`~/.fabric/config.json` with multi-context support)
  4. Defaults (`ws://localhost:8080/ws`, `default-secret`)
- **Package Layout:** Organized under `internal/cli/` (`root.go`, `config.go`, `client.go`, command handlers) with a thin wrapper in `cmd/cli/main.go`.
