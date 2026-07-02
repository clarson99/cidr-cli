# CIDR CLI — Go CIDR calculation tool

## Project

A CLI tool written in Go that performs CIDR calculations: display a reference table of prefix lengths /0–/32 with IP counts, netmasks, wildcards, and legacy class; check if an IP is within a CIDR range; show detailed info about a CIDR block (network, broadcast, usable hosts).

- **Stack:** Go 1.24, standard library only (no external dependencies)
- **Entry point:** `main.go`
- **Output binary:** `cidr`

## Commands

| Task | Command |
|------|---------|
| Build | `go build -o cidr .` |
| Run (no args) | `./cidr` |
| Run (dev) | `go run .` |
| Run (with args) | `go run . -- contains 10.0.0.1 10.0.0.0/8` |
| Test | `go test ./...` |
| Test (verbose) | `go test ./... -v` |
| Clean | `rm -f cidr` |

Or use `task` with `Taskfile.yaml`:
| Taskfile target | Command |
|----------------|---------|
| build | `task build` |
| test | `task test` |
| clean | `task clean` |
| run | `task run -- <args>` |

## Architecture

- **`main.go`** — CLI entry point: parses `os.Args`, dispatches to table/contains/info/help subcommands.
- **`internal/cidr/`** — Core library package with no external dependencies:
  - `GenerateTable()` — returns `[]TableRow` for prefixes 0–32 with IP count, netmask, wildcard, legacy class.
  - `Contains(ip, cidr)` — checks if an IP string is within a CIDR network.
  - `NetworkInfo(cidr)` — returns detailed `Info` struct (network, broadcast, first/last host, usable hosts, etc.).
  - `FormatCount(n)` — formats uint64 with comma separators.

## Conventions

- Use `internal/` for packages not meant to be imported externally.
- Subcommands dispatch via `os.Args[1]` with short aliases (`c` for `contains`, `i` for `info`).
- Always use `os.Exit(1)` on user-facing errors; print errors to `os.Stderr`.
- Tests live alongside source as `*_test.go` in the same package.
- Use standard library `net` package for IP/CIDR parsing — no external dependencies.
- Mask and wildcard display uses dotted-decimal notation via custom `formatMask()`.

## Notes

- Prefixes /0–/23 grouped as A/B/C, /24–/31 as D/E, /32 as unclassified in the legacy class column.
- /31 prefix follows RFC 3021 (2 usable hosts, no network/broadcast subtraction).
