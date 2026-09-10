# go2rtc compatibility fork

This fork tracks AlexxIT/go2rtc and carries small, backportable library changes
consumed by frapbod/infra. Preserve the upstream module path
`github.com/AlexxIT/go2rtc`, public APIs, layout, build files and dependency pins.
The consuming infrastructure repository owns its deployed binary and version.

Use the Go version from go.mod or a compatible newer toolchain. Format changed
Go files with gofmt. For changes to HAP dialing and its HomeKit producer, run
`go test ./pkg/hap ./pkg/homekit` and `go vet ./pkg/hap ./pkg/homekit`; exercise
the caller as well. Run broader checks when they cover changed behavior, and
compare any failures with the unmodified base. `go build .` builds the upstream
application; the infrastructure consumer builds its own bounded helper.

This existing upstream codebase deliberately retains its module path, layout
and toolchain instead of adopting a new versions.env, Makefile, lint framework,
configuration model or release pipeline for a narrow compatibility patch.
Record that proportional deviation from the infrastructure Go repository
baseline here; do not mix an upstream restructuring into a library fix.
