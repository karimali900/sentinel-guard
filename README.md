# Release CLI

A small, well-focused Go CLI maintained by GitLab that wraps the Releases API for use in CI pipelines.

## Architecture
- **`internal/app`**: Core application lifecycle and execution flow setup.
- **`internal/commands`**: CLI command definitions and subcommand routing.
- **`internal/gitlab`**: GitLab API client wrappers and payload structuring.
- **`internal/flags`**: Flag parsing, validation, and default value mapping.

## Local Development
To build, test, and lint locally, run:
- Build: `go build ./...`
- Test: `go test ./... -v`
- Lint: `golangci-lint run`

## Requirements
- Go 1.24+
- Environment variables: `CI_SERVER_URL`, `CI_PROJECT_ID`, `CI_JOB_TOKEN` (see `internal/flags` for defaults).
