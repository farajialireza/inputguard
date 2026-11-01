# InputGuard

A lightweight Go input validation and sanitization utility with a REST API.

InputGuard provides a small set of reusable functions for validating text, labels, application names, filesystem paths, and bare command names. It also exposes these functions through a simple HTTP API.

## Features

- Text validation with configurable length limits.
- Optional newline and tab support for text formatting.
- Label validation with restrictions on potentially problematic characters and path-like values.
- Application name validation with an optional allowlist.
- Absolute filesystem path validation with optional allowed roots.
- Relative path validation with path traversal checks.
- Bare command name validation without accepting arguments or paths.
- JSON REST API for all supported validation functions.
- Unit tests for the sanitization package.

## Project Structure

```text
inputguard/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── api/
│   │   └── router.go
│   └── sanitize/
│       └── sanitize.go
├── go.mod
└── README.md
```

## Getting Started

Clone the repository:

```bash
git clone https://github.com/farajialireza/inputguard.git
cd inputguard
```

Install dependencies:

```bash
go mod tidy
```

Run the API server:

```bash
go run ./cmd/server
```

The server listens on port `8080`.

## REST API

All endpoints accept `POST` requests with JSON bodies.

| Endpoint                      | Description                        |
| ----------------------------- | ---------------------------------- |
| `/v1/validate/text`           | Validate text                      |
| `/v1/validate/label`          | Validate labels                    |
| `/v1/validate/app-name`       | Validate application names         |
| `/v1/validate/absolute-path`  | Validate absolute filesystem paths |
| `/v1/validate/relative-path`  | Validate relative filesystem paths |
| `/v1/validate/opener-command` | Validate bare command names        |

### Request Examples

**Text validation**

```json
{
  "value": "Hello World",
  "max_len": 512,
  "keep_formatting": false
}
```

**Application name validation**

```json
{
  "value": "my_app",
  "allowlist": ["my_app", "another_app"]
}
```

**Absolute path validation**

```json
{
  "value": "/var/data/files",
  "allowed_roots": ["/var/data"]
}
```

**Relative path validation**

```json
{
  "value": "documents/report.pdf",
  "max_len": 4096,
  "allow_dot": false
}
```

### Response Format

Successful validation:

```json
{
  "valid": true,
  "value": "Hello World"
}
```

Failed validation:

```json
{
  "valid": false,
  "error": "contains disallowed characters"
}
```

Successful requests return HTTP `200`. Invalid requests and validation failures return HTTP `400`.

The API also enforces a request body size limit and rejects unknown JSON fields.

## Using the Go Package

The sanitization functions are available inside the repository under:

```go
import "github.com/farajialireza/inputguard/internal/sanitize"
```

Available functions:

- `SanitizeText`
- `SanitizeLabel`
- `SanitizeAppName`
- `SanitizeAbsolutePath`
- `SanitizeSafeRelativePath`
- `SanitizeOpenerCommand`

The package is currently located under Go's `internal` directory and is intended for use within this repository.

## Running Tests

Run all tests:

```bash
go test ./...
```

## Scope and Limitations

InputGuard provides input validation and basic sanitization. It is not a comprehensive security framework.

- Filesystem path validation is lexical and does not resolve symbolic links.
- Path validation does not replace filesystem permission checks.
- Command name validation does not execute commands or make process execution inherently safe.
- Validation does not replace context-specific escaping, parameterized queries, or proper authorization checks.

Use the validation functions according to the requirements of the application consuming them.

## License

No open-source license has been specified for this repository.

