# Everywhere CLI

A command-line interface for managing cloud sandboxes.

## Installation

Using go install (recommended)

Prerequisites:
- Go 1.24+ installed and on your PATH.

Install the latest version:
```bash
go install github.com/everywhere-dev/everywhere-cli/everywhere@latest
```

This builds and places the `everywhere` binary into GOBIN (if set) or GOPATH/bin.

Ensure the install location is on your PATH:
- macOS/Linux (bash/zsh):
```bash
export PATH="$(go env GOPATH)/bin:$PATH"
# or, if you use GOBIN:
export PATH="$(go env GOBIN):$PATH"
```

- Windows (PowerShell):
```powershell
$env:Path += ';' + (go env GOPATH) + '\bin'
```

Verify the install:
```bash
everywhere --help
```

Pin or upgrade:
```bash
# Install a specific version
go install github.com/everywhere-dev/everywhere-cli/everywhere@vX.Y.Z

# Upgrade to the latest
go install github.com/everywhere-dev/everywhere-cli/everywhere@latest
```

Alternative: build from source
```bash
git clone https://github.com/everywhere-dev/everywhere-cli.git
cd everywhere-cli
go build -o everywhere ./everywhere
```

## Usage

Global help:
```bash
everywhere --help
everywhere [command] --help
```

Version:
```bash
everywhere --version
```

### Authentication
```bash
everywhere login [token]           # Login with authentication token (positional or prompted)
everywhere logout                  # Logout and clear credentials
```
Options:
- `-t, --token string`  Authentication token (optional; can also be provided as positional argument). If omitted, you will be prompted (input hidden).

### Sandbox Management
```bash
everywhere sandboxes list                         # List all sandboxes
everywhere sandboxes create [flags]               # Create a new sandbox
everywhere sandboxes start NAME                   # Start a sandbox
everywhere sandboxes stop NAME                    # Stop a sandbox
everywhere sandboxes delete NAME [-f|--force]     # Delete a sandbox (with optional force)
```
Create flags:
- `-n, --name string`   Sandbox name (auto-generated if empty)
- `-p, --port string`   Upstream port
- `-e, --env KEY=VALUE` Environment variable (repeatable; can be specified multiple times)

Delete flags:
- `-f, --force`         Force delete without confirmation prompt

### File Management
```bash
everywhere files list SANDBOX                              # List files (with small content previews)
everywhere files download SANDBOX [-o|--output FILE.zip]   # Download all files as a zip
everywhere files update SANDBOX PATH [--file F | stdin]    # Create or update a file
everywhere files upload SANDBOX INPUT [flags]              # Upload a directory or archive
```
Update flags:
- `-f, --file string`   Read content from a local file; if omitted, content is read from stdin
- `-a, --append`        Append to existing file instead of overwrite (default is overwrite)

Download flags:
- `-o, --output string` Output file path (defaults to server-provided filename)

Upload behavior and flags:
- INPUT can be a directory, a `.zip`, `.tar.gz`/`.tgz`, or a single file (non-archives will be zipped automatically)
- `-p, --path string`   Target path in the sandbox (directory to extract into), default `/`
- `-f, --format string` Archive format (`zip` or `tar.gz`); auto-detected by default

### Command Execution
```bash
everywhere exec "echo hello"               # Run a shell command in a sandbox
```
Options:
- `-s, --sandbox string`  Sandbox name (use `auto` to create a temporary sandbox). Default: `auto`

### Python Execution
```bash
everywhere run script.py                    # Execute a local Python file
everywhere run "print('hello')"             # Execute inline Python code
```
Options:
- `-s, --sandbox string`  Sandbox name (use `auto` to create a temporary sandbox). Default: `auto`

Notes:
- Only Python `.py` files are supported for file-based execution.
- When a path does not exist but ends with `.py`, it is treated as an error. Non-`.py` inputs are treated as inline code.

### Configuration
```bash
everywhere config show                      # Show current config
```
Outputs the API endpoint, user email, and authentication status.

## Commands Overview

- `login` / `logout`
- `sandboxes` (`list`, `create`, `start`, `stop`, `delete`)
- `files` (`list`, `download`, `update`, `upload`)
- `exec` (run shell commands in a sandbox)
- `run` (run Python code or .py files)
- `config` (`show`)

## Environment Variables

- `EVERYWHERE_AUTH_TOKEN`  Set authentication token
- `EVERYWHERE_USER_EMAIL`  Optional: set the user email stored in config

## Configuration

Config stored at `~/.everywhere/config.json`.
