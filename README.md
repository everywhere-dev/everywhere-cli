# everywhere-cli

Command-line tool for [everywhere.dev](https://everywhere.dev). Create and manage apps, deploy code, stream logs, and interact with the platform from your terminal.

## Install

Requires **Go 1.24+**:

```bash
go install github.com/everywhere-dev/everywhere-cli@latest
```

Make sure `$(go env GOPATH)/bin` is in your `PATH`.

## Authenticate

```bash
# Interactive login (opens browser)
everywhere auth login

# Or use an API key / token
everywhere auth login --with-token
```

## Quick start

```bash
# Create and start an app
everywhere apps create my-app
everywhere apps start my-app

# Push local code
everywhere push my-app ./my-project

# Deploy (auto-detects stack, installs deps, starts)
everywhere deploy my-app

# Stream logs
everywhere logs my-app

# Run a command
everywhere exec my-app "python train.py --epochs 10"
```

## Commands

```
everywhere login               Authenticate with everywhere.dev
everywhere logout              Clear local credentials
everywhere auth status         Show current auth status
everywhere auth api-keys       Manage API keys
everywhere auth set-endpoint   Change API base URL

everywhere apps list           List all apps
everywhere apps create         Create a new app
everywhere apps start          Start an app
everywhere apps stop           Stop an app
everywhere apps delete         Delete an app
everywhere apps update         Update settings (entrypoint, port, env)
everywhere apps info           Show app environment info

everywhere exec                Execute a command in an app
everywhere run                 Run a Python file or code snippet
everywhere push                Upload local files to an app
everywhere deploy              Deploy code to an app
everywhere rollback            Roll back to a previous deploy
everywhere deploys             View deploy history
everywhere logs                Stream app logs
everywhere ssh                 Open a terminal session

everywhere files list          List files in an app
everywhere files download      Download files as a zip
everywhere files update        Create or update a file

everywhere jobs submit         Submit a background job
everywhere jobs list           List jobs
everywhere jobs get            Get job details
everywhere jobs restart        Restart a failed job
everywhere jobs cancel         Cancel a running job

everywhere templates create    Snapshot an app as a template
everywhere templates list      List templates
everywhere templates delete    Delete a template

everywhere buckets create      Create an S3-compatible storage bucket
everywhere buckets list        List buckets
everywhere buckets get         Get bucket details and credentials
everywhere buckets delete      Delete a bucket
everywhere buckets ls          List objects in a bucket
everywhere buckets cp          Upload/download objects
everywhere buckets rm          Delete an object

everywhere tenant info         Show tenant details
everywhere tenant claim        Claim a tenant slug
```

## Configuration

Credentials and settings are stored in `~/.everywhere/config.json`. Set a custom API endpoint:

```bash
everywhere auth set-endpoint https://api.example.com/api/v1
```

## Documentation

Full documentation at [everywhere.dev/docs](https://everywhere.dev/docs).

## License

Proprietary. All rights reserved.
