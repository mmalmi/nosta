# Nosta

A Rust daemon for uploading and serving files via Scionic Merkle Trees with LMDB storage.

## Features

- Upload files and directories as Merkle DAG nodes
- Store data in LMDB via heed
- HTTP server with web UI for file uploads and management
- REST API endpoints for file operations
- CLI for daemon control and file management
- Merkle tree verification using Scionic Merkle Trees
- Drag & drop file uploads via web interface
- Built-in STUN server for WebRTC NAT traversal

## Usage

### Start the daemon

```bash
nosta start --addr 127.0.0.1:8080
```

### Upload a file

```bash
nosta upload --path /bitcoin.pdf /path/to/bitcoin.pdf
```

### Upload a directory

```bash
nosta upload-dir --path /mydir /path/to/directory
```

### List all uploaded files

```bash
nosta list
```

### Get file information

```bash
nosta info /bitcoin.pdf
```

### Access the Web Interface

Once the daemon is running, open your browser to:

```
http://127.0.0.1:8080/
```

The web interface provides:
- Drag & drop file uploads
- File list with merkle hashes
- Direct download links

### API Endpoints

```
GET  /                     - Web interface
GET  /files/*path          - Download a file
POST /upload               - Upload a file (multipart/form-data)
GET  /api/list             - List files as JSON with hashes
GET  /list                 - List files as plain text
```

## Data Directory

By default, nosta stores data in `./nosta-data`. Use `--data-dir` to specify a custom location:

```bash
nosta --data-dir /custom/path start
nosta --data-dir /custom/path upload --path /file.txt /path/to/file.txt
```

## Examples

### CLI Usage

```bash
# Upload bitcoin.pdf
nosta upload --path /bitcoin.pdf ./tests/data/bitcoin.pdf

# Start server
nosta start --addr 127.0.0.1:8080

# Fetch the file
curl http://127.0.0.1:8080/files/bitcoin.pdf > downloaded.pdf

# List all files
curl http://127.0.0.1:8080/list
```

### Web UI Usage

1. Start the server:
   ```bash
   nosta start --addr 127.0.0.1:8080
   ```

2. Open http://127.0.0.1:8080 in your browser

3. Drag and drop files or click to browse

4. Files are automatically uploaded and stored as merkle trees

### API Usage

```bash
# Upload via API
curl -F "file=@bitcoin.pdf" -F "path=/bitcoin.pdf" http://127.0.0.1:8080/upload

# List files with hashes (JSON)
curl http://127.0.0.1:8080/api/list

# Download file
curl http://127.0.0.1:8080/files/bitcoin.pdf -o downloaded.pdf
```

## Git Integration

Nosta provides git hosting via HTTP smart protocol. Push repositories to your nostr identity and clone from anyone's pubkey.

### Setup

1. Install the git-remote-nostr helper:
   ```bash
   cargo install --path crates/git-remote-nostr
   ```

2. Start the nosta daemon:
   ```bash
   nosta start --addr 127.0.0.1:8080
   ```

### Push a repository

Push to your own pubkey (hex format):
```bash
cd myrepo
git remote add nosta http://localhost:8080/git/<your-pubkey-hex>/myrepo
git push nosta main
```

The pubkey is derived from your nostr identity stored at `~/.nosta/nsec`. Only you can push to your own pubkey - the server verifies ownership.

### Clone a repository

Clone from any pubkey:
```bash
git clone http://localhost:8080/git/<pubkey-hex>/reponame
```

### Using nostr:// URLs (experimental)

The `git-remote-nostr` helper enables native nostr URLs:
```bash
git clone nostr://<npub>/reponame
git push nostr://<npub>/reponame main
```

This requires a running nosta daemon to handle the actual transport.

### How it works

- Git objects are stored in a hashtree merkle tree with LMDB persistence
- The repository root hash (SHA-256) can be published to nostr relays
- Push is only allowed to the pubkey matching the server's identity
- Fetch works for any pubkey

### Package Manager Support

Since nosta speaks standard git HTTP protocol, any package manager that supports git dependencies works out of the box:

| Package Manager | Example |
|-----------------|---------|
| **npm/pnpm/yarn** | `"dep": "git+http://localhost:8080/git/<pubkey>/repo"` |
| **Cargo** | `dep = { git = "http://localhost:8080/git/<pubkey>/repo" }` |
| **Go** | `go get localhost:8080/git/<pubkey>/repo` |
| **pip** | `pip install git+http://localhost:8080/git/<pubkey>/repo` |
| **Composer** | `"url": "http://localhost:8080/git/<pubkey>/repo"` |
| **Bundler** | `gem 'dep', git: 'http://localhost:8080/git/<pubkey>/repo'` |
| **Mix** | `{:dep, git: "http://localhost:8080/git/<pubkey>/repo"}` |
| **Pub** | `dep: { git: url: http://localhost:8080/git/<pubkey>/repo }` |
| **Homebrew** | `brew tap mytap http://localhost:8080/git/<pubkey>/homebrew-mytap` |

Any tool that can clone from an HTTP git remote will work with nosta.

#### Homebrew Taps

Homebrew taps are git repositories containing formula files. To host a tap on nosta:

```bash
# Create a tap repo with a formula
mkdir homebrew-mytap && cd homebrew-mytap
git init
mkdir Formula
cat > Formula/hello.rb << 'EOF'
class Hello < Formula
  desc "Example formula"
  url "https://example.com/hello-1.0.tar.gz"
  sha256 "abc123..."
end
EOF
git add . && git commit -m "Add hello formula"

# Push to nosta
git remote add nosta http://localhost:8080/git/<pubkey>/homebrew-mytap
git push nosta main

# Users can now install
brew tap mytap http://localhost:8080/git/<pubkey>/homebrew-mytap
brew install mytap/hello
```

## STUN Server

Nosta includes a built-in STUN server for WebRTC NAT traversal. Clients can discover their public IP address and port for peer-to-peer connections.

### Configuration

In `~/.nosta/config.toml`:

```toml
[server]
# Port for the built-in STUN server (0 = disabled)
stun_port = 3478
```

The STUN server listens on UDP and responds to binding requests with the client's reflexive transport address.

## Architecture

- **Storage**: Uses heed (LMDB wrapper) for persistent storage
- **Merkle Trees**: Uses hashtree for DAG creation and verification
- **HTTP Server**: Built with axum for high-performance serving
- **CLI**: Uses clap for command-line interface
- **Git Protocol**: Smart HTTP via nosta-git crate

## Testing

```bash
cargo test
```

Tests include:
- Storage operations (upload, retrieve, list)
- HTTP server endpoints
- Bitcoin.pdf integration test
- Directory upload/serving
- Git push/clone via HTTP and CLI
