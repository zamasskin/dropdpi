# DropDPI Proxy

A custom proxy system designed to bypass DPI (Deep Packet Inspection) by splitting data into encrypted chunks and sending them over multiple concurrent TCP connections.

## Features

- **Chunking & Reassembly**: Splits data streams into small chunks to evade signature detection.
- **Multi-Stream Transport**: Sends chunks across multiple TCP connections to randomize traffic patterns.
- **Encryption**: Uses AES-GCM to encrypt all data in transit.
- **SOCKS5 Interface**: Standard SOCKS5 client interface for easy integration with browsers and tools (curl, SwitchyOmega, etc.).
- **Reliability**: Handles out-of-order packet delivery and connection multiplexing.

## Architecture

1. **Client (`cmd/client`)**:
   - Listens on `127.0.0.1:1080` (SOCKS5).
   - Accepts connections from user apps (Browser, curl).
   - Initiates a "Session" with the Server.
   - Opens multiple TCP connections to the Server for this Session.
   - Encrypts and splits data into chunks.
   - Sends chunks round-robin across connections.

2. **Server (`cmd/server`)**:
   - Listens on `:8443`.
   - Accepts multiple TCP connections.
   - Aggregates connections by Session ID.
   - Reorders and decrypts chunks.
   - Forwards data to the actual target (e.g., google.com).

## Usage

### Prerequisites
- Go 1.20+

### 1. Start the Server
Run the server on the remote machine (or localhost for testing):
```bash
go run cmd/server/main.go
```
The server will listen on port `8443`.

### 2. Start the Client
Run the client on your local machine:
```bash
go run cmd/client/main.go
```
The client will listen on port `1080`.

### 3. Configure Your Application
Point your browser or tool to use SOCKS5 proxy at `127.0.0.1:1080`.

**Example with curl:**
```bash
curl -x socks5h://127.0.0.1:1080 https://www.google.com
```

**Firefox/Chrome:**
Use a proxy extension (like SwitchyOmega) or system settings to set SOCKS5 Host: `127.0.0.1`, Port: `1080`.

## Configuration
Currently, keys and addresses are hardcoded in `main.go` files for simplicity.
- Server Address: `cmd/client/main.go` -> `serverAddr`
- Encryption Key: `cmd/client/main.go` & `cmd/server/main.go` -> `serverKey` (Must match!)
