# Solana RPC Middleware

Solana RPC Middleware is a lightweight, secure proxy that enhances Solana RPC handling. It allows for **IP whitelisting**, **token authentication**, and **automatic fallback to healthy RPC nodes**. Designed for both **standalone use** and **full Solana node integration**.

## Features

✅ Secure API with **IP whitelist & token authentication**\
✅ **Automatic failover** to healthy RPC nodes\
✅ **Works with or without a full Solana node**\
✅ **Solana gossip integration** for node discovery\
✅ **Docker & Systemd support** for easy deployment\
✅ **Health check system** to validate Solana node status\
✅ **High-performance & lightweight**

---

## Project Structure

```
solana-rpc-middleware/
│── config/
│   ├── config.yaml        # Main configuration file
│── src/
│   ├── main.go            # Middleware source code
│── docker/
│   ├── Dockerfile         # Docker build file
│   ├── docker-compose.yml # Docker Compose setup
│── systemd/
│   ├── solana-middleware.service  # Systemd service
│── .gitignore
│── README.md
│── LICENSE
```

---

## Configuration (`config/config.yaml`)

```yaml
localRpc: "http://127.0.0.1:8899"
listenAddr: ":8181"
nodeCheckInterval: 5 # minutes
healthCheckInterval: 30 # seconds
maxRetries: 3
maxSlotsBehind: 30

services:
  - name: "metrics"
    path: "8083"
    targetPort: 9393

auth:
  enableTokenAuth: true
  tokens:
    - "secure-token-123"
  enableIPWhitelist: true
  whitelistedIPs:
    - "192.168.1.1"
```

---

## Installation & Usage

### **1. Install Solana CLI (Required)**

Solana CLI is **required** for node discovery and must be installed.

```sh
curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/solana-developers/solana-install/main/install.sh | bash
```

After installation, add it to your path:

```sh
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
```

Verify installation:

```sh
solana --version
```

---

### **2. Run Manually**

```sh
go build -o solana-middleware src/main.go
./solana-middleware --config=config/config.yaml
```

### **3. Run with Docker**

#### Dockerfile (`docker/Dockerfile`)

```dockerfile
FROM golang:1.20-bullseye

WORKDIR /app

COPY src/ src/
COPY config/ config/

RUN go mod init solana-middleware && go mod tidy

# Set environment variables for Go and Solana CLI
ENV PATH="/root/.cargo/bin:$PATH"
ENV PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

# Install dependencies using Debian's package manager (apt)
RUN apt-get update && apt-get install -y \
    build-essential pkg-config libudev-dev llvm clang protobuf-compiler libssl-dev curl bash && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . "$HOME/.cargo/env" && \
    sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)" && \
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH" && \
    echo 'export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"' >> ~/.bashrc && \
    echo 'export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"' >> ~/.zshrc && \
    . ~/.bashrc

# Build the Go application
RUN go build -o solana-middleware ./src/main.go

CMD ["./solana-middleware", "--config=config/config.yaml"]

```

#### Run with Docker

```sh
docker build -t solana-middleware .
docker run -p 8181:8181 -v $(pwd)/config:/app/config solana-middleware
```

### **4. Run with Docker Compose**

#### `docker/docker-compose.yml`

```yaml
services:
  solana-middleware:
    build:
      context: ".."
      dockerfile: "docker/Dockerfile"
    restart: always
    ports:
      - "8181:8181"
    volumes:
      - ../config:/app/config
      - ../src:/app/src
    working_dir: /app
```

#### Run with Compose

```sh
docker-compose up -d
```

### **5. Run as a Systemd Service**

#### Create `systemd/solana-middleware.service`

```ini
[Unit]
Description=Solana RPC Middleware
After=network.target

[Service]
ExecStart=/path/to/solana-middleware --config /path/to/config/config.yaml
Restart=always
User=root
WorkingDirectory=/path/to
Environment="PATH=/usr/local/bin:/usr/bin:/bin:/home/solana/.local/bin:/home/solana/.local/share/solana/install/active_release/bin"

[Install]
WantedBy=multi-user.target
```

#### Enable & Start Service

```sh
sudo cp systemd/solana-middleware.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable solana-middleware
sudo systemctl start solana-middleware
sudo systemctl status solana-middleware
```

---

## Usage Examples

### **1. Test Middleware with CURL**

```sh
curl -X POST http://localhost:8181 -H "Authorization: Bearer secure-token-123" \
    -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0",
      "id": 1,
      "method": "getSlot",
      "params": []
    }'
```

### **2. List All Healthy RPC Nodes**

```sh
curl -X GET http://localhost:8181/health -H "Authorization: Bearer secure-token-123"
```

### **3. Check if a Node is Synced**

```sh
curl -X POST http://localhost:8181 -H "Authorization: Bearer secure-token-123" \
    -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0",
      "id": 1,
      "method": "getHealth"
    }'
```

---

## Notes

- **No Full Node?** You can run this **without a Solana full node**, and it will still detect and use healthy RPC nodes.
- **Security First:** Always **use token authentication & IP whitelisting** in production.
- **Failover Support:** The middleware continuously **monitors nodes** and **switches** to the best available RPC.
- **Extendable:** Add custom services inside `config.yaml`.

---

## Contributing

Feel free to **fork**, submit **pull requests**, or **open issues** to improve this middleware.

🤝 **Join the impulse community!** Made with ❤️ by the [impulse team](https://impulsebot.io). Together, we build better solutions.
