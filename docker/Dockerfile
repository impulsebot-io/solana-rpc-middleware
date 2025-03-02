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
