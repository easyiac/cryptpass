# Installation

## Using Docker

```bash
docker pull arpanrecme/cryptpass:latest
docker run -p 8088:8088 -v /path/to/data:/var/lib/cryptpass -v /path/to/config.json:/etc/cryptpass/config.json arpanrecme/cryptpass:latest
```

### From Source

Prerequisites:

- Rust 1.86.0 or later
- SQLite development libraries

```bash
# Build the project
cargo build --release

# Run the server
./target/release/cryptpass
```

## For Cross compilation: ARM64

Install [AArch64 GNU/Linux target (aarch64-none-linux-gnu)](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads).

Add the following to your Cargo.toml, Make sure to change the path and version according to your installation:

```toml
[target.aarch64-unknown-linux-gnu]
linker = "C:\\Program Files (x86)\\Arm GNU Toolchain aarch64-none-linux-gnu\\14.2 rel1\\bin\\aarch64-none-linux-gnu-gcc"
```

```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu --bin cryptpass
```
