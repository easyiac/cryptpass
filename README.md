# CryptPass

CryptPass is a secure key-value store with encryption capabilities, designed for managing sensitive data in a home lab
environment. It provides a RESTful API for storing, retrieving, and managing encrypted key-value pairs with user
authentication and authorization.

## Features

- **Secure Key-Value Storage**: Store and retrieve encrypted data with versioning support
- **Two-Layer Encryption**: Uses a master encryption key and individual keys for each value
- **User Management**: Built-in user system with roles and privileges
- **RESTful API**: Well-documented API with OpenAPI specification
- **TLS Support**: Optional TLS encryption for secure communication
- **SQLite Backend**: Uses SQLite for data persistence
- **Swagger UI**: Interactive API documentation

## Installation

### Using Docker

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

#### For Cross compilation: ARM64

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

## Configuration

CryptPass can be configured using a JSON configuration file. By default, it looks for a configuration file at
`/etc/cryptpass/config.json`, but you can specify a different location using the `CRYPTPASS_CONFIG` environment
variable.

Example configuration:

```json
{
    "server": {
        "port": 8088,
        "root-password": "your-root-password",
        "auth-header-key": "X-CRYPTPASS-KEY",
        "tls": {
            "key-pem": "/path/to/key.pem",
            "cert-pem": "/path/to/cert.pem"
        },
        "physical": {
            "unlock-details": {
                "master-encryption-key": "your-master-encryption-key"
            },
            "config": {
                "data-dir": "/var/lib/cryptpass"
            }
        }
    }
}
```

### Configuration Options

| Option                                                 | Description                             | Default                        |
|--------------------------------------------------------|-----------------------------------------|--------------------------------|
| `server.port`                                          | Port to listen on                       | 8088                           |
| `server.root_password`                                 | Password for the root user              | Random (logged on first start) |
| `server.auth_header_key`                               | HTTP header for authentication          | X-CRYPTPASS-KEY                |
| `server.tls`                                           | TLS configuration (optional)            | None                           |
| `server.tls.key-pem`                                   | Path to PEM key file or content         | None (use HTTP)                |
| `server.tls.cert-pem`                                  | Path to PEM certificate file or content | None (use HTTP)                |
| `server.physical.unlock-details.master-encryption-key` | Master encryption key for unlocking     | None (set at runtime)          |
| `server.physical.config.data-dir`                      | Directory for data storage              | /var/lib/cryptpass             |

### Environment Variables

| Variable              | Description                                 | Default                    |
|-----------------------|---------------------------------------------|----------------------------|
| `CRYPTPASS_CONFIG`    | Path to configuration file or JSON string   | /etc/cryptpass/config.json |
| `CRYPTPASS_LOG_LEVEL` | Log level (TRACE, DEBUG, INFO, WARN, ERROR) | INFO                       |
| `CRYPTPASS_LOG_DIR`   | Directory for log files                     | /var/log/cryptpass         |

## Usage

### API Endpoints

CryptPass provides the following API endpoints:

#### Key-Value Operations

- `GET /api/v1/keyvalue/data/{key}` - Read a key
- `PUT /api/v1/keyvalue/data/{key}` - Update a key
- `DELETE /api/v1/keyvalue/data/{key}` - Delete a key
- `GET /api/v1/keyvalue/details/{key}` - Get key metadata
- `GET /api/v1/keyvalue/list` - List all keys
- `GET /api/v1/keyvalue/list/{key}` - List nested keys

#### User Management

- `GET /api/v1/users/user/{username}` - Get user details
- `PUT /api/v1/users/user/{username}` - Create or update a user

#### Authentication

- `POST /perpetual/login` - Login with username and password
- `POST /perpetual/unlock` - Unlock with master key

#### Health Check

- `GET /perpetual/health` - Check server health

### Example Usage

#### Login

```bash
curl -X POST http://localhost:8088/login \
  -H "Content-Type: application/json" \
  -d '{"username": "root", "password": "your-password"}'
```

Response:

```json
{
    "token": "your-jwt-token",
    "type": "Bearer"
}
```

#### Store a Key-Value Pair

```bash
curl -X PUT http://localhost:8088/api/v1/keyvalue/data/my-secret \
  -H "Content-Type: application/json" \
  -H "X-CRYPTPASS-KEY: your-jwt-token" \
  -d '{"data": {"Object": {"username": "admin", "password": "secret123"}}}'
```

#### Retrieve a Key-Value Pair

```bash
curl -X GET http://localhost:8088/api/v1/keyvalue/data/my-secret \
  -H "X-CRYPTPASS-KEY: your-jwt-token"
```

Response:

```json
{
    "data": {
        "username": "admin",
        "password": "secret123"
    }
}
```

## Security Considerations

- The master encryption key should be kept secure and not included in the configuration file in production
- Use the `/perpetual/initialize` endpoint to set the master encryption key on the first run
- Use the `/perpetual/unlock` endpoint to set the master encryption key at runtime
- Always use TLS in production environments
- Change the default root password after the first login

## Development

### Generate OpenAPI Specification

CryptPass includes a tool to generate the OpenAPI specification:

```bash
cargo run --bin gen-openapi
```

### Running Tests

```bash
cargo test
```

### Building for Production

```bash
cargo build --release
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
