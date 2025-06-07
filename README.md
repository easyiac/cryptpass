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

## [Installation](docs/install.md)

## [Configuration](docs/config.md)

## [OpenAPI Documentation](docs/openapi.yaml)

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
