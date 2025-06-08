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

## Documentation

- [Installation](docs/Installation.md)
- [Configuration](docs/Configuration.md)
- [OpenAPI](docs/OpenAPI.yaml)
- [Development](docs/Development.md)
- Concepts:
  - [Initialize and Unlock](docs/Concepts/Initialize_and_Unlock.md)

## Security Considerations

- The master encryption key should be kept secure and not included in the configuration file in production
- Use the `/perpetual/initialize` endpoint to set the master encryption key on the first run
- Use the `/perpetual/unlock` endpoint to set the master encryption key at runtime
- Always use TLS in production environments
- Change the default root password after the first login

## [License](LICENSE)

This project is licensed under the GLWTS License.
