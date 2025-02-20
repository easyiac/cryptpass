# crustpass

Manage seed data for my home lab.

## Configuration

`CRUSTPASS_CONFIGURATION_FILE` - Path to the settings file. Default: `/etc/crustpass/configuration.json`

`CRUSTPASS_CONFIGURATION_JSON` - JSON string of settings. Default: `null`

Priorities: `CRUSTPASS_CONFIGURATION_FILE` > `CRUSTPASS_CONFIGURATION_JSON`

```json
{
    "server": "See Server",
    "physical": "See Physical",
    "authentication": "See Authentication",
    "master_key": "Master key for encryption (Optional)"
}
```

`RUST_LOG=crustpass=debug` - Enable debug logging.

### Configuration: Server

Server Settings. `tls` is optional.

```json
{
    "socket_addr": "Listen address for the server, Example: `127.0.0.1:8080`",
    "tls": {
        "cert": "PEM encoded certificate",
        "key": "PEM encoded private key"
    }
}
```

### Configuration: Physical

Persistence layer for the seed data.

```json
{
    "physical_type": "Type of physical storage",
    "physical_details": "Details for the physical storage"
}
```

- `libsql`

    ```json
    {
        "db_url": "Database connection string",
        "auth_token": "Authentication token for the database"
    }
    ```

### Configuration: Authentication

Authentication layer for the API.

```json
{
    "authentication_type": "Type of authentication",
    "authentication_details": "Details for the authentication"
}
```

- `admin_api_key`

    ```json
    {
        "api_key": "Admin API key"
    }
    ```
