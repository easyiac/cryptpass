# Cryptpass

Cryptpass is a basic REST API service for securely managing configuration and secrets. It provides a simple CRUD
interface and is designed to be robust for both small-scale personal deployments and more controlled lab environments.

## Features

- **Secrets Management:** Store, retrieve, update, and delete sensitive configuration and secret data via a secure API.
- **Strong Authentication:** Configurable root password and API key header, with optional TLS support.
- **Encrypted Storage:** Uses `master-key` encryption for secrets at rest.
- **Health Checks:** Simple health endpoint for monitoring.
- **Easy Configuration:** Supports JSON-based and file-based configuration schemes.
- **Extensible Deployment:** Ansible-based deployment scripts for effortless setup on target hosts.
- **Logging:** Customizable log levels and output directories.

## Getting Started

### Configuration

The service reads configuration from the environment or a JSON file (default path: `/etc/cryptpass/config.json`). You
can provide the entire config as a JSON string or reference a config file path using the `CRYPTPASS_CONFIG` environment
variable.

#### Example Config (`/etc/cryptpass/config.json`)

```json
{
    "server": {
        "port": "Port, type: int, default: `8088`",
        "root-password": "Root password, If not present in first run on the first run, it will be generated, and printed in the log on INFO level",
        "auth-header-key": "Auth header key, default is `X-CRYPTPASS-KEY`",
        "tls": {
            "key-pem": "PEM key, if missing then server will run in http",
            "cert-pem": "PEM cert, if missing then server will run in http"
        }
    },
    "physical": {
        "master-encryption-key": "Master encryption key, Recommended: Set it via api endpoint",
        "config": {
            "data-dir": "Path to data directory, Default is `/var/lib/cryptpass`"
        }
    }
}
```

#### Environment Variables

- `CRYPTPASS_CONFIG`: Path to a configuration file or raw JSON. **Default:** `/etc/cryptpass/config.json`
- `CRYPTPASS_LOG_LEVEL`: Log level (`INFO`, `DEBUG`, etc.). **Default:** `INFO`. [Reference](https://logging.apache.org/log4j/2.x/manual/customloglevels.html)
- `CRYPTPASS_LOG_DIR`: Log directory. **Default:** `/var/log/cryptpass`

For first-time setups:

- If the root password is unset, one will be generated on startup and printed to logs at INFO level.
- If TLS fields are omitted, the service will run **HTTP** (not recommended for production).

## API Endpoints

- `POST /api/v1/admin/...` — Admin operations (authentication, unlocking, etc.).
- `POST /api/v1/keyvalue/...` — CRUD for secret key-value pairs.
- `GET /health` — Health check endpoint, returns `OK` if running.

*See OpenAPI/Swagger documentation for full REST interface details and payload formats.*

## Deployment

Deployment is automated using **Ansible**.

### Steps

1. Edit `ansible/inventory.yaml` to set required variables (see template below):

    ```yaml
    all:
        vars:
            cryptpass_config: "<Cryptpass configuration in yaml/json format>"
    ```

2. The Ansible Vault password for secure var files can be retrieved from your organization's Bitwarden or with
   `ansible/vault_pass.sh`.

3. Deploy with:

```textmate
./ansible/deploy.sh
```

---

## Development Setup

1. Clone the repository and install Rust (if not installed):

    ```textmate
    rustup install stable
    ```

2. [Optional] For Ansible vault diff support, add to `~/.gitattributes`:

    ```.gitignore (gitignore)
    ansible/inventory.yaml diff=ansible-vault merge=binary
    ```

   Then, configure git diff:

    ```textmate
    git config diff.ansible-vault.textconv "ansible-vault view"
    ```

3. Run the project locally (with a dev configuration):

    ```textmate
    cargo run
    ```

## Roadmap

- **Backup:** Automated secret backups (planned after base feature stabilization).
- **Additional Integrations:** Extending the API for broader use-cases.
- **Factory & Safety Improvements:** Ensure robust data durability and safety protocols.

## License

See the [LICENSE](LICENSE) file for license information.

## Contributing

Pull requests and issues are welcome! Please open an issue for questions, feature requests, or bug reports.
