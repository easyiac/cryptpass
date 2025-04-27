# Cryptpass

A basic CRUD rest api wrapper for managing configuration and secrets.

## Configuration

env vars:

- CRYPTPASS_CONFIG: Configuration in json format or Path to the configuration file, default is `/etc/cryptpass/config.json`.

```json
{
    "server": {
        "port": "Port, type: int, default: `8088`",
        "root-password": "Root password, If not present in first run, it will be generated, and printed in the log on INFO level",
        "auth-header-key": "Auth header key, default is `Authorization`",
        "tls": {
            "key-pem": "PEM key, if missing then server will run in http",
            "cert-pem": "PEM cert, if missing then server will run in http"
        }
    },
    "physical": {
        "master-encryption-key": "Master encryption key, Recommended: Set it via `/admin/unlock` endpoint",
        "config": {
            "data-dir": "Path to data directory, Default is `/var/lib/cryptpass`"
        }
    }
}
```

- CRYPTPASS_LOG_LEVEL: Log level, default is INFO. [Reference](https://logging.apache.org/log4j/2.x/manual/customloglevels.html)
- CRYPTPASS_LOG_DIR: Log directory, default is /var/log/cryptpass.

## CRUD API: V1

route: /api/v1

### API: V1: admin

All the data is stored with zero knowledge encryption.
You can provide/change the encryption key with the unlock endpoint.

route: /admin

- unlock -> PUT /unlock -> returns 201 status code

  body:

    ```json
    {
        "key": "key"
    }
    ```

- read user -> GET /user/{username} -> returns 200 status code

- write user -> PUT /user/{username} -> returns 201 status code

  body:

    ```json
    {
        "email": null,
        "password": "test123",
        "roles": [
            {
                "name": "ADMIN",
                "privileges": [
                    {
                        "name": "SUDO"
                    }
                ]
            }
        ],
        "lastLogin": 0,
        "locked": false,
        "enabled": true
    }
    ```

- list keys -> GET /list/keys/{key} -> returns 200 status code with a list of keys.
- In case of /list/keys or /list/keys/ it will return all the keys.

### API: V1: secrets

route: /secrets

It performs only 3 operations: `read`, `write`, and `delete`.

- read -> GET /{key} -> returns the secret value with 200 status code

- write -> POST /{key} -> returns 201 status code

  body:

    ```json
    {
        "secret1": "value1"
    }
    ```

- delete -> DELETE /{key} -> returns 204 status code

## Deployment

Add all the variables in `ansible/inventory.yml` and run the following command.

Ansible vault password is in bitwarden `ansible/vault_pass.sh`.

In `ansible/inventory.yml`, the following variables are required.

```yaml
---
all:
    vars:
        cryptpass_config: "Cryptpass configuration in yaml/json format"
```

Start the deployment with the following command.

```sh
./ansible/deploy.sh
```

## Development

### Setup

For ansible vault diff.

Add the following line in `~/.gitattributes`.

```gitignore
ansible/inventory.yml diff=ansible-vault merge=binary
```

And then run the following command.

```sh
git config diff.ansible-vault.textconv "ansible-vault view"
```

## Backup

In the roadmap, after I set up a factory for milk bottle, seat belt and helmet, I will implement a backup mechanism for
the secrets.
