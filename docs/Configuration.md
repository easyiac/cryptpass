# Configuration

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

## Configuration Options

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
