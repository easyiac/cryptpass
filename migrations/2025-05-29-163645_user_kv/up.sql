CREATE TABLE IF NOT EXISTS app_settings_t
(
    settings_c        TEXT PRIMARY KEY NOT NULL,
    value_c           TEXT             NOT NULL,
    last_updated_at_c INTEGER          NOT NULL
);

CREATE TABLE IF NOT EXISTS encryption_keys_t
(
    encrypted_encryption_key_c TEXT NOT NULL,
    encryption_key_hash_c      TEXT NOT NULL,
    encryptor_key_hash_c       TEXT NOT NULL,
    PRIMARY KEY (encryption_key_hash_c, encryptor_key_hash_c),
    UNIQUE (encryption_key_hash_c)
);

CREATE TABLE IF NOT EXISTS key_value_t
(
    key_c             TEXT                  NOT NULL,
    encrypted_value_c TEXT                  NOT NULL,
    deleted_c         BOOLEAN DEFAULT FALSE NOT NULL,
    version_c         INTEGER               NOT NULL,
    last_updated_at_c INTEGER               NOT NULL,
    PRIMARY KEY (key_c, version_c)
);

CREATE TABLE IF NOT EXISTS users_t
(
    username_c                           TEXT PRIMARY KEY      NOT NULL,
    email_c                              TEXT,
    password_hash_c                      TEXT,
    password_last_changed_c              INTEGER               NOT NULL,
    roles_c                              TEXT                  NOT NULL,
    last_login_c                         INTEGER               NOT NULL,
    locked_c                             BOOLEAN DEFAULT TRUE  NOT NULL,
    enabled_c                            BOOLEAN DEFAULT FALSE NOT NULL,
    api_token_jwt_secret_b64_encrypted_c TEXT                  NOT NULL
);
