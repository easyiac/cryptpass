-- Your SQL goes here

CREATE TABLE IF NOT EXISTS encryption_keys_t
(
    id_c                       INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    encrypted_encryption_key_c TEXT                              NOT NULL,
    encryption_key_hash_c      TEXT                              NOT NULL,
    encryptor_key_hash_c       TEXT                              NOT NULL,
    UNIQUE (encryption_key_hash_c)
);

CREATE TABLE IF NOT EXISTS key_value_t
(
    id_c                 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    key_c                TEXT                              NOT NULL,
    encrypted_value_c    TEXT                              NOT NULL,
    deleted_c            BOOLEAN DEFAULT FALSE             NOT NULL,
    version_c            INTEGER                           NOT NULL,
    last_updated_at_c    INTEGER                           NOT NULL,
    encryptor_key_hash_c TEXT                              NOT NULL,
    FOREIGN KEY (encryptor_key_hash_c) REFERENCES encryption_keys_t (encryption_key_hash_c),
    UNIQUE (key_c, version_c)
);

CREATE TABLE IF NOT EXISTS users_t
(
    id_c                    INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username_c              TEXT                              NOT NULL,
    email_c                 TEXT,
    password_hash_c         TEXT,
    password_last_changed_c INTEGER                           NOT NULL,
    roles_c                 TEXT                              NOT NULL,
    last_login_c            INTEGER                           NOT NULL,
    locked_c                BOOLEAN DEFAULT TRUE              NOT NULL,
    enabled_c               BOOLEAN DEFAULT FALSE             NOT NULL,
    UNIQUE (username_c)
);
