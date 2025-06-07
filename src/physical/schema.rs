diesel::table! {
    #[sql_name = "encryption_keys_t"]
    encryption_keys_table (key_hash, encryptor_hash) {
        #[sql_name = "encrypted_key_c"]
        encrypted_key -> Text,
        #[sql_name = "key_hash_c"]
        key_hash -> Text,
        #[sql_name = "encryptor_hash_c"]
        encryptor_hash -> Text,
    }
}

diesel::table! {
    #[sql_name = "app_settings_t"]
    app_settings_table (settings) {
        #[sql_name = "settings_c"]
        settings -> Text,
        #[sql_name = "value_c"]
        value -> Text,
        #[sql_name = "last_updated_at_c"]
        last_updated_at -> BigInt,
    }
}

diesel::table! {
    #[sql_name = "key_value_t"]
    key_value_table (key, version) {
        #[sql_name = "key_c"]
        key -> Text,
        #[sql_name = "encrypted_value_c"]
        encrypted_value -> Text,
        #[sql_name = "deleted_c"]
        deleted -> Bool,
        #[sql_name = "version_c"]
        version -> Integer,
        #[sql_name = "last_updated_at_c"]
        last_updated_at -> BigInt,
        #[sql_name = "encryptor_hash_c"]
        encryptor_hash -> Text,
    }
}

diesel::table! {
    #[sql_name = "users_t"]
    users_table (username) {
        #[sql_name = "username_c"]
        username -> Text,
        #[sql_name = "email_c"]
        email -> Nullable<Text>,
        #[sql_name = "password_hash_c"]
        password_hash -> Nullable<Text>,
        #[sql_name = "password_last_changed_c"]
        password_last_changed -> BigInt,
        #[sql_name = "roles_c"]
        roles -> Text,
        #[sql_name = "last_login_c"]
        last_login -> BigInt,
        #[sql_name = "locked_c"]
        locked -> Bool,
        #[sql_name = "enabled_c"]
        enabled -> Bool,   #[sql_name = "encryptor_hash_c"]
        encryptor_hash -> Text,
        #[sql_name = "jwt_secret_b64_encrypted_c"]
        jwt_secret_b64_encrypted -> Text,
    }
}
