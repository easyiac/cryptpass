// @generated automatically by Diesel CLI.

diesel::table! {
    #[sql_name = "encryption_keys_t"]
    encryption_keys (encryption_key_hash) {
        #[sql_name = "id_c"]
        id -> Nullable<BigInt>,
        #[sql_name = "encrypted_encryption_key_c"]
        encrypted_encryption_key -> Text,
        #[sql_name = "encryption_key_hash_c"]
        encryption_key_hash -> Text,
        #[sql_name = "encryptor_key_hash_c"]
        encryptor_key_hash -> Text,
    }
}

diesel::table! {
    #[sql_name = "key_value_t"]
    key_value (key, version) {
        #[sql_name = "id_c"]
        id -> Nullable<BigInt>,
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
        #[sql_name = "encryptor_key_hash_c"]
        encryptor_key_hash -> Text,
    }
}

diesel::joinable!(key_value -> encryption_keys (encryptor_key_hash));
diesel::allow_tables_to_appear_in_same_query!(encryption_keys, key_value,);

diesel::table! {
    #[sql_name = "users_t"]
    users (username) {
        #[sql_name = "id_c"]
        id -> Nullable<BigInt>,
        #[sql_name = "username_c"]
        username -> Text,
        #[sql_name = "email_c"]
        email -> Nullable<Text>,
        #[sql_name = "password_hash_c"]
        password_hash -> Nullable<Text>,
        #[sql_name = "password_last_changed_c"]
        password_last_changed -> Nullable<BigInt>,
        #[sql_name = "roles_c"]
        roles -> Text,
        #[sql_name = "last_login_c"]
        last_login -> Nullable<BigInt>,
        #[sql_name = "locked_c"]
        locked -> Bool,
        #[sql_name = "enabled_c"]
        enabled -> Bool,
    }
}
