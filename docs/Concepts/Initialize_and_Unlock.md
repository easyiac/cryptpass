# Initialize and Unlock Concepts

CryptPass uses a two-phase security model for managing encryption keys and securing data access. This document explains the **Initialize** and **Unlock** concepts and their processes.

## Overview

CryptPass implements a **two-layer encryption system**:

1. **Master Encryption Key**: The primary key that encrypts the internal encryption key
2. **Internal Encryption Key**: Used to encrypt individual data values stored in the system

The Initialize and Unlock processes manage these keys securely to ensure data protection while allowing controlled access.

## Initialize Process

### Initialize Process: Purpose

The **Initialize** process is a **one-time setup** that:

- Creates the master encryption key
- Generates the internal encryption key
- Establishes the encryption hierarchy
- Prepares the application for secure data storage

### Initialize Process: When to Use

- First-time setup of a new CryptPass instance
- When no encryption keys exist in the system
- During initial deployment

### Initialize Process: Process Flow

1. **Endpoint**: `POST /perpetual/initialize`
2. **Master Key Generation**:
   - System generates a secure random master encryption key
   - Key format: Base64-encoded 256-bit AES key with IV (`key:$:iv`)
3. **Internal Key Generation**:
   - System generates a separate internal encryption key
   - This key will encrypt/decrypt actual data values
4. **Key Encryption**:
   - Internal encryption key is encrypted using the master key
   - Only the encrypted internal key is stored in the database
5. **Storage**:
   - Encrypted internal key details are stored in settings table
   - Master key is returned to the user (NOT stored in database)
6. **User Management**:
   - Root user account is created for initial access

### Initialize Process: Response

```json
{
  "master_key": "generated_master_key_base64"
}
```

### Initialize Process: Security Notes

- **Master key is NEVER stored** in the database or configuration files
- User must securely store the returned master key
- Process can only be run once per instance
- Subsequent calls will return an error if already initialized

## Unlock Process

### Unlock Process: Purpose

The **Unlock** process is required **every time** the application starts to:

- Provide the master encryption key to the running application
- Decrypt the internal encryption key
- Enable access to encrypted data
- Activate the encryption/decryption functionality

### Unlock Process: When to Use

- After application startup/restart
- When the application needs to access encrypted data
- Following any system reboot or service restart

### Unlock Process: Process Flow

1. **Endpoint**: `POST /perpetual/unlock`
2. **Master Key Provision**:
   - User provides the master encryption key via API request
   - Key can be provided as direct string or file path
3. **Validation**:
   - System retrieves encrypted internal key from database
   - Verifies master key by checking hash matches stored encryptor hash
4. **Decryption**:
   - Uses provided master key to decrypt the internal encryption key
   - Validates decrypted key against stored hash
5. **Memory Storage**:
   - Decrypted internal key is stored in application memory (OnceLock)
   - Enables encryption/decryption operations for data access
6. **User Setup**:
   - Ensures root user exists and is properly configured

### Unlock Process: Request Format

```json
{
  "master_encryption_key": "your_master_key_or_file_path"
}
```

### Unlock Process: Response

```json
{
  "encrypted_key": "encrypted_internal_key",
  "hash": "internal_key_hash", 
  "encryptor_hash": "master_key_hash"
}
```

### Unlock Process: Security Notes

- Master key is only held in memory during the unlock process
- Internal key remains in memory for the application lifetime
- Application must be unlocked before any data operations
- Unlock fails if wrong master key is provided

## Unlock Process: Key Relationships

```
Master Key (User-provided)
    ↓ (encrypts)
Internal Encryption Key (Database-stored, encrypted)
    ↓ (encrypts)
Individual Data Values (Database-stored, encrypted)
```

## Security Benefits

1. **Separation of Concerns**: Master key never stored persistently
2. **Two-Layer Protection**: Data encrypted with internal key, internal key encrypted with master key
3. **Runtime Security**: Keys only exist in memory during operation
4. **Access Control**: Application unusable without proper master key
5. **Key Rotation**: Internal keys can be rotated without affecting master key

## Error States

### Initialize Errors

- **Application Already Initialized**: Attempting to initialize when keys already exist
- **Database Errors**: Unable to store encryption key details
- **Key Generation Failures**: Cryptographic operations fail

### Unlock Errors

- **Application Not Initialized**: No encrypted internal key exists
- **Invalid Master Key**: Provided key doesn't match stored hash
- **Key Corruption**: Internal key hash validation fails
- **Database Access**: Unable to retrieve stored key details

## Best Practices

1. **Secure Master Key Storage**: Store master key in secure key management system
2. **Environment Variables**: Use environment variables or secure files for master key
3. **Backup Strategy**: Ensure master key is backed up securely
4. **Access Logging**: Monitor initialize/unlock operations
5. **Network Security**: Always use TLS for key transmission
6. **Key Rotation**: Regularly review and rotate encryption keys as needed

## Example Usage

### Initial Setup

```bash
# Initialize the application
curl -X POST https://cryptpass.example.com/perpetual/initialize

# Response: {"master_key": "generated_key_here"}
# Store this key securely!
```

### Runtime Unlock

```bash
# Unlock with direct key
curl -X POST https://cryptpass.example.com/perpetual/unlock \
  -H "Content-Type: application/json" \
  -d '{"master_encryption_key": "your_stored_master_key"}'

# Unlock with file path
curl -X POST https://cryptpass.example.com/perpetual/unlock \
  -H "Content-Type: application/json" \
  -d '{"master_encryption_key": "/secure/path/to/master.key"}'
```

This design ensures that CryptPass maintains strong security while providing practical access control for encrypted data storage and retrieval.
