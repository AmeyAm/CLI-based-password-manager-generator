# Password Manager

A small CLI-based password generator and encrypted password store written in C.

The project currently targets Linux and other Unix-like systems. Future improvements could include cross-platform support, a GUI, and easier access across devices.

## Features

- Generates random passwords using OpenSSL secure randomness
- Ensures generated passwords include lowercase, uppercase, digits, and symbols
- Encrypts saved passwords with AES-256-GCM
- Derives encryption keys from a master password with PBKDF2-HMAC-SHA256
- Stores encrypted records in `passwords.txt`

## Requirements

- Linux or another Unix-like system
- A C compiler such as `gcc` or `clang`
- OpenSSL development headers and libraries
- `make`

On Debian/Ubuntu:

```bash
sudo apt install build-essential libssl-dev
```

On Fedora:

```bash
sudo dnf install gcc make openssl-devel
```

## Build

```bash
make
```

## Run

```bash
./password_manager
```

The program asks for:

- An account label
- A generated password length
- A master password used to encrypt the saved record

New saved records are written to `passwords.txt` in this format:

```text
v1:label:iterations:salt:iv:tag:ciphertext
```

The account label is readable. The generated password is encrypted.

## Important Security Notes

Do not commit `passwords.txt` to GitHub. It may contain sensitive data, especially if older entries were saved before encryption was added.

This is a learning project, not a replacement for a mature password manager. For real accounts, use an audited password manager such as Bitwarden, 1Password, KeePassXC, or similar.

## Clean Build Files

```bash
make clean
```
