"""Encrypt and decrypt files with password-based authenticated encryption.

This uses AES-256-GCM for confidentiality and integrity, and Scrypt to derive
the encryption key from a password. It is intended for files you own or are
authorized to protect.
"""

import argparse
import getpass
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


OLD_MAGIC = b"PYCRYPT1"
MAGIC = b"PYCRYPT2"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits
CHUNK_SIZE = 1024 * 1024


def password_strength_errors(password):
    """Return password-policy violations without exposing the password."""
    errors = []
    if len(password) < 16:
        errors.append("use at least 16 characters")

    character_types = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if character_types < 3:
        errors.append("include at least three of lowercase, uppercase, numbers, and symbols")
    return errors


def derive_key(password, salt):
    """Derive a 256-bit encryption key from a password and random salt."""
    return Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**15,
        r=8,
        p=1,
    ).derive(password.encode("utf-8"))


def show_progress(label, completed, total):
    percent = 100 if total == 0 else min(100, completed * 100 // total)
    print(f"\r{label}: {percent:3d}%", end="", flush=True)


def encrypt_file(source, destination, password):
    print("Starting encryption...", flush=True)
    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(8)
    print("Deriving encryption key...", flush=True)
    key = derive_key(password, salt)
    print("Encrypting file...", flush=True)
    total = source.stat().st_size
    completed = 0
    header = MAGIC + salt + nonce_prefix + struct.pack(">I", CHUNK_SIZE)

    with source.open("rb") as input_file, destination.open("wb") as output_file:
        output_file.write(header)
        counter = 0
        while True:
            chunk = input_file.read(CHUNK_SIZE)
            if not chunk and (counter or total):
                break
            nonce = nonce_prefix + counter.to_bytes(4, "big")
            encrypted = AESGCM(key).encrypt(nonce, chunk, header + counter.to_bytes(4, "big"))
            output_file.write(struct.pack(">I", len(encrypted)))
            output_file.write(encrypted)
            completed += len(chunk)
            counter += 1
            show_progress("Encrypting", completed, total)
            if not chunk:
                break
    print("\nEncryption complete.", flush=True)


def decrypt_file(source, destination, password):
    encrypted = source.read_bytes()
    if encrypted.startswith(OLD_MAGIC):
        decrypt_old_file(encrypted, destination, password)
        return
    header_size = len(MAGIC) + SALT_SIZE + 8 + 4
    if len(encrypted) <= header_size or not encrypted.startswith(MAGIC):
        raise ValueError("This is not a supported encrypted file.")

    offset = len(MAGIC)
    salt = encrypted[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce_prefix = encrypted[offset : offset + 8]
    offset += 8
    chunk_size = struct.unpack(">I", encrypted[offset : offset + 4])[0]
    offset += 4
    if not chunk_size or chunk_size > 16 * CHUNK_SIZE:
        raise ValueError("invalid encrypted file chunk size")
    header = encrypted[:header_size]
    key = derive_key(password, salt)

    temporary = destination.with_name(destination.name + ".part")
    completed = 0
    try:
        with temporary.open("wb") as output_file:
            counter = 0
            while offset < len(encrypted):
                if offset + 4 > len(encrypted):
                    raise ValueError("truncated encrypted file")
                length = struct.unpack(">I", encrypted[offset : offset + 4])[0]
                offset += 4
                ciphertext = encrypted[offset : offset + length]
                if len(ciphertext) != length:
                    raise ValueError("truncated encrypted file")
                offset += length
                nonce = nonce_prefix + counter.to_bytes(4, "big")
                plaintext = AESGCM(key).decrypt(
                    nonce, ciphertext, header + counter.to_bytes(4, "big")
                )
                output_file.write(plaintext)
                counter += 1
                show_progress("Decrypting", offset, len(encrypted))
        os.replace(temporary, destination)
        print()
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def decrypt_old_file(encrypted, destination, password):
    """Decrypt files produced by version 1 of this program."""
    header_size = len(OLD_MAGIC) + SALT_SIZE + NONCE_SIZE
    if len(encrypted) <= header_size:
        raise ValueError("This is not a supported encrypted file.")
    offset = len(OLD_MAGIC)
    salt = encrypted[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted[offset : offset + NONCE_SIZE]
    ciphertext = encrypted[offset + NONCE_SIZE :]
    key = derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, OLD_MAGIC)
    destination.write_bytes(plaintext)
    show_progress("Decrypting", 1, 1)
    print()


def output_path(path, operation):
    if operation == "encrypt":
        return path.with_name(path.name + ".encrypted")
    if path.name.endswith(".encrypted"):
        return path.with_name(path.name[: -len(".encrypted")])
    return path.with_name(path.name + ".decrypted")


def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file securely")
    subparsers = parser.add_subparsers(dest="operation")
    for operation in ("encrypt", "decrypt"):
        command = subparsers.add_parser(operation)
        command.add_argument("file", type=Path, nargs="?", help="input file")
        command.add_argument("-o", "--output", type=Path, help="output file")
        command.add_argument("--force", action="store_true", help="allow replacing the output file")
    args = parser.parse_args()

    # PyCharm often runs a script with no command-line parameters. Offer a
    # small interactive fallback while retaining the normal CLI interface.
    if args.operation is None and len(sys.argv) == 1:
        choice = input("Choose an operation (encrypt/decrypt): ").strip().lower()
        if choice not in {"encrypt", "decrypt"}:
            parser.error("operation must be encrypt or decrypt")
        args.operation = choice
        args.file = Path(input("File to process: ").strip().strip('"'))
        args.output = None
        args.force = False
    elif args.operation is None:
        parser.error("choose an operation: encrypt or decrypt")
    elif args.file is None:
        parser.error(f"provide a file after {args.operation}")

    if not args.file.is_file():
        parser.error(f"input file does not exist: {args.file}")
    destination = args.output or output_path(args.file, args.operation)
    if destination.exists() and not args.force:
        parser.error(f"output already exists: {destination} (use --force to replace it)")
    if destination.resolve() == args.file.resolve():
        parser.error("input and output files must be different")

    print("File accepted. Waiting for your password (your typing will be hidden)...", flush=True)
    password = getpass.getpass("Password: ")
    if not password:
        parser.error("password cannot be empty")
    if args.operation == "encrypt":
        strength_errors = password_strength_errors(password)
        if strength_errors:
            parser.error("password is too weak: " + "; ".join(strength_errors))
        if getpass.getpass("Repeat password: ") != password:
            parser.error("passwords did not match")
        print("Password confirmed. Beginning encryption...", flush=True)

    try:
        if args.operation == "encrypt":
            encrypt_file(args.file, destination, password)
        else:
            decrypt_file(args.file, destination, password)
    except InvalidTag:
        parser.error("decryption failed: wrong password or file was modified")
    except ValueError as error:
        parser.error(str(error))
    print(f"{args.operation.title()}ed file written to: {destination}", flush=True)


if __name__ == "__main__":
    main()
