"""SecureVault PKI Command-Line Interface.

Provides a unified CLI entry point for all SecureVault PKI operations:
CA initialization, key generation, certificate issuance, file signing,
signature verification, file encryption, file decryption, and certificate
revocation.

Uses Python's argparse (standard library) for argument parsing. Each command
delegates to the appropriate module function and handles errors gracefully
with user-friendly messages printed to stderr.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from securevault import certificate_authority, encryption_engine, key_manager, signature_engine


def _cmd_init_ca(args: argparse.Namespace) -> None:
    """Handle the init-ca command.

    Initializes the Certificate Authority with the given name and password.
    """
    certificate_authority.init_ca(ca_name=args.name, password=args.password)
    print(f"CA initialized: {args.name}")


def _cmd_keygen(args: argparse.Namespace) -> None:
    """Handle the keygen command.

    Generates a key pair with the specified type and size.
    """
    key_manager.generate_keypair(
        name=args.name,
        key_type=args.type,
        key_size=args.size,
        password=args.password,
    )
    print(f"Key pair generated: {args.name} ({args.type})")


def _cmd_issue_cert(args: argparse.Namespace) -> None:
    """Handle the issue-cert command.

    Loads a public key from file and issues a CA-signed certificate.
    """
    pubkey_path = Path(args.pubkey)
    if not pubkey_path.exists():
        raise FileNotFoundError(f"Public key file not found: {args.pubkey}")

    pubkey_pem = pubkey_path.read_bytes()

    cert = certificate_authority.issue_certificate(
        subject=args.subject,
        public_key_pem=pubkey_pem,
        validity_days=args.days,
        password=args.ca_password,
    )

    # Save certificate to {subject}.cert.json in current directory
    cert_filename = f"{args.subject}.cert.json"
    Path(cert_filename).write_text(json.dumps(cert, indent=2), encoding="utf-8")

    print(f"Certificate issued for {args.subject} (serial: {cert['serial']})")


def _cmd_sign(args: argparse.Namespace) -> None:
    """Handle the sign command.

    Signs a file with the specified private key and signer certificate.
    """
    # Load private key
    private_key_pem = key_manager.load_private_key(args.key, args.password)

    # Load signer certificate from file
    cert_path = Path(args.cert)
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {args.cert}")

    signer_cert = json.loads(cert_path.read_text(encoding="utf-8"))

    # Sign the file
    signature_bytes = signature_engine.sign_file(args.file, private_key_pem, signer_cert)

    # Save signature to {filepath}.sig
    sig_path = f"{args.file}.sig"
    Path(sig_path).write_bytes(signature_bytes)

    print(f"Signature created: {sig_path}")


def _cmd_verify(args: argparse.Namespace) -> None:
    """Handle the verify command.

    Verifies a file signature against the CA certificate chain.
    """
    # Load signature from sig_file
    sig_path = Path(args.sig)
    if not sig_path.exists():
        raise FileNotFoundError(f"Signature file not found: {args.sig}")

    signature = sig_path.read_bytes()

    # Load CA cert from ca_cert_file
    ca_cert_path = Path(args.ca_cert)
    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate file not found: {args.ca_cert}")

    ca_cert = json.loads(ca_cert_path.read_text(encoding="utf-8"))

    # Extract signer_cert from the signature JSON
    sig_data = json.loads(signature)
    signer_cert = sig_data["signer_cert"]

    # Load CRL if available
    crl = certificate_authority.get_crl() if _ca_initialized() else None

    # Verify
    is_valid, reason = signature_engine.verify_file_signature(
        args.file, signature, signer_cert, ca_cert, crl
    )

    if is_valid:
        subject = signer_cert.get("subject", "unknown")
        print(f"VALID: Signed by {subject}")
    else:
        print(f"INVALID: {reason}")


def _cmd_encrypt(args: argparse.Namespace) -> None:
    """Handle the encrypt command.

    Encrypts a file for a recipient using hybrid encryption.
    """
    # Load recipient cert from cert_file
    cert_path = Path(args.cert)
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {args.cert}")

    recipient_cert = json.loads(cert_path.read_text(encoding="utf-8"))

    # Determine output path
    output_path = args.output if args.output else f"{args.file}.enc"

    # Encrypt the file
    encryption_engine.encrypt_file(args.file, recipient_cert, output_path)

    print(f"Encrypted: {output_path}")


def _cmd_decrypt(args: argparse.Namespace) -> None:
    """Handle the decrypt command.

    Decrypts an encrypted file using the recipient's private key.
    """
    # Load private key
    private_key_pem = key_manager.load_private_key(args.key, args.password)

    # Determine output path
    if args.output:
        output_path = args.output
    elif args.file.endswith(".enc"):
        output_path = args.file[:-4]
    else:
        output_path = args.file + ".dec"

    # Decrypt the file
    encryption_engine.decrypt_file(args.file, private_key_pem, output_path)

    print(f"Decrypted: {output_path}")


def _cmd_revoke_cert(args: argparse.Namespace) -> None:
    """Handle the revoke-cert command.

    Revokes a certificate by adding its serial number to the CRL.
    """
    certificate_authority.revoke_certificate(
        serial=args.serial, password=args.ca_password
    )
    print(f"Certificate revoked: serial {args.serial}")


def _ca_initialized() -> bool:
    """Check if the CA has been initialized.

    Returns:
        True if the CA certificate file exists, False otherwise.
    """
    try:
        certificate_authority.get_ca_certificate()
        return True
    except RuntimeError:
        return False


def main() -> None:
    """Set up argparse and dispatch CLI commands.

    Entry point for the SecureVault PKI CLI. Parses command-line arguments,
    dispatches to the appropriate handler function, and handles errors
    gracefully with user-friendly messages to stderr.
    """
    parser = argparse.ArgumentParser(
        prog="securevault",
        description=(
            "SecureVault PKI - Cryptographic toolkit for digital signatures, "
            "encryption, and certificate management"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- init-ca ---
    init_ca_parser = subparsers.add_parser(
        "init-ca", help="Initialize the Certificate Authority"
    )
    init_ca_parser.add_argument(
        "--name", required=True, help="Name for the Certificate Authority"
    )
    init_ca_parser.add_argument(
        "--password", required=True, help="Password to protect the CA private key"
    )
    init_ca_parser.set_defaults(func=_cmd_init_ca)

    # --- keygen ---
    keygen_parser = subparsers.add_parser(
        "keygen", help="Generate a cryptographic key pair"
    )
    keygen_parser.add_argument(
        "--name", required=True, help="Unique name for the key pair"
    )
    keygen_parser.add_argument(
        "--type",
        default="rsa",
        choices=["rsa", "ecc"],
        help="Key type: rsa or ecc (default: rsa)",
    )
    keygen_parser.add_argument(
        "--size",
        type=int,
        default=4096,
        help="Key size in bits (RSA only, default: 4096)",
    )
    keygen_parser.add_argument(
        "--password", required=True, help="Password to encrypt the private key"
    )
    keygen_parser.set_defaults(func=_cmd_keygen)

    # --- issue-cert ---
    issue_cert_parser = subparsers.add_parser(
        "issue-cert", help="Issue a CA-signed certificate"
    )
    issue_cert_parser.add_argument(
        "--subject", required=True, help="Subject name for the certificate"
    )
    issue_cert_parser.add_argument(
        "--pubkey", required=True, help="Path to the subject's public key file (PEM)"
    )
    issue_cert_parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Certificate validity in days (default: 365)",
    )
    issue_cert_parser.add_argument(
        "--ca-password", required=True, help="CA password for signing"
    )
    issue_cert_parser.set_defaults(func=_cmd_issue_cert)

    # --- sign ---
    sign_parser = subparsers.add_parser(
        "sign", help="Create a detached digital signature for a file"
    )
    sign_parser.add_argument(
        "--file", required=True, help="Path to the file to sign"
    )
    sign_parser.add_argument(
        "--key", required=True, help="Name of the signing key in the keystore"
    )
    sign_parser.add_argument(
        "--password", required=True, help="Password for the signing key"
    )
    sign_parser.add_argument(
        "--cert", required=True, help="Path to the signer's certificate file (JSON)"
    )
    sign_parser.set_defaults(func=_cmd_sign)

    # --- verify ---
    verify_parser = subparsers.add_parser(
        "verify", help="Verify a detached digital signature"
    )
    verify_parser.add_argument(
        "--file", required=True, help="Path to the original file"
    )
    verify_parser.add_argument(
        "--sig", required=True, help="Path to the signature file"
    )
    verify_parser.add_argument(
        "--ca-cert", required=True, help="Path to the CA certificate file (JSON)"
    )
    verify_parser.set_defaults(func=_cmd_verify)

    # --- encrypt ---
    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file for a recipient"
    )
    encrypt_parser.add_argument(
        "--file", required=True, help="Path to the file to encrypt"
    )
    encrypt_parser.add_argument(
        "--cert", required=True, help="Path to the recipient's certificate file (JSON)"
    )
    encrypt_parser.add_argument(
        "--output",
        default=None,
        help="Output file path (default: {file}.enc)",
    )
    encrypt_parser.set_defaults(func=_cmd_encrypt)

    # --- decrypt ---
    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt an encrypted file"
    )
    decrypt_parser.add_argument(
        "--file", required=True, help="Path to the encrypted file"
    )
    decrypt_parser.add_argument(
        "--key", required=True, help="Name of the decryption key in the keystore"
    )
    decrypt_parser.add_argument(
        "--password", required=True, help="Password for the decryption key"
    )
    decrypt_parser.add_argument(
        "--output",
        default=None,
        help="Output file path (default: input without .enc extension)",
    )
    decrypt_parser.set_defaults(func=_cmd_decrypt)

    # --- revoke-cert ---
    revoke_cert_parser = subparsers.add_parser(
        "revoke-cert", help="Revoke a certificate by serial number"
    )
    revoke_cert_parser.add_argument(
        "--serial", type=int, required=True, help="Serial number of the certificate to revoke"
    )
    revoke_cert_parser.add_argument(
        "--ca-password", required=True, help="CA password for authorization"
    )
    revoke_cert_parser.set_defaults(func=_cmd_revoke_cert)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Dispatch to the appropriate command handler with error handling
    try:
        args.func(args)
    except (ValueError, FileNotFoundError, FileExistsError, RuntimeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
