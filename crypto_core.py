"""
Cryptographic Core Module
Handles all encryption, decryption, hashing, and key management operations
Implements hybrid RSA+AES encryption with HMAC for message authentication
"""
import os
import json
import hashlib
import hmac
import time
import secrets
from pathlib import Path
from typing import Tuple, Dict, Optional, Union
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import bcrypt

from config import SecurityConfig, DatabaseConfig, LoggingConfig


class CryptoUtils:
    """Core cryptographic utility functions"""

    @staticmethod
    def generate_random_bytes(length: int) -> bytes:
        """Generate cryptographically secure random bytes"""
        return secrets.token_bytes(length)

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """Generate a random salt for key derivation"""
        return CryptoUtils.generate_random_bytes(length)

    @staticmethod
    def derive_key(password: Union[str, bytes], salt: bytes, key_length: int = 32) -> bytes:
        """
        Derive a cryptographic key from a password using PBKDF2
        Args:
            password: Password string or bytes
            salt: Salt for key derivation
            key_length: Desired key length in bytes (default: 32 for AES-256)
        Returns:
            Derived key as bytes
        """
        if isinstance(password, str):
            password = password.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,  # High iteration count for security
            backend=default_backend()
        )
        return kdf.derive(password)

    @staticmethod
    def compute_hash(data: Union[str, bytes], algorithm: str = 'SHA256') -> str:
        """
        Compute cryptographic hash of data
        Args:
            data: Data to hash
            algorithm: Hash algorithm to use (SHA256, SHA512, etc.)
        Returns:
            Hexadecimal hash string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        hash_func = getattr(hashlib, algorithm.lower())()
        hash_func.update(data)
        return hash_func.hexdigest()

    @staticmethod
    def compute_hmac(data: Union[str, bytes], key: bytes, algorithm: str = 'SHA256') -> str:
        """
        Compute HMAC for message authentication
        Args:
            data: Data to authenticate
            key: HMAC key
            algorithm: Hash algorithm for HMAC
        Returns:
            Hexadecimal HMAC string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        hmac_digest = hmac.new(key, data, getattr(hashlib, algorithm.lower())).hexdigest()
        return hmac_digest

    @staticmethod
    def verify_hmac(data: Union[str, bytes], key: bytes, received_hmac: str, algorithm: str = 'SHA256') -> bool:
        """
        Verify HMAC of received data
        Uses constant-time comparison to prevent timing attacks
        """
        computed_hmac = CryptoUtils.compute_hmac(data, key, algorithm)
        return hmac.compare_digest(computed_hmac, received_hmac)


class PasswordHasher:
    """Secure password hashing using bcrypt"""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt
        Args:
            password: Plain text password
        Returns:
            Salted bcrypt hash
        """
        salt = bcrypt.gensalt(rounds=SecurityConfig.BCRYPT_ROUNDS)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        Args:
            password: Plain text password to verify
            hashed_password: Stored bcrypt hash
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception:
            return False


class RSAKeyManager:
    """RSA key generation, storage, and management"""

    @staticmethod
    def generate_key_pair(username: str) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair for a user
        Args:
            username: Username to generate keys for
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=SecurityConfig.RSA_PUBLIC_EXPONENT,
            key_size=SecurityConfig.RSA_KEY_SIZE,
            backend=default_backend()
        )

        # Extract public key
        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def save_key_pair(username: str, private_key: bytes, public_key: bytes) -> bool:
        """Save RSA key pair to disk"""
        try:
            private_key_path = DatabaseConfig.KEYS_DIR / f"{username}{DatabaseConfig.PRIVATE_KEY_SUFFIX}"
            public_key_path = DatabaseConfig.KEYS_DIR / f"{username}{DatabaseConfig.PUBLIC_KEY_SUFFIX}"

            # Save with restrictive permissions
            with open(private_key_path, 'wb') as f:
                f.write(private_key)
            os.chmod(private_key_path, 0o600)  # Read/write for owner only

            with open(public_key_path, 'wb') as f:
                f.write(public_key)
            os.chmod(public_key_path, 0o644)  # Read for all, write for owner

            return True
        except Exception as e:
            print(f"Error saving keys: {e}")
            return False

    @staticmethod
    def load_private_key(username: str) -> Optional[rsa.RSAPrivateKey]:
        """Load user's private key from disk"""
        try:
            private_key_path = DatabaseConfig.KEYS_DIR / f"{username}{DatabaseConfig.PRIVATE_KEY_SUFFIX}"
            if not private_key_path.exists():
                return None

            with open(private_key_path, 'rb') as f:
                private_key_pem = f.read()

            return serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            print(f"Error loading private key: {e}")
            return None

    @staticmethod
    def load_public_key(username: str) -> Optional[rsa.RSAPublicKey]:
        """Load user's public key from disk"""
        try:
            public_key_path = DatabaseConfig.KEYS_DIR / f"{username}{DatabaseConfig.PUBLIC_KEY_SUFFIX}"
            if not public_key_path.exists():
                return None

            with open(public_key_path, 'rb') as f:
                public_key_pem = f.read()

            return serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
        except Exception as e:
            print(f"Error loading public key: {e}")
            return None

    @staticmethod
    def encrypt_with_rsa(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
        """
        Encrypt data using RSA with OAEP padding
        Args:
            public_key: RSA public key
            plaintext: Data to encrypt (must be smaller than key size)
        Returns:
            Encrypted data
        """
        # RSA can only encrypt data smaller than key size
        max_length = (public_key.key_size // 8) - 2 * hashes.SHA256.digest_size - 2

        if len(plaintext) > max_length:
            raise ValueError(f"Data too large for RSA encryption. Max: {max_length} bytes")

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def decrypt_with_rsa(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        """
        Decrypt RSA-encrypted data
        Args:
            private_key: RSA private key
            ciphertext: Encrypted data
        Returns:
            Decrypted plaintext
        """
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext


class AESCipher:
    """AES encryption/decryption operations"""

    @staticmethod
    def encrypt(plaintext: Union[str, bytes], key: bytes, iv: Optional[bytes] = None) -> Dict[str, str]:
        """
        Encrypt data using AES-256-CBC
        Args:
            plaintext: Data to encrypt
            key: AES key (32 bytes for AES-256)
            iv: Initialization vector (optional, will be generated if not provided)
        Returns:
            Dictionary containing encrypted data, IV, and other metadata
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Generate IV if not provided
        if iv is None:
            iv = CryptoUtils.generate_random_bytes(SecurityConfig.AES_BLOCK_SIZE)

        # Pad plaintext to block size
        def pad(data):
            padding_length = SecurityConfig.AES_BLOCK_SIZE - (len(data) % SecurityConfig.AES_BLOCK_SIZE)
            return data + (chr(padding_length) * padding_length).encode('utf-8')

        padded_plaintext = pad(plaintext)

        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'algorithm': f'AES-{SecurityConfig.AES_KEY_SIZE}-CBC',
            'timestamp': datetime.utcnow().isoformat()
        }

    @staticmethod
    def decrypt(encrypted_data: Dict[str, str], key: bytes) -> bytes:
        """
        Decrypt AES-encrypted data
        Args:
            encrypted_data: Dictionary containing ciphertext, IV, and metadata
            key: AES key
        Returns:
            Decrypted plaintext
        """
        try:
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            iv = bytes.fromhex(encrypted_data['iv'])

            # Decrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding with bounds check
            def unpad(data):
                if not data:
                    raise ValueError("Empty data after decryption")
                padding_length = data[-1]
                if padding_length < 1 or padding_length > SecurityConfig.AES_BLOCK_SIZE:
                    raise ValueError(f"Invalid padding length: {padding_length}")
                # Verify all padding bytes have the correct value
                if data[-padding_length:] != bytes([padding_length] * padding_length):
                    raise ValueError("Invalid PKCS7 padding bytes")
                return data[:-padding_length]

            plaintext = unpad(padded_plaintext)
            return plaintext

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


class HybridEncryption:
    """
    Hybrid encryption system using RSA for key exchange and AES for message encryption
    This provides the security of RSA with the efficiency of AES
    """

    @staticmethod
    def encrypt_message(message: str, recipient_public_key: rsa.RSAPublicKey) -> Dict[str, str]:
        """
        Encrypt a message using hybrid RSA+AES encryption
        Process:
        1. Generate random AES key
        2. Encrypt message with AES
        3. Encrypt AES key with RSA
        4. Return everything needed for decryption
        """
        try:
            # Step 1: Generate random AES key
            aes_key = CryptoUtils.generate_random_bytes(SecurityConfig.AES_KEY_SIZE // 8)
            aes_iv = CryptoUtils.generate_random_bytes(SecurityConfig.AES_BLOCK_SIZE)

            # Step 2: Encrypt message with AES
            encrypted_message = AESCipher.encrypt(message, aes_key, aes_iv)

            # Step 3: Encrypt AES key with RSA
            encrypted_aes_key = RSAKeyManager.encrypt_with_rsa(recipient_public_key, aes_key)

            # Step 4: Generate HMAC for integrity
            hmac_key = CryptoUtils.generate_random_bytes(32)
            message_data = json.dumps({
                'ciphertext': encrypted_message['ciphertext'],
                'iv': encrypted_message['iv']
            }).encode('utf-8')
            message_hmac = CryptoUtils.compute_hmac(message_data, hmac_key)

            # Step 5: Encrypt HMAC key with RSA
            encrypted_hmac_key = RSAKeyManager.encrypt_with_rsa(recipient_public_key, hmac_key)

            return {
                'encrypted_message': encrypted_message,
                'encrypted_aes_key': encrypted_aes_key.hex(),
                'encrypted_hmac_key': encrypted_hmac_key.hex(),
                'message_hmac': message_hmac,
                'timestamp': encrypted_message['timestamp']
            }

        except Exception as e:
            raise ValueError(f"Hybrid encryption failed: {str(e)}")

    @staticmethod
    def decrypt_message(encrypted_package: Dict[str, str], private_key: rsa.RSAPrivateKey) -> Tuple[str, bool]:
        """
        Decrypt a message encrypted with hybrid encryption
        Returns:
            Tuple of (decrypted_message, integrity_verified)
        """
        try:
            # Step 1: Decrypt AES key
            encrypted_aes_key = bytes.fromhex(encrypted_package['encrypted_aes_key'])
            aes_key = RSAKeyManager.decrypt_with_rsa(private_key, encrypted_aes_key)

            # Step 2: Decrypt HMAC key
            encrypted_hmac_key = bytes.fromhex(encrypted_package['encrypted_hmac_key'])
            hmac_key = RSAKeyManager.decrypt_with_rsa(private_key, encrypted_hmac_key)

            # Step 3: Verify message integrity
            encrypted_message = encrypted_package['encrypted_message']
            message_data = json.dumps({
                'ciphertext': encrypted_message['ciphertext'],
                'iv': encrypted_message['iv']
            }).encode('utf-8')

            integrity_verified = CryptoUtils.verify_hmac(
                message_data,
                hmac_key,
                encrypted_package['message_hmac']
            )

            if not integrity_verified:
                raise SecurityException("Message integrity check failed - possible tampering!")

            # Step 4: Decrypt message with AES
            decrypted_message = AESCipher.decrypt(encrypted_message, aes_key).decode('utf-8')

            return decrypted_message, integrity_verified

        except Exception as e:
            raise ValueError(f"Hybrid decryption failed: {str(e)}")


class SecurityException(Exception):
    """Custom exception for security-related errors"""
    pass


class MessageIntegrityManager:
    """
    Message integrity and authentication system
    Ensures messages haven't been tampered with during transmission
    """

    @staticmethod
    def create_message_package(message: str, sender_private_key: rsa.RSAPrivateKey,
                                recipient_public_key: rsa.RSAPublicKey,
                                message_id: str, sender: str, recipient: str) -> Dict:
        """
        Create a complete secure message package with all integrity checks.
        The sender and recipient are included in the metadata BEFORE signing,
        so the digital signature covers the full, final metadata.
        """
        timestamp = datetime.utcnow().isoformat()
        nonce = CryptoUtils.generate_random_bytes(16).hex()

        # Prepare complete message metadata (signed as-is — do not mutate after signing)
        metadata = {
            'message_id': message_id,
            'timestamp': timestamp,
            'nonce': nonce,
            'sender': sender,
            'recipient': recipient,
        }

        # Encrypt the message
        encrypted_package = HybridEncryption.encrypt_message(message, recipient_public_key)

        # Create digital signature of the final metadata
        metadata_json = json.dumps(metadata, sort_keys=True)
        signature = HMACMessageAuthenticator.sign_message(metadata_json, sender_private_key)

        return {
            'metadata': metadata,
            'encrypted_package': encrypted_package,
            'signature': signature.hex()
        }

    @staticmethod
    def verify_message_package(message_package: Dict, sender_public_key: rsa.RSAPublicKey) -> Tuple[str, bool]:
        """
        Verify and decrypt a message package
        Returns:
            Tuple of (message, is_valid)
        """
        try:
            # Verify signature
            metadata_json = json.dumps(message_package['metadata'], sort_keys=True)
            signature_valid = HMACMessageAuthenticator.verify_signature(
                metadata_json,
                bytes.fromhex(message_package['signature']),
                sender_public_key
            )

            if not signature_valid:
                raise SecurityException("Invalid signature - sender authentication failed!")

            # Return the encrypted_package for the caller to decrypt with the recipient's private key
            # Full decryption is done via HybridEncryption.decrypt_message(encrypted_package, private_key)
            encrypted_package = message_package['encrypted_package']
            return encrypted_package, True

        except Exception as e:
            raise SecurityException(f"Message verification failed: {str(e)}")


class HMACMessageAuthenticator:
    """
    HMAC-based message authentication system
    Provides message authentication and integrity verification
    """

    @staticmethod
    def sign_message(message: str, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Create digital signature of a message
        """
        message_bytes = message.encode('utf-8') if isinstance(message, str) else message

        # Use private key to sign the hash of the message
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        signature = private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(message: str, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """
        Verify digital signature of a message
        """
        try:
            message_bytes = message.encode('utf-8') if isinstance(message, str) else message

            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


def initialize_crypto_system():
    """Initialize the cryptographic system"""
    print("Initializing Cryptographic System...")
    print(f"RSA Key Size: {SecurityConfig.RSA_KEY_SIZE} bits")
    print(f"AES Encryption: {SecurityConfig.AES_KEY_SIZE}-bit {SecurityConfig.AES_MODE}")
    print(f"Password Hashing: {SecurityConfig.PASSWORD_HASH_ALGORITHM}")
    print(f"HMAC Algorithm: {SecurityConfig.HMAC_ALGORITHM}")
    print("Cryptographic system initialized successfully!")


if __name__ == "__main__":
    # Test the cryptographic system
    initialize_crypto_system()

    # Test password hashing
    print("\nTesting Password Hashing...")
    password = "SecurePassword123!"
    hashed = PasswordHasher.hash_password(password)
    print(f"Password: {password}")
    print(f"Hash: {hashed}")
    print(f"Verification: {PasswordHasher.verify_password(password, hashed)}")

    # Test RSA key generation
    print("\nTesting RSA Key Generation...")
    username = "testuser"
    private_key, public_key = RSAKeyManager.generate_key_pair(username)
    print(f"Generated RSA key pair for {username}")
    RSAKeyManager.save_key_pair(username, private_key, public_key)

    # Test AES encryption
    print("\nTesting AES Encryption...")
    test_message = "This is a secret message!"
    aes_key = CryptoUtils.generate_random_bytes(32)
    encrypted = AESCipher.encrypt(test_message, aes_key)
    decrypted = AESCipher.decrypt(encrypted, aes_key).decode('utf-8')
    print(f"Original: {test_message}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_message == decrypted}")

    print("\nAll cryptographic tests passed!")
