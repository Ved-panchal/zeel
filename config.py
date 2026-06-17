"""
Configuration file for Secure Messaging System
Defines all security parameters, constants, and settings
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = DATA_DIR / "keys"
LOGS_DIR = BASE_DIR / "logs"
USERS_DIR = DATA_DIR / "users"

# Create directories if they don't exist
for dir_path in [DATA_DIR, KEYS_DIR, LOGS_DIR, USERS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Security Configuration
class SecurityConfig:
    """Security parameters and cryptographic constants"""

    # RSA Configuration
    RSA_KEY_SIZE = 2048  # bits - RSA key length for asymmetric encryption
    RSA_PUBLIC_EXPONENT = 65537  # Standard public exponent

    # AES Configuration
    AES_KEY_SIZE = 256  # bits - AES-256 for symmetric encryption
    AES_MODE = 'CBC'  # Cipher Block Chaining mode
    AES_BLOCK_SIZE = 16  # bytes - AES block size

    # Hashing Configuration
    PASSWORD_HASH_ALGORITHM = 'bcrypt'  # For password storage
    BCRYPT_ROUNDS = 12  # Computational cost factor for bcrypt
    MESSAGE_HASH_ALGORITHM = 'SHA256'  # For message integrity
    HMAC_ALGORITHM = 'SHA256'  # For HMAC-based message authentication

    # Session Configuration
    SESSION_TIMEOUT = 1800  # seconds (30 minutes)
    SESSION_TOKEN_LENGTH = 32  # bytes

    # Message Configuration
    MAX_MESSAGE_SIZE = 10240  # bytes (10KB)
    MESSAGE_RETENTION_DAYS = 30

    # Rate Limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # seconds (15 minutes)
    MAX_MESSAGES_PER_MINUTE = 30

    # Attack Simulation Configuration
    ATTACK_SIMULATION_ENABLED = True
    MITM_PROBABILITY = 0.3  # 30% chance of MITM attack during simulation
    REPLAY_ATTACK_WINDOW = 60  # seconds
    BRUTE_FORCE_ATTEMPTS = 1000

# Database Configuration
class DatabaseConfig:
    """Database and file storage configuration"""

    # User database
    USERS_FILE = USERS_DIR / "users.json"
    ACTIVE_SESSIONS_FILE = DATA_DIR / "sessions.json"

    # Message storage
    MESSAGES_DIR = DATA_DIR / "messages"

    # Key storage
    KEYS_DIR = DATA_DIR / "keys"  # RSA key pair storage directory
    PRIVATE_KEY_SUFFIX = "_private.pem"
    PUBLIC_KEY_SUFFIX = "_public.pem"

# Logging Configuration
class LoggingConfig:
    """Logging system configuration"""

    # Log files
    AUTH_LOG = LOGS_DIR / "authentication.log"
    CRYPTO_LOG = LOGS_DIR / "cryptographic_operations.log"
    MESSAGE_LOG = LOGS_DIR / "messaging.log"
    ATTACK_LOG = LOGS_DIR / "attack_simulations.log"
    SYSTEM_LOG = LOGS_DIR / "system.log"

    # Log levels and formats
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
    BACKUP_COUNT = 5

# Flask/Web Configuration
class WebConfig:
    """Web application configuration"""

    # ⚠️ SECURITY WARNING: Change this before deploying to production!
    # Use a strong random key and store it as an environment variable
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'CHANGE-THIS-SECRET-KEY-IN-PRODUCTION')
    
    # ⚠️ SECURITY WARNING: Set to False in production!
    DEBUG = False  # Set to False in production
    TESTING = False

    # WebSocket configuration
    SOCKETIO_ASYNC_MODE = 'threading'
    SOCKETIO_CORSER_ENABLED = True

    # UI Configuration
    APP_NAME = "Secure Messaging System"
    APP_VERSION = "1.0.0"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size

# Attack Simulation Configuration
class AttackConfig:
    """Attack simulation parameters"""

    # Man-in-the-Middle Attack
    MITM_ENABLED = True
    MITM_MESSAGE_MODIFICATION_TEXT = "[MITM ATTACK] Message intercepted and modified!"
    MITM_KEY_REPLACEMENT_ENABLED = True

    # Replay Attack
    REPLAY_ENABLED = True
    REPLAY_MESSAGE_STORE_SIZE = 100
    REPLAY_DELAY_RANGE = (5, 30)  # seconds

    # Brute Force Attack
    BRUTE_FORCE_ENABLED = True
    BRUTE_FORCE_COMMON_PASSWORDS = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "master", "letmein", "login", "password123"
    ]

# Initialize all directories
def initialize_system():
    """Initialize the secure messaging system"""
    print(f"Initializing {WebConfig.APP_NAME} v{WebConfig.APP_VERSION}...")
    print(f"Data directory: {DATA_DIR}")
    print(f"RSA Key Size: {SecurityConfig.RSA_KEY_SIZE} bits")
    print(f"AES Encryption: {SecurityConfig.AES_KEY_SIZE}-bit {SecurityConfig.AES_MODE}")
    print(f"Password Hashing: {SecurityConfig.PASSWORD_HASH_ALGORITHM}")
    print(f"Message Integrity: {SecurityConfig.HMAC_ALGORITHM}")
    print(f"Attack Simulations: {'Enabled' if AttackConfig.MITM_ENABLED else 'Disabled'}")

    # Create message storage directory
    DatabaseConfig.MESSAGES_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize log files
    for log_file in [
        LoggingConfig.AUTH_LOG,
        LoggingConfig.CRYPTO_LOG,
        LoggingConfig.MESSAGE_LOG,
        LoggingConfig.ATTACK_LOG,
        LoggingConfig.SYSTEM_LOG
    ]:
        if not log_file.exists():
            log_file.touch()

    print("System initialization complete!")

if __name__ == "__main__":
    initialize_system()
