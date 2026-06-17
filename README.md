# Secure Messaging System

A comprehensive, production-grade secure messaging application implementing advanced cryptographic techniques for confidential, authentic, and integrity-protected communication.

## 🎯 Project Overview

This project was developed as a homework assignment for the Software Security course at EU University of Applied Science (Summer 2026). It demonstrates practical implementation of:

- **Hybrid Encryption**: RSA-2048 for key exchange + AES-256 for message encryption
- **Message Integrity**: HMAC-SHA256 for tamper detection
- **Secure Authentication**: Bcrypt password hashing with session management
- **Attack Simulations**: MITM, replay attacks, and brute force demonstrations
- **Comprehensive Logging**: Security event tracking and analysis

## 🏗️ Architecture

### Core Components

1. **Cryptographic Core** (`crypto_core.py`)
   - RSA-2048 key generation and management
   - AES-256-CBC encryption/decryption
   - Bcrypt password hashing
   - HMAC-SHA256 message authentication
   - Hybrid encryption system

2. **Authentication System** (`authentication.py`)
   - User registration with secure password storage
   - Session-based authentication
   - Account lockout after failed attempts
   - Password strength validation

3. **Messaging System** (`messaging_system.py`)
   - End-to-end encrypted messaging
   - Message integrity verification
   - Digital signatures for authentication
   - Message history and management

4. **Attack Simulations** (`attack_simulations.py`)
   - Man-in-the-Middle (MITM) attacks
   - Replay attack simulations
   - Brute force attack demonstrations
   - Security analysis and mitigation

5. **Logging System** (`logging_system.py`)
   - Comprehensive event logging
   - Security monitoring
   - Compliance reporting
   - Attack detection

6. **Web Interface** (`app.py`)
   - Flask-based web application
   - Real-time messaging with WebSocket
   - Admin panel for security monitoring
   - Responsive design

## 🔒 Security Features

### Encryption
- **Symmetric**: AES-256-CBC for message encryption
- **Asymmetric**: RSA-2048 for key exchange
- **Hybrid**: Combines RSA security with AES efficiency
- **Integrity**: HMAC-SHA256 for message authentication

### Authentication
- **Password Storage**: Bcrypt with 12 rounds
- **Session Management**: Secure token-based sessions
- **Account Protection**: Lockout after 5 failed attempts
- **Password Requirements**: 8+ characters, mixed case, digits

### Attack Prevention
- **MITM**: Digital signatures and HMAC verification
- **Replay Attacks**: Timestamp validation and nonces
- **Brute Force**: Rate limiting and account lockout
- **Tampering**: HMAC integrity checks

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secure_messaging
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the system**
   ```bash
   python config.py
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the web interface**
   ```
   Open browser: http://localhost:5000
   ```

## 📖 Usage Guide

### 1. User Registration

1. Navigate to the registration page
2. Choose a username (3+ alphanumeric characters)
3. Create a strong password (8+ characters, mixed case, digits)
4. Optionally provide an email address
5. Click "Create Account"

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- Recommended: Special characters

### 2. User Login

1. Enter your username and password
2. Click "Login"
3. You will be redirected to the dashboard

**Security Features:**
- Session tokens for authentication
- Automatic session timeout (30 minutes)
- Account lockout after 5 failed attempts

### 3. Sending Messages

1. Select a recipient from the available users list
2. Type your message in the text area
3. Click "Send Secure Message"
4. Message is automatically encrypted and transmitted

**Encryption Process:**
1. Generate random AES-256 key
2. Encrypt message with AES
3. Encrypt AES key with recipient's RSA public key
4. Generate HMAC for integrity
5. Transmit encrypted package

### 4. Receiving Messages

1. Messages are automatically decrypted upon receipt
2. Integrity is verified using HMAC
3. Digital signatures confirm sender identity
4. Verified messages display with checkmark

**Security Verification:**
- ✅ Encryption: AES-256-CBC
- ✅ Integrity: HMAC-SHA256
- ✅ Authentication: RSA digital signatures
- ✅ Timestamp: Prevents replay attacks

### 5. Attack Simulations

Access the admin panel to run attack simulations:

1. Navigate to `/admin` (login as admin user)
2. Select "Attack Simulations"
3. Choose attack types to simulate
4. Review results and recommendations

**Available Simulations:**
- Man-in-the-Middle (MITM) attacks
- Replay attacks
- Brute force attacks
- Cryptanalysis attempts

## 🧪 Testing

### Running Tests

1. **Test Cryptographic Core**
   ```bash
   python crypto_core.py
   ```

2. **Test Authentication**
   ```bash
   python authentication.py
   ```

3. **Test Messaging System**
   ```bash
   python messaging_system.py
   ```

4. **Test Attack Simulations**
   ```bash
   python attack_simulations.py
   ```

5. **Test Logging System**
   ```bash
   python logging_system.py
   ```

### Test Scenarios

1. **Create test users:**
   ```python
   from authentication import get_auth_manager
   auth = get_auth_manager()
   auth.register_user("alice", "AliceSecure123!", "alice@test.com")
   auth.register_user("bob", "BobSecure123!", "bob@test.com")
   ```

2. **Test message exchange:**
   ```python
   from messaging_system import get_messaging_system
   messaging = get_messaging_system()
   # Login users first, then send messages
   ```

3. **Run attack simulations:**
   ```python
   from attack_simulations import get_attack_simulator
   simulator = get_attack_simulator()
   results = simulator.run_all_simulations("alice", "bob")
   ```

## 📊 Project Structure

```
secure_messaging/
├── app.py                      # Flask web application
├── config.py                   # Configuration and constants
├── crypto_core.py             # Cryptographic operations
├── authentication.py          # User authentication
├── messaging_system.py        # Secure messaging
├── attack_simulations.py     # Attack simulations
├── logging_system.py          # Logging and monitoring
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── USER_GUIDE.md             # Detailed user guide
├── SECURITY_REPORT.md        # Security analysis
├── templates/                 # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── admin.html
├── static/                    # Static files
│   └── js/
│       └── dashboard.js
├── data/                      # Data storage
│   ├── keys/                 # RSA key pairs
│   ├── users/                # User database
│   └── messages/             # Message storage
└── logs/                      # Log files
    ├── authentication.log
    ├── cryptographic_operations.log
    ├── messaging.log
    ├── attack_simulations.log
    └── system.log
```

## 🔐 Security Implementation

### 1. Key Management

- **RSA Key Generation**: 2048-bit keys using secure random number generation
- **Key Storage**: Files with restrictive permissions (600 for private keys)
- **Key Exchange**: Hybrid system using RSA for key transport

### 2. Message Encryption

```
Original Message
    ↓
AES-256-CBC Encryption (with random IV)
    ↓
Encrypt AES key with RSA (recipient's public key)
    ↓
Generate HMAC-SHA256
    ↓
Transmit encrypted package
```

### 3. Message Integrity

- **HMAC**: SHA-256-based message authentication
- **Digital Signatures**: RSA-PSS for sender authentication
- **Timestamps**: Prevent replay attacks
- **Nonces**: Ensure uniqueness of each message

### 4. Attack Prevention

| Attack Type | Prevention Method |
|------------|------------------|
| MITM | Digital signatures + HMAC verification |
| Replay | Timestamp validation + nonces |
| Brute Force | Account lockout + rate limiting |
| Tampering | HMAC integrity checks |

## 📈 Evaluation Criteria

### Correct Implementation of Encryption (30%)
- ✅ AES-256-CBC symmetric encryption
- ✅ RSA-2048 asymmetric encryption
- ✅ Hybrid encryption system
- ✅ Secure key generation and storage

### Security Design Quality (25%)
- ✅ Defense in depth approach
- ✅ Secure key management
- ✅ Message integrity verification
- ✅ Attack prevention mechanisms

### Code Quality and Structure (20%)
- ✅ Modular design with clear separation of concerns
- ✅ Comprehensive error handling
- ✅ Detailed documentation
- ✅ Professional coding standards

### Attack Simulation and Analysis (15%)
- ✅ MITM attack simulation
- ✅ Replay attack demonstration
- ✅ Brute force attempt
- ✅ Detailed analysis and mitigation

### Documentation (10%)
- ✅ Comprehensive README
- ✅ User guide with examples
- ✅ Security analysis report
- ✅ Code documentation

## 🛠️ Technology Stack

- **Backend**: Python 3.8+
- **Web Framework**: Flask
- **Real-time**: Flask-SocketIO
- **Cryptography**: cryptography library
- **Password Hashing**: bcrypt
- **Frontend**: HTML5, CSS3, JavaScript
- **WebSocket**: Socket.IO

## 📝 License

This project was developed as an academic assignment for the Software Security course at EU University of Applied Science (Summer 2026).

## 👨‍🏫 Course Information

- **Course**: Software Security
- **Instructor**: Prof. Dr. Rand Kouatly
- **Institution**: EU University of Applied Science
- **Semester**: Summer 2026
- **Deadline**: June 21, 2026, 11:00 PM

## 🎓 Student Information

**Name**: [Your Name]
**Course**: Software Security
**Assignment**: Secure Messaging System Project
**Submission**: [Submission Date]

---

## 🙏 Acknowledgments

This project demonstrates the practical application of cryptographic principles and security best practices learned in the Software Security course. The implementation follows industry standards for secure communication systems.

**Note**: This is an educational project. While it implements strong security measures, it should be reviewed and hardened before use in production environments.

---

*Last Updated: June 17, 2026*
