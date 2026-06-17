# Secure Messaging System - User Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [User Registration](#user-registration)
3. [Login Process](#login-process)
4. [Sending Messages](#sending-messages)
5. [Receiving Messages](#receiving-messages)
6. [Security Features](#security-features)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## Getting Started

### System Requirements
- **Operating System**: Windows, macOS, or Linux
- **Browser**: Chrome, Firefox, Safari, or Edge (latest version)
- **Internet**: Local network access for web interface

### Initial Setup

1. **Start the Application**
   ```bash
   cd secure_messaging
   python app.py
   ```

2. **Access the Interface**
   - Open your web browser
   - Navigate to: `http://localhost:5000`
   - You will see the login page

3. **First-Time Users**
   - Click "Register here" to create an account
   - Follow the registration process below

---

## User Registration

### Step 1: Access Registration Page
- From the login page, click "Register here"
- Or navigate directly to: `http://localhost:5000/register`

### Step 2: Fill Registration Form

**Username Requirements:**
- Minimum 3 characters
- Alphanumeric only (letters and numbers)
- Case-sensitive
- Example: `alice123`, `Bob_Secure`

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- Special characters recommended (!@#$%^&*)

**Email (Optional):**
- Not required for basic functionality
- Used for account recovery (if implemented)
- Example: `alice@example.com`

### Step 3: Submit Registration
1. Click "Create Account"
2. Wait for confirmation
3. If successful, you'll be redirected to login

### Registration Success Example:
```
✅ Registration successful! You can now login.
```

### Common Registration Errors:

| Error | Solution |
|-------|----------|
| "Username already exists" | Choose a different username |
| "Password too weak" | Use stronger password with mixed case |
| "Passwords do not match" | Ensure both password fields match |
| "Username too short" | Use at least 3 characters |

---

## Login Process

### Step 1: Enter Credentials
1. **Username**: Your registered username
2. **Password**: Your account password

### Step 2: Click Login
- Click the "Login" button
- Wait for authentication

### Step 3: Access Dashboard
- Upon successful login, you'll see the main dashboard
- Your username appears in the header
- Connection status shows "Connected"

### Security Features During Login:

1. **Failed Login Attempts**
   - After 5 failed attempts, account locks for 15 minutes
   - Each failed attempt is logged
   - IP address is recorded

2. **Session Management**
   - Session token created upon successful login
   - Automatic timeout after 30 minutes of inactivity
   - Secure token storage

3. **Login Success Indicators**
   - Redirect to dashboard
   - Username displayed in header
   - Green connection status

---

## Sending Messages

### Step 1: Select Recipient
1. Look at the "Available Users" sidebar
2. Click on the user you want to message
3. Selected user highlights in blue

### Step 2: Compose Message
1. Type your message in the text area
2. Watch character count (max 10,000 characters)
3. Use Enter for new lines
4. Shift+Enter sends the message

### Step 3: Send Message
1. Click "🔐 Send Secure Message" button
2. Message automatically encrypts
3. Shows "Message sent successfully" confirmation

### Message Encryption Process:

```
Your Message → AES-256 Encryption → RSA Key Exchange → Transmission
```

**What happens when you send:**
1. ✅ Message content encrypted with AES-256
2. ✅ AES key encrypted with recipient's RSA public key
3. ✅ HMAC generated for integrity verification
4. ✅ Digital signature added for authentication
5. ✅ Encrypted package transmitted

### Message Sending Example:

```
Recipient: bob
Message: Hello Bob! This is a secret message.
Status: ✅ Message sent successfully!
```

---

## Receiving Messages

### Automatic Message Reception

Messages are automatically:
1. ✅ **Decrypted** using your private RSA key
2. ✅ **Verified** for integrity using HMAC
3. ✅ **Authenticated** using digital signatures
4. ✅ **Displayed** in your conversation

### Message Verification Indicators:

| Symbol | Meaning |
|--------|---------|
| ✅ Verified | Message integrity confirmed |
| ⚠️ Not verified | Potential tampering detected |
| 🔒 Encrypted | Message was encrypted |
| 🔓 Decrypted | Message successfully decrypted |

### Message Display:

**Sent Messages (Blue background):**
```
You | 10:30 AM
🔒 Encrypted message sent
✅ Verified
```

**Received Messages (Gray background):**
```
alice | 10:32 AM
🔓 Decrypted message received
✅ Verified
```

### Real-time Notifications:
- New messages appear automatically
- Notification shows sender name
- No need to refresh manually

---

## Security Features

### 🔒 Encryption

**Symmetric Encryption (AES-256-CBC):**
- 256-bit encryption key
- Cipher Block Chaining mode
- Random Initialization Vector (IV)
- Military-grade security

**Asymmetric Encryption (RSA-2048):**
- 2048-bit key pairs
- Secure key exchange
- Digital signatures
- Public key cryptography

**Hybrid System:**
- RSA for secure key exchange
- AES for efficient message encryption
- Best of both worlds

### ✅ Message Integrity

**HMAC-SHA256:**
- Cryptographic hash function
- Message authentication codes
- Tamper detection
- Instant verification

**Digital Signatures:**
- RSA-PSS signatures
- Sender authentication
- Non-repudiation
- Identity verification

### 🛡️ Attack Prevention

**Man-in-the-Middle (MITM) Protection:**
- Digital signatures verify sender
- HMAC prevents message modification
- Public key fingerprinting

**Replay Attack Prevention:**
- Timestamp validation
- Unique nonces per message
- Time-based rejection
- Duplicate detection

**Brute Force Protection:**
- Account lockout (5 attempts)
- Time delays between attempts
- IP-based rate limiting
- Strong password requirements

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Cannot Login

**Problem**: "Invalid username or password"

**Solutions:**
- Check username spelling (case-sensitive)
- Verify password is correct
- Clear browser cache and cookies
- Check if account is locked (wait 15 minutes)
- Try registering a new account

#### 2. Messages Not Sending

**Problem**: "Failed to send message"

**Solutions:**
- Check internet connection
- Verify recipient is selected
- Ensure message is not empty
- Check message length (< 10,000 characters)
- Refresh the page and try again

#### 3. Messages Not Receiving

**Problem**: No new messages appearing

**Solutions:**
- Click "Refresh" button
- Check connection status (should be green)
- Wait 30 seconds for auto-refresh
- Verify recipient sent the message
- Check browser console for errors

#### 4. Connection Issues

**Problem**: "Connection status: Disconnected"

**Solutions:**
- Check if application is running
- Verify localhost:5000 is accessible
- Refresh the page
- Check firewall settings
- Restart the application

#### 5. Account Locked

**Problem**: "Account is locked due to multiple failed attempts"

**Solutions:**
- Wait 15 minutes for automatic unlock
- Contact administrator if issue persists
- Use password recovery (if available)

---

## Best Practices

### 🔐 Security Best Practices

1. **Password Security**
   - Use unique, strong passwords
   - Don't share passwords with others
   - Change passwords regularly
   - Use password managers

2. **Message Security**
   - Verify encryption status before sending
   - Check integrity verification on received messages
   - Report any security concerns immediately
   - Don't share sensitive info in messages

3. **Session Management**
   - Logout when finished
   - Don't leave sessions unattended
   - Clear browser data after use
   - Use private browsing when possible

### 💡 Usage Tips

1. **Efficient Messaging**
   - Use keyboard shortcuts (Enter to send)
   - Keep messages concise
   - Organize conversations by user
   - Use refresh for immediate updates

2. **Performance**
   - Close unused browser tabs
   - Keep application updated
   - Monitor connection status
   - Report performance issues

3. **Communication**
   - Verify recipient before sending
   - Double-check message content
   - Use appropriate language
   - Follow communication etiquette

---

## Advanced Features

### Admin Panel

Access admin features by logging in as `admin` user:

**Available Features:**
- View system logs
- Generate security reports
- Run attack simulations
- Monitor user activity
- Analyze security events

### Attack Simulations

**Available Simulations:**
1. **Man-in-the-Middle (MITM)**
   - Key interception attempts
   - Message modification tests
   - Signature verification

2. **Replay Attacks**
   - Message replay tests
   - Timestamp validation
   - Nonce reuse prevention

3. **Brute Force**
   - Password cracking attempts
   - Encryption breaking tests
   - Lockout mechanism testing

### Security Reports

Generate comprehensive security reports:
- Authentication events
- Cryptographic operations
- Messaging statistics
- Attack attempts
- Compliance status

---

## FAQ

**Q: Is my messaging really secure?**
A: Yes! Messages use AES-256 encryption (military-grade), RSA-2048 key exchange, and HMAC integrity verification.

**Q: Can anyone read my messages?**
A: No. Messages are encrypted end-to-end. Only the intended recipient can decrypt them using their private key.

**Q: What happens if I forget my password?**
A: You'll need to contact the administrator. Passwords are securely hashed and cannot be recovered.

**Q: How are keys stored?**
A: RSA keys are stored in secure files with restricted permissions. Private keys are never shared.

**Q: Can I use this on mobile?**
A: The web interface is responsive and works on mobile browsers with internet connection.

**Q: What if someone intercepts my messages?**
A: Intercepted messages cannot be read without the recipient's private key. Any modification is detected by HMAC.

**Q: How do I know a message is really from the sender?**
A: Digital signatures verify sender identity. Check for the ✅ Verified indicator.

**Q: Can I delete messages?**
A: Yes, recipients can delete received messages. This removes them from the system.

---

## Support and Contact

For technical support or questions:
- Check the troubleshooting section above
- Review system logs for error details
- Contact your system administrator
- Review the security report for issues

---

## Conclusion

This secure messaging system provides enterprise-grade security for your communications. By following this user guide and implementing best practices, you can ensure your messages remain confidential, authentic, and tamper-proof.

**Remember:**
- 🔒 Always use strong passwords
- ✅ Verify message integrity
- 🚪 Logout when finished
- 📊 Monitor security reports

*Stay secure, communicate safely!*

---

*Document Version: 1.0*
*Last Updated: June 17, 2026*
*Course: Software Security - EU University of Applied Science*
