"""
User Authentication Module
Handles user registration, login, session management, and authentication
Uses bcrypt for secure password hashing and implements session security
"""
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List
import threading

from config import SecurityConfig, DatabaseConfig, LoggingConfig
from crypto_core import PasswordHasher, RSAKeyManager, CryptoUtils


class AuthenticationManager:
    """
    Manages user authentication, registration, and session handling
    Implements secure password storage and session management
    """

    def __init__(self):
        self.users_db = self._load_users_database()
        self.sessions = self._load_sessions()
        self.login_attempts = {}  # Track failed login attempts
        self.lockout_timer = {}   # Track account lockouts
        self._lock = threading.Lock()  # Thread safety for database operations

    def _load_users_database(self) -> Dict:
        """Load users database from file"""
        try:
            if DatabaseConfig.USERS_FILE.exists():
                with open(DatabaseConfig.USERS_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading users database: {e}")
        return {}

    def _save_users_database(self):
        """Save users database to file"""
        try:
            with open(DatabaseConfig.USERS_FILE, 'w') as f:
                json.dump(self.users_db, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving users database: {e}")
            return False

    def _load_sessions(self) -> Dict:
        """Load active sessions from file"""
        try:
            if DatabaseConfig.ACTIVE_SESSIONS_FILE.exists():
                with open(DatabaseConfig.ACTIVE_SESSIONS_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading sessions: {e}")
        return {}

    def _save_sessions(self):
        """Save active sessions to file"""
        try:
            with open(DatabaseConfig.ACTIVE_SESSIONS_FILE, 'w') as f:
                json.dump(self.sessions, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving sessions: {e}")
            return False

    def register_user(self, username: str, password: str, email: Optional[str] = None) -> Dict:
        """
        Register a new user with secure password hashing
        Args:
            username: Desired username
            password: User's password
            email: Optional email address
        Returns:
            Dictionary with success status and message
        """
        with self._lock:
            try:
                # Validate username
                if not username or len(username) < 3:
                    return {
                        'success': False,
                        'message': 'Username must be at least 3 characters long'
                    }

                if not username.isalnum():
                    return {
                        'success': False,
                        'message': 'Username can only contain letters and numbers'
                    }

                # Check if user already exists
                if username in self.users_db:
                    return {
                        'success': False,
                        'message': 'Username already exists'
                    }

                # Validate password strength
                password_validation = self._validate_password_strength(password)
                if not password_validation['valid']:
                    return {
                        'success': False,
                        'message': password_validation['message']
                    }

                # Hash password securely
                password_hash = PasswordHasher.hash_password(password)

                # Generate RSA key pair for the user
                private_key, public_key = RSAKeyManager.generate_key_pair(username)
                RSAKeyManager.save_key_pair(username, private_key, public_key)

                # Create user record
                user_data = {
                    'username': username,
                    'password_hash': password_hash,
                    'email': email,
                    'created_at': datetime.utcnow().isoformat(),
                    'last_login': None,
                    'login_count': 0,
                    'is_active': True,
                    'is_locked': False,
                    'failed_login_attempts': 0
                }

                self.users_db[username] = user_data
                self._save_users_database()

                # Log registration
                self._log_authentication_event('USER_REGISTERED', username, True, 'User registered successfully')

                return {
                    'success': True,
                    'message': f'User {username} registered successfully',
                    'username': username
                }

            except Exception as e:
                self._log_authentication_event('USER_REGISTRATION_FAILED', username, False, str(e))
                return {
                    'success': False,
                    'message': f'Registration failed: {str(e)}'
                }

    def login_user(self, username: str, password: str, ip_address: str = 'unknown') -> Dict:
        """
        Authenticate user and create session
        Args:
            username: Username
            password: User's password
            ip_address: Client IP address for logging
        Returns:
            Dictionary with success status, session token, and message
        """
        with self._lock:
            try:
                # Check if user exists
                if username not in self.users_db:
                    self._track_failed_attempt(username, ip_address)
                    self._log_authentication_event('LOGIN_FAILED', username, False,
                                                   'User does not exist', ip_address)
                    return {
                        'success': False,
                        'message': 'Invalid username or password'
                    }

                user_data = self.users_db[username]

                # Check if account is locked
                if user_data.get('is_locked', False):
                    # Check if lockout period has expired
                    if self._check_lockout_expiration(username):
                        user_data['is_locked'] = False
                        user_data['failed_login_attempts'] = 0
                        self._save_users_database()
                    else:
                        self._log_authentication_event('LOGIN_FAILED', username, False,
                                                       'Account is locked', ip_address)
                        return {
                            'success': False,
                            'message': 'Account is locked due to multiple failed attempts. Try again later.'
                        }

                # Check if account is active
                if not user_data.get('is_active', True):
                    self._log_authentication_event('LOGIN_FAILED', username, False,
                                                   'Account is inactive', ip_address)
                    return {
                        'success': False,
                        'message': 'Account is inactive'
                    }

                # Verify password
                if not PasswordHasher.verify_password(password, user_data['password_hash']):
                    self._track_failed_attempt(username, ip_address)
                    user_data['failed_login_attempts'] = user_data.get('failed_login_attempts', 0) + 1

                    # Check if we should lock the account
                    if user_data['failed_login_attempts'] >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
                        user_data['is_locked'] = True
                        self.lockout_timer[username] = time.time()
                        self._save_users_database()
                        self._log_authentication_event('ACCOUNT_LOCKED', username, False,
                                                       f'Account locked after {user_data["failed_login_attempts"]} failed attempts',
                                                       ip_address)
                        return {
                            'success': False,
                            'message': f'Account locked due to multiple failed login attempts'
                        }

                    self._save_users_database()
                    self._log_authentication_event('LOGIN_FAILED', username, False,
                                                   f'Invalid password (attempt {user_data["failed_login_attempts"]})',
                                                   ip_address)
                    return {
                        'success': False,
                        'message': 'Invalid username or password'
                    }

                # Successful login - reset failed attempts
                user_data['failed_login_attempts'] = 0
                user_data['last_login'] = datetime.utcnow().isoformat()
                user_data['login_count'] = user_data.get('login_count', 0) + 1
                self._save_users_database()

                # Create session
                session_token = self._create_session(username, ip_address)

                # Log successful login
                self._log_authentication_event('LOGIN_SUCCESS', username, True,
                                               f'Login successful (session: {session_token[:8]}...)',
                                               ip_address)

                return {
                    'success': True,
                    'message': f'Welcome back, {username}!',
                    'username': username,
                    'session_token': session_token,
                    'expires_in': SecurityConfig.SESSION_TIMEOUT
                }

            except Exception as e:
                self._log_authentication_event('LOGIN_ERROR', username, False, str(e), ip_address)
                return {
                    'success': False,
                    'message': f'Login failed: {str(e)}'
                }

    def logout_user(self, session_token: str) -> Dict:
        """
        Logout user by invalidating session
        Args:
            session_token: User's session token
        Returns:
            Dictionary with success status
        """
        with self._lock:
            try:
                if session_token in self.sessions:
                    username = self.sessions[session_token]['username']
                    del self.sessions[session_token]
                    self._save_sessions()

                    self._log_authentication_event('LOGOUT_SUCCESS', username, True,
                                                   f'User logged out (session: {session_token[:8]}...)')
                    return {
                        'success': True,
                        'message': 'Logged out successfully'
                    }
                else:
                    return {
                        'success': False,
                        'message': 'Invalid session token'
                    }
            except Exception as e:
                return {
                    'success': False,
                    'message': f'Logout failed: {str(e)}'
                }

    def verify_session(self, session_token: str) -> Optional[Dict]:
        """
        Verify if session token is valid and not expired
        Args:
            session_token: Session token to verify
        Returns:
            User data if session is valid, None otherwise
        """
        with self._lock:
            try:
                if session_token not in self.sessions:
                    return None

                session_data = self.sessions[session_token]
                created_at = datetime.fromisoformat(session_data['created_at'])
                expires_at = created_at + timedelta(seconds=SecurityConfig.SESSION_TIMEOUT)

                # Check if session has expired
                if datetime.utcnow() > expires_at:
                    # Remove expired session
                    username = session_data['username']
                    del self.sessions[session_token]
                    self._save_sessions()
                    self._log_authentication_event('SESSION_EXPIRED', username, False,
                                                   f'Session expired (session: {session_token[:8]}...)')
                    return None

                # Update last activity
                session_data['last_activity'] = datetime.utcnow().isoformat()
                self._save_sessions()

                return {
                    'username': session_data['username'],
                    'created_at': session_data['created_at'],
                    'last_activity': session_data['last_activity']
                }

            except Exception as e:
                print(f"Session verification error: {e}")
                return None

    def get_user_info(self, username: str) -> Optional[Dict]:
        """Get user information"""
        if username in self.users_db:
            user_data = self.users_db[username].copy()
            # Remove sensitive information
            user_data.pop('password_hash', None)
            return user_data
        return None

    def get_all_users(self) -> List[str]:
        """Get list of all registered users"""
        return list(self.users_db.keys())

    def _validate_password_strength(self, password: str) -> Dict:
        """
        Validate password strength according to security requirements
        Returns: Dictionary with 'valid' boolean and 'message' string
        """
        if len(password) < 8:
            return {'valid': False, 'message': 'Password must be at least 8 characters long'}

        if len(password) > 128:
            return {'valid': False, 'message': 'Password must not exceed 128 characters'}

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password)

        complexity_count = sum([has_upper, has_lower, has_digit, has_special])

        if complexity_count < 3:
            return {
                'valid': False,
                'message': 'Password must contain at least 3 of: uppercase, lowercase, digits, special characters'
            }

        # Check for common passwords
        common_passwords = ['password', '12345678', 'qwerty', 'abc123', 'password123']
        if password.lower() in common_passwords:
            return {'valid': False, 'message': 'Password is too common'}

        return {'valid': True, 'message': 'Password meets security requirements'}

    def _create_session(self, username: str, ip_address: str = 'unknown') -> str:
        """
        Create a new session for authenticated user
        Returns:
            Session token
        """
        # Generate secure random session token
        session_token = secrets.token_hex(SecurityConfig.SESSION_TOKEN_LENGTH)

        session_data = {
            'username': username,
            'created_at': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'ip_address': ip_address
        }

        self.sessions[session_token] = session_data
        self._save_sessions()

        return session_token

    def _track_failed_attempt(self, username: str, ip_address: str):
        """Track failed login attempts for rate limiting"""
        key = f"{username}:{ip_address}"
        if key not in self.login_attempts:
            self.login_attempts[key] = {'count': 0, 'first_attempt': time.time()}

        self.login_attempts[key]['count'] += 1
        self.login_attempts[key]['last_attempt'] = time.time()

    def _check_lockout_expiration(self, username: str) -> bool:
        """Check if account lockout has expired"""
        if username in self.lockout_timer:
            lockout_time = self.lockout_timer[username]
            if time.time() - lockout_time > SecurityConfig.LOCKOUT_DURATION:
                del self.lockout_timer[username]
                return True
        return False

    def _log_authentication_event(self, event_type: str, username: str, success: bool,
                                   details: str, ip_address: str = 'unknown'):
        """Log authentication events to file"""
        try:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'username': username,
                'success': success,
                'ip_address': ip_address,
                'details': details
            }

            # Append to authentication log
            with open(LoggingConfig.AUTH_LOG, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')

        except Exception as e:
            print(f"Error logging authentication event: {e}")

    def cleanup_expired_sessions(self):
        """Remove expired sessions from database"""
        with self._lock:
            try:
                current_time = datetime.utcnow()
                expired_sessions = []

                for session_token, session_data in self.sessions.items():
                    created_at = datetime.fromisoformat(session_data['created_at'])
                    expires_at = created_at + timedelta(seconds=SecurityConfig.SESSION_TIMEOUT)

                    if current_time > expires_at:
                        expired_sessions.append(session_token)

                for session_token in expired_sessions:
                    username = self.sessions[session_token]['username']
                    del self.sessions[session_token]
                    self._log_authentication_event('SESSION_CLEANED_UP', username, True,
                                                   f'Expired session removed: {session_token[:8]}...')

                if expired_sessions:
                    self._save_sessions()

                return len(expired_sessions)
            except Exception as e:
                print(f"Error cleaning up sessions: {e}")
                return 0


class SessionManager:
    """
    Enhanced session management with security features
    """

    def __init__(self, auth_manager: AuthenticationManager):
        self.auth_manager = auth_manager

    def get_active_sessions(self, username: str) -> List[Dict]:
        """Get all active sessions for a user"""
        user_sessions = []
        for session_token, session_data in self.auth_manager.sessions.items():
            if session_data['username'] == username:
                user_sessions.append({
                    'token': session_token[:16] + '...',  # Show only first 16 chars
                    'created_at': session_data['created_at'],
                    'last_activity': session_data['last_activity']
                })
        return user_sessions

    def invalidate_all_sessions(self, username: str) -> int:
        """Invalidate all sessions for a user (e.g., for security reasons)"""
        count = 0
        sessions_to_remove = []

        for session_token, session_data in self.auth_manager.sessions.items():
            if session_data['username'] == username:
                sessions_to_remove.append(session_token)
                count += 1

        for session_token in sessions_to_remove:
            del self.auth_manager.sessions[session_token]

        if count > 0:
            self.auth_manager._save_sessions()
            self.auth_manager._log_authentication_event('ALL_SESSIONS_INVALIDATED', username,
                                                       True, f'Invalidated {count} sessions')

        return count


# Initialize authentication manager
auth_manager = AuthenticationManager()
session_manager = SessionManager(auth_manager)


def get_auth_manager() -> AuthenticationManager:
    """Get the global authentication manager instance"""
    return auth_manager


def get_session_manager() -> SessionManager:
    """Get the global session manager instance"""
    return session_manager


if __name__ == "__main__":
    # Test the authentication system
    print("Testing Authentication System...")

    # Test user registration
    print("\n1. Testing User Registration...")
    result = auth_manager.register_user("testuser", "SecurePass123!", "test@example.com")
    print(f"Registration result: {result}")

    # Test duplicate registration
    print("\n2. Testing Duplicate Registration...")
    result = auth_manager.register_user("testuser", "AnotherPass456!", "test2@example.com")
    print(f"Duplicate registration result: {result}")

    # Test successful login
    print("\n3. Testing Successful Login...")
    result = auth_manager.login_user("testuser", "SecurePass123!", "127.0.0.1")
    print(f"Login result: {result}")
    session_token = result.get('session_token')

    # Test failed login
    print("\n4. Testing Failed Login...")
    result = auth_manager.login_user("testuser", "WrongPassword123!", "127.0.0.1")
    print(f"Failed login result: {result}")

    # Test session verification
    print("\n5. Testing Session Verification...")
    if session_token:
        session_data = auth_manager.verify_session(session_token)
        print(f"Session verification result: {session_data}")

    # Test logout
    print("\n6. Testing Logout...")
    if session_token:
        result = auth_manager.logout_user(session_token)
        print(f"Logout result: {result}")

    print("\nAuthentication tests completed!")
