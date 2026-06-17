"""
Secure Messaging System
Handles encrypted message exchange, key management, and message integrity
Implements hybrid RSA+AES encryption with HMAC for secure communication
"""
import json
import uuid
import os
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from config import SecurityConfig, DatabaseConfig, LoggingConfig
from crypto_core import (
    HybridEncryption, MessageIntegrityManager, HMACMessageAuthenticator,
    RSAKeyManager, CryptoUtils, SecurityException
)
from authentication import get_auth_manager


class SecureMessage:
    """
    Represents a secure message with all metadata and encryption information
    """

    def __init__(self, message_id: str, sender: str, recipient: str, encrypted_package: Dict,
                 metadata: Dict, signature: str, plaintext_content: str = None):
        self.message_id = message_id
        self.sender = sender
        self.recipient = recipient
        self.encrypted_package = encrypted_package
        self.metadata = metadata
        self.signature = signature
        self.created_at = metadata.get('timestamp')
        self.is_read = False
        self.integrity_verified = False
        self.plaintext_content = plaintext_content  # Store for sender's copy

    def to_dict(self) -> Dict:
        """Convert message to dictionary for storage/transmission"""
        result = {
            'message_id': self.message_id,
            'sender': self.sender,
            'recipient': self.recipient,
            'encrypted_package': self.encrypted_package,
            'metadata': self.metadata,
            'signature': self.signature,
            'created_at': self.created_at,
            'is_read': self.is_read,
            'integrity_verified': self.integrity_verified
        }
        if self.plaintext_content is not None:
            result['plaintext_content'] = self.plaintext_content
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> 'SecureMessage':
        """Create SecureMessage from dictionary"""
        message = cls(
            data['message_id'],
            data['sender'],
            data['recipient'],
            data['encrypted_package'],
            data['metadata'],
            data['signature'],
            data.get('plaintext_content')  # Load plaintext if available
        )
        message.is_read = data.get('is_read', False)
        message.integrity_verified = data.get('integrity_verified', False)
        return message


class MessagingSystem:
    """
    Core messaging system with encryption, decryption, and integrity checking
    """

    def __init__(self):
        self.auth_manager = get_auth_manager()
        self.messages = {}  # In-memory message storage
        self.user_inboxes = defaultdict(list)  # User's inbox message IDs
        self.message_queue = []  # Queue for message delivery
        self._lock = threading.Lock()
        self._initialize_storage()

    def _initialize_storage(self):
        """Initialize message storage system"""
        DatabaseConfig.MESSAGES_DIR.mkdir(parents=True, exist_ok=True)
        self._load_messages_from_storage()

    def _load_messages_from_storage(self):
        """Load existing messages from disk"""
        try:
            for user_file in DatabaseConfig.MESSAGES_DIR.glob("*.json"):
                try:
                    with open(user_file, 'r') as f:
                        user_messages = json.load(f)
                        for msg_data in user_messages:
                            message = SecureMessage.from_dict(msg_data)
                            self.messages[message.message_id] = message
                            self.user_inboxes[message.recipient].append(message.message_id)
                except Exception as e:
                    print(f"Error loading messages from {user_file}: {e}")
        except Exception as e:
            print(f"Error initializing message storage: {e}")

    def _save_messages_to_storage(self):
        """Save messages to disk - saves for both sender and recipient"""
        try:
            # Group messages by user (both sent and received)
            messages_by_user = defaultdict(list)

            for message in self.messages.values():
                # Save to recipient's file (received messages)
                messages_by_user[message.recipient].append(message.to_dict())
                # Also save to sender's file (sent messages)
                messages_by_user[message.sender].append(message.to_dict())

            # Save each user's messages
            for username, user_messages in messages_by_user.items():
                # Remove duplicates based on message_id
                unique_messages = {msg['message_id']: msg for msg in user_messages}.values()
                user_file = DatabaseConfig.MESSAGES_DIR / f"{username}_messages.json"
                with open(user_file, 'w') as f:
                    json.dump(list(unique_messages), f, indent=2)

            return True
        except Exception as e:
            print(f"Error saving messages to storage: {e}")
            return False

    def send_message(self, sender: str, recipient: str, message_content: str,
                     session_token: str) -> Dict:
        """
        Send an encrypted message to another user
        Args:
            sender: Sender's username
            recipient: Recipient's username
            message_content: Plain text message to send
            session_token: Sender's session token for authentication
        Returns:
            Dictionary with success status and message details
        """
        with self._lock:
            try:
                # Verify sender's session
                session_data = self.auth_manager.verify_session(session_token)
                if not session_data or session_data['username'] != sender:
                    return {
                        'success': False,
                        'message': 'Invalid session or unauthorized access'
                    }

                # Verify recipient exists
                all_users = self.auth_manager.get_all_users()
                if recipient not in all_users:
                    return {
                        'success': False,
                        'message': f'User {recipient} does not exist'
                    }

                # Validate message content
                if not message_content or len(message_content.strip()) == 0:
                    return {
                        'success': False,
                        'message': 'Message content cannot be empty'
                    }

                if len(message_content) > SecurityConfig.MAX_MESSAGE_SIZE:
                    return {
                        'success': False,
                        'message': f'Message too large. Max size: {SecurityConfig.MAX_MESSAGE_SIZE} bytes'
                    }

                # Get keys for encryption
                sender_private_key = RSAKeyManager.load_private_key(sender)
                recipient_public_key = RSAKeyManager.load_public_key(recipient)

                if not sender_private_key:
                    return {
                        'success': False,
                        'message': 'Could not load sender\'s private key'
                    }

                if not recipient_public_key:
                    return {
                        'success': False,
                        'message': 'Could not load recipient\'s public key'
                    }

                # Generate unique message ID
                message_id = str(uuid.uuid4())

                # Create encrypted message package
                message_package = MessageIntegrityManager.create_message_package(
                    message_content,
                    sender_private_key,
                    recipient_public_key,
                    message_id,
                    sender,
                    recipient
                )

                # Create secure message object (store plaintext for sender's copy)
                secure_message = SecureMessage(
                    message_id,
                    sender,
                    recipient,
                    message_package['encrypted_package'],
                    message_package['metadata'],
                    message_package['signature'],
                    message_content  # Store plaintext for sender
                )

                # Store message
                self.messages[message_id] = secure_message
                self.user_inboxes[recipient].append(message_id)

                # Save to storage
                self._save_messages_to_storage()

                # Log message event
                self._log_message_event('MESSAGE_SENT', sender, recipient, message_id,
                                       f"Message sent successfully (size: {len(message_content)} bytes)")

                return {
                    'success': True,
                    'message': 'Message sent successfully',
                    'message_id': message_id,
                    'recipient': recipient,
                    'timestamp': secure_message.created_at
                }

            except Exception as e:
                self._log_message_event('MESSAGE_SEND_FAILED', sender, recipient, 'N/A', str(e))
                return {
                    'success': False,
                    'message': f'Failed to send message: {str(e)}'
                }

    def receive_messages(self, username: str, session_token: str) -> Dict:
        """
        Retrieve and decrypt messages for a user
        Args:
            username: User's username
            session_token: User's session token
        Returns:
            Dictionary with decrypted messages and metadata
        """
        with self._lock:
            try:
                # Verify session
                session_data = self.auth_manager.verify_session(session_token)
                if not session_data or session_data['username'] != username:
                    return {
                        'success': False,
                        'message': 'Invalid session or unauthorized access'
                    }

                # Get user's private key for decryption
                user_private_key = RSAKeyManager.load_private_key(username)
                if not user_private_key:
                    return {
                        'success': False,
                        'message': 'Could not load user\'s private key'
                    }

                # Get all messages involving this user (received + sent)
                received_message_ids = self.user_inboxes.get(username, [])
                all_relevant_message_ids = []
                
                # Add received messages
                all_relevant_message_ids.extend(received_message_ids)
                
                # Add sent messages
                for msg_id, msg in self.messages.items():
                    if msg.sender == username and msg_id not in all_relevant_message_ids:
                        all_relevant_message_ids.append(msg_id)
                
                decrypted_messages = []

                for message_id in all_relevant_message_ids:
                    if message_id in self.messages:
                        message = self.messages[message_id]

                        # Check if this is a sent message (user is sender)
                        is_sent_message = (message.sender == username)

                        if is_sent_message:
                            # For sent messages, use stored plaintext
                            if message.plaintext_content:
                                decrypted_messages.append({
                                    'message_id': message.message_id,
                                    'sender': message.sender,
                                    'content': message.plaintext_content,
                                    'timestamp': message.created_at,
                                    'integrity_verified': True,
                                    'signature_valid': True
                                })
                            continue

                        # For received messages, decrypt normally
                        # Verify sender's signature
                        sender_public_key = RSAKeyManager.load_public_key(message.sender)
                        if not sender_public_key:
                            continue

                        # Verify signature
                        metadata_json = json.dumps(message.metadata, sort_keys=True)
                        signature_valid = HMACMessageAuthenticator.verify_signature(
                            metadata_json,
                            bytes.fromhex(message.signature),
                            sender_public_key
                        )

                        if not signature_valid:
                            self._log_message_event('MESSAGE_SIGNATURE_INVALID', message.sender,
                                                   username, message_id, 'Message signature verification failed')
                            continue

                        try:
                            # Decrypt message
                            decrypted_content, integrity_verified = HybridEncryption.decrypt_message(
                                message.encrypted_package,
                                user_private_key
                            )

                            # Update message status
                            message.is_read = True
                            message.integrity_verified = integrity_verified

                            decrypted_messages.append({
                                'message_id': message.message_id,
                                'sender': message.sender,
                                'content': decrypted_content,
                                'timestamp': message.created_at,
                                'integrity_verified': integrity_verified,
                                'signature_valid': signature_valid
                            })

                            # Log successful decryption
                            self._log_message_event('MESSAGE_DECRYPTED', message.sender, username,
                                                   message_id, f"Message decrypted (integrity: {integrity_verified})")

                        except Exception as e:
                            self._log_message_event('MESSAGE_DECRYPTION_FAILED', message.sender,
                                                   username, message_id, f"Decryption error: {str(e)}")
                            continue

                # Save updated message states
                self._save_messages_to_storage()

                return {
                    'success': True,
                    'messages': decrypted_messages,
                    'count': len(decrypted_messages),
                    'message': f'Retrieved {len(decrypted_messages)} messages'
                }

            except Exception as e:
                return {
                    'success': False,
                    'message': f'Failed to receive messages: {str(e)}'
                }

    def get_message_history(self, username: str, session_token: str,
                            other_user: Optional[str] = None) -> Dict:
        """
        Get message history for a user
        Args:
            username: User's username
            session_token: User's session token
            other_user: Optional - filter to show only messages with this user
        Returns:
            Dictionary with message history
        """
        with self._lock:
            try:
                # Verify session
                session_data = self.auth_manager.verify_session(session_token)
                if not session_data or session_data['username'] != username:
                    return {
                        'success': False,
                        'message': 'Invalid session or unauthorized access'
                    }

                # Get relevant messages
                relevant_messages = []

                for message in self.messages.values():
                    # Check if message involves this user
                    if message.sender == username or message.recipient == username:
                        # Filter by other_user if specified
                        if other_user and message.sender != other_user and message.recipient != other_user:
                            continue

                        relevant_messages.append({
                            'message_id': message.message_id,
                            'sender': message.sender,
                            'recipient': message.recipient,
                            'timestamp': message.created_at,
                            'is_read': message.is_read,
                            'integrity_verified': message.integrity_verified,
                            'direction': 'sent' if message.sender == username else 'received'
                        })

                # Sort by timestamp (newest first)
                relevant_messages.sort(key=lambda x: x['timestamp'], reverse=True)

                return {
                    'success': True,
                    'messages': relevant_messages,
                    'count': len(relevant_messages),
                    'filter': f'with {other_user}' if other_user else 'all messages'
                }

            except Exception as e:
                return {
                    'success': False,
                    'message': f'Failed to get message history: {str(e)}'
                }

    def delete_message(self, username: str, message_id: str, session_token: str) -> Dict:
        """Delete a message for a user"""
        with self._lock:
            try:
                # Verify session
                session_data = self.auth_manager.verify_session(session_token)
                if not session_data or session_data['username'] != username:
                    return {
                        'success': False,
                        'message': 'Invalid session or unauthorized access'
                    }

                # Find and remove message
                if message_id in self.messages:
                    message = self.messages[message_id]

                    # Only recipient can delete
                    if message.recipient != username:
                        return {
                            'success': False,
                            'message': 'You can only delete messages sent to you'
                        }

                    # Remove from inbox
                    if message_id in self.user_inboxes[username]:
                        self.user_inboxes[username].remove(message_id)

                    # Remove from storage
                    del self.messages[message_id]
                    self._save_messages_to_storage()

                    self._log_message_event('MESSAGE_DELETED', username, username, message_id,
                                           'Message deleted by recipient')

                    return {
                        'success': True,
                        'message': 'Message deleted successfully'
                    }
                else:
                    return {
                        'success': False,
                        'message': 'Message not found'
                    }

            except Exception as e:
                return {
                    'success': False,
                    'message': f'Failed to delete message: {str(e)}'
                }

    def get_user_list(self, username: str, session_token: str) -> Dict:
        """Get list of available users to message"""
        try:
            # Verify session
            session_data = self.auth_manager.verify_session(session_token)
            if not session_data or session_data['username'] != username:
                return {
                    'success': False,
                    'message': 'Invalid session or unauthorized access'
                }

            # Get all users except the current user
            all_users = self.auth_manager.get_all_users()
            other_users = [user for user in all_users if user != username]

            return {
                'success': True,
                'users': other_users,
                'count': len(other_users)
            }

        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to get user list: {str(e)}'
            }

    def get_conversation_stats(self, username: str, session_token: str) -> Dict:
        """Get messaging statistics for a user"""
        try:
            # Verify session
            session_data = self.auth_manager.verify_session(session_token)
            if not session_data or session_data['username'] != username:
                return {
                    'success': False,
                    'message': 'Invalid session or unauthorized access'
                }

            # Calculate statistics
            total_messages = 0
            sent_messages = 0
            received_messages = 0
            unread_messages = 0
            verified_messages = 0

            conversation_partners = set()

            for message in self.messages.values():
                if message.sender == username:
                    sent_messages += 1
                    conversation_partners.add(message.recipient)
                elif message.recipient == username:
                    received_messages += 1
                    if not message.is_read:
                        unread_messages += 1
                    conversation_partners.add(message.sender)

                total_messages += 1
                if message.integrity_verified:
                    verified_messages += 1

            return {
                'success': True,
                'statistics': {
                    'total_messages': total_messages,
                    'sent_messages': sent_messages,
                    'received_messages': received_messages,
                    'unread_messages': unread_messages,
                    'verified_messages': verified_messages,
                    'conversation_partners': len(conversation_partners),
                    'partners': list(conversation_partners)
                }
            }

        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to get statistics: {str(e)}'
            }

    def _log_message_event(self, event_type: str, sender: str, recipient: str,
                          message_id: str, details: str):
        """Log message-related events"""
        try:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'sender': sender,
                'recipient': recipient,
                'message_id': message_id,
                'details': details
            }

            # Append to message log
            with open(LoggingConfig.MESSAGE_LOG, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')

        except Exception as e:
            print(f"Error logging message event: {e}")

    def cleanup_old_messages(self, days: int = SecurityConfig.MESSAGE_RETENTION_DAYS):
        """Clean up messages older than specified days"""
        with self._lock:
            try:
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                messages_to_delete = []

                for message_id, message in self.messages.items():
                    message_date = datetime.fromisoformat(message.created_at)
                    if message_date < cutoff_date:
                        messages_to_delete.append(message_id)

                for message_id in messages_to_delete:
                    message = self.messages[message_id]
                    if message_id in self.user_inboxes[message.recipient]:
                        self.user_inboxes[message.recipient].remove(message_id)
                    del self.messages[message_id]

                if messages_to_delete:
                    self._save_messages_to_storage()
                    self._log_message_event('OLD_MESSAGES_CLEANED', 'system', 'system',
                                          f'{len(messages_to_delete)}', f'Cleaned up {len(messages_to_delete)} old messages')

                return len(messages_to_delete)

            except Exception as e:
                print(f"Error cleaning up old messages: {e}")
                return 0


# Global messaging system instance
messaging_system = MessagingSystem()


def get_messaging_system() -> MessagingSystem:
    """Get the global messaging system instance"""
    return messaging_system


if __name__ == "__main__":
    # Test the messaging system
    print("Testing Messaging System...")

    # Create test users
    print("\n1. Creating test users...")
    from authentication import get_auth_manager
    auth = get_auth_manager()

    # Register test users
    auth.register_user("alice", "AlicePass123!", "alice@example.com")
    auth.register_user("bob", "BobPass123!", "bob@example.com")

    # Login users
    alice_session = auth.login_user("alice", "AlicePass123!", "127.0.0.1")['session_token']
    bob_session = auth.login_user("bob", "BobPass123!", "127.0.0.1")['session_token']

    # Test sending messages
    print("\n2. Testing message sending...")
    result = messaging_system.send_message("alice", "bob", "Hello Bob! This is a secret message.", alice_session)
    print(f"Send result: {result}")

    # Test receiving messages
    print("\n3. Testing message receiving...")
    result = messaging_system.receive_messages("bob", bob_session)
    print(f"Receive result: {result}")
    if result['success'] and result['messages']:
        print(f"Decrypted message: {result['messages'][0]['content']}")

    # Test message history
    print("\n4. Testing message history...")
    result = messaging_system.get_message_history("alice", alice_session)
    print(f"History result: {result}")

    # Test statistics
    print("\n5. Testing statistics...")
    result = messaging_system.get_conversation_stats("alice", alice_session)
    print(f"Statistics result: {result}")

    print("\nMessaging system tests completed!")
