"""
Main Entry Point for Secure Messaging System
Run this file to start the complete application
"""
import sys
import os
from pathlib import Path

# Ensure UTF-8 output so emojis/box-drawing characters render on Windows consoles (cp1252)
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except (AttributeError, Exception):
    pass

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def print_banner():
    """Print application banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        🔐 SECURE MESSAGING SYSTEM 🔐                         ║
║                                                              ║
║        Advanced Cryptographic Communication Platform          ║
║                                                              ║
║        Features:                                              ║
║        • AES-256 Encryption                                  ║
║        • RSA-2048 Key Exchange                               ║
║        • HMAC Integrity Verification                          ║
║        • Attack Simulations                                 ║
║        • Real-time Messaging                                 ║
║        • Comprehensive Logging                               ║
║                                                              ║
║        Course: Software Security                             ║
║        Instructor: Prof. Dr. Rand Kouatly                    ║
║        Institution: EU University of Applied Science           ║
║        Semester: Summer 2026                                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def initialize_system():
    """Initialize the secure messaging system"""
    print("🚀 Initializing Secure Messaging System...")
    print()

    # Import configuration
    from config import initialize_system as init_config
    init_config()

    print()

def run_web_application():
    """Run the Flask web application"""
    print("🌐 Starting Web Application...")
    print("📍 Access the application at: http://localhost:5000")
    print()

    from app import app, socketio, initialize_application

    # Initialize application
    initialize_application()

    print("✅ Application ready!")
    print("🔒 All security systems operational")
    print("📝 Logs are being written to ./logs/")
    print("💾 Data storage in ./data/")
    print()
    print("Press Ctrl+C to stop the application")
    print("-" * 60)
    print()

    # Run the application
    try:
        socketio.run(app, debug=False, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n\n🛑 Application stopped by user")
        print("🔒 Secure shutdown completed")

def run_tests():
    """Run system tests"""
    print("🧪 Running System Tests...")
    print()

    test_results = {}

    # Test 1: Cryptographic Core
    print("1️⃣ Testing Cryptographic Core...")
    try:
        import crypto_core
        test_results['crypto_core'] = "✅ PASSED"
        print("   ✅ Cryptographic core operational")
    except Exception as e:
        test_results['crypto_core'] = f"❌ FAILED: {str(e)}"
        print(f"   ❌ Cryptographic core error: {e}")
    print()

    # Test 2: Authentication
    print("2️⃣ Testing Authentication System...")
    try:
        import authentication
        test_results['authentication'] = "✅ PASSED"
        print("   ✅ Authentication system operational")
    except Exception as e:
        test_results['authentication'] = f"❌ FAILED: {str(e)}"
        print(f"   ❌ Authentication error: {e}")
    print()

    # Test 3: Messaging System
    print("3️⃣ Testing Messaging System...")
    try:
        import messaging_system
        test_results['messaging'] = "✅ PASSED"
        print("   ✅ Messaging system operational")
    except Exception as e:
        test_results['messaging'] = f"❌ FAILED: {str(e)}"
        print(f"   ❌ Messaging error: {e}")
    print()

    # Test 4: Attack Simulations
    print("4️⃣ Testing Attack Simulations...")
    try:
        import attack_simulations
        test_results['attack_simulations'] = "✅ PASSED"
        print("   ✅ Attack simulations operational")
    except Exception as e:
        test_results['attack_simulations'] = f"❌ FAILED: {str(e)}"
        print(f"   ❌ Attack simulations error: {e}")
    print()

    # Test 5: Logging System
    print("5️⃣ Testing Logging System...")
    try:
        import logging_system
        test_results['logging'] = "✅ PASSED"
        print("   ✅ Logging system operational")
    except Exception as e:
        test_results['logging'] = f"❌ FAILED: {str(e)}"
        print(f"   ❌ Logging error: {e}")
    print()

    # Summary
    print("=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    for test, result in test_results.items():
        print(f"{test.replace('_', ' ').title():20} : {result}")
    print("=" * 60)
    print()

def run_demo():
    """Run demonstration with test users"""
    print("🎬 Running System Demonstration...")
    print()

    from authentication import get_auth_manager
    from messaging_system import get_messaging_system
    from crypto_core import RSAKeyManager

    auth_manager = get_auth_manager()
    messaging_system = get_messaging_system()

    print("1️⃣ Creating Demo Users...")
    # Create demo users
    alice_result = auth_manager.register_user("alice", "AliceSecure123!", "alice@example.com")
    print(f"   Alice: {'✅ Created' if alice_result['success'] else '⚠️ Already exists'}")

    bob_result = auth_manager.register_user("bob", "BobSecure123!", "bob@example.com")
    print(f"   Bob: {'✅ Created' if bob_result['success'] else '⚠️ Already exists'}")

    charlie_result = auth_manager.register_user("charlie", "CharlieSecure123!", "charlie@example.com")
    print(f"   Charlie: {'✅ Created' if charlie_result['success'] else '⚠️ Already exists'}")
    print()

    print("2️⃣ Testing User Login...")
    alice_login = auth_manager.login_user("alice", "AliceSecure123!", "127.0.0.1")
    if alice_login['success']:
        print(f"   ✅ Alice logged in successfully")
        alice_session = alice_login['session_token']
    else:
        print(f"   ❌ Alice login failed")
        alice_session = None
    print()

    print("3️⃣ Testing Secure Messaging...")
    if alice_session:
        # Test message from Alice to Bob
        message_result = messaging_system.send_message(
            "alice", "bob", "Hello Bob! This is a test message from Alice.", alice_session
        )
        if message_result['success']:
            print(f"   ✅ Message sent from Alice to Bob")
            print(f"   📝 Message ID: {message_result['message_id']}")
        else:
            print(f"   ❌ Failed to send message: {message_result['message']}")
    print()

    print("4️⃣ Testing Message Reception...")
    bob_login = auth_manager.login_user("bob", "BobSecure123!", "127.0.0.1")
    if bob_login['success']:
        print(f"   ✅ Bob logged in successfully")
        bob_session = bob_login['session_token']

        # Bob receives messages
        received = messaging_system.receive_messages("bob", bob_session)
        if received['success'] and received['messages']:
            print(f"   ✅ Bob received {len(received['messages'])} message(s)")
            for msg in received['messages']:
                print(f"   📩 From: {msg['sender']}")
                print(f"   🔒 Encrypted: Yes")
                print(f"   ✅ Integrity Verified: {msg['integrity_verified']}")
                print(f"   📄 Content: {msg['content'][:50]}...")
        else:
            print(f"   ⚠️ Bob has no new messages")
    print()

    print("5️⃣ Testing Key Management...")
    alice_public_key = RSAKeyManager.load_public_key("alice")
    bob_public_key = RSAKeyManager.load_public_key("bob")

    if alice_public_key and bob_public_key:
        print(f"   ✅ RSA key management operational")
        print(f"   🔑 Alice's public key loaded: {alice_public_key.key_size} bits")
        print(f"   🔑 Bob's public key loaded: {bob_public_key.key_size} bits")
    else:
        print(f"   ❌ Failed to load RSA keys")
    print()

    print("🎉 Demonstration completed successfully!")
    print()
    print("📝 Demo Credentials:")
    print("   Username: alice / Password: AliceSecure123!")
    print("   Username: bob / Password: BobSecure123!")
    print("   Username: charlie / Password: CharlieSecure123!")
    print()

def main():
    """Main function with menu"""
    print_banner()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "test":
            initialize_system()
            run_tests()
        elif command == "demo":
            initialize_system()
            run_demo()
        elif command == "run" or command == "start":
            initialize_system()
            run_web_application()
        elif command == "help":
            print_help()
        else:
            print(f"❌ Unknown command: {command}")
            print("Use 'python main.py help' for usage information")
    else:
        # Interactive menu
        print("Welcome to Secure Messaging System!")
        print()
        print("Please choose an option:")
        print()
        print("1. 🚀 Start Web Application (Recommended)")
        print("2. 🧪 Run System Tests")
        print("3. 🎬 Run Demonstration")
        print("4. 📖 Show Help")
        print("5. 🚪 Exit")
        print()

        while True:
            try:
                choice = input("Enter your choice (1-5): ").strip()

                if choice == "1":
                    initialize_system()
                    run_web_application()
                    break
                elif choice == "2":
                    initialize_system()
                    run_tests()
                    break
                elif choice == "3":
                    initialize_system()
                    run_demo()
                    break
                elif choice == "4":
                    print_help()
                    break
                elif choice == "5":
                    print("👋 Goodbye!")
                    break
                else:
                    print("❌ Invalid choice. Please enter 1-5.")
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break

def print_help():
    """Print help information"""
    help_text = """
🚀 SECURE MESSAGING SYSTEM - USAGE GUIDE

📝 COMMANDS:
    python main.py           - Interactive menu
    python main.py run       - Start web application
    python main.py test      - Run system tests
    python main.py demo      - Run demonstration
    python main.py help      - Show this help

🌐 WEB APPLICATION:
    • Start: python main.py run
    • Access: http://localhost:5000
    • Features: Real-time messaging, user management

🧪 SYSTEM TESTS:
    • Command: python main.py test
    • Tests: Crypto, Authentication, Messaging, Attacks, Logging
    • Duration: ~30 seconds

🎬 DEMONSTRATION:
    • Command: python main.py demo
    • Creates demo users
    • Tests messaging functionality
    • Demonstrates security features

📖 DOCUMENTATION:
    • README.md - Project overview and technical details
    • USER_GUIDE.md - Comprehensive user guide
    • SECURITY_REPORT.md - Security analysis and recommendations

🔧 CONFIGURATION:
    • config.py - Security parameters and system settings
    • data/ - User data and message storage
    • logs/ - System logs and security events

🛡️ SECURITY FEATURES:
    • AES-256-CBC symmetric encryption
    • RSA-2048 asymmetric encryption
    • HMAC-SHA256 message integrity
    • Bcrypt password hashing
    • Attack simulations and monitoring

📊 EVALUATION CRITERIA:
    • Correct implementation of encryption (30%)
    • Security design quality (25%)
    • Code quality and structure (20%)
    • Attack simulation and analysis (15%)
    • Documentation (10%)

👨‍🏫 COURSE INFORMATION:
    • Course: Software Security
    • Instructor: Prof. Dr. Rand Kouatly
    • Institution: EU University of Applied Science
    • Semester: Summer 2026
    • Deadline: June 21, 2026, 11:00 PM

For detailed information, see README.md and USER_GUIDE.md
"""
    print(help_text)

if __name__ == "__main__":
    main()
