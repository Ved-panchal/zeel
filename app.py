"""
Secure Messaging System - Web Application
Flask-based web interface with real-time messaging and security features
"""
import os
import json
import secrets
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from functools import wraps

from config import WebConfig, SecurityConfig
from authentication import get_auth_manager, get_session_manager
from messaging_system import get_messaging_system
from crypto_core import RSAKeyManager
from attack_simulations import get_attack_simulator
from logging_system import get_security_logger, get_log_analyzer

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = WebConfig.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = WebConfig.MAX_CONTENT_LENGTH

# Enable CORS
CORS(app)

# Initialize SocketIO for real-time messaging
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=WebConfig.SOCKETIO_ASYNC_MODE)

# Get system components
auth_manager = get_auth_manager()
session_manager = get_session_manager()
messaging_system = get_messaging_system()
security_logger = get_security_logger()
log_analyzer = get_log_analyzer()
attack_simulator = get_attack_simulator()


# Authentication decorators
def login_required(f):
    """Decorator for HTML pages — redirects to login if not authenticated.

    Also validates that the session token is still active server-side (not just
    present in the cookie), so expired/invalidated sessions are caught.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('session_token')
        if not token or not auth_manager.verify_session(token):
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    """Decorator for API endpoints — returns 401 JSON if not authenticated.

    Crucially does NOT redirect: a redirect would be auto-followed by fetch()
    to /login (which returns 200), making the frontend think it's authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('session_token')
        if not token or not auth_manager.verify_session(token):
            session.clear()
            return jsonify({
                'success': False,
                'message': 'Authentication required',
                'authenticated': False
            }), 401
        return f(*args, **kwargs)
    return decorated_function


# ==================== Main Routes ====================

@app.route('/')
def index():
    """Home page - redirect to login or dashboard"""
    if 'session_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login')
def login():
    """Login page"""
    return render_template('login.html', app_name=WebConfig.APP_NAME)


@app.route('/register')
def register():
    """Registration page"""
    return render_template('register.html', app_name=WebConfig.APP_NAME)


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard - messaging interface"""
    username = session.get('username')
    return render_template('dashboard.html', username=username, app_name=WebConfig.APP_NAME)


@app.route('/admin')
@login_required
def admin():
    """Admin panel - security monitoring and logs"""
    username = session.get('username')
    if username != 'admin':  # Basic admin check
        return redirect(url_for('dashboard'))
    return render_template('admin.html', username=username, app_name=WebConfig.APP_NAME)


# ==================== API Routes ====================

@app.route('/api/register', methods=['POST'])
def api_register():
    """User registration API"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '')

        if not username or not password:
            return jsonify({
                'success': False,
                'message': 'Username and password are required'
            }), 400

        result = auth_manager.register_user(username, password, email)
        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Registration error: {str(e)}'
        }), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    """User login API"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        ip_address = request.remote_addr or 'unknown'

        if not username or not password:
            return jsonify({
                'success': False,
                'message': 'Username and password are required'
            }), 400

        result = auth_manager.login_user(username, password, ip_address)

        if result['success']:
            session['session_token'] = result['session_token']
            session['username'] = username

        status_code = 200 if result['success'] else 401
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Login error: {str(e)}'
        }), 500


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """User logout API"""
    try:
        if 'session_token' in session:
            result = auth_manager.logout_user(session['session_token'])
            session.clear()
            return jsonify(result)
        else:
            return jsonify({
                'success': True,
                'message': 'Already logged out'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Logout error: {str(e)}'
        }), 500


@app.route('/api/users', methods=['GET'])
@api_login_required
def api_get_users():
    """Get list of available users"""
    try:
        username = session.get('username')
        session_token = session.get('session_token')

        result = messaging_system.get_user_list(username, session_token)
        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error getting users: {str(e)}'
        }), 500


@app.route('/api/messages/send', methods=['POST'])
@api_login_required
def api_send_message():
    """Send message API"""
    try:
        data = request.get_json()
        sender = session.get('username')
        recipient = data.get('recipient', '').strip()
        message_content = data.get('message', '').strip()
        session_token = session.get('session_token')

        if not recipient or not message_content:
            return jsonify({
                'success': False,
                'message': 'Recipient and message are required'
            }), 400

        result = messaging_system.send_message(sender, recipient, message_content, session_token)

        # Emit real-time message payload to recipient so they render without polling
        if result['success']:
            socketio.emit('new_message', {
                'sender': sender,
                'content': message_content,
                'message_id': result['message_id'],
                'timestamp': result['timestamp'],
                'integrity_verified': True
            }, room=f"user_{recipient}")

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error sending message: {str(e)}'
        }), 500


@app.route('/api/messages/receive', methods=['GET'])
@api_login_required
def api_receive_messages():
    """Receive messages API"""
    try:
        username = session.get('username')
        session_token = session.get('session_token')

        result = messaging_system.receive_messages(username, session_token)
        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error receiving messages: {str(e)}'
        }), 500


@app.route('/api/messages/history', methods=['GET'])
@api_login_required
def api_message_history():
    """Get message history API"""
    try:
        username = session.get('username')
        session_token = session.get('session_token')
        other_user = request.args.get('user', None)

        result = messaging_system.get_message_history(username, session_token, other_user)
        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error getting history: {str(e)}'
        }), 500


@app.route('/api/messages/<message_id>', methods=['DELETE'])
@api_login_required
def api_delete_message(message_id):
    """Delete message API"""
    try:
        username = session.get('username')
        session_token = session.get('session_token')

        result = messaging_system.delete_message(username, message_id, session_token)
        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error deleting message: {str(e)}'
        }), 500


@app.route('/api/stats', methods=['GET'])
@api_login_required
def api_get_stats():
    """Get user statistics API"""
    try:
        username = session.get('username')
        session_token = session.get('session_token')

        result = messaging_system.get_conversation_stats(username, session_token)
        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error getting stats: {str(e)}'
        }), 500


# ==================== Admin Routes ====================

@app.route('/api/admin/logs', methods=['GET'])
@api_login_required
def api_get_logs():
    """Get system logs API"""
    try:
        username = session.get('username')
        if username != 'admin':
            return jsonify({
                'success': False,
                'message': 'Unauthorized access'
            }), 403

        log_type = request.args.get('type', 'system')
        limit = int(request.args.get('limit', 100))

        logs = security_logger.get_json_logs(log_type, limit)
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error getting logs: {str(e)}'
        }), 500


@app.route('/api/admin/security-report', methods=['GET'])
@api_login_required
def api_security_report():
    """Get security report API"""
    try:
        username = session.get('username')
        if username != 'admin':
            return jsonify({
                'success': False,
                'message': 'Unauthorized access'
            }), 403

        report = security_logger.generate_security_report()
        return jsonify(report)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error generating report: {str(e)}'
        }), 500


@app.route('/api/admin/attack-simulation', methods=['POST'])
@api_login_required
def api_run_attack_simulation():
    """Run attack simulation API"""
    try:
        username = session.get('username')
        if username != 'admin':
            return jsonify({
                'success': False,
                'message': 'Unauthorized access'
            }), 403

        data = request.get_json()
        user1 = data.get('user1', 'alice')
        user2 = data.get('user2', 'bob')

        results = attack_simulator.run_all_simulations(user1, user2)
        return jsonify(results)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error running simulation: {str(e)}'
        }), 500


@app.route('/api/admin/compliance-report', methods=['GET'])
@api_login_required
def api_compliance_report():
    """Get compliance report API"""
    try:
        username = session.get('username')
        if username != 'admin':
            return jsonify({
                'success': False,
                'message': 'Unauthorized access'
            }), 403

        report = log_analyzer.generate_compliance_report()
        return jsonify(report)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error generating compliance report: {str(e)}'
        }), 500


# ==================== User-accessible simulation / log routes ====================

@app.route('/api/attack-simulation', methods=['POST'])
@api_login_required
def api_user_attack_simulation():
    """Run attack simulation — available to all logged-in users"""
    try:
        from crypto_core import RSAKeyManager
        import traceback

        data = request.get_json() or {}
        user1 = data.get('user1', 'alice')
        user2 = data.get('user2', 'bob')

        # Ensure RSA keys exist for simulation users (auto-generate if missing)
        for user in [user1, user2]:
            if not RSAKeyManager.load_public_key(user):
                private_pem, public_pem = RSAKeyManager.generate_key_pair(user)
                RSAKeyManager.save_key_pair(user, private_pem, public_pem)
                print(f"[AttackSim] Generated RSA key pair for user: {user}")

        results = attack_simulator.run_all_simulations(user1, user2)
        return jsonify(results)
    except Exception as e:
        import traceback as tb
        print(f"[AttackSim] Error: {e}\n{tb.format_exc()}")
        return jsonify({
            'success': False,
            'message': str(e),
            'traceback': tb.format_exc() if os.environ.get('FLASK_DEBUG') else ''
        }), 500


@app.route('/api/security-logs', methods=['GET'])
@api_login_required
def api_user_security_logs():
    """Get recent security logs — available to all logged-in users"""
    try:
        log_type = request.args.get('type', 'all')
        limit = min(int(request.args.get('limit', 100)), 500)
        
        # Map 'all' to get logs from all sources
        if log_type == 'all':
            all_logs = []
            for lt in ['authentication', 'messaging', 'crypto', 'attack', 'system']:
                logs = security_logger.get_json_logs(lt, limit)
                all_logs.extend(logs)
            # Sort by timestamp descending
            all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            return jsonify({'success': True, 'logs': all_logs[:limit], 'count': len(all_logs[:limit])})
        else:
            # Map frontend filter names to backend log types
            log_type_map = {
                'auth': 'authentication',
                'crypto': 'crypto',
                'messaging': 'messaging',
                'attack': 'attack',
                'system': 'system'
            }
            backend_type = log_type_map.get(log_type, log_type)
            logs = security_logger.get_json_logs(backend_type, limit)
            return jsonify({'success': True, 'logs': logs, 'count': len(logs)})
    except Exception as e:
        print(f"Error getting security logs: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/system-info', methods=['GET'])
@api_login_required
def api_system_info():
    """Get system/crypto info — available to all logged-in users"""
    try:
        from config import SecurityConfig
        username = session.get('username')
        session_token = session.get('session_token')
        stats = messaging_system.get_conversation_stats(username, session_token)
        return jsonify({
            'success': True,
            'crypto': {
                'rsa_key_size': SecurityConfig.RSA_KEY_SIZE,
                'aes_key_size': SecurityConfig.AES_KEY_SIZE,
                'hash_algorithm': SecurityConfig.MESSAGE_HASH_ALGORITHM,
                'pbkdf2_iterations': 100000,  # From crypto_core.py
                'bcrypt_rounds': SecurityConfig.BCRYPT_ROUNDS,
                'session_timeout_minutes': SecurityConfig.SESSION_TIMEOUT // 60,
                'max_login_attempts': SecurityConfig.MAX_LOGIN_ATTEMPTS,
            },
            'stats': stats.get('stats', {}),
            'username': username,
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if 'username' in session:
        username = session['username']
        room = f"user_{username}"
        join_room(room)
        print(f"User {username} connected to WebSocket")
        emit('connection_status', {'status': 'connected', 'username': username})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    if 'username' in session:
        username = session['username']
        print(f"User {username} disconnected from WebSocket")
        leave_room(f"user_{username}")


@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator"""
    recipient = data.get('recipient')
    if recipient:
        emit('user_typing', {
            'sender': session.get('username'),
            'timestamp': datetime.utcnow().isoformat()
        }, room=f"user_{recipient}")


# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'message': 'Resource not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500


# ==================== Main Application ====================

def initialize_application():
    """Initialize the Flask application"""
    print(f"\nInitializing {WebConfig.APP_NAME} v{WebConfig.APP_VERSION}...")
    print(f"Security Configuration:")
    print(f"  - RSA Key Size: {SecurityConfig.RSA_KEY_SIZE} bits")
    print(f"  - AES Encryption: {SecurityConfig.AES_KEY_SIZE}-bit {SecurityConfig.AES_MODE}")
    print(f"  - Password Hashing: {SecurityConfig.PASSWORD_HASH_ALGORITHM}")
    print(f"  - HMAC Algorithm: {SecurityConfig.HMAC_ALGORITHM}")
    print(f"  - Session Timeout: {SecurityConfig.SESSION_TIMEOUT} seconds")
    print(f"  - Max Login Attempts: {SecurityConfig.MAX_LOGIN_ATTEMPTS}")
    print(f"\nAttack Simulations: {'ENABLED' if True else 'DISABLED'}")
    print(f"Web Interface: http://localhost:5000")
    print(f"\nApplication initialized successfully!")


if __name__ == '__main__':
    initialize_application()
    socketio.run(app, debug=WebConfig.DEBUG, host='0.0.0.0', port=5000)
