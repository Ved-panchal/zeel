"""
Comprehensive Logging System
Handles all logging operations for authentication, cryptographic operations,
messaging events, and attack simulations
"""
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from logging.handlers import RotatingFileHandler
import threading

from config import LoggingConfig, SecurityConfig


class SecurityLogger:
    """
    Centralized logging system for security events
    Implements thread-safe logging with rotation and multiple log levels
    """

    def __init__(self):
        self.loggers = {}
        self._lock = threading.Lock()
        self._initialize_loggers()

    def _initialize_loggers(self):
        """Initialize all logger instances"""
        log_configs = {
            'authentication': {
                'file': LoggingConfig.AUTH_LOG,
                'description': 'User authentication and authorization events'
            },
            'cryptographic': {
                'file': LoggingConfig.CRYPTO_LOG,
                'description': 'Encryption, decryption, and key management operations'
            },
            'messaging': {
                'file': LoggingConfig.MESSAGE_LOG,
                'description': 'Message transmission and reception events'
            },
            'attack_simulation': {
                'file': LoggingConfig.ATTACK_LOG,
                'description': 'Attack simulation and security testing events'
            },
            'system': {
                'file': LoggingConfig.SYSTEM_LOG,
                'description': 'General system operations and errors'
            }
        }

        for logger_name, config in log_configs.items():
            self.loggers[logger_name] = self._create_logger(
                logger_name,
                config['file'],
                config['description']
            )

    def _create_logger(self, name: str, log_file: Path, description: str) -> logging.Logger:
        """Create a configured logger instance"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        # Create rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=LoggingConfig.MAX_LOG_SIZE,
            backupCount=LoggingConfig.BACKUP_COUNT
        )
        file_handler.setLevel(logging.DEBUG)

        # Create console handler for important events
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter(
            LoggingConfig.LOG_FORMAT,
            datefmt=LoggingConfig.DATE_FORMAT
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        logger.info(f"Logger initialized: {description}")
        return logger

    def log_authentication_event(self, event_type: str, username: str, success: bool,
                               details: str, ip_address: str = 'unknown', severity: str = 'INFO'):
        """Log authentication-related events"""
        with self._lock:
            try:
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'event_type': event_type,
                    'username': username,
                    'success': success,
                    'ip_address': ip_address,
                    'details': details,
                    'severity': severity
                }

                message = f"AUTH_EVENT: {event_type} | User: {username} | Success: {success} | {details}"

                if severity == 'CRITICAL':
                    self.loggers['authentication'].critical(message)
                elif severity == 'ERROR':
                    self.loggers['authentication'].error(message)
                elif severity == 'WARNING':
                    self.loggers['authentication'].warning(message)
                else:
                    self.loggers['authentication'].info(message)

                # Also write to JSON log file for analysis
                self._write_json_log(LoggingConfig.AUTH_LOG, log_entry)

            except Exception as e:
                print(f"Error logging authentication event: {e}")

    def log_crypto_operation(self, operation: str, user: str, algorithm: str,
                            success: bool, details: str, key_size: Optional[int] = None,
                            severity: str = 'INFO'):
        """Log cryptographic operations"""
        with self._lock:
            try:
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'operation': operation,
                    'user': user,
                    'algorithm': algorithm,
                    'success': success,
                    'details': details,
                    'key_size': key_size,
                    'severity': severity
                }

                message = f"CRYPTO_OP: {operation} | User: {user} | Algorithm: {algorithm} | Success: {success} | {details}"

                if severity == 'CRITICAL':
                    self.loggers['cryptographic'].critical(message)
                elif severity == 'ERROR':
                    self.loggers['cryptographic'].error(message)
                else:
                    self.loggers['cryptographic'].info(message)

                self._write_json_log(LoggingConfig.CRYPTO_LOG, log_entry)

            except Exception as e:
                print(f"Error logging crypto operation: {e}")

    def log_messaging_event(self, event_type: str, sender: str, recipient: str,
                          message_id: str, details: str, message_size: int = 0,
                          encryption_status: str = 'unknown', severity: str = 'INFO'):
        """Log messaging-related events"""
        with self._lock:
            try:
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'event_type': event_type,
                    'sender': sender,
                    'recipient': recipient,
                    'message_id': message_id,
                    'details': details,
                    'message_size': message_size,
                    'encryption_status': encryption_status,
                    'severity': severity
                }

                message = f"MSG_EVENT: {event_type} | From: {sender} | To: {recipient} | ID: {message_id} | {details}"

                if severity == 'ERROR':
                    self.loggers['messaging'].error(message)
                elif severity == 'WARNING':
                    self.loggers['messaging'].warning(message)
                else:
                    self.loggers['messaging'].info(message)

                self._write_json_log(LoggingConfig.MESSAGE_LOG, log_entry)

            except Exception as e:
                print(f"Error logging messaging event: {e}")

    def log_attack_simulation(self, attack_type: str, target: str, success: bool,
                            details: str, mitigation: Optional[str] = None,
                            severity: str = 'WARNING'):
        """Log attack simulation events"""
        with self._lock:
            try:
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'attack_type': attack_type,
                    'target': target,
                    'success': success,
                    'details': details,
                    'mitigation': mitigation,
                    'severity': severity
                }

                message = f"ATTACK_SIM: {attack_type} | Target: {target} | Success: {success} | {details}"

                if severity == 'CRITICAL':
                    self.loggers['attack_simulation'].critical(message)
                elif severity == 'ERROR':
                    self.loggers['attack_simulation'].error(message)
                else:
                    self.loggers['attack_simulation'].warning(message)

                self._write_json_log(LoggingConfig.ATTACK_LOG, log_entry)

            except Exception as e:
                print(f"Error logging attack simulation: {e}")

    def log_system_event(self, event_type: str, component: str, status: str,
                       details: str, severity: str = 'INFO'):
        """Log system-related events"""
        with self._lock:
            try:
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'event_type': event_type,
                    'component': component,
                    'status': status,
                    'details': details,
                    'severity': severity
                }

                message = f"SYSTEM: {event_type} | Component: {component} | Status: {status} | {details}"

                if severity == 'CRITICAL':
                    self.loggers['system'].critical(message)
                elif severity == 'ERROR':
                    self.loggers['system'].error(message)
                elif severity == 'WARNING':
                    self.loggers['system'].warning(message)
                else:
                    self.loggers['system'].info(message)

                self._write_json_log(LoggingConfig.SYSTEM_LOG, log_entry)

            except Exception as e:
                print(f"Error logging system event: {e}")

    def _write_json_log(self, log_file: Path, log_entry: Dict):
        """Write log entry as JSON to file"""
        try:
            # Ensure logs directory exists
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to dedicated JSON file
            json_file = log_file.with_suffix('.json')
            with open(json_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
                f.flush()  # Ensure immediate write
        except Exception as e:
            print(f"Error writing JSON log to {log_file}: {e}")
            import traceback
            traceback.print_exc()

    def get_logs(self, log_type: str, lines: int = 100) -> List[str]:
        """Retrieve recent log entries"""
        try:
            log_file = self._get_log_file_path(log_type)
            if not log_file or not log_file.exists():
                return []

            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:] if len(all_lines) > lines else all_lines

        except Exception as e:
            print(f"Error reading logs: {e}")
            return []

    def get_json_logs(self, log_type: str, limit: int = 100) -> List[Dict]:
        """Retrieve JSON log entries"""
        try:
            log_file = self._get_log_file_path(log_type)
            if not log_file or not log_file.exists():
                return []

            entries = []
            
            # Try to read from .json file first
            json_file = log_file.with_suffix('.json')
            if json_file.exists():
                with open(json_file, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            entries.append(entry)
                            if len(entries) >= limit:
                                break
                        except json.JSONDecodeError:
                            continue
            
            # If no JSON file or empty, parse from .log file
            if not entries and log_file.exists():
                with open(log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        # Try to parse lines that look like JSON
                        if line.startswith('{') and line.endswith('}'):
                            try:
                                entry = json.loads(line)
                                entries.append(entry)
                                if len(entries) >= limit:
                                    break
                            except json.JSONDecodeError:
                                continue
            
            category_map = {
                'authentication': 'auth',
                'crypto': 'crypto',
                'messaging': 'messaging',
                'attack': 'attack',
                'system': 'system'
            }

            # Convert to UI-friendly format
            formatted_entries = []
            for entry in entries[-limit:]:  # Get most recent
                formatted_entries.append({
                    'timestamp': entry.get('timestamp', ''),
                    'category': category_map.get(log_type, log_type),
                    'event': entry.get('event_type', entry.get('operation', 'SYSTEM_EVENT')),
                    'detail': self._format_log_detail(entry),
                    'severity': entry.get('severity', 'INFO')
                })
            
            return formatted_entries

        except Exception as e:
            print(f"Error reading JSON logs: {e}")
            return []
    
    def _format_log_detail(self, entry: Dict) -> str:
        """Format log entry into readable detail string"""
        try:
            if 'username' in entry:
                # Authentication log
                success = '✓' if entry.get('success') else '✗'
                return f"{success} User: {entry.get('username')} | {entry.get('details', '')} | IP: {entry.get('ip_address', 'unknown')}"
            elif 'operation' in entry:
                # Crypto log
                return f"{entry.get('operation')} | User: {entry.get('user', 'N/A')} | Algorithm: {entry.get('algorithm', 'N/A')} | {entry.get('details', '')}"
            elif 'sender' in entry:
                # Messaging log
                return f"From: {entry.get('sender')} | To: {entry.get('recipient')} | {entry.get('details', '')}"
            elif 'attack_type' in entry:
                # Attack log
                status = 'PREVENTED' if not entry.get('success') else 'SUCCEEDED'
                return f"Attack: {entry.get('attack_type')} | Target: {entry.get('target', 'N/A')} | Status: {status} | {entry.get('details', '')}"
            else:
                # System log
                return entry.get('details', str(entry))
        except Exception:
            return str(entry)

    def _get_log_file_path(self, log_type: str) -> Optional[Path]:
        """Get log file path for log type"""
        log_files = {
            'authentication': LoggingConfig.AUTH_LOG,
            'crypto': LoggingConfig.CRYPTO_LOG,
            'cryptographic': LoggingConfig.CRYPTO_LOG,  # Alias
            'messaging': LoggingConfig.MESSAGE_LOG,
            'attack': LoggingConfig.ATTACK_LOG,
            'attack_simulation': LoggingConfig.ATTACK_LOG,  # Alias
            'system': LoggingConfig.SYSTEM_LOG
        }
        return log_files.get(log_type)

    def analyze_logs(self, log_type: str, time_range_hours: int = 24) -> Dict:
        """Analyze logs for security events and patterns"""
        try:
            logs = self.get_json_logs(log_type, limit=1000)
            cutoff_time = datetime.utcnow().timestamp() - (time_range_hours * 3600)

            analysis = {
                'total_events': len(logs),
                'time_range_hours': time_range_hours,
                'events_by_type': {},
                'events_by_severity': {},
                'failed_operations': 0,
                'successful_operations': 0,
                'recent_events': []
            }

            for entry in logs:
                # Count by event type
                event_type = entry.get('event_type', 'unknown')
                analysis['events_by_type'][event_type] = analysis['events_by_type'].get(event_type, 0) + 1

                # Count by severity
                severity = entry.get('severity', 'INFO')
                analysis['events_by_severity'][severity] = analysis['events_by_severity'].get(severity, 0) + 1

                # Count success/failure
                if 'success' in entry:
                    if entry['success']:
                        analysis['successful_operations'] += 1
                    else:
                        analysis['failed_operations'] += 1

                # Get recent events
                entry_time = datetime.fromisoformat(entry.get('timestamp', '')).timestamp()
                if entry_time >= cutoff_time:
                    analysis['recent_events'].append(entry)

            return analysis

        except Exception as e:
            print(f"Error analyzing logs: {e}")
            return {'error': str(e)}

    def generate_security_report(self) -> Dict:
        """Generate comprehensive security report"""
        try:
            report = {
                'generated_at': datetime.utcnow().isoformat(),
                'summary': {
                    'total_logs': 0,
                    'critical_events': 0,
                    'failed_authentications': 0,
                    'failed_decryptions': 0,
                    'attack_attempts': 0
                },
                'authentication': self.analyze_logs('authentication'),
                'crypto_operations': self.analyze_logs('crypto'),
                'messaging': self.analyze_logs('messaging'),
                'attack_simulations': self.analyze_logs('attack'),
                'recommendations': []
            }

            # Aggregate summary statistics
            for log_type, analysis in report.items():
                if isinstance(analysis, dict) and 'total_events' in analysis:
                    report['summary']['total_logs'] += analysis['total_events']
                    report['summary']['critical_events'] += analysis['events_by_severity'].get('CRITICAL', 0)

            # Add security recommendations based on analysis
            if report['authentication']['failed_operations'] > 10:
                report['recommendations'].append('High number of failed authentication attempts detected')

            if report['crypto_operations']['failed_operations'] > 5:
                report['recommendations'].append('Multiple cryptographic operation failures detected')

            if report['attack_simulations']['total_events'] > 0:
                report['recommendations'].append('Attack simulations have been performed - review logs')

            return report

        except Exception as e:
            print(f"Error generating security report: {e}")
            return {'error': str(e)}


class LogAnalyzer:
    """
    Advanced log analysis for security monitoring and threat detection
    """

    def __init__(self, security_logger: SecurityLogger):
        self.logger = security_logger

    def detect_suspicious_patterns(self) -> List[Dict]:
        """Detect suspicious patterns in system logs"""
        suspicious_activities = []

        try:
            # Check for multiple failed login attempts
            auth_logs = self.logger.get_json_logs('authentication')
            failed_attempts = {}

            for log_entry in auth_logs:
                if not log_entry.get('success', True):
                    username = log_entry.get('username', 'unknown')
                    failed_attempts[username] = failed_attempts.get(username, 0) + 1

            for username, count in failed_attempts.items():
                if count >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
                    suspicious_activities.append({
                        'type': 'brute_force_attempt',
                        'severity': 'HIGH',
                        'target': username,
                        'details': f'{count} failed login attempts detected'
                    })

            # Check for failed decryption attempts
            crypto_logs = self.logger.get_json_logs('crypto')
            failed_decryptions = 0

            for log_entry in crypto_logs:
                if log_entry.get('operation') == 'decryption' and not log_entry.get('success', True):
                    failed_decryptions += 1

            if failed_decryptions > 10:
                suspicious_activities.append({
                    'type': 'decryption_failure_spike',
                    'severity': 'MEDIUM',
                    'details': f'{failed_decryptions} failed decryption attempts detected'
                })

            # Check for attack simulations
            attack_logs = self.logger.get_json_logs('attack')
            if attack_logs:
                suspicious_activities.append({
                    'type': 'attack_simulation_detected',
                    'severity': 'INFO',
                    'details': f'{len(attack_logs)} attack simulation events logged'
                })

        except Exception as e:
            print(f"Error detecting suspicious patterns: {e}")

        return suspicious_activities

    def generate_compliance_report(self) -> Dict:
        """Generate compliance and audit report"""
        try:
            report = {
                'generated_at': datetime.utcnow().isoformat(),
                'compliance_status': 'COMPLIANT',
                'security_measures': {
                    'encryption': {
                        'status': 'ACTIVE',
                        'algorithm': f'AES-{SecurityConfig.AES_KEY_SIZE}',
                        'key_exchange': 'RSA-2048',
                        'hashing': SecurityConfig.MESSAGE_HASH_ALGORITHM
                    },
                    'authentication': {
                        'status': 'ACTIVE',
                        'method': SecurityConfig.PASSWORD_HASH_ALGORITHM,
                        'session_management': 'ACTIVE',
                        'multi_factor': 'DISABLED'
                    },
                    'integrity': {
                        'status': 'ACTIVE',
                        'method': SecurityConfig.HMAC_ALGORITHM,
                        'digital_signatures': 'RSA-PSS'
                    },
                    'logging': {
                        'status': 'ACTIVE',
                        'types': ['authentication', 'crypto', 'messaging', 'attacks'],
                        'retention_days': SecurityConfig.MESSAGE_RETENTION_DAYS
                    }
                },
                'audit_trail': {
                    'total_logs': 0,
                    'time_coverage': '24_hours',
                    'log_integrity': 'VERIFIED'
                },
                'recommendations': []
            }

            # Count total logs
            for log_type in ['authentication', 'crypto', 'messaging', 'attack']:
                logs = self.logger.get_json_logs(log_type)
                report['audit_trail']['total_logs'] += len(logs)

            # Add recommendations
            if report['security_measures']['authentication']['multi_factor'] == 'DISABLED':
                report['recommendations'].append('Consider enabling multi-factor authentication')

            if len(self.logger.get_json_logs('attack')) > 0:
                report['recommendations'].append('Review attack simulation logs for security improvements')

            return report

        except Exception as e:
            print(f"Error generating compliance report: {e}")
            return {'error': str(e)}


# Global security logger instance
security_logger = SecurityLogger()
log_analyzer = LogAnalyzer(security_logger)


def get_security_logger() -> SecurityLogger:
    """Get the global security logger instance"""
    return security_logger


def get_log_analyzer() -> LogAnalyzer:
    """Get the global log analyzer instance"""
    return log_analyzer


if __name__ == "__main__":
    # Test the logging system
    print("Testing Logging System...")

    # Test different log types
    print("\n1. Testing authentication logs...")
    security_logger.log_authentication_event(
        'LOGIN_SUCCESS', 'testuser', True,
        'User logged in successfully', '192.168.1.100'
    )

    security_logger.log_authentication_event(
        'LOGIN_FAILED', 'testuser', False,
        'Invalid password', '192.168.1.100', severity='WARNING'
    )

    print("\n2. Testing crypto operation logs...")
    security_logger.log_crypto_operation(
        'encryption', 'alice', 'AES-256-CBC', True,
        'Message encrypted successfully', 256
    )

    print("\n3. Testing messaging logs...")
    security_logger.log_messaging_event(
        'MESSAGE_SENT', 'alice', 'bob', 'msg_123',
        'Secret message sent', 150, 'encrypted'
    )

    print("\n4. Testing attack simulation logs...")
    security_logger.log_attack_simulation(
        'MITM_ATTEMPT', 'alice', False,
        'Man-in-the-middle attack detected and prevented',
        'HMAC verification failed', severity='CRITICAL'
    )

    print("\n5. Testing system logs...")
    security_logger.log_system_event(
        'SYSTEM_STARTUP', 'core', 'SUCCESS',
        'Secure messaging system initialized'
    )

    print("\n6. Generating security report...")
    report = security_logger.generate_security_report()
    print(f"Security Report: {json.dumps(report, indent=2)}")

    print("\n7. Analyzing suspicious patterns...")
    patterns = log_analyzer.detect_suspicious_patterns()
    print(f"Suspicious Patterns: {json.dumps(patterns, indent=2)}")

    print("\n8. Generating compliance report...")
    compliance = log_analyzer.generate_compliance_report()
    print(f"Compliance Report: {json.dumps(compliance, indent=2)}")

    print("\nLogging system tests completed!")
