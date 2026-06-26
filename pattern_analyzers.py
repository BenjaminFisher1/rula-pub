from abc import ABC, abstractmethod
import ipaddress
from psycopg2.extras import RealDictCursor
import requests

class PatternAnalyzer(ABC):
    """Base class for all pattern analyzers."""
    
    @property
    @abstractmethod
    def tag_name(self):
        """Unique tag identifier."""
        pass
    
    @property
    def default_severity(self):
        """Default severity if pattern detected."""
        return 'medium'
    
    @abstractmethod
    def analyze(self, user_id, db_handler):
        """
        Analyze user behavior and return detection result.
        
        Returns:
            dict: {
                'detected': bool,
                'severity': str,
                'details': dict
            }
        """
        pass


class MultipleInterruptedSignins(PatternAnalyzer):
    tag_name = 'multi_app_interruption'
    default_severity = 'medium'
    
    def __init__(self, threshold=5, time_window_hours=24):
        self.threshold = threshold
        self.time_window_hours = time_window_hours

    def _extract_status_class(self, sign_in):
        status = sign_in.get('status') or {}
        if isinstance(status, dict):
            error_code = status.get('errorCode')
            failure_reason = str(status.get('failureReason') or '')
            additional_details = str(status.get('additionalDetails') or '')
        else:
            error_code = None
            failure_reason = ''
            additional_details = ''

        try:
            error_code = int(error_code)
        except (TypeError, ValueError):
            error_code = None

        status_text = f"{failure_reason} {additional_details}".lower()
        if error_code == 0:
            return 'success'
        if 'interrupted' in status_text or 'mfa' in status_text:
            return 'interrupted'
        return 'failed'

    def _extract_app_name(self, sign_in):
        app_name = (
            sign_in.get('appDisplayName')
            or sign_in.get('resourceDisplayName')
            or sign_in.get('clientAppUsed')
            or 'Unknown App'
        )
        return str(app_name)

    def analyze(self, user_id, db):
        """Detect interrupted sign-ins across multiple apps."""
        try:
            sign_ins = db.graph_handler.list_all_sign_ins_for_user(user_id, hours=self.time_window_hours)
        except requests.exceptions.HTTPError as exc:
            status_code = getattr(getattr(exc, 'response', None), 'status_code', None)
            if status_code == 403:
                # If sign-in log access is forbidden, skip this analyzer without failing assessment.
                return {'detected': False}
            raise

        interrupted_app_names = []
        successful_signins = 0

        for sign_in in sign_ins:
            status_class = self._extract_status_class(sign_in)
            if status_class == 'interrupted':
                interrupted_app_names.append(self._extract_app_name(sign_in))
            elif status_class == 'success':
                successful_signins += 1

        unique_apps = len(set(interrupted_app_names))
        total_interruptions = len(interrupted_app_names)

        if unique_apps >= self.threshold:
            return {
                'detected': True,
                'severity': 'critical' if successful_signins >= 1 else 'medium',
                'details': {
                    'unique_apps': unique_apps,
                    'total_interruptions': total_interruptions,
                    'successful_signins': successful_signins,
                    'app_names': sorted(set(interrupted_app_names))[:5],
                    'time_window_hours': self.time_window_hours,
                    'data_source': 'graph_audit_signins'
                }
            }

        return {'detected': False}


class MultiIPSuccessfulInterruptedSignins(PatternAnalyzer):
    tag_name = 'multi_ip_successful_interrupted_signins'
    default_severity = 'medium'

    def __init__(self, ip_threshold=3, time_window_hours=24):
        self.ip_threshold = ip_threshold
        self.time_window_hours = time_window_hours

    def _extract_status_class(self, sign_in):
        status = sign_in.get('status') or {}
        if isinstance(status, dict):
            error_code = status.get('errorCode')
            failure_reason = str(status.get('failureReason') or '')
            additional_details = str(status.get('additionalDetails') or '')
        else:
            error_code = None
            failure_reason = ''
            additional_details = ''

        try:
            error_code = int(error_code)
        except (TypeError, ValueError):
            error_code = None

        status_text = f"{failure_reason} {additional_details}".lower()
        if error_code == 0:
            return 'success'
        if 'interrupted' in status_text or 'mfa' in status_text:
            return 'interrupted'
        return 'failed'

    def analyze(self, user_id, db):
        """Detect successful + interrupted sign-ins across multiple IPs."""
        try:
            sign_ins = db.graph_handler.list_all_sign_ins_for_user(user_id, hours=self.time_window_hours)
        except requests.exceptions.HTTPError as exc:
            status_code = getattr(getattr(exc, 'response', None), 'status_code', None)
            if status_code == 403:
                # If sign-in log access is forbidden, skip this analyzer without failing assessment.
                return {'detected': False}
            raise

        interrupted_ips = []
        successful_ips = []

        for sign_in in sign_ins:
            ip_address = sign_in.get('ipAddress')
            if not ip_address:
                continue

            status_class = self._extract_status_class(sign_in)
            if status_class == 'interrupted':
                interrupted_ips.append(str(ip_address))
            elif status_class == 'success':
                successful_ips.append(str(ip_address))

        all_ips = set(interrupted_ips) | set(successful_ips)
        unique_ips = len(all_ips)
        interrupted_signins = len(interrupted_ips)
        successful_signins = len(successful_ips)

        if unique_ips >= self.ip_threshold and interrupted_signins >= 1:
            return {
                'detected': True,
                'severity': 'critical' if successful_signins >= 1 else 'medium',
                'details': {
                    'unique_ips': unique_ips,
                    'interrupted_signins': interrupted_signins,
                    'successful_signins': successful_signins,
                    'ip_addresses': sorted(all_ips)[:5],
                    'time_window_hours': self.time_window_hours,
                    'data_source': 'graph_audit_signins'
                }
            }

        return {'detected': False}


class ManyFailedPasswordAttempts(PatternAnalyzer):
    tag_name = 'many_failed_password_attempts'
    default_severity = 'low'

    def __init__(self, threshold=10, time_window_hours=24):
        self.threshold = threshold
        self.time_window_hours = time_window_hours

    def _extract_status_class(self, sign_in):
        status = sign_in.get('status') or {}
        if isinstance(status, dict):
            error_code = status.get('errorCode')
            failure_reason = str(status.get('failureReason') or '')
            additional_details = str(status.get('additionalDetails') or '')
        else:
            error_code = None
            failure_reason = ''
            additional_details = ''

        try:
            error_code = int(error_code)
        except (TypeError, ValueError):
            error_code = None

        status_text = f"{failure_reason} {additional_details}".lower()
        if error_code == 0:
            return 'success'
        if 'interrupted' in status_text or 'mfa' in status_text:
            return 'interrupted'
        return 'failed'

    def analyze(self, user_id, db):
        """Detect repeated failed password attempts in a short period."""
        try:
            sign_ins = db.graph_handler.list_all_sign_ins_for_user(user_id, hours=self.time_window_hours)
        except requests.exceptions.HTTPError as exc:
            status_code = getattr(getattr(exc, 'response', None), 'status_code', None)
            if status_code == 403:
                # If sign-in log access is forbidden, skip this analyzer without failing assessment.
                return {'detected': False}
            raise

        failed_attempts = [
            sign_in for sign_in in sign_ins
            if self._extract_status_class(sign_in) == 'failed'
        ]

        failed_attempt_count = len(failed_attempts)
        if failed_attempt_count >= self.threshold:
            most_recent_failed_attempt = max(
                (attempt.get('createdDateTime') for attempt in failed_attempts if attempt.get('createdDateTime')),
                default=None
            )

            return {
                'detected': True,
                'severity': 'low',
                'details': {
                    'failed_attempt_count': failed_attempt_count,
                    'most_recent_failed_attempt': most_recent_failed_attempt,
                    'time_window_hours': self.time_window_hours,
                    'data_source': 'graph_audit_signins'
                }
            }

        return {'detected': False}


class AzureAppPasswordSignins(PatternAnalyzer):
    tag_name = 'azure_app_password_signins'
    default_severity = 'critical'

    def __init__(self, time_window_hours=24):
        self.time_window_hours = time_window_hours

    def analyze(self, user_id, db):
        """Detect failed/interrupted Azure app sign-ins from live Graph sign-in logs."""

        def extract_app_name(sign_in):
            app_name = sign_in.get('appDisplayName') or sign_in.get('resourceDisplayName') or ''
            if not app_name:
                client_app = sign_in.get('clientAppUsed') or ''
                app_name = client_app
            return str(app_name)

        def extract_status(sign_in):
            status = sign_in.get('status') or {}
            if isinstance(status, dict):
                error_code = status.get('errorCode')
                failure_reason = str(status.get('failureReason') or '')
                additional_details = str(status.get('additionalDetails') or '')
            else:
                error_code = None
                failure_reason = ''
                additional_details = ''

            try:
                error_code = int(error_code)
            except (TypeError, ValueError):
                error_code = None

            status_text = f"{failure_reason} {additional_details}".lower()
            if error_code == 0:
                return 'success'
            if 'interrupted' in status_text or 'mfa' in status_text:
                return 'interrupted'
            return 'failed'

        try:
            sign_ins = db.graph_handler.list_all_sign_ins_for_user(user_id, hours=self.time_window_hours)
        except requests.exceptions.HTTPError as exc:
            status_code = getattr(getattr(exc, 'response', None), 'status_code', None)
            if status_code == 403:
                # If sign-in log access is forbidden, skip this analyzer without failing assessment.
                return {'detected': False}
            raise

        azure_attempts = []
        for sign_in in sign_ins:
            app_name = extract_app_name(sign_in)
            if 'azure' not in app_name.lower():
                continue

            status_class = extract_status(sign_in)
            if status_class in ('failed', 'interrupted'):
                azure_attempts.append({
                    'app_name': app_name,
                    'status_class': status_class,
                    'createdDateTime': sign_in.get('createdDateTime'),
                    'ipAddress': sign_in.get('ipAddress'),
                })

        if azure_attempts:
            interrupted_count = sum(1 for attempt in azure_attempts if attempt['status_class'] == 'interrupted')
            failed_count = sum(1 for attempt in azure_attempts if attempt['status_class'] == 'failed')
            return {
                'detected': True,
                'severity': 'critical',
                'details': {
                    'interrupted_signins': interrupted_count,
                    'failed_signins': failed_count,
                    'app_names': sorted({attempt['app_name'] for attempt in azure_attempts})[:5],
                    'attempt_count': len(azure_attempts),
                    'time_window_hours': self.time_window_hours
                }
            }

        return {'detected': False}


class ImpossibleTravel(PatternAnalyzer):
    tag_name = 'impossible_travel'
    default_severity = 'high'
    
    def analyze(self, user_id, db):
        """Detect sign-ins from distant locations in short time."""
        with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    location_city,
                    location_country_code,
                    activity_datetime
                FROM risky_events
                WHERE user_id = %s
                  AND location_city IS NOT NULL
                  AND activity_datetime > NOW() - INTERVAL '48 hours'
                ORDER BY activity_datetime ASC
            """, (user_id,))
            
            events = cur.fetchall()
            
            # different countries within 4 hours
            for i in range(len(events) - 1):
                curr = events[i]
                next_event = events[i + 1]
                
                time_diff = next_event['activity_datetime'] - curr['activity_datetime']
                
                if (curr['location_country_code'] != next_event['location_country_code'] and 
                    time_diff.total_seconds() < 4 * 3600):  # 4 hours
                    return {
                        'detected': True,
                        'severity': 'high',
                        'details': {
                            'from_location': f"{curr['location_city']}, {curr['location_country_code']}",
                            'to_location': f"{next_event['location_city']}, {next_event['location_country_code']}",
                            'time_difference_hours': round(time_diff.total_seconds() / 3600, 1)
                        }
                    }
            
            return {'detected': False}


class AnonymousIPPattern(PatternAnalyzer):
    tag_name = 'anonymous_ip_usage'
    default_severity = 'low'
    
    def analyze(self, user_id, db):
        """Detect access from anonymous/VPN IPs."""
        with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT COUNT(*) as anon_count
                FROM risky_events
                WHERE user_id = %s
                  AND risk_type = 'anonymizedIPAddress'
                  AND activity_datetime > NOW() - INTERVAL '7 days'
            """, (user_id,))
            
            result = cur.fetchone()
            
            if result and result['anon_count'] >= 3:
                return {
                    'detected': True,
                    'severity': 'low',
                    'details': {
                        'anonymous_access_count': result['anon_count']
                    }
                }
            
            return {'detected': False}


class SuccessfulLoginFromKnownRiskyIP(PatternAnalyzer):
    tag_name = 'successful_login_known_risky_ip'
    default_severity = 'high'

    def __init__(self, time_window_hours=24, risky_ip_window_hours=30 * 24):
        self.time_window_hours = time_window_hours
        self.risky_ip_window_hours = risky_ip_window_hours

    def _extract_status_class(self, sign_in):
        status = sign_in.get('status') or {}
        if isinstance(status, dict):
            error_code = status.get('errorCode')
            failure_reason = str(status.get('failureReason') or '')
            additional_details = str(status.get('additionalDetails') or '')
        else:
            error_code = None
            failure_reason = ''
            additional_details = ''

        try:
            error_code = int(error_code)
        except (TypeError, ValueError):
            error_code = None

        status_text = f"{failure_reason} {additional_details}".lower()
        if error_code == 0:
            return 'success'
        if 'interrupted' in status_text or 'mfa' in status_text:
            return 'interrupted'
        return 'failed'

    def _mask_ipv4_24(self, ip_address):
        # Backward-compatible match for older masked IPv4 values like x.y.0.0.
        parts = str(ip_address).split('.')
        if len(parts) != 4:
            return None
        if not all(p.isdigit() for p in parts):
            return None
        return f"{parts[0]}.{parts[1]}.0.0"

    def _normalize_ip(self, ip_address):
        try:
            return ipaddress.ip_address(str(ip_address)).compressed.lower()
        except ValueError:
            return str(ip_address).strip().lower()

    def _mask_ipv6_64(self, ip_address):
        try:
            ip_obj = ipaddress.ip_address(str(ip_address))
        except ValueError:
            return None

        if ip_obj.version != 6:
            return None

        network = ipaddress.ip_network(f"{ip_obj.compressed}/64", strict=False)
        return network.network_address.compressed.lower()

    def _ip_matches_known_risky(self, ip_address, known_risky_ips):
        normalized_known = {self._normalize_ip(ip) for ip in known_risky_ips if ip}
        ip_norm = self._normalize_ip(ip_address)

        if ip_norm in normalized_known:
            return True

        masked = self._mask_ipv4_24(ip_norm)
        if masked and self._normalize_ip(masked) in normalized_known:
            return True

        masked_v6 = self._mask_ipv6_64(ip_norm)
        if masked_v6 and self._normalize_ip(masked_v6) in normalized_known:
            return True

        return False

    def analyze(self, user_id, db):
        """Detect successful sign-ins that come from known risky IP addresses."""
        known_risky_ips = set(db.get_known_risky_ip_addresses(hours=self.risky_ip_window_hours))
        if not known_risky_ips:
            return {'detected': False}

        try:
            sign_ins = db.graph_handler.list_all_sign_ins_for_user(user_id, hours=self.time_window_hours)
        except requests.exceptions.HTTPError as exc:
            status_code = getattr(getattr(exc, 'response', None), 'status_code', None)
            if status_code == 403:
                # If sign-in log access is forbidden, skip this analyzer without failing assessment.
                return {'detected': False}
            raise

        matching_logins = []
        for sign_in in sign_ins:
            if self._extract_status_class(sign_in) != 'success':
                continue

            ip_address = sign_in.get('ipAddress')
            if not ip_address:
                continue

            if not self._ip_matches_known_risky(ip_address, known_risky_ips):
                continue

            app_name = (
                sign_in.get('appDisplayName')
                or sign_in.get('resourceDisplayName')
                or sign_in.get('clientAppUsed')
            )
            matching_logins.append({
                'ip_address': str(ip_address),
                'app_name': app_name,
                'createdDateTime': sign_in.get('createdDateTime')
            })

        if matching_logins:
            return {
                'detected': True,
                'severity': 'high',
                'details': {
                    'known_risky_ip_count': len(known_risky_ips),
                    'matching_login_count': len(matching_logins),
                    'matching_ips': sorted({login['ip_address'] for login in matching_logins})[:5],
                    'apps': sorted({login['app_name'] for login in matching_logins if login.get('app_name')})[:5],
                    'time_window_hours': self.time_window_hours,
                    'risky_ip_window_hours': self.risky_ip_window_hours,
                    'data_source': 'graph_audit_signins'
                }
            }

        return {'detected': False}


# Registry of all analyzers
PATTERN_ANALYZERS = [
    MultipleInterruptedSignins(threshold=5, time_window_hours=24),
    MultiIPSuccessfulInterruptedSignins(ip_threshold=3, time_window_hours=24),
    ManyFailedPasswordAttempts(threshold=10, time_window_hours=24),
    AzureAppPasswordSignins(time_window_hours=24),
    ImpossibleTravel(),
    AnonymousIPPattern(),
    SuccessfulLoginFromKnownRiskyIP(time_window_hours=24, risky_ip_window_hours=30 * 24),
]