from pattern_analyzers import PATTERN_ANALYZERS
from psycopg2.extras import RealDictCursor, Json

class RiskAssessmentEngine:
    """Engine to run pattern analyzers and assess custom risk."""
    
    def __init__(self, db_handler):
        self.db = db_handler
        self.analyzers = PATTERN_ANALYZERS
    
    def assess_user(self, user_id):
        """
        Run all pattern analyzers on a user and calculate custom risk.
        
        Returns:
            dict: Custom risk assessment
        """
        tags_applied = []
        
        # Clear old tags for this user
        self._clear_old_tags(user_id)
        
        # Run all pattern analyzers
        for analyzer in self.analyzers:
            try:
                result = analyzer.analyze(user_id, self.db)
            except Exception:
                # Skip failing analyzers so one integration issue doesn't stop all assessments.
                continue
            
            if result.get('detected'):
                # Apply tag
                tag_id = self._apply_tag(
                    user_id=user_id,
                    tag_name=analyzer.tag_name,
                    severity=result.get('severity', analyzer.default_severity),
                    pattern_data=result.get('details', {})
                )
                
                tags_applied.append({
                    'tag_id': tag_id,
                    'tag_name': analyzer.tag_name,
                    'severity': result['severity']
                })
        
        # Calculate overall custom risk
        assessment = self._calculate_custom_risk(user_id)
        
        # Store assessment
        self._store_assessment(user_id, assessment, tags_applied)
        
        return assessment
    
    def _clear_old_tags(self, user_id):
        """Remove existing tags for this user before re-assessment."""
        with self.db.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM user_risk_tags
                WHERE user_id = %s
            """, (user_id,))
            self.db.conn.commit()
    
    def _apply_tag(self, user_id, tag_name, severity, pattern_data):
        """Apply a risk tag to a user."""
        with self.db.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO user_risk_tags (
                    user_id, tag_name, severity, pattern_data
                ) VALUES (%s, %s, %s, %s)
                RETURNING tag_id
            """, (user_id, tag_name, severity, Json(pattern_data)))
            
            tag_id = cur.fetchone()[0]
            self.db.conn.commit()
            return tag_id
    
    def _calculate_custom_risk(self, user_id):
        """Calculate custom risk level from active tags."""
        with self.db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    tag_name,
                    severity,
                    pattern_data
                FROM user_risk_tags
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
            
            active_tags = cur.fetchall()
        
        if not active_tags:
            return {
                'custom_risk_level': 'none',
                'custom_risk_score': 0,
                'active_tags': []
            }
        
        # Scoring system
        severity_weights = {
            'critical': 40,
            'high': 25,
            'medium': 15,
            'low': 5
        }
        
        total_score = sum(severity_weights.get(tag['severity'], 0) for tag in active_tags)
        
        # Cap at 100
        total_score = min(total_score, 100)

        # Any critical finding should force the overall level to critical.
        has_critical = any((tag.get('severity') or '').lower() == 'critical' for tag in active_tags)
        
        # Convert score to level
        if has_critical:
            level = 'critical'
        elif total_score >= 70:
            level = 'critical'
        elif total_score >= 50:
            level = 'high'
        elif total_score >= 25:
            level = 'medium'
        elif total_score > 0:
            level = 'low'
        else:
            level = 'none'

        # Policy override:
        #Only faculty/staff can be critical.
        #Faculty/staff with high risk are elevated to critical.
        user_type = self.db.get_user_type_by_id(user_id)
        if user_type == 'faculty_staff' and level in ('high', 'critical'):
            level = 'critical'
        elif level == 'critical':
            level = 'high'
        
        return {
            'custom_risk_level': level,
            'custom_risk_score': total_score,
            'active_tags': [
                {
                    'name': tag['tag_name'],
                    'severity': tag['severity'],
                    'details': tag['pattern_data']
                }
                for tag in active_tags
            ]
        }
    
    def _store_assessment(self, user_id, assessment, tags_applied):
        """Store the custom risk assessment."""
        with self.db.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO custom_risk_assessments (
                    user_id, custom_risk_level, custom_risk_score, active_tags
                ) VALUES (%s, %s, %s, %s)
            """, (
                user_id,
                assessment['custom_risk_level'],
                assessment['custom_risk_score'],
                Json(assessment['active_tags'])
            ))
            self.db.conn.commit()
    
    def assess_all_users(self):
        """Run assessment on all risky users."""
        with self.db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM risky_users")
            users = cur.fetchall()
        
        results = []
        for user in users:
            assessment = self.assess_user(user['id'])
            results.append({
                'user_id': user['id'],
                'assessment': assessment
            })
        
        return results

    def assess_recent_users(self, hours=24):
        """Run assessment only for users whose risk was updated in the past N hours."""
        with self.db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id
                FROM risky_users
                WHERE risk_last_updated_datetime > NOW() - INTERVAL '1 hour' * %s
                ORDER BY risk_last_updated_datetime DESC
            """, (hours,))
            users = cur.fetchall()

        results = []
        for user in users:
            assessment = self.assess_user(user['id'])
            results.append({
                'user_id': user['id'],
                'assessment': assessment
            })

        return results