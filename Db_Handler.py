import psycopg2
from psycopg2.extras import execute_values, RealDictCursor, Json
from typing import List, Dict, Any
from Encrypt_Keeper import Encrypt_Keeper

class Db_Handler:
    def __init__(self, host, database, user, password, graph_handler):
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.graph_handler = graph_handler
        self.conn = self.connect()
        self.encrypt_keeper = Encrypt_Keeper()

    #start db connection
    def connect(self):
        return psycopg2.connect(
            host=self.host,
            database=self.database,
            user=self.user,
            password=self.password
        )
    
    #close db connection
    def close(self):
        self.conn.close()

    def _classify_user_type(self, user_principal_name):
        """Classify user type by UPN: students contain at least one digit."""
        if not user_principal_name:
            return 'unknown'
        return 'student' if any(ch.isdigit() for ch in user_principal_name) else 'faculty_staff'



    #sync risky users AND EVENTS from endpoint to db
    def sync_users(self):
        fetch_id = self.start_fetch()

        try:
            #Get all risky users from azure via graph handler
            users=self.graph_handler.list_all_risky_users()

            #Get all risk events from Azure via graph handler
            events= self.graph_handler.list_all_risky_events()

            #save to db
            user_count = self.upsert_users(users)

            event_count = self.upsert_events(events)

            #log completed fetch
            self.complete_fetch(fetch_id, user_count, event_count)

            return user_count
        
        except Exception as e:
            #If fails, rollback
            self.conn.rollback()
            
            #Now mark as failed
            try:
                self.fail_fetch(fetch_id, str(e))
            except:
                pass  # If this fails too, pass
            raise  # raise original error

    def sync_single_user(self, user_principal_name):
        fetch_id = self.start_fetch()
        try:
            # Fetch specific user from Azure
            filter_query = f"userPrincipalName eq '{user_principal_name}'"
            response = self.graph_handler.list_risky_users(filter=filter_query)
            users = response.get('value', [])
            
            if users:
                count = self.upsert_users(users)
                self.complete_fetch(fetch_id, count, 0)
                return count
            else:
                self.complete_fetch(fetch_id, 0, 0)
                return 0
                
        
        
        except Exception as e:
            # Rollback and mark as failed
            self.conn.rollback()
            try:
                self.fail_fetch(fetch_id, str(e))
            except:
                pass
            raise

    #start new fetch run
    def start_fetch(self):
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO fetch_runs (started_at, status)
                VALUES (NOW(), 'running')
                RETURNING fetch_id
            """)
            fetch_id = cur.fetchone()[0]
            self.conn.commit()
            return fetch_id

    #log fetch as failed :(  
    def fail_fetch(self, fetch_id, error_message):
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE fetch_runs SET
                    completed_at = NOW(),
                    status = 'failed',
                    error_message =%s
                WHERE fetch_id =%s
                """, (error_message, fetch_id))
            self.conn.commit()

    #Mark fetch as completed
    def complete_fetch(self, fetch_id, users_synced, events_synced):
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE fetch_runs SET
                    completed_at = NOW(),
                    status = 'completed',
                    users_synced = %s,
                    events_synced = %s
                WHERE fetch_id = %s
            """, (users_synced, events_synced, fetch_id))
            self.conn.commit()

    def get_last_sync(self):
        """Get info about the last sync."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    fetch_id,
                    started_at,
                    completed_at,
                    status,
                    users_synced,
                    events_synced,
                    completed_at - started_at as duration
                FROM fetch_runs
                ORDER BY started_at DESC
                LIMIT 1
            """)
            return cur.fetchone()
        
    #Get recently changed users in n hours (default 24 hours)
    def get_recent_changes(self, hours=24, decrypt=False):
        try: 
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        user_principal_name,
                        user_display_name,
                        risk_level,
                        risk_state,
                        risk_detail,
                        risk_last_updated_datetime,
                        created_at
                    FROM risky_users
                    WHERE risk_last_updated_datetime > NOW() - INTERVAL '1 hour' * %s
                    ORDER BY risk_last_updated_datetime DESC
                """, (hours,))
                recent_users = cur.fetchall()
                
                # Only decrypt if requested
                if decrypt:
                    for user in recent_users:
                        user['user_principal_name'] = self.encrypt_keeper.decrypt(
                            user['user_principal_name']
                        )
                        user['user_display_name'] = self.encrypt_keeper.decrypt(
                            user['user_display_name']
                        )
                        user['user_type'] = self._classify_user_type(user['user_principal_name'])
                else:
                    for user in recent_users:
                        user['user_type'] = 'unknown'
            
            return {
                'recent_users': recent_users
            }
        
        except Exception as e:
            self.conn.rollback()
            raise

    #risky users
    
    #insert/update risky users in db
    def upsert_users(self, users):
        with self.conn.cursor() as cur:
            user_data = [
                (
                    user['id'],
                    self.encrypt_keeper.encrypt(user.get('userPrincipalName')),
                    self.encrypt_keeper.encrypt(user.get('userDisplayName')),
                    user['riskLevel'],
                    user['riskState'],
                    user['riskDetail'],
                    user.get('riskLastUpdatedDateTime'),
                    user.get('isDeleted', False),
                    user.get('isProcessing', False)
                )
                for user in users
            ]

            execute_values(cur, """
                INSERT INTO risky_users (
                           id, user_principal_name, user_display_name, risk_level, risk_state, risk_detail,
                           risk_last_updated_datetime, is_deleted, is_processing, created_at, updated_at)
                        VALUES %s
                        ON CONFLICT (id) DO UPDATE SET
                            user_principal_name = EXCLUDED.user_principal_name,
                            user_display_name = EXCLUDED.user_display_name,
                            risk_level = EXCLUDED.risk_level,
                            risk_state = EXCLUDED.risk_state,
                            risk_detail = EXCLUDED.risk_detail,
                            risk_last_updated_datetime = EXCLUDED.risk_last_updated_datetime,
                            is_deleted = EXCLUDED.is_deleted,
                            is_processing = EXCLUDED.is_processing,
                            updated_at = NOW()
                           """, user_data, template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())")
            
            self.conn.commit()
            return len(users)
        
    #insert/update risky events in db
    def upsert_events(self, events):
        """Insert or update risky events in batch."""
        if not events:
            return 0
        
        try:
            with self.conn.cursor() as cur:
                event_data = [
                    (
                        event['id'],
                        event.get('userId'),
                        self.encrypt_keeper.encrypt(event.get('userPrincipalName')),
                        event.get('activity'),
                        event.get('activityDateTime'),
                        event.get('detectedDateTime'),
                        event.get('lastUpdatedDateTime'),
                        # Graph risk detections commonly expose riskEventType; keep riskType as fallback.
                        event.get('riskType') or event.get('riskEventType'),
                        event.get('riskLevel'),
                        event.get('riskState'),
                        event.get('riskDetail'),
                        self.encrypt_keeper.mask_ip(event.get('ipAddress')) or None,
                        (event.get('location') or {}).get('city'),
                        (event.get('location') or  {}).get('state'),
                        (event.get('location') or {}).get('countryOrRegion'),
                        event.get('userAgent'),
                        Json(event.get('additionalInfo') or {})
                    )
                    for event in events
                ]
                
                execute_values(cur, """
                    INSERT INTO risky_events (
                        event_id, user_id, user_principal_name,
                        activity, activity_datetime, detected_datetime, last_updated_datetime,
                        risk_type, risk_level, risk_state, risk_detail,
                        ip_address, location_city, location_state, location_country_code,
                        user_agent, additional_info,
                        created_at, updated_at
                    ) VALUES %s
                    ON CONFLICT (event_id) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        user_principal_name = EXCLUDED.user_principal_name,
                        activity = EXCLUDED.activity,
                        activity_datetime = EXCLUDED.activity_datetime,
                        detected_datetime = EXCLUDED.detected_datetime,
                        last_updated_datetime = EXCLUDED.last_updated_datetime,
                        risk_type = EXCLUDED.risk_type,
                        risk_level = EXCLUDED.risk_level,
                        risk_state = EXCLUDED.risk_state,
                        risk_detail = EXCLUDED.risk_detail,
                        ip_address = EXCLUDED.ip_address,
                        location_city = EXCLUDED.location_city,
                        location_state = EXCLUDED.location_state,
                        location_country_code = EXCLUDED.location_country_code,
                        user_agent = EXCLUDED.user_agent,
                        additional_info = EXCLUDED.additional_info,
                        updated_at = NOW()
                """, event_data, template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())")
                
                self.conn.commit()
                return len(events)
    
        except Exception as e:
            self.conn.rollback()
            raise
                        
    #get risky users from db with option to filter by risk level/state
    def get_users(self, risk_level=None, risk_state=None, limit=100, decrypt=False):
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM risky_users WHERE 1=1"
                params = []
                
                if risk_level:
                    query += " AND risk_level = %s"
                    params.append(risk_level)
                
                if risk_state:
                    query += " AND risk_state = %s"
                    params.append(risk_state)
                
                query += " ORDER BY updated_at DESC LIMIT %s"
                params.append(limit)
                
                cur.execute(query, params)
                results = cur.fetchall()
                
                # Only decrypt if requested
                if decrypt:
                    for result in results:
                        result['user_principal_name'] = self.encrypt_keeper.decrypt(
                            result['user_principal_name']
                        )
                        result['user_display_name'] = self.encrypt_keeper.decrypt(
                            result['user_display_name']
                        )
                        result['user_type'] = self._classify_user_type(result['user_principal_name'])
                else:
                    for result in results:
                        result['user_type'] = 'unknown'
                
                return results
        
        except Exception as e:
            self.conn.rollback()
            raise
            
    def get_user_by_upn(self, user_principal_name, decrypt=False):
            # Encrypt search term
            encrypted_upn = self.encrypt_keeper.encrypt(user_principal_name)
            
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM risky_users 
                    WHERE user_principal_name = %s
                """, (encrypted_upn,))
                
                result = cur.fetchone()
                
                # Only decrypt if requested
                if result and decrypt:
                    result['user_principal_name'] = self.encrypt_keeper.decrypt(
                        result['user_principal_name']
                    )
                    result['user_display_name'] = self.encrypt_keeper.decrypt(
                        result['user_display_name']
                    )
                    result['user_type'] = self._classify_user_type(result['user_principal_name'])
                elif result:
                    result['user_type'] = 'unknown'
                
                return result

    def get_user_type_by_id(self, user_id):
        """Return user type for a user_id based on decrypted UPN."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT user_principal_name
                FROM risky_users
                WHERE id = %s
            """, (user_id,))

            result = cur.fetchone()
            if not result or not result.get('user_principal_name'):
                return 'unknown'

            decrypted_upn = self.encrypt_keeper.decrypt(result['user_principal_name'])
            return self._classify_user_type(decrypted_upn)

    def has_activity_in_new_paltz_ip_range(self, user_id, ip_prefix='137.140.103'):
        """
        Return True if user has events from the New Paltz IPv4 prefix.

        Supports both precise prefix matching (e.g. 137.140.103.*)
        and masked /16 storage fallback (e.g. 137.140.0.0).
        """
        prefix = (ip_prefix or '').strip().rstrip('.')
        if not prefix:
            return False

        precise_like = f"{prefix}.%"
        octets = prefix.split('.')
        coarse_like = None
        if len(octets) >= 2:
            coarse_like = f"{octets[0]}.{octets[1]}.%"

        with self.conn.cursor() as cur:
            if coarse_like:
                cur.execute("""
                    SELECT COUNT(*)
                    FROM risky_events
                    WHERE user_id = %s
                      AND ip_address IS NOT NULL
                      AND (
                          ip_address::text LIKE %s
                          OR ip_address::text LIKE %s
                      )
                """, (user_id, precise_like, coarse_like))
            else:
                cur.execute("""
                    SELECT COUNT(*)
                    FROM risky_events
                    WHERE user_id = %s
                      AND ip_address IS NOT NULL
                      AND ip_address::text LIKE %s
                """, (user_id, precise_like))

            return (cur.fetchone()[0] or 0) > 0

    def get_known_risky_ip_addresses(self, hours=30*24):
        """Collect risky IP addresses that were surfaced by custom risk tags."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    tag_name,
                    pattern_data
                FROM user_risk_tags
                WHERE created_at > NOW() - make_interval(hours => %s)
                  AND pattern_data IS NOT NULL
                ORDER BY created_at DESC
            """, (hours,))

            rows = cur.fetchall()
            risky_ips = set()

            for row in rows:
                pattern_data = row.get('pattern_data') or {}

                for key in ('ip_addresses', 'matching_ips'):
                    values = pattern_data.get(key) or []
                    if isinstance(values, list):
                        for ip_address in values:
                            if ip_address:
                                risky_ips.add(str(ip_address))

            return sorted(risky_ips)

    #
    def get_user_by_encrypted_upn(self, encrypted_upn, decrypt=False):
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM risky_users 
                WHERE user_principal_name = %s
            """, (encrypted_upn,))
            
            result = cur.fetchone()
            
            # Decrypt if requested
            if result and decrypt:
                result['user_principal_name'] = self.encrypt_keeper.decrypt(
                    result['user_principal_name']
                )
                result['user_display_name'] = self.encrypt_keeper.decrypt(
                    result['user_display_name']
                )
                result['user_type'] = self._classify_user_type(result['user_principal_name'])
            elif result:
                result['user_type'] = 'unknown'
            
            return result
               
    #get all risky users from db
    def get_all_users(self):
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM risky_users ORDER BY updated_at DESC")
            return cur.fetchall()
        
        
    #get risky events w optional filter
    def get_events(self, user_id=None, risk_type=None, limit=100):
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            query = "SELECT * FROM risky_events WHERE 1=1"
            params = []
            
            if user_id:
                query += " AND user_id = %s"
                params.append(user_id)
            
            if risk_type:
                query += " AND risk_type = %s"
                params.append(risk_type)
            
            query += " ORDER BY activity_datetime DESC LIMIT %s"
            params.append(limit)
            
            cur.execute(query, params)
            return cur.fetchall()
        
    #get events for a specific user
    def get_events_for_user(self, user_principal_name, decrypt=False):
        # Encrypt search term
        encrypted_upn = self.encrypt_keeper.encrypt(user_principal_name)
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM risky_events 
                WHERE user_principal_name = %s
                ORDER BY activity_datetime DESC
            """, (encrypted_upn,))
            
            results = cur.fetchall()
            
            # Only decrypt if requested
            if decrypt:
                for result in results:
                    result['user_principal_name'] = self.encrypt_keeper.decrypt(
                        result['user_principal_name']
                    )
            
            return results

    

    def get_users_by_custom_risk(self, custom_risk_level, hours=24, decrypt=False):
        """
        Get users with a specific custom risk level in the past N hours.
        
        Args:
            custom_risk_level: critical, high, etc
            hours: in past n hours (default 24)
            decrypt: default false
        """
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                WITH latest_assessments AS (
                    SELECT DISTINCT ON (user_id)
                        user_id,
                        custom_risk_level,
                        custom_risk_score,
                        active_tags,
                        assessed_at
                    FROM custom_risk_assessments
                    WHERE assessed_at > NOW() - INTERVAL '1 hour' * %s
                    ORDER BY user_id, assessed_at DESC
                )
                SELECT 
                    u.id,
                    u.user_principal_name,
                    u.user_display_name,
                    u.risk_level as azure_risk_level,
                    u.risk_state as azure_risk_state,
                    c.custom_risk_level,
                    c.custom_risk_score,
                    c.active_tags,
                    c.assessed_at
                FROM risky_users u
                JOIN latest_assessments c ON u.id = c.user_id
                WHERE c.custom_risk_level = %s
                ORDER BY c.custom_risk_score DESC, c.assessed_at DESC
            """, (hours, custom_risk_level))
            
            results = cur.fetchall()
            
            # Decrypt if requested
            if decrypt:
                for result in results:
                    result['user_principal_name'] = self.encrypt_keeper.decrypt(
                        result['user_principal_name']
                    )
                    result['user_display_name'] = self.encrypt_keeper.decrypt(
                        result['user_display_name']
                    )
                    result['user_type'] = self._classify_user_type(result['user_principal_name'])
            else:
                for result in results:
                    result['user_type'] = 'unknown'
            
            return results