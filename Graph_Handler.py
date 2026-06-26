from urllib import response
import requests
import time
from datetime import datetime, timedelta, timezone

class Graph_Handler: 
    def __init__(self, endpoint, tenant_id, client_id, client_secret):
        self.endpoint = endpoint
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = self.authenticate()

    def authenticate(self):
        #Method to authenticate, called upon instantiation of a graph handler. 
                token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

                token_data = {
                    'grant_type': 'client_credentials',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'scope': 'https://graph.microsoft.com/.default'
                }
                
                response = requests.post(token_url, data=token_data)
                if not response.ok:
                    print(f"Status Code: {response.status_code}")
                    print(f"Error Response: {response.text}")
                response.raise_for_status()  

                token_response = response.json()
                return token_response['access_token']

     
    def build_request(self, path, parameters):
        #general GET request building method.
        url = f"{self.endpoint}/{path}"
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        

        response = requests.get(url, headers=headers, params=parameters)
        response.raise_for_status()  
        return response.json()
    
    #other more specific/common requests here
    
    def list_risky_users(self, filter=None, select=None, top=None):
        #method to list risky users, with optional parameters for filtering, selecting specific fields, and limiting results.
        parameters = {}
        if filter:
            parameters['$filter'] = filter
        if select:
            parameters['$select'] = select
        if top:
            parameters['$top'] = top
        
        return self.build_request('identityProtection/riskyUsers', parameters)

    def list_all_risky_users(self):
        #method to dump ALL risky users. This will be useful to populate database later on.

        temp_all_users = []
        page_count = 0

        #500 is max page size for this endpoint, according to Microsoft documentation
        response = self.list_risky_users(top=500)
        temp_all_users.extend(response.get('value', []))
        page_count+= 1

        print(f"Page {page_count}: Fetched {len(response.get('value', []))} users (Total: {len(temp_all_users)})")
        
        # Paginate through remaining pages
        while '@odata.nextLink' in response:
            # Wait 3 seconds between pages (avoid rate limiting)
            time.sleep(3)
            
            next_url = response['@odata.nextLink']
            response = self._get_next_page_with_retry(next_url)
            
            users_in_page = response.get('value', [])
            temp_all_users.extend(users_in_page)
            page_count += 1
            
            print(f"Page {page_count}: Fetched {len(users_in_page)} users (Total: {len(temp_all_users)})")
        
        print(f"\n✓ Completed! Total pages: {page_count}, Total users: {len(temp_all_users)}")
        
        return temp_all_users
    
    def list_risky_events(self, filter=None, select=None, top=None):
        """Method to list risky events (risk detections) with optional parameters."""
        parameters = {}
        if filter:
            parameters['$filter'] = filter
        if select:
            parameters['$select'] = select
        if top:
            parameters['$top'] = top
        
        return self.build_request('identityProtection/riskDetections', parameters)

    def list_sign_ins(self, filter=None, select=None, top=None):
        """Method to list sign-in logs with optional parameters."""
        parameters = {}
        if filter:
            parameters['$filter'] = filter
        if select:
            parameters['$select'] = select
        if top:
            parameters['$top'] = top

        return self.build_request('auditLogs/signIns', parameters)

    def list_all_sign_ins(self, filter=None, select=None, top=500):
        """Method to dump sign-in logs with optional parameters and pagination."""
        temp_all_sign_ins = []
        page_count = 0

        response = self.list_sign_ins(filter=filter, select=select, top=top)
        temp_all_sign_ins.extend(response.get('value', []))
        page_count += 1

        while '@odata.nextLink' in response:
            time.sleep(3)
            next_url = response['@odata.nextLink']
            response = self._get_next_page_with_retry(next_url)
            sign_ins_in_page = response.get('value', [])
            temp_all_sign_ins.extend(sign_ins_in_page)
            page_count += 1

        return temp_all_sign_ins

    def list_all_sign_ins_for_user(self, user_id, hours=24, top=500):
        """Fetch sign-ins for a user from the past N hours."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_str = since.isoformat().replace('+00:00', 'Z')
        filter_query = f"userId eq '{user_id}' and createdDateTime ge {since_str}"
        select_fields = (
            'id,userId,userDisplayName,userPrincipalName,appDisplayName,'
            'resourceDisplayName,createdDateTime,status,ipAddress,clientAppUsed'
        )
        return self.list_all_sign_ins(filter=filter_query, select=select_fields, top=top)

    def list_all_risky_events(self):
        """Method to dump ALL risky events (risk detections)."""
        temp_all_events = []
        page_count = 0
        
        # Start with first page
        response = self.list_risky_events(top=500)
        temp_all_events.extend(response.get('value', []))
        page_count += 1
        
        print(f"Page {page_count}: Fetched {len(response.get('value', []))} events (Total: {len(temp_all_events)})")
        
        # Paginate through remaining pages
        while '@odata.nextLink' in response:
            # Wait 3 seconds between pages (avoid rate limiting)
            time.sleep(3)
            
            next_url = response['@odata.nextLink']
            response = self._get_next_page_with_retry(next_url)
            
            events_in_page = response.get('value', [])
            temp_all_events.extend(events_in_page)
            page_count += 1
            
            print(f"Page {page_count}: Fetched {len(events_in_page)} events (Total: {len(temp_all_events)})")
        
        print(f"\n✓ Completed! Total pages: {page_count}, Total events: {len(temp_all_events)}")
        
        return temp_all_events
    
    def _get_next_page_with_retry(self, next_url, max_retries=10):
        """
        Fetch next page with automatic retry on rate limiting.
        """
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        for attempt in range(max_retries):
            try:
                response = requests.get(next_url, headers=headers)
                
                # If rate limited (429), wait and retry
                if response.status_code == 429:
                    # Check for Retry-After header
                    retry_after = int(response.headers.get('Retry-After', 120))
                    
                    print(f"Rate limited. Waiting {retry_after} seconds... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(retry_after)
                    continue  # Retry
                
                # Raise for other errors
                response.raise_for_status()
                return response.json()
            
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    # Last attempt, give up
                    raise
                
                # Wait with exponential backoff (up to 5 minutes max)
                wait_time = min(2 ** attempt, 300)  # 1s, 2s, 4s, 8s, ... max 300s
                
                print(f"Request failed: {e}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
        
        raise Exception(f"Failed to fetch page after {max_retries} attempts")

    def _get_next_page(self, next_url):
         #helper method to grab next page while paginating results.
        response = requests.get(next_url,headers={
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'

        })
        response.raise_for_status()  
        return response.json()