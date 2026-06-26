from dotenv import load_dotenv
import os
from Graph_Handler import Graph_Handler

load_dotenv()


gh = Graph_Handler(
    endpoint=os.getenv('GRAPH_ENDPOINT'),
    tenant_id=os.getenv('TENANT_ID'),
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET')
)

print("Top 5 Risky Users: (list_risky_users)")
try:
    risky_users = gh.list_risky_users(top=5)
    for user in risky_users.get('value', []):
        print(f"- {user.get('userPrincipalName')}: {user.get('riskLevel')}")
except Exception as e:
    print(f"Error: {e}")

print("\nAll Risky Users: (list_all_risky_users)")
count = 0
try:
    all_risky_users = gh.list_all_risky_users()
    for user in all_risky_users:
        print(f"- {user.get('userPrincipalName')}: {user.get('riskLevel')}")
        count += 1
    print(f"\nTotal Risky Users: {count}")
except Exception as e:
    print(f'Error: {e}') 