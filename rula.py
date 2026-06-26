import json
import os
import base64
import click
from dotenv import load_dotenv
from Graph_Handler import Graph_Handler
from Db_Handler import Db_Handler

#This is the Main entry point for RULA, including the CLI. 

@click.group()
@click.pass_context
def cli(ctx):
    """Welcome to RULA - Risky User Log Analyzer."""
    
    #checks if context exists, if not, creates it
    ctx.ensure_object(dict)

    load_dotenv()

    #add graph handler to context.
    ctx.obj['graph_handler'] = Graph_Handler(
        os.getenv('GRAPH_ENDPOINT'),
        os.getenv('TENANT_ID'),
        os.getenv('CLIENT_ID'),
        os.getenv('CLIENT_SECRET')
    )

    #add db handler to context
    ctx.obj['db_handler'] = Db_Handler(
        os.getenv('DB_HOST'),
        os.getenv('DB_NAME'),
        os.getenv('DB_USER'),
        os.getenv('DB_PASSWORD'),
        ctx.obj['graph_handler']
    )
   

@cli.command()
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def sync(ctx, quiet):
    """Sync all risky users from Azure to database."""
    db = ctx.obj['db_handler']
    
    try:
        if not quiet:
            print("Syncing risky users from Azure to database...")
        
        # DB handler uses graph handler internally
        user_count = db.sync_users()
        
        if not quiet:
            print(f"✓ Sync completed! {user_count} users synced.")
    
    except Exception as e:
        if not quiet:
            print(f"✗ Sync failed: {e}")
            import traceback
            traceback.print_exc()


@cli.command()
@click.argument('email')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def sync_user(ctx, email, quiet):
    """Sync a specific user from Azure to database."""
    db = ctx.obj['db_handler']
    
    try:
        if not quiet:
            print(f"Syncing user {email} from Azure...")
        
        # DB handler uses graph handler internally
        count = db.sync_single_user(email)
        
        if count > 0:
            if not quiet:
                print(f"✓ User synced!")
        else:
            if not quiet:
                print(f"✗ User not found in Azure: {email}")
    
    except Exception as e:
        if not quiet:
            print(f"✗ Sync failed: {e}")

@cli.command()
@click.option('--hours', default=24, type=int, help='Look back N hours (default: 24)')
@click.option('--no-decrypt', '-nod', is_flag=True, help='Show encrypted data (default: decrypt)')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def recent(ctx, hours, no_decrypt, quiet):
    """Show users whose risk status changed in Azure in the past N hours."""
    db = ctx.obj['db_handler']
    
    try:
        results = db.get_recent_changes(hours, decrypt=not no_decrypt)
        recent_users = results['recent_users']
        
        if not quiet:
            print(f"=== Users with risk changes in the last {hours} hours ===\n")
            
            if recent_users:
                for user in recent_users:
                    print(
                        f"  - {user['user_principal_name']} "
                        f"[{user.get('user_type', 'unknown')}]: "
                        f"{user['risk_level']} ({user['risk_detail']})"
                    )
                    print(f"    Risk updated: {user['risk_last_updated_datetime']}")
            else:
                print("  (no recent changes)")
            
            print(f"\nTotal: {len(recent_users)} users")
    
    except Exception as e:
        if not quiet:
            print(f"Error: {e}")

@cli.command()
@click.option('--risk-level', default=None, help='Filter by risk level (e.g., high, medium, low, none, hidden')
@click.option('--risk-state', default=None, help='Filter by risk state, (e.g., atRisk, confirmedSafe, dismissed, remediated)')
@click.option('--no-decrypt', '-nod', is_flag=True, help='Show encrypted data (default: decrypt)')
@click.option('--limit', default=100, type=int, help='Limit results')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def list_users(ctx, risk_level, risk_state, limit, no_decrypt, quiet):
    """List risky users from database."""
    db = ctx.obj['db_handler']
    
    try:
        users = db.get_users(risk_level, risk_state, limit, decrypt=not no_decrypt)
                
        for user in users:
            if not quiet:
                print(
                    f"- {user['user_principal_name']} "
                    f"[{user.get('user_type', 'unknown')}]: "
                    f"{user['risk_level']} ({user['risk_state']})"
                )
        
        if not quiet:
            print(f"\nTotal: {len(users)} users")
    
    except Exception as e:
        if not quiet:
            print(f"Error: {e}")


@cli.command()
@click.argument('email')
@click.option('--no-decrypt', '-nod', is_flag=True, help='Show encrypted data (default: decrypt)')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def user_details(ctx, email, no_decrypt, quiet):
    """Get details for a specific user from database."""
    db = ctx.obj['db_handler']
    
    try:
        # Auto-detect: if input looks encrypted (long base64), use directly
        # Otherwise, encrypt it first
        is_encrypted = len(email) > 50 and not '@' in email
        
        if is_encrypted:
            # Already encrypted
            user = db.get_user_by_encrypted_upn(email, decrypt=not no_decrypt)
        else:
            # Plaintext
            user = db.get_user_by_upn(email, decrypt=not no_decrypt)
        
        if user:
            if not quiet:
                print(json.dumps(dict(user), indent=2, default=str))
        else:
            if not quiet:
                print(f"User not found in database: {email}")
    
    except Exception as e:
        if not quiet:
            print(f"Error: {e}")

@cli.command()
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def last_sync(ctx, quiet):
    """Show info about the last sync."""
    db = ctx.obj['db_handler']
    
    try:
        sync_info = db.get_last_sync()
        
        if sync_info:
            if not quiet:
                print(json.dumps(dict(sync_info), indent=2, default=str))
        else:
            if not quiet:
                print("No sync history found")
    
    except Exception as e:
        if not quiet:
            print(f"Error: {e}")

#old commands
@cli.command()
@click.option('--filter', 'filter_by', default=None, help='Filter expression for risky users i.e. --filter "riskLevel eq \'medium\'"')
@click.option('--select', 'select_by', default=None, help='Fields to select for risky users i.e. --select "userPrincipalName,riskState"')
@click.option('--top', default=None, type=int, help='Limit number of users returned')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode: No printing.' )
@click.pass_context
def fetch(ctx, filter_by, select_by, top, quiet):
    """NO DB: Fetch risky users, filter_by, select fields, and limit results."""
    gh = ctx.obj['graph_handler']
    try:
        risky_users = gh.list_risky_users(filter_by, select_by, top)
        for user in risky_users.get('value', []):
            if not quiet:
                print(f"- {json.dumps(user, indent=2)}")
                # print(f"- {user.get('userPrincipalName')}: {user.get('riskLevel')}")
    except Exception as e:
        if not quiet:
            print(f"Error: {e}")
    return risky_users



@cli.command()
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode: No printing.' )
@click.pass_context
def fetch_all(ctx, quiet):
    """NO DB:Fetch all risky users. For filtering, use just --fetch."""
    count = 0
    gh = ctx.obj['graph_handler']
    try:
        all_risky_users = gh.list_all_risky_users()
        for user in all_risky_users:
            if not quiet:
                print(f"- {json.dumps(user, indent=2)}")
                # print(f"- {user.get('userPrincipalName')}: {user.get('riskLevel')}")
            count += 1
        
        if not quiet:
            print(f"\nTotal Risky Users: {count}")
    except Exception as e:
        if not quiet:
            print(f'Error: {e}') 
    return all_risky_users



@cli.command()
@click.option('--hours', default=24, type=int, show_default=True,
              help='Assess users whose risk was updated in the past N hours')
@click.option('--all-users', is_flag=True,
              help='Assess all users (overrides --hours filter)')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def assess_risk(ctx, hours, all_users, quiet):
    """Run custom risk assessment (defaults to users updated in past 24 hours)."""
    from risk_engine import RiskAssessmentEngine
    
    db = ctx.obj['db_handler']
    engine = RiskAssessmentEngine(db)
    
    try:
        if not quiet:
            if all_users:
                print("Running custom risk assessment on all users...")
            else:
                print(f"Running custom risk assessment on users updated in last {hours} hours...")
        
        results = engine.assess_all_users() if all_users else engine.assess_recent_users(hours=hours)
        
        # Count by risk level
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'none': 0,
        }
        for r in results:
            level = (r.get('assessment') or {}).get('custom_risk_level', 'none')
            if level not in counts:
                level = 'none'
            counts[level] += 1

        total_assessed = len(results)
        users_with_patterns = total_assessed - counts['none']
        
        if not quiet:
            print(f"\n Assessment complete! Results:")
            print(f"  Total Assessed: {total_assessed}")
            print(f"  Users With Patterns: {users_with_patterns}")
            print(f"  Critical: {counts['critical']}")
            print(f"  High: {counts['high']}")
            print(f"  Medium: {counts['medium']}")
            print(f"  Low: {counts['low']}")
            print(f"  None: {counts['none']}")
    
    except Exception as e:
        if not quiet:
            print(f"Error: {e}")


@cli.command()
@click.argument('risk_level')  # critical, high, medium, low
@click.option('--hours', default=24, type=int, help='Look back N hours (default: 24)')
@click.option('--export', type=click.Path(), help='Export to CSV file')
@click.option('--no-decrypt', '-nod', is_flag=True, help='Show encrypted data')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def customrisk(ctx, risk_level, hours, export, no_decrypt, quiet):
    """Show users with custom risk level in past n hours."""
    import csv
    import json
    
    db = ctx.obj['db_handler']
    
    try:
        users = db.get_users_by_custom_risk(
            risk_level,
            hours=hours,
            decrypt=not no_decrypt
        )
        
        if export:
            # Export to CSV
            with open(export, 'w', newline='') as csvfile:
                if users:
                    fieldnames = ['user_principal_name', 'user_display_name', 'user_type',
                                'azure_risk_level', 'azure_risk_state', 'custom_risk_level', 
                                'custom_risk_score', 'active_tags', 'assessed_at']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for user in users:
                        writer.writerow({
                            'user_principal_name': user['user_principal_name'],
                            'user_display_name': user['user_display_name'],
                            'user_type': user.get('user_type', 'unknown'),
                            'azure_risk_level': user['azure_risk_level'],
                            'azure_risk_state': user['azure_risk_state'],
                            'custom_risk_level': user['custom_risk_level'],
                            'custom_risk_score': user['custom_risk_score'],
                            'active_tags': json.dumps(user['active_tags'], default=str),
                            'assessed_at': user['assessed_at'].isoformat()
                        })
            
            if not quiet:
                print(f"✓ Exported {len(users)} users to {export}")
        
        else:
            # Display in terminal
            if not quiet:
                print(f"=== Users with custom risk '{risk_level}' in last {hours} hours ===\n")
                
                for user in users:
                    active_tags = user.get('active_tags') or []

                    print(f"- {user['user_principal_name']} [{user.get('user_type', 'unknown')}]")
                    print(f"  Azure Risk: {user['azure_risk_level']} ({user['azure_risk_state']})")
                    print(f"  Custom Risk: {user['custom_risk_level']} (score: {user['custom_risk_score']})")
                    if active_tags:
                        print("  Tags:")
                        for tag in active_tags:
                            print(f"    - {tag.get('name', 'unknown')} [{tag.get('severity', 'unknown')}]")
                            details = tag.get('details') or {}
                            if details:
                                print(f"      Details: {json.dumps(details, default=str)}")
                    else:
                        print("  Tags: none")
                    print(f"  Assessed: {user['assessed_at']}")
                    print()
                
                print(f"Total: {len(users)} users")
    
    except Exception as e:
        if not quiet:
            print(f"Error: {e}")


@cli.command('debug_roles')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def debug_roles(ctx, quiet):
    """Decode current Graph access token and print app roles."""
    gh = ctx.obj['graph_handler']

    try:
        token = gh.token
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError('Access token is not in JWT format')

        # JWT payload is base64url without padding.
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64.encode('utf-8')).decode('utf-8')
        payload = json.loads(payload_json)

        roles = payload.get('roles', [])
        if not isinstance(roles, list):
            roles = [roles]

        result = {
            'tenant_id': payload.get('tid'),
            'app_id': payload.get('appid'),
            'audience': payload.get('aud'),
            'roles': roles,
            'has_auditlog_read_all': 'AuditLog.Read.All' in roles,
        }

        if not quiet:
            print(json.dumps(result, indent=2, default=str))

    except Exception as e:
        if not quiet:
            print(f"Error: {e}")


#runs cli if rula.py is main entry point
if __name__ == '__main__':
    cli()
