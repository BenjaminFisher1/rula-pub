# Setup and use: 

### Prerequisites: 
- Git
- One of the following:
	- Docker Desktop
	- Docker Engine
	- Podman Desktop (Docker Compatibility Mode Enabled)
- Visual Studio Code
	- VSCode Dev Containers extension: `ms-vscode-remote.remote-containers` 
- An Azure account with at least the **Cloud Application Administrator** role (for app registration)
- A **Microsoft Entra ID P2 license** to access the riskyUsers API

That's it! You're ready to get started.

### Setup: 
1. Clone this repository to your machine.
2. Open the repository folder in VSCode
3. Create `.env` following the structure of .env.example
4. Register rula application in Azure
	  - Copy Tenant ID and Client ID to `.env` 
	  - Create client secret and copy to `.env` ONLY SHOWS ONCE
	  - Grant API Permissions:
		  - IdentityRiskEvent.Read.All
		  - IdentityRiskAgent.Read.All
		  - IdentityRiskyServicePrincipal.Read.All
		  - IdentityRiskyUser.Read.All
		  - RiskPreventionProviders.Read.All
		  - User.Read
		  - User.ReadBasic.All
          - AuditLog.Read.All
5. VSCode should prompt you to "Reopen In Container". Click this option.
6. Wait for containers to build. 

You're now ready to use rula!

### Using Rula:

#### Typical Workflow:
*This is the average use case scenario for rula.*

Sync your users and events from Azure endpoint:
```
python3 rula.py sync
```

Assess risk  using pattern analyzers:
```
python3 rula.py assess-risk 
```

This will output something like:
```
Assessment complete! Results:
  Total Assessed: 25
  Users With Patterns: 16
  Critical: 0
  High: 1
  Medium: 5
  Low: 10
  None: 9
```

View users of chosen risk level (ex. high).
```
python3 rula.py customrisk high
```
Which will show us:

```
fakename@domain.com [student]
  Azure Risk: high (atRisk)
  Custom Risk: high (score: 75)
  Tags:
    - anonymous_ip_usage [low]
      Details: {"anonymous_access_count": 3}
    - impossible_travel [high]
      Details: {"to_location": "Amsterdam, NL", "from_location": "Fontainbleau, US", "time_difference_hours": 0.3}
    - azure_app_password_signins [critical]
      Details: {"app_names": ["Microsoft Azure CLI"], "attempt_count": 18, "failed_signins": 18, "time_window_hours": 24, "interrupted_signins": 0}
    - many_failed_password_attempts [low]
      Details: {"data_source": "graph_audit_signins", "time_window_hours": 24, "failed_attempt_count": 19, "most_recent_failed_attempt": "2026-04-19T07:20:37Z"}
  Assessed: 2026-04-19 15:14:11.150032+00:00


```

Now, the user can take this information, and determine if the user demands immediate attention based off the tags provided. They can then take action in Azure. 

### How to use other commands:
Basic syntax: python3 rula.py --command --flag(s) parameters
Example:        python3 rula.py --recent --hours 12
*This will display users from the DB with a risk status change in the past 12 hours*

#### **Full Command List:**
  - **fetch**         NO DB: Fetch risky users, filter_by, select fields, and limit results
  - **fetch-all**     NO DB: Fetch all risky users.
  - **last-sync**     Show info about the last sync.
  - **list-users**    List risky users from database.
  - **recent**        Show users whose risk status changed in Azure in the past N hours
  - **sync**          Sync all risky users from Azure to database.
  - **sync-user**     Sync a specific user from Azure to database.
  - **user-details**  Get details for a specific user from database.

##### Common flags:
- **--no-decrypt/-nod**  Displays command result without decrypting encrypted values
- **--quiet/-q**   Does not print command result.
 

Project Proposal:
# Capstone Project Proposal: RULA (Risky Users Log Analyzer)

### **PREPARED BY**

Project Lead: Benjamin Fisher

### **OBJECTIVE**
RULA will be a lightweight CLI Application to help an information security team analyze Risky User logs in Microsoft Entra ID more efficiently by reducing time spent sorting through noisy entries and surfacing the most important risks faster. 

Currently, the Risky User section of Microsoft Entra ID offers large amounts of information for Risky Users, but does not provide an efficient way to filter through large quantities of entries. This forces Information Security team members to manually sift through logs, many of which are mostly noise (i.e. failed brute force password attempts) in order to find cases of high concern. 

RULA will provide a shortcut to the "meat" of the Risky User logs, allowing for user-specified filtration based on factors such as the IP address of login attempts, login attempts across a time period, and a risk-severity grading system based on user specified thresholds. 

### **COMPONENTS** 
RULA will consist of four main parts which communicate using REST constraints:

- CLI: Send user requests to Graph Handler, including custom or predefined filtered searches. 
	- Built on the [Click Python Package](https://click.palletsprojects.com/en/stable/) for extensible CLI design and customizable command creation.
	- Allows for output specification (i.e. output to a .csv file)

- Graph Handler: Accept user requests from CLI, forwards them to Entra ID endpoint, and sends response to Encryptkeeper.
	- Use the [Requests Python Library](https://pypi.org/project/requests/) to send requests and receive response from the Microsoft Entra ID Endpoint.
	- Requires creation of a RULA application in Microsoft Graph with IdentityRiskyUser.Read.All permissions 

- Encryptkeeper: Obfuscate sensitive information passing between other components.
	- Implements AES-GCM-SIV for symmetric, nonce-misuse resistance encryption to produce deterministic cypher text via [Cryptography](https://pypi.org/project/cryptography/) to secure sensitive information in a modern manner efficient for large sets of data. 
	- Fetches secured database entries upon user request, requiring the user to provide the AES-GCM-SIV key from .env to decrypt and view sensitive information.

- DB Handler: Manage database operations and requests.
	- Parse secured responses and store to an on-premise Postgresql database.
	- Return secured database entries to the Encryptkeeper.


### **FEATURES**
1. RISK SEVERITY GRADE
	- An in-depth risk scaling system ranging from 1-10 attached to each Risky User entry.
	- Allows for a more focused view of Risky Users without noise entries.
2. EASY DATA FILTRATION
	- Allows the user to build custom filter rulesets via config files
	- Built in predefined search filters hunting for common searches.
3. EFFICIENT DATA STORAGE
	- The user can view previous searches straight from postgresql database, rather than re-running the request to the Entra ID endpoint.
	- Automated database cleanup based on a user specified time frame to keep storage requirements low
4. NO SENSITIVE DATA IN MEMORY
	- Elliptic-Curve Cryptography secures sensitive data of database entries unless decrypted using private key
	- Only information required for searching and metrics will be available in the database.
5. SETUP GUIDE
	- Repo for RULA will contain detailed instructions on how to set up RULA in a new environment
	- Fast and easy process to set up RULA for a new user's Azure


### **TIMELINE**
- (Weeks 1-2)
	- [x] Request permissions and roles necessary for development in Azure
	- [x] Register Application in Microsoft Entra ID
	- [x] Create development environment	
- (Week 3)
	- [x] Build Graph Handler Component
	- [x] Connect Graph Handler to Microsoft Graph Endpoint
- (Weeks 4-5)
	- [x] Build CLI component
	- [x] Connect CLI to Graph Handler
- (Weeks 6-7)
	- [x] Build DB Handler component
	- [x] Create and connect Postgresql database
	- [x] Connect existing components and run tests
- (Week 8)
	- [x] Build EncryptKeeper component
	- [x] Implement AES-GCM-SIV Cryptosystem
- (Weeks 10-11)
	- [x] Implement Configurable Risk-Severity system
	- [x] Configure data filtration options
	- [x] Create common preset search filters 
- (Weeks 12-13)
	- [x] Create and run extensive functionality testing (encrypt test)
	- [x] Output custom risk table to CSV file 
	- [x] Write set-up guide and documentation for future project volunteers
	- [x] Organized representation of project structure
	- [x] Collect user feedback
- (Week 14) Last day of classes 5/5/26, project presentations are 5/6/26
	- [x] Implement final changes and optimizations
	- [x] Present project and finalize setup guide and documentation.

### **EXPECTED OUTCOME**
RULA will be a valuable time saving tool for any information security team whenever they need to analyze Risky User logs. It will cut down on time spent sifting through noise entries, allow for in depth user customization of filtering, and maintain security in all parts of the application. 

The setup guide and documentation will allow any user to set up their own version of RULA for their own Risky User log analysis, as well as provide guidance to future volunteers for the project on how to expand. 

Future volunteers can consider expansions such as adding a GUI, adding more levels of customization to the filtering system, or allowing user specification of different cryptosystems.







