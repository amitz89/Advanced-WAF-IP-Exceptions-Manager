F5 WAF IP Exceptions Manager

A desktop GUI application for managing IP Address Exceptions (whitelist IPs) across F5 BIG-IP Advanced WAF / ASM security policies using the iControl REST API.


Built with Python 3 and Tkinter — no third-party dependencies required.




Features


Connect to any BIG-IP management interface (self-signed TLS supported)
Policy Lookup tab — search, filter, and select one or more ASM policies
IP Lookup tab — add, inspect, and delete IP exceptions with full control over all exception flags
Bulk import — load a text file of IPs, configure each individually or apply settings to all at once, then review before submitting
Check All Policies — search for a specific IP across every loaded policy at once
Delete exceptions — select any row from the results table and remove it, with optional immediate policy apply
Activity Log tab — scrollable console showing every API action with timestamps
Dark, modern UI — F5-branded red/dark theme, responsive layout, keyboard-friendly



Screenshots


Add screenshots of the three tabs here once the tool is running in your environment.




Requirements

RequirementDetailPython3.8 or laterTkinterIncluded with Python on Windows and macOS. Linux may need a separate install (see below).BIG-IPTested on BIG-IP 17.1.x with Advanced WAF / ASM licensed and provisionedNetworkMust be run on a machine with direct HTTPS access to the BIG-IP management interface

Install Tkinter on Linux

bash# Debian / Ubuntu
sudo apt install python3-tk

# Fedora / RHEL / Rocky
sudo dnf install python3-tkinter


Installation

bashgit clone https://github.com/your-username/f5-waf-ip-exceptions-manager.git
cd f5-waf-ip-exceptions-manager
python3 ip-exception-manager.py

No pip install needed — the entire application uses the Python standard library only.


Usage

1. Connect

Fill in the Host/IP, Username, and Password fields at the top of the window and click Connect / Refresh.


Leave Verify TLS certificate unchecked for lab environments with self-signed BIG-IP certificates.
Once connected, the header badge turns green and all ASM policies are loaded automatically.



2. Policy Lookup tab

Use the Search box to filter by policy name or ID. Select one or more policies using Ctrl or Shift click, then:


Click View All Exceptions to load every IP exception for the selected policies into the results table on the IP Lookup tab.
Click Select All to select every visible (filtered) policy at once.



3. IP Lookup tab — Add Exception

Fill in an IP Address or CIDR range (e.g. 1.1.1.5 or 10.0.0.0/24) and optionally a Description, then configure the exception flags:

FlagAPI fieldDescriptionTrusted by Policy BuildertrustedByPolicyBuilderTrust traffic from this IP when building security policy suggestionsNever log requestsneverLogRequestsSuppress all request logging for this IPIgnore anomaliesignoreAnomaliesSkip anomaly detection for traffic from this IPIgnore IP reputationignoreIpReputationIgnore threat intelligence / IP reputation scores for this IPNever learn requestsneverLearnRequestsExclude requests from this IP from Policy Builder learning

Block behavior (blockRequests) is a three-way option, not a simple on/off:

OptionAPI valueMeaningPolicy defaultpolicy-defaultFollow the policy's normal blocking rules (recommended)Never block this IPneverNever block this IP regardless of violationsAlways block this IPalwaysAlways block this IP regardless of violations

Check Apply after adding to activate the change immediately, then click Add Exception.


4. Bulk Import from File

Click Load IPs from File… (in the Add Exception section) to import a list of IPs.

File format — plain text, one entry per line:

# Lines starting with # are ignored
1.1.1.5
10.0.0.0/24
192.168.1.100, Management server
172.16.0.0/16, Internal range


Lines with a comma are split into ip, description.
Both plain IPs and CIDR ranges are supported.
Invalid lines are skipped with a warning — they don't block the rest of the import.


Bulk import wizard:


A step-by-step dialog opens showing each IP one at a time, pre-filled with your current Add Exception settings.
Adjust the bypass options and block behavior for each IP individually using Next / Back.
Or click "Apply these settings to ALL IPs in the list" at any point to skip the per-IP walkthrough and use the same options for every IP (file descriptions are preserved).
A Review screen shows a summary table of every IP and its final settings before anything is sent.
Click Submit to add all IPs to every selected policy, with a single policy apply at the end.



5. IP Lookup tab — Manage Existing Exceptions

View All Exceptions (triggered from the Policy Lookup tab) loads every IP exception for the selected policies into the results table.

Check All Policies searches every loaded policy for an IP you type in the filter box — useful for finding whether a specific IP is already excluded somewhere without knowing which policy it's in. Partial matches are supported (e.g. typing 10.0.0 will surface any exception in the 10.0.0.x range).

Delete Selected removes the selected rows from their respective policies:


Select one or more rows in the table (Ctrl/Shift click for multiple).
Check Apply after deleting if you want the change to take effect immediately.
Click Delete Selected and confirm the prompt.


The table refreshes automatically after every add or delete.


6. Activity Log tab

Every API call, response, error, and status message is written to a scrollable console. Use Clear Log to reset it.


Security Notes


TLS verification is disabled by default (equivalent to curl -k) to support the self-signed certificates typical on BIG-IP management interfaces. For production use with a proper certificate chain, tick Verify TLS certificate.
Basic authentication is used. Your password is held in memory only for the lifetime of the application and is never written to disk.
For automated / scheduled use, consider switching to a BIG-IP auth token (X-F5-Auth-Token) instead of basic auth.



iControl REST API Reference

The tool uses the following BIG-IP iControl REST endpoints:

ActionMethodEndpointList policiesGET/mgmt/tm/asm/policies?$select=name,idList exceptionsGET/mgmt/tm/asm/policies/{id}/whitelist-ipsAdd exceptionPOST/mgmt/tm/asm/policies/{id}/whitelist-ipsDelete exceptionDELETE/mgmt/tm/asm/policies/{id}/whitelist-ips/{entry-id}Apply policyPOST/mgmt/tm/asm/tasks/apply-policy/Check apply statusGET/mgmt/tm/asm/tasks/apply-policy/{task-id}


Tested On


BIG-IP 17.1.x with Advanced WAF / ASM
Python 3.11 / 3.12 on Windows 11 and Ubuntu 24.04



License

MIT — see LICENSE for details.


Author

Amit Zakay
