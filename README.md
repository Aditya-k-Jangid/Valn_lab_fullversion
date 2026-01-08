```markdown
# Active Directory Penetration Testing Lab

A vulnerable AD lab environment for practicing CPTS-style penetration testing 
techniques. This lab includes multiple attack vectors and privilege escalation 
paths commonly found in real-world assessments.

## Repository Contents

### `Setup.ps1`
PowerShell script that automatically deploys a vulnerable Active Directory 
environment on your domain controller. 

**Creates:**
- Vulnerable web application (SQL injection, file upload flaws)
- Multiple user accounts with weak configurations
- Misconfigured permissions (DCSync, constrained delegation)
- GPP passwords in SYSVOL
- Several privilege escalation vectors
- Intentionally weakened security settings

**The script is fully dynamic** - adapts to any domain automatically.

### `challenge_guide.html`
Interactive challenge worksheet with 10 progressively difficult tasks 
covering the full attack chain from initial foothold to domain compromise.

**Features:**
- Points system (1000 total points)
- Built-in hints for each challenge
- Answer validation
- Progress tracking

## Setup Instructions

### Prerequisites
- Windows Server with Active Directory Domain Services installed
- Domain Controller role configured
- PowerShell 5.1+ with ActiveDirectory module
- Domain Admin privileges

### Lab Deployment

1. **Download the script** to your Domain Controller

2. **Run as Administrator**:
   ```powershell
   .\Setup.ps1
   ```

3. **Reboot the DC** (required for LDAP signing changes):
   ```powershell
   Restart-Computer -Force
   ```

4. **Access the web application**:
   - URL: `http://DC-HOSTNAME/portal`
   - Guest credentials: `guest / guest123`

### Using the Challenge Guide

1. **Open the HTML file** in any browser:
   ```bash
   # Just double-click the file, or:
   firefox challenge_guide.html
   ```

2. **Work through challenges** in order (they build on each other)

3. **Use hints** if stuck - each challenge has a hint button

4. **Submit answers** to track your progress and score

## Attack Paths Overview

The lab includes multiple routes to domain compromise:

- **Path 1**: Web app → Backup config → AS-REP roasting → Lateral movement
- **Path 2**: GPP password → Instant Domain Admin
- **Path 3**: Kerberoasting → Nested groups → Domain Admin
- **Path 4**: DCSync rights abuse
- **Path 5**: Constrained delegation exploitation

## Cleanup

To remove all vulnerable configurations:

```powershell
.\Setup.ps1 -Cleanup
```

## Important Notes

- **For lab environments only** - never deploy in production
- Script requires Domain Admin privileges
- All configurations are intentionally insecure
- Perfect for OSCP/CPTS/CRTP practice

## Tools You'll Need

- Impacket suite (GetNPUsers, GetUserSPNs, secretsdump, psexec)
- Hashcat or John the Ripper
- Nmap
- Optional: BloodHound, PowerView, CrackMapExec

## Challenge Breakdown

| Challenge | Focus Area | Points |
|-----------|------------|--------|
| 1-2 | Web enumeration & info disclosure | 175 |
| 3-4 | AS-REP roasting & hash cracking | 175 |
| 5 | Kerberoasting | 100 |
| 6 | GPP password exploitation | 125 |
| 7 | DCSync permissions | 125 |
| 8 | Privilege escalation analysis | 100 |
| 9 | Kerberos delegation | 100 |
| 10 | Domain compromise | 100 |

**Total: 1000 points**

## Learning Objectives

- Active Directory enumeration techniques
- Kerberos attacks (AS-REP, Kerberoasting)
- Credential harvesting from various sources
- Permission abuse and privilege escalation
- Lateral movement strategies
- Complete domain compromise methodologies

---

**Happy Hacking!** 
```
