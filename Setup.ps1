#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    CPTS Master Lab Setup - Universal Deployment
.DESCRIPTION
    One-click setup for CPTS penetration testing lab
    Works on ANY domain - fully dynamic configuration
.NOTES
    Run on Domain Controller as Domain Admin
#>

param(
    [switch]$Cleanup
)

$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"

# ============================================================================
# DYNAMIC CONFIGURATION - Auto-detects domain settings
# ============================================================================
$DomainDN = (Get-ADDomain).DistinguishedName
$DomainName = (Get-ADDomain).DNSRoot
$NetBIOSName = (Get-ADDomain).NetBIOSName
$DCHostname = $env:COMPUTERNAME
$DCFQDN = "$DCHostname.$DomainName"

# Banner
Write-Host "
===============================================================================
             CPTS LAB ENVIRONMENT SETUP v3.0 (UNIVERSAL)
                 Works on ANY Active Directory Domain
===============================================================================

Domain: $DomainName
NetBIOS: $NetBIOSName
DC: $DCFQDN

WARNING: Creates INTENTIONALLY VULNERABLE configurations!
         For training/testing purposes ONLY!
" -ForegroundColor Cyan

if ($Cleanup) {
    Write-Host "`n[CLEANUP MODE] Removing all vulnerable configurations..." -ForegroundColor Red
    
    # Remove users
    $UsersToRemove = @("svc-sql", "svc-web", "svc-backup", "john.doe", "sarah.connor", "bob.smith", 
                       "alice.johnson", "webadmin", "svc-iis", "helpdesk", "devuser")
    foreach ($User in $UsersToRemove) {
        try {
            Remove-ADUser -Identity $User -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "[+] Removed user: $User" -ForegroundColor Green
        } catch {}
    }
    
    # Remove groups
    $GroupsToRemove = @("Web Admins", "SQL Admins", "SupportStaff", "Developers")
    foreach ($Group in $GroupsToRemove) {
        try {
            Remove-ADGroup -Identity $Group -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "[+] Removed group: $Group" -ForegroundColor Green
        } catch {}
    }
    
    # Remove scheduled tasks
    Unregister-ScheduledTask -TaskName "BackupTask" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "WebMaintenance" -Confirm:$false -ErrorAction SilentlyContinue
    
    # Remove services
    sc.exe delete "VulnService" 2>$null
    
    # Reset registry
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    
    # Remove IIS if installed
    Write-Host "[*] Removing IIS..." -ForegroundColor Yellow
    Remove-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction SilentlyContinue
    
    # Remove web directories
    Remove-Item -Path "C:\inetpub\wwwroot\portal" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\WebBackup" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Scripts" -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "`n[+] Cleanup completed!" -ForegroundColor Green
    exit
}

Write-Host "`n[PRE-CHECK] Cleaning up existing objects..." -ForegroundColor Yellow

# Clean up existing users that might conflict
$UsersToClean = @("svc-sql", "svc-web", "svc-backup", "john.doe", "sarah.connor", "bob.smith", 
                  "alice.johnson", "webadmin", "svc-iis", "helpdesk", "devuser")
foreach ($User in $UsersToClean) {
    $UserExists = Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue
    if ($UserExists) {
        try {
            Remove-ADUser -Identity $User -Confirm:$false -ErrorAction Stop
            Write-Host "  [-] Removed existing user: $User" -ForegroundColor Gray
            Start-Sleep -Milliseconds 500
        } catch {
            Write-Host "  [!] Could not remove $User : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Clean up existing groups
$GroupsToClean = @("Web Admins", "SQL Admins", "SupportStaff", "Developers")
foreach ($Group in $GroupsToClean) {
    $GroupExists = Get-ADGroup -Filter "Name -eq '$Group'" -ErrorAction SilentlyContinue
    if ($GroupExists) {
        try {
            Remove-ADGroup -Identity $Group -Confirm:$false -ErrorAction Stop
            Write-Host "  [-] Removed existing group: $Group" -ForegroundColor Gray
            Start-Sleep -Milliseconds 500
        } catch {
            Write-Host "  [!] Could not remove $Group : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host "  [+] Pre-check completed`n" -ForegroundColor Green
Start-Sleep -Seconds 2

Write-Host "[*] Starting automated lab deployment...`n" -ForegroundColor Yellow

# ============================================================================
# STAGE 0: INSTALL IIS WEB SERVER
# ============================================================================
Write-Host "[STAGE 0] Installing IIS Web Server..." -ForegroundColor Cyan

try {
    $IISInstalled = (Get-WindowsFeature Web-Server).Installed
    if (-not $IISInstalled) {
        Write-Host "  -> Installing IIS components..." -ForegroundColor Gray
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null
        Install-WindowsFeature -Name Web-Asp-Net45 | Out-Null
        Install-WindowsFeature -Name Web-Net-Ext45 | Out-Null
        Write-Host "  [+] IIS installed successfully" -ForegroundColor Green
    } else {
        Write-Host "  [+] IIS already installed" -ForegroundColor Green
    }
} catch {
    Write-Host "  [-] Failed to install IIS: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ============================================================================
# STAGE 1: DEPLOY VULNERABLE WEB APPLICATION
# ============================================================================
Write-Host "`n[STAGE 1] Deploying Vulnerable Web Application..." -ForegroundColor Cyan

$WebRoot = "C:\inetpub\wwwroot\portal"
New-Item -ItemType Directory -Path $WebRoot -Force | Out-Null
New-Item -ItemType Directory -Path "$WebRoot\uploads" -Force | Out-Null

# Create the ASPX file content
$aspxPath = "$WebRoot\default.aspx"
$aspxContent = @'
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<!DOCTYPE html>
<html>
<head>
    <title>XYZ Corp - Employee Portal</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh; 
            margin: 0; 
            padding: 20px; 
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            background: white; 
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 30px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { color: #667eea; margin: 0; }
        .header p { color: #666; margin: 10px 0 0 0; }
        .card { 
            background: white; 
            border-radius: 10px; 
            padding: 30px; 
            margin-bottom: 20px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .card h2 { 
            color: #333; 
            border-bottom: 3px solid #667eea; 
            padding-bottom: 10px; 
            margin-top: 0;
        }
        .form-group { margin-bottom: 20px; }
        .form-group label { 
            display: block; 
            font-weight: 600; 
            margin-bottom: 8px; 
            color: #333;
        }
        .form-group input, .form-group textarea { 
            width: 100%; 
            padding: 12px; 
            border: 2px solid #ddd; 
            border-radius: 5px; 
            box-sizing: border-box;
        }
        .btn { 
            background: #667eea; 
            color: white; 
            padding: 12px 30px; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 14px;
            font-weight: 600;
        }
        .btn:hover { background: #5568d3; }
        .info-box { 
            background: #f0f4ff; 
            border-left: 4px solid #667eea; 
            padding: 15px; 
            margin: 15px 0; 
        }
        .error { color: #dc3545; font-weight: bold; }
        .success { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XYZ Corporation - Employee Portal</h1>
            <p>Employee Self-Service Portal | Internal Use Only</p>
        </div>

        <div class="card">
            <h2>Employee Login</h2>
            <form method="post" runat="server">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" placeholder="Enter your username" />
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" placeholder="Enter your password" />
                </div>
                <asp:Button ID="btnLogin" runat="server" Text="Login" CssClass="btn" OnClick="LoginUser" />
                <asp:Label ID="lblLoginMsg" runat="server" CssClass="error"></asp:Label>
            </form>
            <div class="info-box">
                <strong>Info:</strong> Default credentials have been distributed via email. Contact IT if you need assistance.
            </div>
        </div>

        <div class="card">
            <h2>Employee Directory Search</h2>
            <form method="post" runat="server">
                <div class="form-group">
                    <label>Search by name or department:</label>
                    <input type="text" name="search" placeholder="e.g., John or IT Department" />
                </div>
                <asp:Button ID="btnSearch" runat="server" Text="Search" CssClass="btn" OnClick="SearchEmployee" />
                <asp:Label ID="lblSearchResult" runat="server"></asp:Label>
            </form>
        </div>

        <div class="card">
            <h2>Document Upload Center</h2>
            <form method="post" enctype="multipart/form-data" runat="server">
                <div class="form-group">
                    <label>Document Type:</label>
                    <input type="text" name="docType" placeholder="e.g., Report, Invoice" />
                </div>
                <div class="form-group">
                    <label>Upload File:</label>
                    <asp:FileUpload ID="fileUpload" runat="server" />
                </div>
                <asp:Button ID="btnUpload" runat="server" Text="Upload" CssClass="btn" OnClick="UploadFile" />
                <asp:Label ID="lblUploadMsg" runat="server"></asp:Label>
            </form>
            <div class="info-box">
                Accepted formats: PDF, DOC, DOCX, XLS, XLSX, TXT, PNG, JPG
            </div>
        </div>
    </div>

    <script runat="server">
        protected void LoginUser(object sender, EventArgs e)
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            // VULNERABLE: SQL Injection
            string query = "SELECT * FROM Users WHERE username = '" + username + "' AND password = '" + password + "'";
            lblLoginMsg.Text = "<br><span class='error'>Invalid credentials.</span>";
            
            if (username == "guest" && password == "guest123")
            {
                lblLoginMsg.Text = "<br><span class='success'>Login successful! Welcome, Guest.</span>";
            }
        }
        
        protected void SearchEmployee(object sender, EventArgs e)
        {
            string search = Request.Form["search"];
            if (!string.IsNullOrEmpty(search))
            {
                // VULNERABLE: SQL Injection
                string query = "SELECT * FROM Employees WHERE name LIKE '%" + search + "%'";
                lblSearchResult.Text = "<br><div class='info-box'>Results:<br>John Doe - IT Department<br>Sarah Connor - HR</div>";
            }
        }
        
        protected void UploadFile(object sender, EventArgs e)
        {
            if (fileUpload.HasFile)
            {
                string filename = Path.GetFileName(fileUpload.FileName);
                if (Request.Form["docType"] != null && Request.Form["docType"].Length > 0)
                {
                    string savePath = Server.MapPath("~/uploads/" + filename);
                    try 
                    {
                        // VULNERABLE: Unrestricted file upload
                        fileUpload.SaveAs(savePath);
                        lblUploadMsg.Text = "<br><span class='success'>File uploaded successfully!</span>";
                        lblUploadMsg.Text += "<br>Access at: /portal/uploads/" + filename;
                    }
                    catch (Exception ex)
                    {
                        lblUploadMsg.Text = "<br><span class='error'>Upload failed: " + ex.Message + "</span>";
                    }
                }
            }
        }
    </script>
</body>
</html>
'@

Set-Content -Path $aspxPath -Value $aspxContent -Encoding UTF8

# Create web.config
$webConfigPath = "$WebRoot\web.config"
$webConfigContent = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.web>
    <compilation debug="true" targetFramework="4.5" />
    <customErrors mode="Off"/>
  </system.web>
  <system.webServer>
    <directoryBrowse enabled="true" />
  </system.webServer>
</configuration>
'@

Set-Content -Path $webConfigPath -Value $webConfigContent -Encoding UTF8

# Create backup config file with credentials
$backupConfigPath = "C:\WebBackup"
New-Item -ItemType Directory -Path $backupConfigPath -Force | Out-Null

$backupConfigContent = @"
# XYZ Corp - Backup Configuration

[Database]
Server=172.16.10.50
Database=EmployeeDB
Username=dbadmin
Password=DbP@ssw0rd2024!

[ServiceAccounts]
IISAppPool=svc-iis
IISPassword=IISService123!

[ADCredentials]
SupportStaff=helpdesk
SupportStaffPass=Help2024!
"@

Set-Content -Path "$backupConfigPath\config.txt" -Value $backupConfigContent -Encoding UTF8

# Make backup dir accessible via IIS
try {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "backup" -PhysicalPath "C:\WebBackup" -ErrorAction SilentlyContinue
    Write-Host "  [+] Web application deployed at: http://$DCHostname/portal" -ForegroundColor Green
    Write-Host "  [+] Backup config exposed at: http://$DCHostname/backup" -ForegroundColor Green
} catch {
    Write-Host "  [!] Could not create virtual directory for backup" -ForegroundColor Yellow
}

# ============================================================================
# STAGE 2: CREATE DOMAIN USERS (DYNAMIC SPNs)
# ============================================================================
Write-Host "`n[STAGE 2] Creating Domain Users..." -ForegroundColor Cyan

$Users = @(
    @{Name="John Doe"; SAM="john.doe"; Pass="Welcome2024!"; Desc="IT Support - DCSync rights"},
    @{Name="Sarah Connor"; SAM="sarah.connor"; Pass="Skynet123!"; Desc="HR Manager"},
    @{Name="Bob Smith"; SAM="bob.smith"; Pass="P@ssw0rd"; Desc="Finance Analyst"},
    @{Name="Alice Johnson"; SAM="alice.johnson"; Pass="Alice2024!"; Desc="Marketing Manager"; NoPreAuth=$true},
    @{Name="HelpDesk User"; SAM="helpdesk"; Pass="Help2024!"; Desc="HelpDesk Account"},
    @{Name="Developer"; SAM="devuser"; Pass="Dev@2024"; Desc="Development Account"},
    @{Name="SQL Service"; SAM="svc-sql"; Pass="MyS3rviceP@ss!"; Desc="SQL Server Service"; SPN="MSSQLSvc/sql.$DomainName:1433"},
    @{Name="Web Service"; SAM="svc-web"; Pass="WebS3rv1ce!"; Desc="IIS App Pool"; SPN="HTTP/web.$DomainName"},
    @{Name="IIS Service"; SAM="svc-iis"; Pass="IISService123!"; Desc="IIS App Pool Account"},
    @{Name="Backup Service"; SAM="svc-backup"; Pass="BackupS3rv!"; Desc="Backup Service"; AddToBackupOps=$true},
    @{Name="Web Admin"; SAM="webadmin"; Pass="W3bAdm1n2024!"; Desc="Web Administrator"; AddToDA=$true}
)

foreach ($User in $Users) {
    try {
        $UserParams = @{
            Name = $User.Name
            SamAccountName = $User.SAM
            UserPrincipalName = "$($User.SAM)@$DomainName"
            AccountPassword = (ConvertTo-SecureString $User.Pass -AsPlainText -Force)
            Enabled = $true
            PasswordNeverExpires = $true
            Description = $User.Desc
        }
        
        New-ADUser @UserParams -ErrorAction Stop
        Write-Host "  [+] Created: $($User.SAM)" -ForegroundColor Green
        
        # Wait for AD replication
        Start-Sleep -Milliseconds 300
        
        if ($User.SPN) {
            Set-ADUser -Identity $User.SAM -ServicePrincipalNames @{Add=$User.SPN}
            Write-Host "    -> SPN: $($User.SPN)" -ForegroundColor Gray
        }
        
        if ($User.NoPreAuth) {
            Set-ADAccountControl -Identity $User.SAM -DoesNotRequirePreAuth $true
            Write-Host "    -> AS-REP Roastable" -ForegroundColor Gray
        }
        
        if ($User.AddToBackupOps) {
            Add-ADGroupMember -Identity "Backup Operators" -Members $User.SAM -ErrorAction SilentlyContinue
            Write-Host "    -> Added to Backup Operators" -ForegroundColor Gray
        }
        
        if ($User.AddToDA) {
            Add-ADGroupMember -Identity "Domain Admins" -Members $User.SAM -ErrorAction SilentlyContinue
            Write-Host "    -> Added to Domain Admins" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "  [-] Failed: $($User.SAM) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# STAGE 3: CREATE CUSTOM GROUPS
# ============================================================================
Write-Host "`n[STAGE 3] Creating Security Groups..." -ForegroundColor Cyan

$Groups = @(
    @{Name="SupportStaff"; Desc="Support Staff Team"},
    @{Name="Developers"; Desc="Development Team"},
    @{Name="Web Admins"; Desc="Web Administrators"},
    @{Name="SQL Admins"; Desc="SQL Server Administrators"}
)

foreach ($Group in $Groups) {
    try {
        New-ADGroup -Name $Group.Name -GroupScope Global -GroupCategory Security -Description $Group.Desc -Path "CN=Users,$DomainDN" -ErrorAction Stop
        Write-Host "  [+] Created group: $($Group.Name)" -ForegroundColor Green
        Start-Sleep -Milliseconds 300
    } catch {
        Write-Host "  [-] Failed: $($Group.Name) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Wait for group replication
Start-Sleep -Seconds 2

# Add users to groups and create privilege escalation path
try {
    Add-ADGroupMember -Identity "SupportStaff" -Members "helpdesk" -ErrorAction SilentlyContinue
    Write-Host "  [+] Added helpdesk to SupportStaff group" -ForegroundColor Green
} catch {
    Write-Host "  [-] Failed to add helpdesk to SupportStaff group" -ForegroundColor Red
}

try {
    Add-ADGroupMember -Identity "SQL Admins" -Members "svc-sql","john.doe" -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "Domain Admins" -Members "SQL Admins" -ErrorAction SilentlyContinue
    Write-Host "  [+] Nested SQL Admins -> Domain Admins (ESCALATION PATH)" -ForegroundColor Green
} catch {
    Write-Host "  [-] Failed to create nested group escalation" -ForegroundColor Red
}

try {
    Add-ADGroupMember -Identity "Web Admins" -Members "svc-iis","svc-web" -ErrorAction SilentlyContinue
    Write-Host "  [+] Added service accounts to Web Admins" -ForegroundColor Green
} catch {}

# ============================================================================
# STAGE 4: GPP PASSWORD IN SYSVOL
# ============================================================================
Write-Host "`n[STAGE 4] Planting GPP Password..." -ForegroundColor Cyan

$SysvolPath = "C:\Windows\SYSVOL\sysvol\$DomainName\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups"
if (-not (Test-Path $SysvolPath)) {
    New-Item -ItemType Directory -Path $SysvolPath -Force | Out-Null
}

$gppContent = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="webadmin" image="2">
        <Properties action="U" fullName="Web Administrator" 
                    cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
                    userName="webadmin"/>
    </User>
</Groups>
'@

Set-Content -Path "$SysvolPath\Groups.xml" -Value $gppContent -Encoding UTF8
Write-Host "  [+] GPP password planted: $SysvolPath\Groups.xml" -ForegroundColor Green

# ============================================================================
# STAGE 5: PRIVILEGE ESCALATION VECTORS
# ============================================================================
Write-Host "`n[STAGE 5] Configuring Privilege Escalation..." -ForegroundColor Cyan

# Unquoted Service Path
$ServiceDir = "C:\Program Files\Vulnerable Service"
New-Item -ItemType Directory -Path $ServiceDir -Force | Out-Null
"MZ" | Out-File "$ServiceDir\service.exe" -Encoding ASCII

sc.exe create VulnService binPath= "C:\Program Files\Vulnerable Service\service.exe" start= auto | Out-Null
sc.exe config VulnService obj= "LocalSystem" | Out-Null

$Acl = Get-Acl "C:\Program Files"
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$Acl.SetAccessRule($Ar)
Set-Acl "C:\Program Files" $Acl

Write-Host "  [+] Unquoted service path created" -ForegroundColor Green

# AlwaysInstallElevated
$RegPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$RegPath2 = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if (-not (Test-Path $RegPath1)) { New-Item -Path $RegPath1 -Force | Out-Null }
if (-not (Test-Path $RegPath2)) { New-Item -Path $RegPath2 -Force | Out-Null }
Set-ItemProperty -Path $RegPath1 -Name "AlwaysInstallElevated" -Value 1 -Type DWord
Set-ItemProperty -Path $RegPath2 -Name "AlwaysInstallElevated" -Value 1 -Type DWord
Write-Host "  [+] AlwaysInstallElevated enabled" -ForegroundColor Green

# Vulnerable Scheduled Task
$ScriptDir = "C:\Scripts"
New-Item -ItemType Directory -Path $ScriptDir -Force | Out-Null
"@echo off`necho Running maintenance...`ntimeout /t 5" | Out-File "$ScriptDir\maintenance.bat" -Encoding ASCII

$Acl = Get-Acl $ScriptDir
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$Acl.SetAccessRule($Ar)
Set-Acl $ScriptDir $Acl

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $ScriptDir\maintenance.bat"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "WebMaintenance" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

Write-Host "  [+] Vulnerable scheduled task created" -ForegroundColor Green

# ============================================================================
# STAGE 6: DELEGATION ATTACKS (DYNAMIC)
# ============================================================================
Write-Host "`n[STAGE 6] Configuring Kerberos Delegation..." -ForegroundColor Cyan

try {
    # Use dynamic DC hostname
    Set-ADUser -Identity "svc-web" -Add @{'msDS-AllowedToDelegateTo'=@("cifs/$DCFQDN","cifs/$DCHostname")}
    Write-Host "  [+] Constrained delegation: svc-web -> $DCHostname" -ForegroundColor Green
} catch {
    Write-Host "  [-] Failed to configure delegation: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# STAGE 7: DCSYNC PERMISSIONS
# ============================================================================
Write-Host "`n[STAGE 7] Granting DCSync Rights..." -ForegroundColor Cyan

try {
    $User = Get-ADUser -Identity "john.doe" -ErrorAction Stop
    $UserSID = $User.SID
    
    # Method 1: PowerShell ACL
    $DomainPath = "AD:\$DomainDN"
    $ACL = Get-ACL -Path $DomainPath
    $Identity = [System.Security.Principal.SecurityIdentifier]$UserSID
    
    $GUID1 = New-Object Guid "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    $ACE1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $Identity,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $GUID1,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    
    $GUID2 = New-Object Guid "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    $ACE2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $Identity,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $GUID2,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    
    $ACL.AddAccessRule($ACE1)
    $ACL.AddAccessRule($ACE2)
    Set-ACL -Path $DomainPath -AclObject $ACL
    
    # Method 2: Backup with dsacls
    & dsacls.exe "$DomainDN" /G "$NetBIOSName\john.doe:CA;Replicating Directory Changes" | Out-Null
    & dsacls.exe "$DomainDN" /G "$NetBIOSName\john.doe:CA;Replicating Directory Changes All" | Out-Null
    
    Write-Host "  [+] DCSync rights granted to: john.doe" -ForegroundColor Green
    
    # Verify
    Start-Sleep -Seconds 2
    $VerifyACL = Get-ACL -Path $DomainPath
    $HasReplication = $false
    $HasReplicationAll = $false
    
    foreach ($Access in $VerifyACL.Access) {
        try {
            $AccessSID = ($Access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])).Value
            if ($AccessSID -eq $UserSID.Value) {
                if ($Access.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") {
                    $HasReplication = $true
                }
                if ($Access.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") {
                    $HasReplicationAll = $true
                }
            }
        } catch {
            continue
        }
    }
    
    if ($HasReplication -and $HasReplicationAll) {
        Write-Host "  [+] VERIFIED: DCSync permissions applied" -ForegroundColor Green
    } else {
        Write-Host "  [!] WARNING: DCSync verification incomplete (may still work)" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "  [-] Failed to configure DCSync: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# STAGE 8: WEAKEN SECURITY SETTINGS
# ============================================================================
Write-Host "`n[STAGE 8] Weakening Security..." -ForegroundColor Cyan

# Disable SMB Signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord
Write-Host "  [+] SMB signing disabled" -ForegroundColor Green

# Restart SMB service
try {
    Restart-Service -Name "LanmanServer" -Force -ErrorAction Stop
    Write-Host "  [+] SMB server restarted" -ForegroundColor Green
} catch {
    Write-Host "  [!] SMB restart failed (may require manual restart)" -ForegroundColor Yellow
}

# Weaken LDAP
$NTDSPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
if (-not (Test-Path $NTDSPath)) {
    New-Item -Path $NTDSPath -Force | Out-Null
}
Set-ItemProperty -Path $NTDSPath -Name "LDAPServerIntegrity" -Value 0 -Type DWord
Write-Host "  [+] LDAP signing disabled (requires reboot)" -ForegroundColor Green

# ============================================================================
# STAGE 9: CREATE FLAGS
# ============================================================================
Write-Host "`n[STAGE 9] Planting Flags..." -ForegroundColor Cyan

$FlagPath = "C:\Users\Administrator\Desktop"
if (-not (Test-Path $FlagPath)) { New-Item -ItemType Directory -Path $FlagPath -Force | Out-Null }

$finalFlag = @"
===============================================================================
   CONGRATULATIONS!
   You have successfully compromised the domain!
   
   Domain: $DomainName
   DC: $DCFQDN
   
   FLAG: flag{$($NetBIOSName.ToLower())_d0m41n_pwn3d_cpts_m4st3r_2024}
===============================================================================
"@

Set-Content -Path "$FlagPath\flag.txt" -Value $finalFlag -Encoding UTF8
Write-Host "  [+] Final flag planted" -ForegroundColor Green

"flag{web_server_compromised}" | Out-File "$WebRoot\uploads\flag1.txt" -Encoding UTF8
"flag{credentials_discovered}" | Out-File "C:\WebBackup\flag2.txt" -Encoding UTF8

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Host "`n
===============================================================================
                  CPTS LAB DEPLOYMENT COMPLETE!
===============================================================================
" -ForegroundColor Green

Write-Host "DOMAIN INFORMATION:" -ForegroundColor Cyan
Write-Host "   Domain: $DomainName" -ForegroundColor White
Write-Host "   NetBIOS: $NetBIOSName" -ForegroundColor White
Write-Host "   DC: $DCFQDN" -ForegroundColor White
Write-Host ""

Write-Host "WEB APPLICATION:" -ForegroundColor Cyan
Write-Host "   URL: http://$DCHostname/portal" -ForegroundColor White
Write-Host "   URL: http://$DCFQDN/portal" -ForegroundColor White
Write-Host "   Guest Login: guest / guest123" -ForegroundColor Yellow
Write-Host "   Backup Config: http://$DCHostname/backup/config.txt" -ForegroundColor Yellow
Write-Host ""

Write-Host "CREDENTIALS CREATED:" -ForegroundColor Cyan
Write-Host "   alice.johnson / Alice2024!       (AS-REP Roastable)" -ForegroundColor White
Write-Host "   svc-sql / MyS3rviceP@ss!         (Kerberoastable -> DA)" -ForegroundColor White
Write-Host "   svc-web / WebS3rv1ce!            (Kerberoastable + Delegation)" -ForegroundColor White
Write-Host "   svc-iis / IISService123!         (In web backup config)" -ForegroundColor White
Write-Host "   helpdesk / Help2024!             (In web backup config)" -ForegroundColor White
Write-Host "   john.doe / Welcome2024!          (DCSync rights)" -ForegroundColor White
Write-Host "   webadmin / W3bAdm1n2024!         (Domain Admin, GPP password)" -ForegroundColor White
Write-Host ""

Write-Host "ATTACK CHAIN:" -ForegroundColor Cyan
Write-Host "   1. Enumerate web app -> Find guest creds or exploit upload" -ForegroundColor White
Write-Host "   2. Access /backup/config.txt -> Get service account creds" -ForegroundColor White
Write-Host "   3. Use svc-iis -> Enumerate AD" -ForegroundColor White
Write-Host "   4. AS-REP Roast alice.johnson" -ForegroundColor White
Write-Host "   5. Kerberoast svc-sql (member of DA via SQL Admins)" -ForegroundColor White
Write-Host "   6. OR: Find GPP password in SYSVOL -> webadmin (DA)" -ForegroundColor White
Write-Host "   7. OR: DCSync with john.doe" -ForegroundColor White
Write-Host "   8. Get Administrator hash -> Domain Owned!" -ForegroundColor White
Write-Host ""

Write-Host "IMPORTANT NOTES:" -ForegroundColor Cyan
Write-Host "   - LDAP signing changes require REBOOT to take effect" -ForegroundColor Yellow
Write-Host "   - After reboot, all attack vectors will be fully functional" -ForegroundColor Yellow
Write-Host "   - Script adapts to ANY domain automatically" -ForegroundColor Green
Write-Host ""

Write-Host "TO CLEANUP:" -ForegroundColor Cyan
Write-Host "   Run: .\script.ps1 -Cleanup" -ForegroundColor White
Write-Host ""

Write-Host "NEXT STEP:" -ForegroundColor Cyan
Write-Host "   Reboot the DC: " -NoNewline -ForegroundColor White
Write-Host "Restart-Computer -Force" -ForegroundColor Yellow
Write-Host ""

Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "                        HAPPY HACKING!" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green

Write-Host "`n[!] Remember: This is for TRAINING ONLY. Never deploy in production!" -ForegroundColor Red
Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
